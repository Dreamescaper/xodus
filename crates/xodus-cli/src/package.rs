use std::collections::HashSet;
use std::io::IsTerminal;

use inquire::Select;
use xodus::XBOX_LIVE_PACKAGES_PC;
use xodus::api::displaycatalog::find_products_by_id;
use xodus::models::displaycatalog::Product;
use xodus::models::packagespc::{PackageDetails, PackageResponse};
use xodus::models::secrets::Token;
use xodus::tokens::TokenManager;

use crate::error::CommandError;

/// How many sub-product hops we follow before giving up. Prevents an unbounded walk over a
/// malformed or adversarial store catalogue.
const MAX_SUB_PRODUCT_DEPTH: usize = 4;

/// Whether a prompt is allowed. A launcher never gets a prompt: either stdin or stderr may be
/// redirected, and `--non-interactive` / `XODUS_NON_INTERACTIVE` always wins.
pub fn allowed(non_interactive: bool, stdin_tty: bool, stderr_tty: bool) -> bool {
    !non_interactive && stdin_tty && stderr_tty
}

/// Options shared by every command that may need to ask the user for a package choice.
#[derive(Debug, Clone, Default)]
pub struct SelectionOptions {
    /// Sub-product id to use when the requested product only lists its packages through other
    /// products (see [`get_content_id`]).
    pub sub_product: Option<String>,
    /// Never prompt, even when both stdin and stderr are terminals.
    pub non_interactive: bool,
}

impl SelectionOptions {
    pub fn prompt_allowed(&self) -> bool {
        allowed(
            self.non_interactive,
            std::io::stdin().is_terminal(),
            std::io::stderr().is_terminal(),
        )
    }
}

/// One entry of a product's sub-product list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubProduct {
    pub id: String,
    pub title: Option<String>,
}

impl SubProduct {
    /// A stable label for the interactive prompt: `Title (ID)` when the catalog has a title.
    pub fn label(&self) -> String {
        match self.title.as_deref().map(str::trim) {
            Some(title) if !title.is_empty() => format!("{title} ({})", self.id),
            _ => self.id.clone(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SubProductChoice {
    Selected(String),
    Prompt,
}

fn format_sub_product_choices(choices: &[SubProduct]) -> String {
    if choices.is_empty() {
        return "  (none)".to_owned();
    }
    choices
        .iter()
        .map(|choice| match choice.title.as_deref().map(str::trim) {
            Some(title) if !title.is_empty() => format!("  {}\t{}", choice.id, title),
            _ => format!("  {}", choice.id),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Decide which sub-product to use without touching the network or the terminal.
///
/// `interactive` says whether a prompt is allowed at all; the caller computes it from the global
/// non-interactive switch plus terminal detection.
pub fn choose_sub_product(
    choices: &[SubProduct],
    flag: Option<&str>,
    interactive: bool,
) -> Result<SubProductChoice, String> {
    if let Some(requested) = flag {
        let requested = requested.trim();
        let Some(choice) = choices
            .iter()
            .find(|choice| choice.id.eq_ignore_ascii_case(requested))
        else {
            return Err(format!(
                "error: unknown sub-product {requested}; valid values:\n{}",
                format_sub_product_choices(choices)
            ));
        };
        return Ok(SubProductChoice::Selected(choice.id.clone()));
    }

    match choices {
        [] => Err("error: no sub-products are available".to_owned()),
        [only] => Ok(SubProductChoice::Selected(only.id.clone())),
        _ if interactive => Ok(SubProductChoice::Prompt),
        _ => Err(format!(
            "error: sub-product selection required; pass --sub-product <id>\n{}",
            format_sub_product_choices(choices)
        )),
    }
}

/// What a single already-parsed product tells us to do next.
#[derive(Debug, PartialEq, Eq)]
enum ProductAnalysis {
    Package(String),
    SubProducts(Vec<String>),
    Error(String),
}

/// Pure decision for one product. `visited` and `depth` describe the path that led here; ids are
/// compared upper-cased so catalogue casing cannot defeat cycle detection.
fn analyze_product(
    product_id: &str,
    product: &Product,
    visited: &HashSet<String>,
    depth: usize,
) -> ProductAnalysis {
    let mut found_package = None;
    let mut subprods: Vec<String> = vec![];
    'o: for availability in &product.display_sku_availabilities {
        for package in &availability.sku.properties.packages {
            if package
                .platform_dependencies
                .iter()
                .any(|dep| dep.platform_name == "Windows.Desktop")
            {
                found_package = Some(package);
                break 'o;
            }
        }
        for availability in &availability.availabilities {
            if let Some(licensing_data) = &availability.licensing_data {
                for satisfies in &licensing_data.satisfying_entitlement_keys {
                    for entitlement_key in &satisfies.entitlement_keys {
                        let key: Vec<&str> = entitlement_key.split(":").collect();
                        if key.len() == 3 && key[0] == "big" {
                            subprods.push(key[1].to_string());
                        }
                    }
                }
            }
        }
    }
    subprods.sort();
    subprods.dedup();

    if let Some(package) = found_package {
        let Some(content_id) = &package.content_id else {
            return ProductAnalysis::Error(
                "ContentId not found, if you believe this is an error, please report it".to_owned(),
            );
        };
        return ProductAnalysis::Package(content_id.clone());
    }

    if subprods.is_empty() {
        return ProductAnalysis::Error(
            "Windows.Desktop package not found, if you believe this is an error, please report it"
                .to_owned(),
        );
    }

    let mut remaining = Vec::new();
    let mut skipped = Vec::new();
    for id in subprods {
        if visited.contains(&id.to_ascii_uppercase()) {
            skipped.push(id);
        } else {
            remaining.push(id);
        }
    }
    if remaining.is_empty() {
        let id = skipped
            .into_iter()
            .next()
            .unwrap_or_else(|| product_id.to_owned());
        return ProductAnalysis::Error(format!("sub-product cycle detected at {id}"));
    }
    if depth >= MAX_SUB_PRODUCT_DEPTH {
        return ProductAnalysis::Error(format!("sub-product depth limit reached at {product_id}"));
    }
    ProductAnalysis::SubProducts(remaining)
}

/// Best-effort display titles for the sub-product ids. A failed catalog lookup just means the
/// choice is shown by id alone, which is still enough to select it.
async fn load_sub_products(
    client: &reqwest::Client,
    ids: &[String],
    market: Option<&str>,
) -> Vec<SubProduct> {
    let market = market.unwrap_or("neutral").to_owned();
    let lookups = ids.iter().cloned().map(|id| {
        let market = market.clone();
        async move {
            let title = find_products_by_id(
                client,
                id.clone(),
                market,
                vec!["en".to_owned(), "neutral".to_owned()],
            )
            .await
            .ok()
            .and_then(|response| response.product.localized_properties)
            .and_then(|properties| properties.into_iter().next())
            .map(|properties| properties.product_title.trim().to_owned())
            .filter(|title| !title.is_empty());
            SubProduct { id, title }
        }
    });
    futures_util::future::join_all(lookups).await
}

pub async fn get_content_id(
    client: &reqwest::Client,
    product: String,
    market: Option<String>,
    selection: &SelectionOptions,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut visited = HashSet::new();
    get_content_id_inner(client, product, market, selection, &mut visited, 0).await
}

async fn get_content_id_inner(
    client: &reqwest::Client,
    product: String,
    market: Option<String>,
    selection: &SelectionOptions,
    visited: &mut HashSet<String>,
    depth: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let displaycatalog = find_products_by_id(
        client,
        product.clone(),
        market.clone().unwrap_or("neutral".to_owned()),
        vec!["en".to_string(), "neutral".to_string()],
    )
    .await
    .map_err(|err| std::io::Error::other(err.without_url()))?;

    visited.insert(product.to_ascii_uppercase());

    match analyze_product(&product, &displaycatalog.product, visited, depth) {
        ProductAnalysis::Package(content_id) => {
            if let Some(sub_product) = selection.sub_product.as_deref() {
                tracing::warn!(
                    "--sub-product {sub_product} ignored because {product} has its own Windows.Desktop package"
                );
            }
            Ok(content_id)
        }
        ProductAnalysis::Error(message) => Err(Box::new(std::io::Error::other(message))),
        ProductAnalysis::SubProducts(subprods) => {
            let choices = load_sub_products(client, &subprods, market.as_deref()).await;
            let choice = choose_sub_product(
                &choices,
                selection.sub_product.as_deref(),
                selection.prompt_allowed(),
            )
            .map_err(std::io::Error::other)?;

            let selected = match choice {
                SubProductChoice::Selected(id) => id,
                SubProductChoice::Prompt => {
                    let labels: Vec<String> = choices.iter().map(SubProduct::label).collect();
                    let Ok(item) = Select::new("Select a sub-product", labels.clone())
                        .with_page_size(30)
                        .prompt()
                    else {
                        return Err(Box::new(std::io::Error::other("Selection failed")));
                    };
                    let Some(index) = labels.iter().position(|label| label == &item) else {
                        return Err(Box::new(std::io::Error::other("Selection failed")));
                    };
                    choices[index].id.clone()
                }
            };

            // The flag only describes the current product; clear it before recursing so it cannot
            // accidentally match a sub-product of the selected product.
            let next = SelectionOptions {
                sub_product: None,
                non_interactive: selection.non_interactive,
            };
            Box::pin(get_content_id_inner(
                client,
                selected,
                market,
                &next,
                visited,
                depth + 1,
            ))
            .await
        }
    }
}

pub async fn get_packages(
    client: &reqwest::Client,
    tokens: &TokenManager,
    content_id: String,
) -> Result<PackageDetails, CommandError> {
    let dev_token = tokens.get_device_sts_token().map_err(|err| {
        CommandError::auth_from(format!("could not read the device token: {err}"), err)
    })?;
    let Token::Legacy(dev_token) = dev_token else {
        return Err(CommandError::auth("Invalid STS token"));
    };
    let user_token = tokens.get_user_sts_token().map_err(|err| {
        CommandError::auth_from(format!("could not read the user token: {err}"), err)
    })?;
    let Token::Legacy(legacy) = user_token else {
        return Err(CommandError::auth("Unsupported user token"));
    };

    let xsts_token =
        xodus::api::xbox::run(client, dev_token, legacy, "http://update.xboxlive.com").await;

    let response = client
        .get(format!(
            "{XBOX_LIVE_PACKAGES_PC}/GetBasePackage/{content_id}"
        ))
        .header("x-xbl-contract-version", "3")
        .header(
            "Authorization",
            xodus::api::xbox::get_xsts_auth_header(xsts_token),
        )
        .send()
        .await
        .map_err(|err| {
            let err = err.without_url();
            CommandError::network_from(format!("could not request the package list: {err}"), err)
        })?;

    let res: PackageResponse = response.json().await.map_err(|err| {
        let err = err.without_url();
        CommandError::network_from(format!("could not read the package list: {err}"), err)
    })?;

    let PackageResponse::Found(package) = res else {
        return Err(CommandError::other(
            "Package was not found, is it owned by the user?",
        ));
    };
    Ok(package)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashSet};

    use xodus::models::displaycatalog::{
        Availability, DisplaySkuAvailability, LicensingData, Package, PlatformDependency, Product,
        SatisfyingEntitlementKey, Sku, SkuProperties,
    };

    use super::{
        ProductAnalysis, SubProduct, SubProductChoice, allowed, analyze_product, choose_sub_product,
    };

    fn choice(id: &str, title: Option<&str>) -> SubProduct {
        SubProduct {
            id: id.to_owned(),
            title: title.map(str::to_owned),
        }
    }

    fn bundle(ids: &[&str]) -> Product {
        Product {
            display_sku_availabilities: vec![DisplaySkuAvailability {
                sku: Sku {
                    properties: SkuProperties { packages: vec![] },
                },
                availabilities: vec![Availability {
                    licensing_data: Some(LicensingData {
                        satisfying_entitlement_keys: vec![SatisfyingEntitlementKey {
                            entitlement_keys: ids
                                .iter()
                                .map(|id| format!("big:{id}:0010"))
                                .collect(),
                        }],
                    }),
                }],
            }],
            localized_properties: None,
        }
    }

    fn game(content_id: &str) -> Product {
        Product {
            display_sku_availabilities: vec![DisplaySkuAvailability {
                sku: Sku {
                    properties: SkuProperties {
                        packages: vec![Package {
                            content_id: Some(content_id.to_owned()),
                            platform_dependencies: vec![PlatformDependency {
                                platform_name: "Windows.Desktop".to_owned(),
                            }],
                        }],
                    },
                },
                availabilities: vec![],
            }],
            localized_properties: None,
        }
    }

    fn walk(products: &BTreeMap<&str, Product>, root: &str) -> Result<String, String> {
        let mut visited = HashSet::new();
        let mut current = root.to_owned();
        let mut depth = 0;
        loop {
            visited.insert(current.to_ascii_uppercase());
            let product = products
                .get(current.as_str())
                .expect("missing test product");
            match analyze_product(&current, product, &visited, depth) {
                ProductAnalysis::Package(content_id) => return Ok(content_id),
                ProductAnalysis::Error(message) => return Err(message),
                ProductAnalysis::SubProducts(choices) => {
                    current = choices.first().cloned().expect("non-empty choices");
                    depth += 1;
                }
            }
        }
    }

    #[test]
    fn prompts_are_allowed_only_with_two_terminals_and_no_override() {
        assert!(allowed(false, true, true));
        assert!(!allowed(true, true, true));
        assert!(!allowed(false, false, true));
        assert!(!allowed(false, true, false));
        assert!(!allowed(true, false, false));
    }

    #[test]
    fn a_single_sub_product_is_used_without_a_prompt() {
        let choices = [choice("9AAAAAAAAAAA", Some("Game"))];
        assert_eq!(
            choose_sub_product(&choices, None, false),
            Ok(SubProductChoice::Selected("9AAAAAAAAAAA".to_owned()))
        );
        assert_eq!(
            choose_sub_product(&choices, None, true),
            Ok(SubProductChoice::Selected("9AAAAAAAAAAA".to_owned()))
        );
    }

    #[test]
    fn a_flag_selects_a_matching_sub_product() {
        let choices = [
            choice("9AAAAAAAAAAA", None),
            choice("9BBBBBBBBBBB", Some("Game")),
        ];
        assert_eq!(
            choose_sub_product(&choices, Some("9bbbbbbbbbbb"), false),
            Ok(SubProductChoice::Selected("9BBBBBBBBBBB".to_owned()))
        );
    }

    #[test]
    fn an_unknown_flag_lists_choices_in_a_stable_layout() {
        let choices = [
            choice("9AAAAAAAAAAA", None),
            choice("9BBBBBBBBBBB", Some("Game")),
        ];
        let error = choose_sub_product(&choices, Some("9CCCCCCCCCCC"), false).unwrap_err();
        assert_eq!(
            error,
            "error: unknown sub-product 9CCCCCCCCCCC; valid values:\n  \
             9AAAAAAAAAAA\n  9BBBBBBBBBBB\tGame"
        );
    }

    #[test]
    fn several_sub_products_prompt_only_when_interactive() {
        let choices = [
            choice("9AAAAAAAAAAA", None),
            choice("9BBBBBBBBBBB", Some("Game")),
        ];
        assert_eq!(
            choose_sub_product(&choices, None, true),
            Ok(SubProductChoice::Prompt)
        );

        let error = choose_sub_product(&choices, None, false).unwrap_err();
        assert_eq!(
            error,
            "error: sub-product selection required; pass --sub-product <id>\n  \
             9AAAAAAAAAAA\n  9BBBBBBBBBBB\tGame"
        );
    }

    #[test]
    fn no_sub_products_is_an_error() {
        assert!(choose_sub_product(&[], None, true).is_err());
        assert!(choose_sub_product(&[], Some("9AAAAAAAAAAA"), true).is_err());
    }

    #[test]
    fn self_loop_sub_product_is_a_cycle() {
        let a = "9AAAAAAAAAAA";
        let products = BTreeMap::from([(a, bundle(&[a]))]);
        assert_eq!(
            walk(&products, a),
            Err(format!("sub-product cycle detected at {a}"))
        );
    }

    #[test]
    fn a_to_b_to_a_is_a_cycle() {
        let a = "9AAAAAAAAAAA";
        let b = "9BBBBBBBBBBB";
        let products = BTreeMap::from([(a, bundle(&[b])), (b, bundle(&[a]))]);
        assert_eq!(
            walk(&products, a),
            Err(format!("sub-product cycle detected at {a}"))
        );
    }

    #[test]
    fn sub_product_depth_is_capped() {
        let ids = [
            "9AAAAAAAAAAA",
            "9BBBBBBBBBBB",
            "9CCCCCCCCCCC",
            "9DDDDDDDDDDD",
            "9EEEEEEEEEEE",
            "9FFFFFFFFFFF",
        ];
        let products = BTreeMap::from([
            (ids[0], bundle(&[ids[1]])),
            (ids[1], bundle(&[ids[2]])),
            (ids[2], bundle(&[ids[3]])),
            (ids[3], bundle(&[ids[4]])),
            (ids[4], bundle(&[ids[5]])),
            (ids[5], game("11111111-1111-4111-8111-111111111111")),
        ]);
        assert_eq!(
            walk(&products, ids[0]),
            Err(format!("sub-product depth limit reached at {}", ids[4]))
        );
    }
}
