use std::io::IsTerminal;

use inquire::Select;
use xodus::XBOX_LIVE_PACKAGES_PC;
use xodus::api::displaycatalog::find_products_by_id;
use xodus::models::packagespc::{PackageDetails, PackageResponse};
use xodus::models::secrets::Token;
use xodus::tokens::TokenManager;

use crate::error::CommandError;

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
        !self.non_interactive && std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
    }
}

/// One entry of a product's sub-product list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubProduct {
    pub id: String,
    pub title: Option<String>,
}

impl SubProduct {
    /// A stable label for prompts and error messages: `Title (ID)` when the catalog has a title.
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

fn describe_sub_products(choices: &[SubProduct]) -> String {
    if choices.is_empty() {
        return "none".to_owned();
    }
    choices
        .iter()
        .map(SubProduct::label)
        .collect::<Vec<_>>()
        .join(", ")
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
                "unknown sub-product `{requested}`; valid sub-products: {}",
                describe_sub_products(choices)
            ));
        };
        return Ok(SubProductChoice::Selected(choice.id.clone()));
    }

    match choices {
        [] => Err("this product has no sub-products".to_owned()),
        [only] => Ok(SubProductChoice::Selected(only.id.clone())),
        _ if interactive => Ok(SubProductChoice::Prompt),
        _ => Err(format!(
            "this product contains multiple sub-products; pass one with --sub-product <id>: {}",
            describe_sub_products(choices)
        )),
    }
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
    let displaycatalog = find_products_by_id(
        client,
        product,
        market.clone().unwrap_or("neutral".to_owned()),
        vec!["en".to_string(), "neutral".to_string()],
    )
    .await
    .map_err(|err| std::io::Error::other(err.without_url()))?;

    let product_details = displaycatalog.product;

    let mut found_package = None;
    let mut subprods: Vec<String> = vec![];
    'o: for availability in &product_details.display_sku_availabilities {
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

    let Some(package) = found_package else {
        if subprods.is_empty() {
            return Err(Box::new(std::io::Error::other(
                "Windows.Desktop package not found, if you believe this is an error, please report it",
            )));
        }

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
        return Box::pin(get_content_id(client, selected, market, &next)).await;
    };

    let Some(content_id) = &package.content_id else {
        tracing::error!("ContentId not found, if you believe this is an error, please report it");
        return Err(Box::new(std::io::Error::other(
            "ContentId not found, if you believe this is an error, please report it",
        )));
    };
    Ok(content_id.to_owned())
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
    use super::{SubProduct, SubProductChoice, choose_sub_product};

    fn choice(id: &str, title: Option<&str>) -> SubProduct {
        SubProduct {
            id: id.to_owned(),
            title: title.map(str::to_owned),
        }
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
    fn an_unknown_flag_lists_the_valid_ids_and_titles() {
        let choices = [
            choice("9AAAAAAAAAAA", None),
            choice("9BBBBBBBBBBB", Some("Game")),
        ];
        let error = choose_sub_product(&choices, Some("9CCCCCCCCCCC"), false).unwrap_err();
        assert!(error.contains("9CCCCCCCCCCC"), "{error}");
        assert!(error.contains("9AAAAAAAAAAA"), "{error}");
        assert!(error.contains("Game (9BBBBBBBBBBB)"), "{error}");
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
        assert!(error.contains("--sub-product"), "{error}");
        assert!(error.contains("9AAAAAAAAAAA"), "{error}");
        assert!(error.contains("Game (9BBBBBBBBBBB)"), "{error}");
    }

    #[test]
    fn no_sub_products_is_an_error() {
        assert!(choose_sub_product(&[], None, true).is_err());
        assert!(choose_sub_product(&[], Some("9AAAAAAAAAAA"), true).is_err());
    }
}
