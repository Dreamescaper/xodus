//! Read-only Store entitlements for the stored account.
//!
//! Ported from domsvoboda/nexus-backend
//! `crates/xodus-cli/src/commands/library.rs`, with credit. It keeps Nexus's
//! defensive validation and quarantine rules: malformed, conflicting and
//! dependent entitlement rows never become access, while independently
//! verified rows survive. Tokens, account identifiers and renewal details are
//! never written to stdout.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::process::ExitCode;
use std::time::Duration;

use super::api::{APP_VERSION, CALLING_APP_NAME};
use super::session::{prepare_existing, store_ticket};
use super::subscription;
use crate::error::CommandError;
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use xodus::tokens::TokenManager;
use xodus::tokens::store::TokenStoreError;

const ENTITLEMENTS_URL: &str = "https://beige.xboxservices.com/PCGAFD/entitlements?market={market}&language=en-US&appVersion={appVersion}";
const MAX_PAGE_BYTES: usize = 4_194_304;
const MAX_TOTAL_BYTES: usize = 16_777_216;
const MAX_PAGES: usize = 20;
const MAX_ROWS: usize = 10_000;

fn product_id(id: &str) -> bool {
    id.len() == 12
        && id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Row {
    status: String,
    is_trial: bool,
    sharing_source: String,
    end_date: DateTime<Utc>,
    parent: Option<String>,
    special: bool,
    is_positron: bool,
    kind: Option<&'static str>,
}

fn entry(id: &str, item: &Value) -> Result<Row, &'static str> {
    if !product_id(id) || !item.is_object() {
        return Err("entitlement-product");
    }
    let status = item["status"]
        .as_str()
        .filter(|value| value.len() < 40)
        .ok_or("entitlement-status")?;
    let is_trial = item["isTrial"].as_bool().ok_or("entitlement-trial")?;
    let sharing_source = item["sharingSource"]
        .as_str()
        .filter(|value| value.len() < 40)
        .ok_or("entitlement-sharing")?;
    let end_date = item["endDate"]
        .as_str()
        .filter(|value| value.len() < 50)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
        .ok_or("entitlement-expiry")?;
    let parent = match item.get("satisfiedByProductId") {
        None | Some(Value::Null) => None,
        Some(Value::String(id)) if product_id(id) => Some(id.clone()),
        _ => return Err("entitlement-parent"),
    };
    // Unknown special licensing flags never become permanent ownership.
    let special = item
        .get("isPositron")
        .map(|value| value.as_bool() != Some(false))
        .unwrap_or(false);
    let is_positron = item.get("isPositron").and_then(Value::as_bool) == Some(true);
    Ok(Row {
        status: status.to_owned(),
        is_trial,
        sharing_source: sharing_source.to_owned(),
        end_date,
        parent,
        special,
        is_positron,
        kind: product_kind(item),
    })
}

/// Entitlement rows do not always describe what the product is. Only use a
/// known, explicitly supplied product type; never guess from the license alone.
fn product_kind(item: &Value) -> Option<&'static str> {
    ["productType", "productKind", "type", "contentType"]
        .iter()
        .find_map(|key| item.get(*key).and_then(Value::as_str))
        .filter(|value| value.len() <= 40 && !value.chars().any(char::is_control))
        .map(normalize_kind)
}

fn normalize_kind(value: &str) -> &'static str {
    let compact: String = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(|character| character.to_lowercase())
        .collect();
    match compact.as_str() {
        "game" => "game",
        "gameaddon" | "addon" | "dlc" | "downloadablecontent" | "durable" | "consumable" => "addon",
        "application" | "app" | "software" => "app",
        _ => "unknown",
    }
}

// A malformed row is not ownership. Quarantine that ID across all pages and
// omit its dependent rows, while keeping independently verified entitlements.
#[derive(Default)]
struct Entitlements {
    entries: BTreeMap<String, Row>,
    rejected: HashSet<String>,
    reasons: BTreeMap<&'static str, usize>,
    skipped: usize,
    total: usize,
}

impl Entitlements {
    fn add(&mut self, body: &Value) -> Result<(), &'static str> {
        let rows = body["entitlements"]
            .as_object()
            .ok_or("entitlement-shape")?;
        self.total += rows.len();
        if self.total > MAX_ROWS {
            return Err("entitlement-count");
        }
        for (id, item) in rows {
            match entry(id, item) {
                Ok(row) if !self.rejected.contains(id) => {
                    if self.entries.get(id).is_some_and(|old| old != &row) {
                        self.entries.remove(id);
                        self.rejected.insert(id.clone());
                        self.skipped += 2;
                        *self.reasons.entry("entitlements-inconsistent").or_default() += 1;
                    } else {
                        self.entries.insert(id.clone(), row);
                    }
                }
                Ok(_) => self.skipped += 1,
                Err(reason) => {
                    self.skipped += 1;
                    *self.reasons.entry(reason).or_default() += 1;
                    if product_id(id) {
                        self.rejected.insert(id.clone());
                        if self.entries.remove(id).is_some() {
                            self.skipped += 1;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn finish(&mut self) {
        let mut children: HashMap<String, Vec<String>> = HashMap::new();
        for (id, row) in &self.entries {
            if let Some(parent) = &row.parent {
                children.entry(parent.clone()).or_default().push(id.clone());
            }
        }
        let mut queue: VecDeque<String> = self.rejected.iter().cloned().collect();
        while let Some(parent) = queue.pop_front() {
            for child in children.remove(&parent).unwrap_or_default() {
                if self.rejected.insert(child.clone()) {
                    self.entries.remove(&child);
                    self.skipped += 1;
                    queue.push_back(child);
                }
            }
        }
    }

    fn items(&self, now: DateTime<Utc>) -> Vec<Value> {
        self.entries
            .iter()
            .map(|(id, row)| {
                json!({
                    "productId": id,
                    "access": access(id, &self.entries, now),
                    "kind": kind(id, row),
                })
            })
            .collect()
    }
}

fn kind(product_id: &str, row: &Row) -> Value {
    if subscription::is_plan(product_id) {
        Value::String("subscription".into())
    } else {
        row.kind
            .map(|kind| Value::String(kind.into()))
            .unwrap_or(Value::Null)
    }
}

/// Classify a verified row. Parent chains must themselves be licensed; missing
/// or cyclic parents are reported as unverified rather than guessed as access.
fn access(product_id: &str, entries: &BTreeMap<String, Row>, now: DateTime<Utc>) -> &'static str {
    fn walk<'a>(
        product_id: &'a str,
        entries: &'a BTreeMap<String, Row>,
        now: DateTime<Utc>,
        visited: &mut Vec<&'a str>,
    ) -> &'static str {
        if visited.contains(&product_id) || visited.len() >= 16 {
            return "unverified";
        }
        let Some(row) = entries.get(product_id) else {
            return "unverified";
        };
        if row.status != "Active" {
            return if row.status.eq_ignore_ascii_case("Expired") || row.end_date <= now {
                "expired"
            } else {
                "inactive"
            };
        }
        if row.end_date <= now {
            return "expired";
        }
        if row.is_trial {
            return "trial";
        }
        if row.sharing_source != "None" {
            return "shared";
        }
        if row.special && !row.is_positron {
            return "restricted";
        }
        match &row.parent {
            Some(parent) => {
                // A known plan ID without its own row is still enough to infer
                // subscription access. When the plan row is present, however,
                // its state must be walked like any other parent.
                if subscription::is_plan(parent) && !entries.contains_key(parent) {
                    return "gamepass";
                }
                visited.push(product_id);
                let parent_access = walk(parent, entries, now, visited);
                visited.pop();
                match parent_access {
                    "owned" => "owned",
                    "gamepass" => "gamepass",
                    "trial" => "trial",
                    "expired" => "expired",
                    "shared" => "shared",
                    "inactive" => "inactive",
                    "restricted" => "restricted",
                    // An active PC Game Pass plan row is not a game tile, but
                    // its child is Game Pass access.
                    "subscription" => "gamepass",
                    _ => "unverified",
                }
            }
            None if subscription::is_plan(product_id) => "subscription",
            None => "owned",
        }
    }

    walk(product_id, entries, now, &mut Vec::new())
}

fn diagnostic(stage: &'static str, status: u16, count: usize) {
    // Static stage + bounded numeric metadata only, never a response or account.
    eprintln!("XODUS_LIBRARY_DIAGNOSTIC_V1 {stage} {status} {count}");
}

async fn query(
    client: &reqwest::Client,
    tokens: &TokenManager,
    market: &str,
) -> Result<Value, CommandError> {
    if market.len() != 2 || !market.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(CommandError::other(
            "invalid market; use a two-letter Store market such as US",
        ));
    }
    let account = tokens.get_user().map_err(stored_account)?.username;
    let session = prepare_existing(client, tokens).await?;
    let ticket = store_ticket(&session).await?;
    let client = session.client;

    let mut all = Entitlements::default();
    let mut continuation: Option<String> = None;
    let mut seen = HashSet::new();
    let mut total_bytes = 0usize;
    for _ in 0..MAX_PAGES {
        let correlation = format!(
            "{}.0",
            STANDARD_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes())
        );
        let url = ENTITLEMENTS_URL
            .replace("{market}", market)
            .replace("{appVersion}", APP_VERSION);
        let mut request = client
            .get(url)
            .header("Authorization", &ticket)
            .header("X-MS-API-Version", "1.1")
            .header("Calling-App-Name", CALLING_APP_NAME)
            .header("MS-CV", correlation);
        if let Some(ref cursor) = continuation {
            request = request.header("x-ms-ct", cursor);
        }
        let mut response = request.send().await.map_err(|err| {
            CommandError::network_from(format!("could not read the account library: {err}"), err)
        })?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            diagnostic("entitlements-http", status, 0);
            return if status == 401 || status == 403 {
                Err(CommandError::auth(
                    "Microsoft refused the stored sign-in; sign in again",
                ))
            } else {
                Err(CommandError::other(format!(
                    "the account library request failed with HTTP {status}"
                )))
            };
        }
        continuation = match response.headers().get("x-ms-ct") {
            None => None,
            Some(value) => {
                let value = value.to_str().map_err(|_| {
                    CommandError::other("the account library returned an invalid page cursor")
                })?;
                if value.is_empty() {
                    None
                } else if value.len() > 4096 || !seen.insert(value.to_owned()) {
                    return Err(CommandError::other(
                        "the account library returned an invalid page cursor",
                    ));
                } else {
                    Some(value.to_owned())
                }
            }
        };
        if response
            .content_length()
            .is_some_and(|length| length > MAX_PAGE_BYTES as u64)
        {
            return Err(CommandError::other(
                "the account library response was too large",
            ));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|err| {
            CommandError::network_from(format!("could not read the account library: {err}"), err)
        })? {
            total_bytes += chunk.len();
            if bytes.len() + chunk.len() > MAX_PAGE_BYTES || total_bytes > MAX_TOTAL_BYTES {
                return Err(CommandError::other(
                    "the account library response was too large",
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        let page: Value = serde_json::from_slice(&bytes).map_err(|err| {
            CommandError::other_from(
                format!("the account library response was invalid: {err}"),
                err,
            )
        })?;
        all.add(&page).map_err(library_stage)?;

        if continuation.is_none() {
            let current = tokens.get_user().map_err(stored_account)?;
            if current.username != account {
                return Err(CommandError::auth(
                    "the signed-in account changed; run the command again",
                ));
            }
            all.finish();
            for (reason, count) in &all.reasons {
                diagnostic(reason, 0, *count);
            }
            diagnostic(
                if all.skipped > 0 {
                    "partial"
                } else {
                    "complete"
                },
                0,
                all.skipped,
            );
            let now = Utc::now();
            return Ok(json!({
                "schema": 1,
                "items": all.items(now),
                "skipped": all.skipped,
            }));
        }
    }
    Err(CommandError::other(
        "the account library response had too many pages",
    ))
}

fn stored_account(error: TokenStoreError) -> CommandError {
    match error {
        TokenStoreError::NotFound => {
            CommandError::auth("not signed in; run `xodus-cli login` first")
        }
        error => {
            CommandError::other_from(format!("could not read the stored account: {error}"), error)
        }
    }
}

fn library_stage(stage: &'static str) -> CommandError {
    CommandError::other(format!(
        "the account library response was invalid ({stage})"
    ))
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    json_output: bool,
    market: String,
) -> ExitCode {
    let market = market.to_ascii_uppercase();
    match tokio::time::timeout(Duration::from_secs(45), query(client, tokens, &market)).await {
        Ok(Ok(value)) => {
            if json_output {
                println!("{value}");
            } else {
                print_human(&value);
            }
            ExitCode::SUCCESS
        }
        Ok(Err(error)) => {
            error.report();
            error.exit_code()
        }
        Err(_) => {
            let error = CommandError::network("the account library request timed out; try again");
            error.report();
            error.exit_code()
        }
    }
}

fn print_human(value: &Value) {
    let items = value["items"].as_array().cloned().unwrap_or_default();
    if items.is_empty() {
        println!("No account entitlements found.");
        return;
    }
    println!("{:<12}  {:<12}  KIND", "PRODUCT", "ACCESS");
    for item in &items {
        println!(
            "{:<12}  {:<12}  {}",
            item["productId"].as_str().unwrap_or(""),
            item["access"].as_str().unwrap_or(""),
            item["kind"].as_str().unwrap_or("unknown"),
        );
    }
    if let Some(skipped) = value["skipped"].as_u64().filter(|count| *count > 0) {
        println!("{skipped} entitlement record(s) could not be verified.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "9AAAAAAAAAAA";
    const B: &str = "9BBBBBBBBBBB";
    const C: &str = "9CCCCCCCCCCC";
    const PLAN: &str = "CFQ7TTC0KGQ8";

    fn valid() -> Value {
        json!({"status":"Active","isTrial":false,"sharingSource":"None","endDate":"2099-01-01T00:00:00Z"})
    }

    fn page(rows: Vec<(&str, Value)>) -> Value {
        json!({"entitlements": rows.into_iter().map(|(id, row)| (id.to_owned(), row)).collect::<serde_json::Map<String, Value>>()})
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn item_for(id: &str, entries: &BTreeMap<String, Row>) -> Value {
        json!({
            "productId": id,
            "access": access(id, entries, now()),
            "kind": kind(id, &entries[id]),
        })
    }

    #[test]
    fn positron_provenance_is_explicit_boolean_and_never_copied_from_untrusted_fields() {
        for flag in [
            None,
            Some(json!(false)),
            Some(json!(true)),
            Some(Value::Null),
            Some(json!("true")),
            Some(json!(1)),
            Some(json!({"value":true})),
        ] {
            let mut raw = valid();
            if let Some(ref value) = flag {
                raw["isPositron"] = value.clone();
            }
            raw["special"] = json!(false);
            raw["licenseSource"] = json!("owned");
            let parsed = entry(A, &raw).unwrap();
            assert_eq!(
                parsed.is_positron,
                flag.as_ref().and_then(Value::as_bool) == Some(true)
            );
            assert_eq!(
                parsed.special,
                flag.as_ref()
                    .is_some_and(|value| value.as_bool() != Some(false))
            );
        }
    }

    #[test]
    fn conflicting_positron_and_unknown_special_rows_quarantine_their_children() {
        for changed in [json!(false), json!("true"), Value::Null] {
            let mut first = valid();
            first["isPositron"] = json!(true);
            let mut second = valid();
            second["isPositron"] = changed;
            let mut child = valid();
            child["satisfiedByProductId"] = json!(A);
            let mut result = Entitlements::default();
            result
                .add(&page(vec![(A, first), (B, child), (C, valid())]))
                .unwrap();
            result.add(&page(vec![(A, second)])).unwrap();
            result.finish();
            assert_eq!(
                result.entries.keys().cloned().collect::<Vec<_>>(),
                vec![C.to_owned()]
            );
            assert_eq!(result.skipped, 3);
        }
    }

    #[test]
    fn normalized_fixture_reports_owned_gamepass_trial_and_expired_access() {
        let mut rows = Vec::new();
        for (id, flag, status, parent) in [
            (A, json!(true), "Active", None),
            (B, json!(false), "Active", Some(A)),
            (C, json!(false), "Active", None),
            ("9DDDDDDDDDDD", json!("true"), "Active", None),
            ("9EEEEEEEEEEE", json!(true), "Revoked", None),
        ] {
            let mut raw = valid();
            raw["isPositron"] = flag;
            raw["status"] = json!(status);
            if let Some(parent) = parent {
                raw["satisfiedByProductId"] = json!(parent);
            }
            rows.push((id, raw));
        }
        let mut result = Entitlements::default();
        result.add(&page(rows)).unwrap();
        result.finish();
        assert!(result.entries[A].is_positron);
        assert!(!result.entries["9DDDDDDDDDDD"].is_positron);
        assert_eq!(result.items(now()).len(), 5);
        assert_eq!(item_for(A, &result.entries)["access"], "owned");
        assert_eq!(item_for(B, &result.entries)["access"], "owned");
        assert_eq!(item_for(C, &result.entries)["access"], "owned");
        assert_eq!(
            item_for("9EEEEEEEEEEE", &result.entries)["access"],
            "inactive"
        );
    }

    #[test]
    fn malformed_rows_do_not_hide_independent_licenses_or_become_owned() {
        for field in ["status", "isTrial", "sharingSource", "endDate"] {
            let mut bad = valid();
            bad.as_object_mut().unwrap().remove(field);
            let mut result = Entitlements::default();
            result
                .add(&page(vec![
                    (A, valid()),
                    (B, bad),
                    ("console-variant-id", valid()),
                ]))
                .unwrap();
            result.finish();
            assert_eq!(
                result.entries.keys().cloned().collect::<Vec<_>>(),
                vec![A.to_owned()]
            );
            assert_eq!(result.skipped, 2);
            assert!(result.reasons.values().sum::<usize>() >= 2);
        }
    }

    #[test]
    fn invalid_policy_types_and_parent_are_omitted_not_defaulted() {
        for (field, value) in [
            ("isTrial", json!("false")),
            ("sharingSource", Value::Null),
            ("endDate", json!("not-a-date")),
            ("satisfiedByProductId", json!("bad")),
        ] {
            let mut bad = valid();
            bad[field] = value;
            let mut result = Entitlements::default();
            result.add(&page(vec![(A, bad), (B, valid())])).unwrap();
            assert!(!result.entries.contains_key(A));
            assert!(result.entries.contains_key(B));
            assert_eq!(result.skipped, 1);
        }
    }

    #[test]
    fn conflicting_or_invalid_duplicate_is_quarantined_across_every_page() {
        for mut bad in [valid(), Value::Null] {
            if bad.is_object() {
                bad["isTrial"] = json!(true);
            }
            let mut result = Entitlements::default();
            result.add(&page(vec![(A, valid()), (B, valid())])).unwrap();
            result.add(&page(vec![(A, bad)])).unwrap();
            result.add(&page(vec![(A, valid())])).unwrap();
            result.finish();
            assert_eq!(result.entries.len(), 1);
            assert!(result.entries.contains_key(B));
            assert_eq!(result.skipped, 3);
        }
    }

    #[test]
    fn identical_repeated_row_is_not_a_conflict() {
        let mut result = Entitlements::default();
        result.add(&page(vec![(A, valid())])).unwrap();
        result.add(&page(vec![(A, valid())])).unwrap();
        result.finish();
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.skipped, 0);
    }

    #[test]
    fn rejects_envelopes_and_bounds_total_rows_across_pages() {
        for body in [
            Value::Null,
            json!({}),
            json!({"entitlements":[]}),
            json!({"entitlements":null}),
        ] {
            assert_eq!(Entitlements::default().add(&body), Err("entitlement-shape"));
        }
        let mut result = Entitlements {
            total: MAX_ROWS,
            ..Default::default()
        };
        assert_eq!(
            result.add(&page(vec![(A, valid())])),
            Err("entitlement-count")
        );
    }

    #[test]
    fn quarantines_dependent_chains_including_known_subscription_parents() {
        let mut child = valid();
        child["satisfiedByProductId"] = json!(PLAN);
        let mut descendant = valid();
        descendant["satisfiedByProductId"] = json!(A);
        let mut result = Entitlements::default();
        result
            .add(&page(vec![
                (A, child),
                (B, descendant),
                (C, valid()),
                (PLAN, Value::Null),
            ]))
            .unwrap();
        result.finish();
        assert_eq!(
            result.entries.keys().cloned().collect::<Vec<_>>(),
            vec![C.to_owned()]
        );
        assert_eq!(result.skipped, 3);
    }

    #[test]
    fn expired_trial_shared_and_unknown_state_rows_preserve_their_restrictions() {
        for (field, value) in [
            ("isTrial", json!(true)),
            ("sharingSource", json!("Family")),
            ("status", json!("FutureState")),
            ("endDate", json!("2000-01-01T00:00:00Z")),
            ("isPositron", json!(true)),
            ("isPositron", json!("unknown")),
        ] {
            let mut row = valid();
            row[field] = value.clone();
            let mut result = Entitlements::default();
            result.add(&page(vec![(A, row)])).unwrap();
            let actual = &result.entries[A];
            if field == "isPositron" {
                assert!(actual.special);
            }
            if field == "endDate" {
                assert!(actual.end_date < now());
            }
            if field == "isTrial" {
                assert!(actual.is_trial);
            }
            if field == "sharingSource" {
                assert_eq!(actual.sharing_source, "Family");
            }
            if field == "status" {
                assert_eq!(actual.status, "FutureState");
            }
        }
    }

    #[test]
    fn classifies_owned_gamepass_trial_expired_shared_restricted_and_unverified() {
        let mut result = Entitlements::default();
        let mut plan = valid();
        plan["endDate"] = json!("2099-01-01T00:00:00Z");
        let mut gamepass = valid();
        gamepass["satisfiedByProductId"] = json!(PLAN);
        let mut trial = valid();
        trial["isTrial"] = json!(true);
        let mut expired = valid();
        expired["endDate"] = json!("2000-01-01T00:00:00Z");
        let mut shared = valid();
        shared["sharingSource"] = json!("Family");
        let mut restricted = valid();
        restricted["isPositron"] = json!("unknown");
        let mut orphan = valid();
        orphan["satisfiedByProductId"] = json!("9FFFFFFFFFFF");
        result
            .add(&page(vec![
                (PLAN, plan),
                (A, gamepass),
                (B, trial),
                (C, expired),
                ("9DDDDDDDDDDD", shared),
                ("9EEEEEEEEEEE", restricted),
                ("9FFFFFFFFFFF", orphan),
            ]))
            .unwrap();
        result.finish();
        assert_eq!(item_for(PLAN, &result.entries)["access"], "subscription");
        assert_eq!(item_for(A, &result.entries)["access"], "gamepass");
        assert_eq!(item_for(B, &result.entries)["access"], "trial");
        assert_eq!(item_for(C, &result.entries)["access"], "expired");
        assert_eq!(
            item_for("9DDDDDDDDDDD", &result.entries)["access"],
            "shared"
        );
        assert_eq!(
            item_for("9EEEEEEEEEEE", &result.entries)["access"],
            "restricted"
        );
        // The parent row is absent, so the child isn't guessed into access.
        assert_eq!(
            item_for("9FFFFFFFFFFF", &result.entries)["access"],
            "unverified"
        );
    }

    #[test]
    fn present_expired_or_inactive_plan_parent_limits_the_child() {
        let mut expired_plan = valid();
        expired_plan["endDate"] = json!("2000-01-01T00:00:00Z");
        let mut expired_child = valid();
        expired_child["satisfiedByProductId"] = json!(PLAN);
        let mut result = Entitlements::default();
        result
            .add(&page(vec![(PLAN, expired_plan), (A, expired_child)]))
            .unwrap();
        result.finish();
        assert_eq!(item_for(PLAN, &result.entries)["access"], "expired");
        assert_eq!(item_for(A, &result.entries)["access"], "expired");

        let mut inactive_plan = valid();
        inactive_plan["status"] = json!("Revoked");
        let mut inactive_child = valid();
        inactive_child["satisfiedByProductId"] = json!(PLAN);
        let mut result = Entitlements::default();
        result
            .add(&page(vec![(PLAN, inactive_plan), (A, inactive_child)]))
            .unwrap();
        result.finish();
        assert_eq!(item_for(PLAN, &result.entries)["access"], "inactive");
        assert_eq!(item_for(A, &result.entries)["access"], "inactive");
    }

    #[test]
    fn missing_plan_parent_is_inferred_as_gamepass() {
        let mut child = valid();
        child["satisfiedByProductId"] = json!(PLAN);
        let mut result = Entitlements::default();
        result.add(&page(vec![(A, child)])).unwrap();
        result.finish();
        assert_eq!(item_for(A, &result.entries)["access"], "gamepass");
    }

    #[test]
    fn product_type_is_reported_only_when_the_data_supplies_it() {
        let mut game = valid();
        game["productType"] = json!("Game");
        let mut addon = valid();
        addon["productType"] = json!("GameAddOn");
        let mut app = valid();
        app["productKind"] = json!("Application");
        let mut unknown = valid();
        unknown["type"] = json!("SomethingNew");
        let missing = valid();
        let mut result = Entitlements::default();
        result
            .add(&page(vec![
                (A, game),
                (B, addon),
                (C, app),
                ("9DDDDDDDDDDD", unknown),
                ("9EEEEEEEEEEE", missing),
            ]))
            .unwrap();
        result.finish();
        assert_eq!(item_for(A, &result.entries)["kind"], "game");
        assert_eq!(item_for(B, &result.entries)["kind"], "addon");
        assert_eq!(item_for(C, &result.entries)["kind"], "app");
        assert_eq!(item_for("9DDDDDDDDDDD", &result.entries)["kind"], "unknown");
        assert_eq!(
            item_for("9EEEEEEEEEEE", &result.entries)["kind"],
            Value::Null
        );
    }

    #[test]
    fn keeps_only_license_facts_no_tokens_account_or_renewal_details() {
        let row = json!({"status":"Active","isTrial":false,"sharingSource":"None","endDate":"2099-01-01T00:00:00Z","satisfiedByProductId":PLAN,"secret":"not-output"});
        let mut parsed = Entitlements::default();
        parsed
            .add(&json!({"entitlements":{"9AAAAAAAAAAA":row}}))
            .unwrap();
        assert_eq!(parsed.entries[A].parent.as_deref(), Some(PLAN));
        assert_eq!(parsed.skipped, 0);
        assert!(Entitlements::default().add(&json!({})).is_err());
        let mut invalid = Entitlements::default();
        invalid.add(&json!({"entitlements":{"bad":{}}})).unwrap();
        assert!(invalid.entries.is_empty());
        assert_eq!(invalid.skipped, 1);

        let item = item_for(A, &parsed.entries);
        assert_eq!(item["productId"], A);
        assert_eq!(item["access"], "gamepass");
        assert!(item.get("endDate").is_none());
        assert!(item.get("status").is_none());
        assert!(item.get("secret").is_none());
        assert!(item.get("account").is_none());
        assert!(item.get("username").is_none());
    }
}
