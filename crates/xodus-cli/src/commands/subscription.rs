//! Optional PC Game Pass membership read using existing credentials.
//!
//! Ported from domsvoboda/nexus-backend
//! `crates/xodus-cli/src/commands/subscription.rs`, with credit. The upstream
//! keychain cache and saved-account roles are intentionally not ported: the
//! account command only needs a best-effort answer and never provisions.

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use serde_json::{Value, json};

use super::api::{APP_VERSION, CALLING_APP_NAME};
use super::session::{self, ExistingSession};
use crate::error::CommandError;

/// Known PC Game Pass plan product IDs. A child entitlement whose
/// `satisfiedByProductId` is one of these is subscription access, not ownership.
pub(super) const PLANS: &[&str] = &[
    "CFQ7TTC0KGQ8",
    "CFQ7TTC0KHS0",
    "CFQ7TTC0K5DJ",
    "CFQ7TTC0P85B",
    "CFQ7TTC0K6L8",
    "CFQ7TTC10QFD",
];

const SUBSCRIPTION_URL: &str = "https://beige.xboxservices.com/PCGAFD/entitlements/subscriptions?market={market}&language=en-US&appVersion={appVersion}";
const MAX_RESPONSE_BYTES: usize = 262_144;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GamePassStatus {
    Active,
    Inactive,
    Unknown,
}

impl GamePassStatus {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Unknown => "unknown",
        }
    }
}

pub(super) fn is_plan(product_id: &str) -> bool {
    PLANS.contains(&product_id)
}

/// Ask the Store membership endpoint whether any known PC Game Pass plan is
/// active for the stored account.
pub(super) async fn lookup(
    session: &ExistingSession,
    market: &str,
) -> Result<GamePassStatus, CommandError> {
    if market.len() != 2 || !market.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(CommandError::other(
            "invalid market; use a two-letter Store market such as US",
        ));
    }
    let ticket = session::store_ticket(session).await?;
    let correlation = format!(
        "{}.0",
        STANDARD_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes())
    );
    let url = SUBSCRIPTION_URL
        .replace("{market}", market)
        .replace("{appVersion}", APP_VERSION);
    let response = session
        .client
        .post(url)
        .header("Authorization", ticket)
        .header("X-MS-API-Version", "1.1")
        .header("Calling-App-Name", CALLING_APP_NAME)
        .header("MS-CV", correlation)
        .json(&json!({"productIds": PLANS}))
        .send()
        .await
        .map_err(|err| {
            CommandError::network_from(
                format!("could not check the PC Game Pass subscription: {err}"),
                err,
            )
        })?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        return Err(CommandError::other(format!(
            "the PC Game Pass subscription request failed with HTTP {status}"
        )));
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RESPONSE_BYTES as u64)
    {
        return Err(CommandError::other(
            "the PC Game Pass subscription response was too large",
        ));
    }
    let mut bytes = Vec::new();
    let mut response = response;
    while let Some(chunk) = response.chunk().await.map_err(|err| {
        CommandError::network_from(
            format!("could not read the PC Game Pass subscription: {err}"),
            err,
        )
    })? {
        if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(CommandError::other(
                "the PC Game Pass subscription response was too large",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let body: Value = serde_json::from_slice(&bytes).map_err(|err| {
        CommandError::other_from(
            format!("the PC Game Pass subscription response was invalid: {err}"),
            err,
        )
    })?;
    summary(&body, chrono::Utc::now().timestamp())
}

/// Empty or unsupported data is not proof that the account has no subscription.
fn summary(body: &Value, now: i64) -> Result<GamePassStatus, CommandError> {
    let entries = body["entitlements"].as_object().ok_or_else(|| {
        CommandError::other("the PC Game Pass subscription response had an unexpected shape")
    })?;
    if entries.len() > PLANS.len() {
        return Err(CommandError::other(
            "the PC Game Pass subscription response listed too many plans",
        ));
    }
    if entries.is_empty() {
        return Ok(GamePassStatus::Unknown);
    }

    let mut active = false;
    for (id, item) in entries {
        if !is_plan(id) {
            return Ok(GamePassStatus::Unknown);
        }
        let Some(status) = item["status"].as_str() else {
            return Ok(GamePassStatus::Unknown);
        };
        if status != "Active" {
            continue;
        }
        let expires = item["endDate"]
            .as_str()
            .and_then(|date| chrono::DateTime::parse_from_rfc3339(date).ok())
            .map(|date| date.timestamp());
        match expires {
            Some(expires) if expires > now => active = true,
            Some(_) => {}
            // An active row without a usable expiry is not proof of access.
            None => return Ok(GamePassStatus::Unknown),
        }
    }
    if active {
        Ok(GamePassStatus::Active)
    } else {
        Ok(GamePassStatus::Inactive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn active() -> Value {
        json!({"entitlements":{"CFQ7TTC0KGQ8":{"status":"Active","endDate":chrono::DateTime::from_timestamp(NOW+3600,0).unwrap().to_rfc3339(),"autoRenew":true}}})
    }

    #[test]
    fn real_membership_shape_reports_an_active_pc_plan() {
        assert_eq!(summary(&active(), NOW).unwrap(), GamePassStatus::Active);
    }

    #[test]
    fn expired_unknown_unsupported_and_malformed_are_not_active() {
        for value in [
            json!({}),
            json!({"entitlements":{}}),
            json!({"entitlements":{"unknown":{"status":"Active"}}}),
            json!({"entitlements":{"CFQ7TTC0KGQ8":{"status":"Expired"}}}),
        ] {
            assert_ne!(
                summary(&value, NOW).unwrap_or(GamePassStatus::Unknown),
                GamePassStatus::Active
            );
        }
        let mut value = active();
        value["entitlements"]["CFQ7TTC0KGQ8"]["endDate"] = json!("bad");
        assert_eq!(summary(&value, NOW).unwrap(), GamePassStatus::Unknown);
        assert_eq!(
            summary(&active(), NOW + 3601).unwrap(),
            GamePassStatus::Inactive
        );
    }

    #[test]
    fn an_explicitly_expired_plan_is_inactive_but_empty_data_is_unknown() {
        let mut value = active();
        value["entitlements"]["CFQ7TTC0KGQ8"]["status"] = json!("Cancelled");
        assert_eq!(summary(&value, NOW).unwrap(), GamePassStatus::Inactive);
        assert_eq!(
            summary(&json!({"entitlements":{}}), NOW).unwrap(),
            GamePassStatus::Unknown
        );
    }
}
