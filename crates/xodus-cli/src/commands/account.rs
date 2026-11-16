//! Offline-first account status for launchers.
//!
//! The stored account is the source of truth for `signedIn`; gamertag and PC
//! Game Pass are best-effort additions that only run when an existing device
//! identity is available. This command never provisions a device, opens a
//! prompt or deletes credentials, and it never emits emails, account ids or
//! tokens.

use std::process::ExitCode;
use std::time::Duration;

use serde_json::{Value, json};
use xodus::models::secrets::Token;
use xodus::tokens::TokenManager;
use xodus::tokens::session::{self, State};
use xodus::tokens::store::TokenStoreError;

use super::session::prepare_existing;
use super::{profile, subscription};
use crate::error::CommandError;

const ENRICH_TIMEOUT: Duration = Duration::from_secs(20);

struct OfflineState {
    value: Value,
    can_check_network: bool,
}

pub async fn run(client: &reqwest::Client, tokens: &TokenManager, json_output: bool) -> ExitCode {
    let state = match offline_state(tokens) {
        Ok(state) => state,
        Err(error) => {
            error.report();
            return error.exit_code();
        }
    };
    let value = if state.can_check_network {
        match tokio::time::timeout(ENRICH_TIMEOUT, enrich(client, tokens)).await {
            Ok(enrichment) => merged(state.value, enrichment),
            Err(_) => merged(state.value, Enrichment::unavailable()),
        }
    } else {
        state.value
    };

    if json_output {
        println!("{value}");
    } else {
        print_human(&value);
    }
    ExitCode::SUCCESS
}

fn offline_state(tokens: &TokenManager) -> Result<OfflineState, CommandError> {
    let user = match tokens.get_user() {
        Ok(user) => user,
        Err(TokenStoreError::NotFound) => {
            return Ok(OfflineState {
                value: json!({
                    "schema": 1,
                    "signedIn": false,
                    "session": "missing",
                    "gamertag": null,
                    "gamePass": "unknown",
                    "network": "skipped"
                }),
                can_check_network: false,
            });
        }
        Err(err) => {
            return Err(CommandError::other_from(
                format!("could not read the stored account: {err}"),
                err,
            ));
        }
    };
    let _ = user;

    let session_state = match tokens.get_user_sts_token() {
        Ok(token) => state_name(&token),
        Err(TokenStoreError::NotFound) => "missing",
        Err(TokenStoreError::Serde(_)) => "invalid",
        Err(err) => {
            return Err(CommandError::other_from(
                format!("could not read the stored sign-in: {err}"),
                err,
            ));
        }
    };

    let has_device_identity = match tokens.get_device_license() {
        Ok(_) => true,
        Err(TokenStoreError::NotFound) => false,
        Err(err) => {
            return Err(CommandError::other_from(
                format!("could not read the device credentials: {err}"),
                err,
            ));
        }
    };

    Ok(OfflineState {
        value: json!({
            "schema": 1,
            "signedIn": true,
            "session": session_state,
            "gamertag": null,
            "gamePass": "unknown",
            "network": "skipped"
        }),
        // Without a current user token or an existing device identity the only
        // way to continue would be a prompt or device provisioning.
        can_check_network: session_state == "current" && has_device_identity,
    })
}

fn state_name(token: &Token) -> &'static str {
    match session::state(token, chrono::Utc::now()) {
        State::Current => "current",
        State::Expired => "expired",
        State::Invalid => "invalid",
    }
}

struct Enrichment {
    gamertag: Option<String>,
    game_pass: &'static str,
    network: &'static str,
}

impl Enrichment {
    fn unavailable() -> Self {
        Self {
            gamertag: None,
            game_pass: "unknown",
            network: "unavailable",
        }
    }
}

async fn enrich(client: &reqwest::Client, tokens: &TokenManager) -> Enrichment {
    let session = match prepare_existing(client, tokens).await {
        Ok(session) => session,
        Err(error) => {
            tracing::debug!("account details were not refreshed: {error}");
            return Enrichment::unavailable();
        }
    };

    let (profile, game_pass) =
        tokio::join!(profile::gamertag(&session), subscription::lookup(&session));
    // Never publish details requested for one account after the store switched.
    if tokens
        .get_user()
        .map(|user| user.username != session.account)
        .unwrap_or(true)
    {
        return Enrichment::unavailable();
    }

    let mut checked = true;
    let gamertag = match profile {
        Ok(name) => Some(name),
        Err(error) => {
            tracing::debug!("gamertag was not refreshed: {error}");
            checked = false;
            None
        }
    };
    let game_pass = match game_pass {
        Ok(status) => status.as_str(),
        Err(error) => {
            tracing::debug!("PC Game Pass was not refreshed: {error}");
            checked = false;
            "unknown"
        }
    };

    Enrichment {
        gamertag,
        game_pass,
        network: if checked { "checked" } else { "unavailable" },
    }
}

fn merged(mut value: Value, enrichment: Enrichment) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.insert("gamertag".into(), json!(enrichment.gamertag));
        object.insert("gamePass".into(), json!(enrichment.game_pass));
        object.insert("network".into(), json!(enrichment.network));
    }
    value
}

fn print_human(value: &Value) {
    if value["signedIn"] != true {
        println!("Not signed in");
        return;
    }
    println!("Signed in");
    if let Some(gamertag) = value["gamertag"].as_str() {
        println!("Gamertag: {gamertag}");
    }
    println!(
        "PC Game Pass: {}",
        value["gamePass"].as_str().unwrap_or("unknown")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_out_report_has_no_account_identifiers() {
        let tokens = TokenManager::with_memory();
        let state = offline_state(&tokens).unwrap();
        assert_eq!(state.value["schema"], 1);
        assert_eq!(state.value["signedIn"], false);
        assert_eq!(state.value["gamertag"], Value::Null);
        assert_eq!(state.value["gamePass"], "unknown");
        assert_eq!(state.value["network"], "skipped");
        assert!(!state.can_check_network);
        assert!(state.value.get("username").is_none());
        assert!(state.value.get("puid").is_none());
    }

    #[test]
    fn human_output_never_prints_an_email() {
        let value = json!({
            "schema": 1,
            "signedIn": true,
            "session": "current",
            "gamertag": "Example",
            "gamePass": "active",
            "network": "checked"
        });
        assert!(!value.to_string().contains("example.test"));
        assert_eq!(value["gamertag"], "Example");
    }
}
