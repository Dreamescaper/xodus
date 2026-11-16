//! Existing-session preparation for read-only account commands.
//!
//! Ported from domsvoboda/nexus-backend `crates/xodus-cli/src/commands/session.rs`
//! and `subscription.rs::store_session`, with credit. This deliberately renews
//! only an already registered device: optional reads never provision a device,
//! open a login UI, or delete stored credentials.

use std::fs::{File, OpenOptions};
use std::path::PathBuf;

use xodus::models::live::ExchangeUserTokenOutcome;
use xodus::models::secrets::{LegacyToken, Token, store_ticket as to_store_ticket};
use xodus::models::soap;
use xodus::tokens::session::{self, State};
use xodus::tokens::store::TokenStoreError;
use xodus::tokens::{TokenManager, device};

use crate::error::CommandError;

const STORE_APP: &str = "{d6d5a677-0872-4ab0-9442-bb792fce85c5}";
const STORE_SCOPE: &str = "www.microsoft.com";
const SILENT_UX: &str = "Silent";

pub(super) struct ExistingSession {
    pub client: reqwest::Client,
    pub account: String,
    pub user: LegacyToken,
    pub device: LegacyToken,
}

/// Prepare a stored user session without provisioning anything.
pub(super) async fn prepare_existing(
    client: &reqwest::Client,
    tokens: &TokenManager,
) -> Result<ExistingSession, CommandError> {
    let account = match tokens.get_user() {
        Ok(user) => user,
        Err(TokenStoreError::NotFound) => {
            return Err(CommandError::auth(
                "not signed in; run `xodus-cli login` first",
            ));
        }
        Err(err) => {
            return Err(CommandError::other_from(
                format!("could not read the stored account: {err}"),
                err,
            ));
        }
    };

    let user_token = match tokens.get_user_sts_token() {
        Ok(token) => token,
        Err(TokenStoreError::NotFound) => {
            return Err(CommandError::auth(
                "the stored sign-in is missing; sign in again",
            ));
        }
        Err(err) => {
            return Err(CommandError::other_from(
                format!("could not read the stored sign-in: {err}"),
                err,
            ));
        }
    };
    match session::state(&user_token, chrono::Utc::now()) {
        State::Current => {}
        State::Expired => {
            return Err(CommandError::auth(
                "the stored sign-in has expired; sign in again",
            ));
        }
        State::Invalid => {
            return Err(CommandError::auth(
                "the stored sign-in is invalid; sign in again",
            ));
        }
    }
    let Token::Legacy(user_token) = user_token else {
        return Err(CommandError::auth(
            "the stored sign-in is not usable; sign in again",
        ));
    };

    match tokens.get_device_license() {
        Ok(_) => {}
        Err(TokenStoreError::NotFound) => {
            return Err(CommandError::auth(
                "no device credentials are stored; sign in again",
            ));
        }
        Err(err) => {
            return Err(CommandError::other_from(
                format!("could not read the device credentials: {err}"),
                err,
            ));
        }
    }

    if !device_token_is_current(tokens)? {
        // Parallel library/account runs can renew the same device at once.
        // Serialize refresh + write, then re-read: a process that waited for
        // the lock must reuse the token another process already saved. If the
        // lock itself is unavailable, refresh without it rather than fail.
        let _lock = acquire_device_refresh_lock().await;
        if device_token_is_current(tokens)? {
            tracing::debug!("device token was renewed by another process");
        } else {
            // This renews the existing device only. A missing device license
            // was handled above, so this path cannot register a new one.
            device::refresh_existing_device_credentials(client, tokens)
                .await
                .map_err(CommandError::from)?;
        }
    }

    let device_token = tokens.get_device_sts_token().map_err(|err| {
        CommandError::other_from(format!("could not read the device token: {err}"), err)
    })?;
    let Token::Legacy(device_token) = device_token else {
        return Err(CommandError::auth(
            "the device token is not usable; sign in again",
        ));
    };

    Ok(ExistingSession {
        client: client.clone(),
        account: account.username,
        user: user_token,
        device: device_token,
    })
}

fn device_token_is_current(tokens: &TokenManager) -> Result<bool, CommandError> {
    match tokens.get_device_sts_token() {
        Ok(token) => Ok(session::state(&token, chrono::Utc::now()) == State::Current),
        Err(TokenStoreError::NotFound | TokenStoreError::Serde(_)) => Ok(false),
        Err(err) => Err(CommandError::other_from(
            format!("could not read the device token: {err}"),
            err,
        )),
    }
}

fn device_refresh_lock_path() -> PathBuf {
    #[cfg(unix)]
    let user = rustix::process::geteuid().to_string();
    #[cfg(not(unix))]
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "default".to_owned());
    std::env::temp_dir().join(format!("xodus-device-refresh-{user}.lock"))
}

async fn acquire_device_refresh_lock() -> Option<File> {
    let path = device_refresh_lock_path();
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Never follow a symlink planted in the shared temp directory.
        options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    let file = match options.open(&path) {
        Ok(file) => file,
        Err(err) => {
            tracing::debug!("device refresh lock unavailable, refreshing without it: {err}");
            return None;
        }
    };
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Some(file),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                // Yield to the runtime so the command's outer timeout can
                // cancel a long wait between another process's refresh.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(err) => {
                tracing::debug!("device refresh lock unavailable, refreshing without it: {err}");
                return None;
            }
        }
    }
}

/// Exchange the stored user credential for a compact ticket in `scope`.
pub(super) async fn exchange(
    session: &ExistingSession,
    scope: &str,
) -> Result<String, CommandError> {
    let outcome = xodus::api::live::exchange_user_token(
        &session.client,
        session.user.clone(),
        session.account.clone(),
        session.device.clone(),
        None,
        Some(SILENT_UX.into()),
        STORE_APP.into(),
        &[(scope.into(), Some(soap::PolicyReference::mbi_ssl()))],
    )
    .await
    .map_err(|error| {
        let is_network = error.is_network_request();
        let error = error.without_url();
        let message = format!("could not exchange the stored sign-in: {error}");
        if is_network {
            CommandError::network_from(message, error)
        } else {
            CommandError::other_from(message, error)
        }
    })?;
    compact_ticket(outcome)
}

/// Exchange the stored user credential for a Store ticket.
pub(super) async fn store_ticket(session: &ExistingSession) -> Result<String, CommandError> {
    let ticket = to_store_ticket(exchange(session, STORE_SCOPE).await?);
    if ticket.len() > 2 && ticket.starts_with("t=") && !ticket.contains(char::is_whitespace) {
        Ok(ticket)
    } else {
        Err(CommandError::other(
            "Microsoft returned an unusable Store ticket",
        ))
    }
}

fn compact_ticket(outcome: ExchangeUserTokenOutcome) -> Result<String, CommandError> {
    let responses = match outcome {
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(collection),
        ) => collection.security_tokens,
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
            response,
        )) => vec![*response],
        ExchangeUserTokenOutcome::Fault(_) => {
            return Err(CommandError::auth(
                "Microsoft refused the stored sign-in; sign in again",
            ));
        }
        _ => {
            return Err(CommandError::other(
                "Microsoft returned an unexpected sign-in response",
            ));
        }
    };

    responses
        .into_iter()
        .find_map(|response| {
            let value = response
                .requested_security_token
                .binary_security_token?
                .value;
            match response.token_type.as_str() {
                "urn:passport:compact" => Some(value),
                "urn:passport:delegationcompact" => Some(format!("d={value}")),
                _ => None,
            }
        })
        .ok_or_else(|| CommandError::other("Microsoft returned no usable compact ticket"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xodus::models::secrets::{LegacyToken, Token};
    use xodus::models::soap::Timestamp;
    use xodus::tokens::PASSPORT_STS;

    fn token(expires: &str) -> Token {
        Token::Legacy(LegacyToken {
            key_name: None,
            token: "fixture".into(),
            binary_secret: None,
            tpm_key: None,
            lifetime: Timestamp {
                id: None,
                created: "2000-01-01T00:00:00Z".into(),
                expires: expires.into(),
            },
        })
    }

    #[test]
    fn recheck_skips_refresh_after_another_process_renews_the_token() {
        let tokens = TokenManager::with_memory();
        tokens
            .save_device_token(PASSPORT_STS.into(), token("2001-01-01T00:00:00Z"))
            .unwrap();
        assert!(!device_token_is_current(&tokens).unwrap());

        // Another process renews the token while this process waits for the
        // refresh lock. The post-lock re-check must skip a second refresh.
        tokens
            .save_device_token(PASSPORT_STS.into(), token("2099-01-01T00:00:00Z"))
            .unwrap();
        assert!(device_token_is_current(&tokens).unwrap());
    }

    #[test]
    fn refresh_lock_lives_in_the_temp_directory_per_user() {
        let path = device_refresh_lock_path();
        assert_eq!(path.parent(), Some(std::env::temp_dir().as_path()));
        let name = path.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("xodus-device-refresh-"));
        assert!(name.ends_with(".lock"));
    }
}
