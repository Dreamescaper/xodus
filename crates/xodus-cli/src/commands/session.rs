//! Existing-session preparation for read-only account commands.
//!
//! Ported from domsvoboda/nexus-backend `crates/xodus-cli/src/commands/session.rs`
//! and `subscription.rs::store_session`, with credit. This deliberately renews
//! only an already registered device: optional reads never provision a device,
//! open a login UI, or delete stored credentials.

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

    let device_current = match tokens.get_device_sts_token() {
        Ok(token) => session::state(&token, chrono::Utc::now()) == State::Current,
        Err(TokenStoreError::NotFound | TokenStoreError::Serde(_)) => false,
        Err(err) => {
            return Err(CommandError::other_from(
                format!("could not read the device token: {err}"),
                err,
            ));
        }
    };
    if !device_current {
        // This renews the existing device only. A missing device license was
        // handled above, so this path cannot register a new one.
        device::refresh_existing_device_credentials(client, tokens)
            .await
            .map_err(CommandError::from)?;
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
