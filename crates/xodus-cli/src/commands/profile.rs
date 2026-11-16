//! Bounded Xbox gamertag read for the stored account.
//!
//! Ported from domsvoboda/nexus-backend
//! `crates/xodus-cli/src/commands/profile.rs`, with credit. Only the gamertag
//! is returned: gamerpics, XUIDs and other profile fields are not needed by
//! Highball and are deliberately not read or emitted.

use serde_json::Value;

use super::session::{self, ExistingSession};
use crate::error::CommandError;

const PROFILE_URL: &str =
    "https://profile.xboxlive.com/users/me/profile/settings?settings=Gamertag";
const MAX_RESPONSE_BYTES: usize = 128 * 1024;

pub(super) async fn gamertag(session: &ExistingSession) -> Result<String, CommandError> {
    let ticket = session::exchange(session, "user.auth.xboxlive.com").await?;
    let user = xodus::api::xbox::authenticate_xbox_user(&session.client, ticket)
        .await
        .map_err(|err| {
            CommandError::network_from(format!("could not read the Xbox profile: {err}"), err)
        })?;
    let xsts =
        xodus::api::xbox::request_xsts_token(&session.client, user.token, "http://xboxlive.com")
            .await
            .map_err(|err| {
                CommandError::network_from(format!("could not read the Xbox profile: {err}"), err)
            })?;
    let user_hash = xsts
        .user_hash()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CommandError::auth("Xbox returned an incomplete sign-in"))?;
    if xsts.token.is_empty() {
        return Err(CommandError::auth("Xbox returned an incomplete sign-in"));
    }
    let authorization = format!("XBL3.0 x={user_hash};{}", xsts.token);

    let response = session
        .client
        .get(PROFILE_URL)
        .header("Authorization", authorization)
        .header("x-xbl-contract-version", "2")
        .send()
        .await
        .map_err(|err| {
            CommandError::network_from(format!("could not read the Xbox profile: {err}"), err)
        })?;
    let status = response.status();
    if !status.is_success() {
        let error = if status.as_u16() == 401 || status.as_u16() == 403 {
            CommandError::auth("Xbox refused the stored sign-in; sign in again")
        } else {
            CommandError::other(format!(
                "the Xbox profile request failed with HTTP {}",
                status.as_u16()
            ))
        };
        return Err(error);
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RESPONSE_BYTES as u64)
    {
        return Err(CommandError::other(
            "the Xbox profile response was too large",
        ));
    }
    let mut bytes = Vec::new();
    let mut response = response;
    while let Some(chunk) = response.chunk().await.map_err(|err| {
        CommandError::network_from(format!("could not read the Xbox profile: {err}"), err)
    })? {
        if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(CommandError::other(
                "the Xbox profile response was too large",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|err| {
        CommandError::other_from(format!("the Xbox profile response was invalid: {err}"), err)
    })?;
    fields(&value)
}

fn fields(value: &Value) -> Result<String, CommandError> {
    let users = value["profileUsers"]
        .as_array()
        .ok_or_else(|| CommandError::other("the Xbox profile response had an unexpected shape"))?;
    if users.len() != 1 {
        return Err(CommandError::other(
            "the Xbox profile response did not describe exactly one account",
        ));
    }
    let settings = users[0]["settings"]
        .as_array()
        .ok_or_else(|| CommandError::other("the Xbox profile response had no profile settings"))?;
    let gamertag = settings
        .iter()
        .find(|item| item["id"] == "Gamertag")
        .and_then(|item| item["value"].as_str())
        .map(str::trim)
        .filter(|name| !name.is_empty() && name.len() <= 256 && !name.chars().any(char::is_control))
        .ok_or_else(|| CommandError::other("the Xbox profile response had no usable gamertag"))?;
    Ok(gamertag.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn profile_settings_are_validated_without_exposing_other_fields() {
        let value = json!({"profileUsers":[{"id":"private-id", "settings":[
            {"id":"Gamertag","value":"Example Gamer"},
            {"id":"PublicGamerpic","value":"https://gamerpic.xboxlive.com/avatar.png"}]}]});
        assert_eq!(fields(&value).unwrap(), "Example Gamer");
        assert!(fields(&json!({"profileUsers":[]})).is_err());
        assert!(fields(&json!({"profileUsers":[{},{}]})).is_err());
        assert!(
            fields(&json!({"profileUsers":[{"settings":[{"id":"Gamertag","value":"  "}]}]}))
                .is_err()
        );
        assert!(
            fields(&json!({"profileUsers":[{"settings":[{"id":"Gamertag","value":"bad\nname"}]}]}))
                .is_err()
        );
    }
}
