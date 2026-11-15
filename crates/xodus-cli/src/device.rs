use xodus::tokens::TokenManager;
use xodus::tokens::device::ensure_device_credentials;

use crate::error::CommandError;

/// Make sure a device identity is available right before a command needs it.
///
/// This is deliberately called from each command after its local validation:
/// registering a device contacts Microsoft and touches the secret store, so
/// commands that fail locally (or never need a device) must not reach it.
pub async fn ensure(client: &reqwest::Client, tokens: &TokenManager) -> Result<(), CommandError> {
    ensure_device_credentials(client, tokens)
        .await
        .map_err(CommandError::from)
}
