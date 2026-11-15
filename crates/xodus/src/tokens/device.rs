use std::error::Error;

use crate::hardware;
use crate::licensing::splicense::SPLicense;
use crate::licensing::utils::{generate_string, parse_bcrypt_rsa_private};
use crate::models::devicecredential::{Authentication, ClientInfo, DeviceAddRequest, DeviceInfo};
use crate::models::secrets::Device;
use crate::models::soap::BodyContent;
use crate::tokens::manager::TokenManager;

/// Which kind of failure a device provisioning error represents, so callers can
/// report it the same way they report other command errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceErrorKind {
    Auth,
    Network,
    Other,
}

/// A failure while provisioning or re-authenticating the local device identity.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct DeviceError {
    kind: DeviceErrorKind,
    message: String,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl DeviceError {
    fn new(
        kind: DeviceErrorKind,
        message: impl Into<String>,
        source: Option<Box<dyn Error + Send + Sync>>,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            source,
        }
    }

    pub fn auth(message: impl Into<String>, source: impl Error + Send + Sync + 'static) -> Self {
        Self::new(DeviceErrorKind::Auth, message, Some(Box::new(source)))
    }

    pub fn network(message: impl Into<String>, source: impl Error + Send + Sync + 'static) -> Self {
        Self::new(DeviceErrorKind::Network, message, Some(Box::new(source)))
    }

    pub fn other(message: impl Into<String>, source: impl Error + Send + Sync + 'static) -> Self {
        Self::new(DeviceErrorKind::Other, message, Some(Box::new(source)))
    }

    pub fn other_message(message: impl Into<String>) -> Self {
        Self::new(DeviceErrorKind::Other, message, None)
    }

    pub fn kind(&self) -> DeviceErrorKind {
        self.kind
    }
}

/// Provisions a device (if none is stored yet) or re-authenticates an existing one
/// (if its STS token is missing/expired), persisting the result through `tokens`.
pub async fn ensure_device_credentials(
    client: &reqwest::Client,
    tokens: &TokenManager,
) -> Result<(), DeviceError> {
    match tokens.get_device_license() {
        Err(_) => provision_device(client, tokens).await,
        Ok(license) if tokens.get_device_sts_token().is_err() => {
            reauthenticate_device(client, tokens, license).await
        }
        Ok(_) => Ok(()),
    }
}

async fn provision_device(
    client: &reqwest::Client,
    tokens: &TokenManager,
) -> Result<(), DeviceError> {
    let username = format!("02{}", generate_string(14));
    let password = generate_string(20);
    let provision = DeviceAddRequest {
        client_info: ClientInfo::default(),
        authentication: Authentication::new(username.clone(), password.clone()),
        device_info: Some(DeviceInfo {
            id: "DeviceInfo".to_string(),
            components: hardware::probe_provision_components(),
            tpm_info: None,
        }),
    };

    let dev = crate::api::live::login_device_credential(client, provision)
        .await
        .map_err(|err| {
            DeviceError::network(format!("could not register the device: {err}"), err)
        })?;

    let device = Device {
        username: username.clone(),
        password: password.clone(),
        puid: dev.puid,
        hwid: dev.hw_device_id,
        device_id: dev.license.binding.device_id.unwrap_or_default(),
        splicense: dev.license.splicense_block,
    };

    tokens.save_device_license(&device).map_err(|err| {
        DeviceError::other(format!("could not save the device license: {err}"), err)
    })?;

    reauthenticate_device(client, tokens, device).await
}

async fn reauthenticate_device(
    client: &reqwest::Client,
    tokens: &TokenManager,
    license: Device,
) -> Result<(), DeviceError> {
    let sp_license = SPLicense::parse_base64(&license.splicense).map_err(|err| {
        DeviceError::other(format!("could not parse the device SPLicense: {err}"), err)
    })?;
    let clep_sign_state = sp_license.clep_sign_state.ok_or_else(|| {
        DeviceError::other_message("the device SPLicense has no clep signing state")
    })?;
    let key = clep_sign_state.get_rsa_key();
    let private_key = parse_bcrypt_rsa_private(&key).map_err(|err| {
        DeviceError::other(
            format!("could not parse the device signing key: {err}"),
            err,
        )
    })?;
    let resp = crate::api::live::authenticate_device(client, license.username, private_key)
        .await
        .map_err(|err| {
            let is_network = err.is_network_request();
            let err = err.without_url();
            let message = format!("could not authenticate the device: {err}");
            if is_network {
                DeviceError::network(message, err)
            } else {
                DeviceError::auth(message, err)
            }
        })?;

    if let BodyContent::RequestSecurityTokenResponse(resp) = resp.body.body {
        save_device_sts_token(tokens, resp)?;
    }
    Ok(())
}

fn save_device_sts_token(
    tokens: &TokenManager,
    resp: Box<crate::models::soap::RequestSecurityTokenResponse>,
) -> Result<(), DeviceError> {
    let encrypted_data = resp
        .requested_security_token
        .encrypted_data
        .as_ref()
        .ok_or_else(|| {
            DeviceError::other_message("the device token response has no encrypted data")
        })?;
    let key_name = encrypted_data
        .key_info
        .key_name
        .as_ref()
        .ok_or_else(|| DeviceError::other_message("the device token response has no key name"))?
        .clone();
    let token = (*resp).into();
    tokens
        .save_device_token(key_name, token)
        .map_err(|err| DeviceError::other(format!("could not save the device token: {err}"), err))
}
