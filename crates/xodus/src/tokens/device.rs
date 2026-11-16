use std::error::Error;

use crate::hardware;
use crate::licensing::splicense::SPLicense;
use crate::licensing::utils::{generate_string, parse_bcrypt_rsa_private};
use crate::models::devicecredential::{Authentication, ClientInfo, DeviceAddRequest, DeviceInfo};
use crate::models::secrets::Device;
use crate::models::soap::BodyContent;
use crate::tokens::manager::TokenManager;
use crate::tokens::store::TokenStoreError;

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
    let license = match tokens.get_device_license() {
        Ok(license) => license,
        Err(TokenStoreError::NotFound) => return provision_device(client, tokens).await,
        Err(err) => {
            return Err(DeviceError::other(
                format!("could not read the device license: {err}"),
                err,
            ));
        }
    };

    match tokens.get_device_sts_token() {
        Ok(_) => Ok(()),
        Err(TokenStoreError::NotFound) => reauthenticate_device(client, tokens, license).await,
        Err(err) => Err(DeviceError::other(
            format!("could not read the device token: {err}"),
            err,
        )),
    }
}

/// Renew only an already registered device.
///
/// Optional read-only commands use this instead of [`ensure_device_credentials`]
/// so a missing device identity is reported without silently provisioning one.
pub async fn refresh_existing_device_credentials(
    client: &reqwest::Client,
    tokens: &TokenManager,
) -> Result<(), DeviceError> {
    let license = tokens.get_device_license().map_err(|err| match err {
        TokenStoreError::NotFound => DeviceError::auth(
            "no device credentials are stored; sign in before reading the account",
            err,
        ),
        err => DeviceError::other(format!("could not read the device license: {err}"), err),
    })?;
    reauthenticate_device(client, tokens, license).await
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

    match resp.body.body {
        BodyContent::RequestSecurityTokenResponse(resp) => save_device_sts_token(tokens, resp),
        _ => Err(DeviceError::other_message(
            "unexpected device token response",
        )),
    }
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

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::models::secrets::Device;
    use crate::tokens::backend::MemoryBackend;
    use crate::tokens::store::{TokenBackend, TokenStoreError};

    use super::{
        DeviceErrorKind, TokenManager, ensure_device_credentials,
        refresh_existing_device_credentials,
    };

    struct ErroringBackend {
        device_license: Option<Device>,
    }

    impl TokenBackend for ErroringBackend {
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>, TokenStoreError> {
            if key == "dev_license"
                && let Some(device) = &self.device_license
            {
                return Ok(Some(serde_json::to_vec(device).unwrap()));
            }
            Err(TokenStoreError::Io(io::Error::other("keychain locked")))
        }

        fn set(&self, _key: &str, _value: &[u8]) -> Result<(), TokenStoreError> {
            Err(TokenStoreError::Io(io::Error::other("keychain locked")))
        }

        fn remove(&self, _key: &str) -> Result<(), TokenStoreError> {
            Err(TokenStoreError::Io(io::Error::other("keychain locked")))
        }
    }

    fn manager(device_license: Option<Device>) -> TokenManager {
        TokenManager::new(
            Arc::new(ErroringBackend { device_license }),
            Arc::new(MemoryBackend::default()),
        )
    }

    /// Any device provisioning would go through this loopback proxy. The
    /// listener stays non-blocking so the test can prove it was never used
    /// without ever reaching Microsoft.
    fn guarded_client() -> (reqwest::Client, std::net::TcpListener) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(250))
            .proxy(reqwest::Proxy::all(proxy).unwrap())
            .build()
            .unwrap();
        (client, listener)
    }

    fn assert_no_connection(listener: &std::net::TcpListener) {
        match listener.accept() {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Ok(_) => panic!("device provisioning unexpectedly contacted the network"),
            Err(err) => panic!("proxy listener failed: {err}"),
        }
    }

    fn device() -> Device {
        Device {
            puid: "puid".to_owned(),
            hwid: "hwid".to_owned(),
            device_id: "device".to_owned(),
            splicense: "not-a-real-license".to_owned(),
            username: "user".to_owned(),
            password: "password".to_owned(),
        }
    }

    #[tokio::test]
    async fn sts_token_store_error_is_returned_without_network() {
        let (client, listener) = guarded_client();
        let error = ensure_device_credentials(&client, &manager(Some(device())))
            .await
            .expect_err("a non-NotFound token error must be reported");

        assert_eq!(error.kind(), DeviceErrorKind::Other);
        assert!(
            error
                .to_string()
                .contains("could not read the device token")
        );
        assert_no_connection(&listener);
    }

    #[tokio::test]
    async fn device_license_store_error_is_returned_without_network() {
        let (client, listener) = guarded_client();
        let error = ensure_device_credentials(&client, &manager(None))
            .await
            .expect_err("a non-NotFound license error must be reported");

        assert_eq!(error.kind(), DeviceErrorKind::Other);
        assert!(
            error
                .to_string()
                .contains("could not read the device license")
        );
        assert_no_connection(&listener);
    }

    #[tokio::test]
    async fn refresh_existing_device_never_provisions_a_missing_identity() {
        let (client, listener) = guarded_client();
        let tokens = TokenManager::with_memory();
        let error = refresh_existing_device_credentials(&client, &tokens)
            .await
            .expect_err("a missing device identity must be reported");

        assert_eq!(error.kind(), DeviceErrorKind::Auth);
        assert!(tokens.get_device_license().is_err());
        assert_no_connection(&listener);
    }
}
