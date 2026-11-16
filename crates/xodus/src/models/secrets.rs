use serde::{Deserialize, Serialize};

use crate::models::soap::{self, Timestamp};

#[derive(Debug, Serialize, Deserialize)]
pub struct Device {
    pub puid: String,
    pub hwid: String,
    pub device_id: String,
    pub splicense: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LegacyToken {
    pub key_name: Option<String>,
    pub token: String,
    pub binary_secret: Option<String>,
    #[serde(default)]
    pub tpm_key: Option<String>,
    pub lifetime: Timestamp,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Token {
    Legacy(LegacyToken),
    Compact(String),
}

impl From<soap::RequestSecurityTokenResponse> for Token {
    fn from(value: soap::RequestSecurityTokenResponse) -> Self {
        match value.token_type.as_str() {
            "urn:passport:legacy" => {
                let encrypted_data = value.requested_security_token.encrypted_data.unwrap();
                let key_name = encrypted_data.key_info.key_name.clone();
                let token = quick_xml::se::to_string(&encrypted_data).unwrap();
                let binary_secret = value
                    .requested_proof_token
                    .as_ref()
                    .map(|t| t.binary_secret.clone());
                let tpm_key = value
                    .requested_proof_token
                    .and_then(|t| t.encrypted_key.map(|k| k.cipher_data.cipher_value));
                Self::Legacy(LegacyToken {
                    key_name,
                    token,
                    binary_secret,
                    tpm_key,
                    lifetime: value.lifetime,
                })
            }
            "urn:passport:compact" => Self::Compact(
                value
                    .requested_security_token
                    .binary_security_token
                    .unwrap()
                    .value,
            ),
            "urn:passport:delegationcompact" => Self::Compact(format!(
                "d={}",
                value
                    .requested_security_token
                    .binary_security_token
                    .unwrap()
                    .value
            )),
            _ => unreachable!(),
        }
    }
}

/// Store and licensing services reject delegation-compact tickets in the "d="
/// form that Xbox Live sign-in needs and accept the same value as "t=".
///
/// Ported from domsvoboda/nexus-backend with credit. Convert only where a ticket
/// is sent to those services; the value itself is never decoded or logged.
pub fn store_ticket(ticket: String) -> String {
    match ticket.strip_prefix("d=") {
        Some(value) => format!("t={value}"),
        None => ticket,
    }
}

#[cfg(test)]
mod tests {
    use super::store_ticket;

    #[test]
    fn store_ticket_converts_only_delegation_tickets() {
        assert_eq!(store_ticket("d=abc".into()), "t=abc");
        assert_eq!(store_ticket("t=abc&p=".into()), "t=abc&p=");
        assert_eq!(store_ticket("abc".into()), "abc");
        assert_eq!(store_ticket(String::new()), "");
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenStore {
    #[serde(flatten)]
    pub tokens: std::collections::HashMap<String, Token>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub puid: String,
    pub username: String,
}
