use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum CommandError {
    Auth {
        message: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    Network {
        message: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },
    Other {
        message: String,
        source: Option<Box<dyn Error + Send + Sync>>,
    },
}

impl CommandError {
    pub fn auth(message: impl Into<String>) -> Self {
        Self::Auth {
            message: message.into(),
            source: None,
        }
    }

    pub fn auth_from(
        message: impl Into<String>,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self::Auth {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    pub fn network_from(
        message: impl Into<String>,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self::Network {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    pub fn other(message: impl Into<String>) -> Self {
        Self::Other {
            message: message.into(),
            source: None,
        }
    }

    pub fn other_from(
        message: impl Into<String>,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self::Other {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth { message, .. }
            | Self::Network { message, .. }
            | Self::Other { message, .. } => f.write_str(message),
        }
    }
}

impl Error for CommandError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Auth { source, .. }
            | Self::Network { source, .. }
            | Self::Other { source, .. } => source
                .as_ref()
                .map(|source| source.as_ref() as &(dyn Error + 'static)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_auth_from_network_and_keeps_the_source() {
        let auth = CommandError::auth_from(
            "could not read the token: expired",
            std::io::Error::other("expired"),
        );
        assert!(matches!(auth, CommandError::Auth { .. }));
        assert_eq!(auth.to_string(), "could not read the token: expired");
        assert!(auth.source().is_some());

        let network = CommandError::network_from(
            "could not fetch: offline",
            std::io::Error::other("offline"),
        );
        assert!(matches!(network, CommandError::Network { .. }));
        assert_eq!(network.to_string(), "could not fetch: offline");
        assert!(network.source().is_some());
    }
}
