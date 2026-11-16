//! Identification sent to the Store entitlement endpoints.
//!
//! These values are identification only. They do not grant access, and they are
//! the single place to update if the Store starts requiring a different calling
//! application name or API version.

/// Value of the `Calling-App-Name` request header.
pub(super) const CALLING_APP_NAME: &str = "xodus-cli";

/// Value of the `appVersion` query parameter.
pub(super) const APP_VERSION: &str = "0.2.3";
