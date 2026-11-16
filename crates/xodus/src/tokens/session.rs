//! Freshness checks for stored network sessions, without changing raw reads.
//!
//! Ported from domsvoboda/nexus-backend `crates/xodus/src/tokens/session.rs`
//! with credit. The Nexus renewal lock and account-role support are not needed
//! by the upstream single-account store, so only the token state check remains.

use crate::models::secrets::Token;
use chrono::{DateTime, Duration, Utc};

#[derive(Debug, PartialEq, Eq)]
pub enum State {
    Current,
    Expired,
    Invalid,
}

pub fn state(token: &Token, now: DateTime<Utc>) -> State {
    let Token::Legacy(token) = token else {
        return State::Invalid;
    };
    let (Ok(created), Ok(expires)) = (
        DateTime::parse_from_rfc3339(&token.lifetime.created),
        DateTime::parse_from_rfc3339(&token.lifetime.expires),
    ) else {
        return State::Invalid;
    };
    if expires <= created || created > now + Duration::minutes(5) {
        return State::Invalid;
    }
    if expires <= now {
        State::Expired
    } else {
        State::Current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{secrets::LegacyToken, soap::Timestamp};

    fn token(created: &str, expires: &str) -> Token {
        Token::Legacy(LegacyToken {
            key_name: None,
            token: "fixture".into(),
            binary_secret: None,
            tpm_key: None,
            lifetime: Timestamp {
                id: None,
                created: created.into(),
                expires: expires.into(),
            },
        })
    }

    #[test]
    fn lifetime_boundaries_and_offsets_are_checked_strictly() {
        let now = DateTime::parse_from_rfc3339("2026-10-19T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            state(&token("2026-10-19T09:00:00Z", "2026-10-19T10:00:01Z"), now),
            State::Current
        );
        assert_eq!(
            state(&token("2026-10-19T09:00:00Z", "2026-10-19T10:00:00Z"), now),
            State::Expired
        );
        assert_eq!(
            state(
                &token("2026-10-19T11:00:00+02:00", "2026-10-19T13:00:00+02:00"),
                now
            ),
            State::Current
        );
        for (created, expires) in [
            ("bad", "2099-01-01T00:00:00Z"),
            ("2000-01-01T00:00:00Z", "bad"),
            ("2026-10-19T10:05:01Z", "2099-01-01T00:00:00Z"),
            ("2026-10-19T09:00:00Z", "2000-01-01T00:00:00Z"),
        ] {
            assert_eq!(state(&token(created, expires), now), State::Invalid);
        }
        assert_eq!(
            state(&Token::Compact("fixture".into()), now),
            State::Invalid
        );
    }
}
