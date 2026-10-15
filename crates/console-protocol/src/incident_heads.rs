//! Redacted request and response heads of one incident. They travel as hex so the
//! interface can render the bytes under a chosen character set.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::codec::{Decode, DecodeError, Encode, Fields, Path, WireEnum, counter_field, field};
use crate::text::Text;

/// The longest redacted request head, in bytes.
pub const REQUEST_BYTES: usize = 2048;
/// The longest redacted response head, in bytes.
pub const RESPONSE_BYTES: usize = 1024;
/// The request head's length in hex digits.
pub const REQUEST_HEX: usize = REQUEST_BYTES * 2;
/// The response head's length in hex digits.
pub const RESPONSE_HEX: usize = RESPONSE_BYTES * 2;

/// Reads the heads of one incident.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Read {
    /// SHA-256 of the session cookie or bearer token.
    pub session_digest: [u8; 32],
    /// The route requires an enrolled second factor.
    pub require_totp: bool,
    /// The incident id.
    pub id: u64,
}

/// What became of the origin response head. Stored as its ordinal, sent as its name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ResponseState {
    /// Rows written before the state was recorded.
    #[default]
    Unknown,
    /// The origin's head was captured.
    Captured,
    /// The firewall answered locally; there is no origin response.
    Local,
    /// Forward-auth mode never sees the origin response.
    Unobserved,
    /// The relay produced no head.
    Unavailable,
}

impl WireEnum for ResponseState {
    const ALL: &'static [ResponseState] = &[
        ResponseState::Unknown,
        ResponseState::Captured,
        ResponseState::Local,
        ResponseState::Unobserved,
        ResponseState::Unavailable,
    ];

    fn name(self) -> &'static str {
        match self {
            ResponseState::Unknown => "unknown",
            ResponseState::Captured => "captured",
            ResponseState::Local => "local",
            ResponseState::Unobserved => "unobserved",
            ResponseState::Unavailable => "unavailable",
        }
    }
}

/// The heads of one incident (version 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Heads {
    /// The format version.
    pub version: u8,
    /// The incident id.
    pub id: u64,
    /// Heads were captured for this incident.
    pub recorded: bool,
    /// The redacted request head as hex.
    pub request: Text<REQUEST_HEX>,
    /// The redacted response head as hex.
    pub response: Text<RESPONSE_HEX>,
    /// The request head was truncated after redaction.
    pub request_truncated: bool,
    /// The response head was truncated after redaction.
    pub response_truncated: bool,
    /// What became of the origin response.
    pub response_state: ResponseState,
}

impl Default for Heads {
    fn default() -> Heads {
        Heads {
            version: 1,
            id: 0,
            recorded: false,
            request: Text::default(),
            response: Text::default(),
            request_truncated: false,
            response_truncated: false,
            response_state: ResponseState::Unknown,
        }
    }
}

impl Encode for Heads {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "version", &self.version)?;
        counter_field(json, "id", self.id)?;
        field(json, "recorded", &self.recorded)?;
        field(json, "request", &self.request)?;
        field(json, "response", &self.response)?;
        field(json, "request_truncated", &self.request_truncated)?;
        field(json, "response_truncated", &self.response_truncated)?;
        field(json, "response_state", &self.response_state)?;
        json.end_object()
    }
}

impl Decode for Heads {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Heads, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let heads = Heads {
            version: fields.or("version", 1)?,
            id: fields.required("id")?,
            recorded: fields.or_default("recorded")?,
            request: fields.or_default("request")?,
            response: fields.or_default("response")?,
            request_truncated: fields.or_default("request_truncated")?,
            response_truncated: fields.or_default("response_truncated")?,
            response_state: fields.or_default("response_state")?,
        };
        fields.finish()?;
        Ok(heads)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_json, to_json};

    #[test]
    fn heads_round_trip() {
        let heads = Heads {
            id: 5,
            recorded: true,
            request: Text::new("474554").unwrap(),
            response_state: ResponseState::Local,
            ..Heads::default()
        };
        let text = to_json(&heads);
        assert_eq!(
            text,
            "{\"version\":1,\"id\":5,\"recorded\":true,\"request\":\"474554\",\"response\":\"\",\
             \"request_truncated\":false,\"response_truncated\":false,\
                 \"response_state\":\"local\"}"
        );
        assert_eq!(from_json::<Heads>(text.as_bytes()), Ok(heads));
        assert_eq!(
            from_json::<Heads>(b"{\"id\":1,\"response_state\":2}").unwrap().response_state,
            ResponseState::Local
        );
    }
}
