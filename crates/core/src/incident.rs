//! The incident record a request thread hands to storage.
//!
//! An incident borrows everything from the request that produced it; the storage queue
//! copies what it keeps into its own bounded slots, so recording an incident never
//! allocates on the request path.

pub use crate::incident_heads::ResponseState;

/// One security incident, borrowed from the request that produced it.
///
/// Fields taken off the wire are bytes, because a request may carry bytes that are not
/// UTF-8; names the daemon chose itself are text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Incident<'a> {
    /// The client address as text.
    pub client_ip: &'a str,
    /// The `User-Agent` value as received.
    pub user_agent: &'a [u8],
    /// The method name.
    pub method: &'a str,
    /// The request path as received.
    pub path: &'a [u8],
    /// The category that recorded the incident (a WAF category or a policy action).
    pub category: &'a str,
    /// The forensic payload (the query, or else the body); empty when nothing is kept.
    pub payload: &'a [u8],
    /// The time of the incident in Unix seconds.
    pub now: u64,
    /// What was captured and how much of it.
    pub evidence: Evidence,
    /// The redacted request head (see [`crate::incident_heads`]); empty when capture is off.
    pub request_head: &'a [u8],
    /// The redacted origin response head; empty when there was none or capture is off.
    pub response_head: &'a [u8],
    /// True when the request head was cut at its capacity.
    pub request_truncated: bool,
    /// True when the response head was cut at its capacity.
    pub response_truncated: bool,
    /// How the response side was observed.
    pub response_state: ResponseState,
}

/// Metadata for explicitly captured evidence. Version zero means historical or unrecorded.
///
/// No headers, cookie values, query values or request body bytes belong in this envelope.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Evidence {
    /// The evidence format version; zero when nothing was recorded.
    pub version: u8,
    /// The status the daemon selected for its answer.
    pub selected_status: u16,
    /// The length of the query in bytes.
    pub query_bytes: u32,
    /// The body bytes received.
    pub body_bytes: u32,
    /// The body length the client declared.
    pub declared_body_bytes: u32,
    /// Bits, lowest first: IP, User-Agent, method, path, category, forensic payload,
    /// incomplete body, then saturated byte lengths. They describe capture, not later
    /// display shortening.
    pub truncated: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_default_incident_records_nothing() {
        let incident = Incident::default();
        assert_eq!(incident.evidence.version, 0);
        assert_eq!(incident.response_state, ResponseState::Unknown);
        assert!(incident.request_head.is_empty() && incident.response_head.is_empty());
        let recorded = Incident { category: "sqli", now: 7, ..Incident::default() };
        assert_eq!(recorded.category, "sqli");
    }
}
