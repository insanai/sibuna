//! How the requests of one pool are carried (SID 0019): the bounds on each wait and the
//! number of other servers a request may try. Every member has a default, so a pool that
//! sets none of them is complete.

use std::io;
use std::time::Duration;

use sibuna_json::ObjectReader;

use crate::config::{Protocol, duration, field, invalid};

/// The most other servers one request may try.
const MAX_RETRIES: u64 = 8;

/// The traffic options of one pool. Fill it with struct-update syntax:
/// `PoolPolicy { retries: 0, ..PoolPolicy::default() }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolPolicy {
    /// The longest wait for a TCP connection to one server.
    pub connect_timeout: Duration,
    /// The longest silence of a server that owes bytes: before the response head and
    /// between two pieces of the body.
    pub response_timeout: Duration,
    /// How many other servers one request may try after a failure. Zero turns failover off.
    pub retries: u8,
}

impl Default for PoolPolicy {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            response_timeout: Duration::from_secs(60),
            retries: 2,
        }
    }
}

impl PoolPolicy {
    /// Reads the traffic members of a pool of `protocol` from its object. Members that
    /// are absent keep their defaults.
    ///
    /// # Errors
    ///
    /// A diagnostic for a malformed value, or for a member that only an HTTP pool has.
    pub(crate) fn parse(r: &mut ObjectReader<'_, '_>, protocol: Protocol) -> io::Result<Self> {
        let mut policy = Self::default();
        let http = protocol == Protocol::Http;
        if let Some(bound) = time(r, "connect_timeout", http)? {
            policy.connect_timeout = bound;
        }
        if let Some(bound) = time(r, "response_timeout", http)? {
            policy.response_timeout = bound;
        }
        match field(r.take_u64("retries"))? {
            None => {}
            Some(_) if !http => return Err(http_only(r, "retries")),
            Some(count) if count <= MAX_RETRIES => policy.retries = count as u8,
            Some(_) => {
                return Err(invalid(format!(
                    "{} must be in 0..={MAX_RETRIES}. Hint: it counts the other servers \
                     one request may try; 0 turns failover off.",
                    r.field_path("retries")
                )));
            }
        }
        Ok(policy)
    }
}

/// Reads an optional duration member that only an HTTP pool has.
fn time(r: &mut ObjectReader<'_, '_>, key: &str, http: bool) -> io::Result<Option<Duration>> {
    let Some(text) = field(r.take_str(key))? else { return Ok(None) };
    if !http {
        return Err(http_only(r, key));
    }
    duration(text).map(Some).ok_or_else(|| {
        invalid(format!(
            "{}: expected a duration such as \"500ms\", \"5s\" or \"2m\", found {text:?}. \
             Hint: the longest duration is \"24h\".",
            r.field_path(key)
        ))
    })
}

/// The diagnostic for an HTTP member on a TCP or UDP pool.
pub(crate) fn http_only(r: &ObjectReader<'_, '_>, key: &str) -> io::Error {
    invalid(format!(
        "{} applies to requests, so it needs \"mode\": \"http\". Hint: remove it from \
         this pool.",
        r.field_path(key)
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn parse(source: &str, protocol: Protocol) -> io::Result<PoolPolicy> {
        let value = sibuna_json::parse(source.as_bytes()).unwrap();
        let mut reader = ObjectReader::with_path(&value, "backends.app".to_owned()).unwrap();
        let policy = PoolPolicy::parse(&mut reader, protocol)?;
        field(reader.finish())?;
        Ok(policy)
    }

    #[test]
    fn a_pool_without_traffic_members_has_the_defaults() {
        let policy = parse("{}", Protocol::Http).unwrap();
        assert_eq!(policy, PoolPolicy::default());
        assert_eq!(policy.connect_timeout, Duration::from_secs(5));
        assert_eq!(policy.response_timeout, Duration::from_secs(60));
        assert_eq!(policy.retries, 2);
        assert_eq!(parse("{}", Protocol::Tcp).unwrap(), PoolPolicy::default());
    }

    #[test]
    fn timeouts_and_retries_are_read_and_checked() {
        let source = r#"{"connect_timeout":"250ms","response_timeout":"2m","retries":0}"#;
        let policy = parse(source, Protocol::Http).unwrap();
        assert_eq!(policy.connect_timeout, Duration::from_millis(250));
        assert_eq!(policy.response_timeout, Duration::from_secs(120));
        assert_eq!(policy.retries, 0);
        for bad in [
            r#"{"connect_timeout":"soon"}"#,
            r#"{"response_timeout":"0s"}"#,
            r#"{"response_timeout":60}"#,
            r#"{"retries":9}"#,
        ] {
            assert!(parse(bad, Protocol::Http).is_err(), "{bad}");
        }
        let error = parse(r#"{"retries":1}"#, Protocol::Tcp).unwrap_err().to_string();
        assert!(error.contains("backends.app.retries") && error.contains("Hint:"), "{error}");
        assert!(parse(r#"{"connect_timeout":"1s"}"#, Protocol::Udp).is_err());
    }
}
