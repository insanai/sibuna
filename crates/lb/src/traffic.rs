//! How the requests of one pool are carried (SID 0019): the bounds on each wait, the
//! number of other servers a request may try, and when failures take a server out. Every
//! member has a default, so a pool that sets none of them is complete.

use std::io;
use std::time::Duration;

use sibuna_json::ObjectReader;

use crate::config::{Protocol, duration, field, invalid, number};

/// The most other servers one request may try.
const MAX_RETRIES: u64 = 8;

/// Passive health: failures seen on live requests take a server out for a while.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Passive {
    /// Consecutive failures that eject a server.
    pub failures: u32,
    /// How long an ejected server takes no new request while another server can.
    pub ejection: Duration,
    /// Count a response with status 500, 502, 503 or 504 as a failure. A response
    /// timeout always counts.
    pub http_5xx: bool,
}

impl Default for Passive {
    fn default() -> Self {
        Self { failures: 3, ejection: Duration::from_secs(10), http_5xx: false }
    }
}

impl Passive {
    /// Whether a response with `status` is a failure of the server under this rule.
    /// 501 and 505 describe the request, not the server.
    pub fn counts(&self, status: u16) -> bool {
        self.http_5xx && matches!(status, 500 | 502 | 503 | 504)
    }

    /// One step of the failure count: the count after an outcome, and whether the server
    /// is ejected now. A success sets the count to zero. The failure that reaches
    /// `failures` ejects, and the count starts again.
    pub fn step(&self, count: u32, failed: bool) -> (u32, bool) {
        if !failed {
            return (0, false);
        }
        let count = count.saturating_add(1);
        if count >= self.failures { (0, true) } else { (count, false) }
    }

    /// Reads `passive_health`: `"off"`, or an object whose members default.
    fn parse(r: &mut ObjectReader<'_, '_>, http: bool) -> io::Result<Option<Self>> {
        let defaults = Self::default();
        let Some(value) = r.take("passive_health") else { return Ok(Some(defaults)) };
        if !http {
            return Err(http_only(r, "passive_health"));
        }
        if value.as_str() == Some("off") {
            return Ok(None);
        }
        let path = r.field_path("passive_health");
        let mut rule = field(ObjectReader::with_path(value, path.clone())).map_err(|_| {
            invalid(format!(
                "{path}: expected \"off\" or an object. Hint: the members are failures, \
                 ejection and http_5xx, and each has a default."
            ))
        })?;
        let failures = number(&mut rule, "failures", defaults.failures as usize, 100)? as u32;
        let ejection = match field(rule.take_str("ejection"))? {
            None => defaults.ejection,
            Some(text) => duration(text).ok_or_else(|| {
                invalid(format!(
                    "{}: expected a duration such as \"10s\". Hint: use \
                     \"passive_health\": \"off\" to keep failing servers in rotation.",
                    rule.field_path("ejection")
                ))
            })?,
        };
        let http_5xx = field(rule.take_bool("http_5xx"))?.unwrap_or(defaults.http_5xx);
        field(rule.finish())?;
        Ok(Some(Self { failures, ejection, http_5xx }))
    }
}

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
    /// Passive health, or `None` when it is off.
    pub passive: Option<Passive>,
}

impl Default for PoolPolicy {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            response_timeout: Duration::from_secs(60),
            retries: 2,
            passive: Some(Passive::default()),
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
        policy.passive = Passive::parse(r, http)?;
        // A TCP or UDP pool has no response to judge, so it has no passive health.
        if !http {
            policy.passive = None;
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
        let stream = parse("{}", Protocol::Tcp).unwrap();
        assert_eq!(stream, PoolPolicy { passive: None, ..PoolPolicy::default() });
    }

    #[test]
    fn passive_health_is_on_by_default_and_reads_its_members() {
        let policy = parse("{}", Protocol::Http).unwrap();
        let rule = policy.passive.unwrap();
        assert_eq!(
            (rule.failures, rule.ejection, rule.http_5xx),
            (3, Duration::from_secs(10), false)
        );
        assert_eq!(parse(r#"{"passive_health":"off"}"#, Protocol::Http).unwrap().passive, None);
        let source = r#"{"passive_health":{"failures":5,"ejection":"30s","http_5xx":true}}"#;
        let rule = parse(source, Protocol::Http).unwrap().passive.unwrap();
        assert_eq!(
            (rule.failures, rule.ejection, rule.http_5xx),
            (5, Duration::from_secs(30), true)
        );
        for bad in [
            r#"{"passive_health":"on"}"#,
            r#"{"passive_health":{"failures":0}}"#,
            r#"{"passive_health":{"ejection":"long"}}"#,
            r#"{"passive_health":{"unknown":1}}"#,
        ] {
            assert!(parse(bad, Protocol::Http).is_err(), "{bad}");
        }
        assert!(parse(r#"{"passive_health":"off"}"#, Protocol::Tcp).is_err());
    }

    #[test]
    fn the_failure_count_ejects_at_its_limit_and_a_success_clears_it() {
        let rule = Passive { failures: 3, ..Passive::default() };
        assert_eq!(rule.step(0, true), (1, false));
        assert_eq!(rule.step(1, true), (2, false));
        assert_eq!(rule.step(2, true), (0, true));
        assert_eq!(rule.step(2, false), (0, false));
        assert!(!rule.counts(503));
        let strict = Passive { http_5xx: true, ..rule };
        assert!(strict.counts(500) && strict.counts(502) && strict.counts(503));
        assert!(strict.counts(504) && !strict.counts(501) && !strict.counts(505));
        assert!(!strict.counts(404) && !strict.counts(200));
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
