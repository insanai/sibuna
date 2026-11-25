//! The `global.acme.on_demand` object: the guards of issuance at the first handshake
//! (SID 0021). Nothing here opens a socket or a file.

use std::io;

use sibuna_json::ObjectReader;

use crate::config::{field, invalid};

/// The most suffixes of `allow`.
const MAX_SUFFIXES: usize = 64;
/// The longest host name.
const MAX_NAME: usize = 253;

/// The `global.acme.on_demand` object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnDemand {
    /// The URL that is asked `GET URL?domain=NAME`. A status from 200 to 299 allows.
    pub ask: Option<String>,
    /// Suffixes in lower case. `example.org` allows that name and every name below it.
    /// Empty: no suffix guard.
    pub allow: Vec<String>,
    /// New certificates per hour.
    pub rate: u32,
    /// The most names held at once.
    pub names: usize,
    /// The longest wait of a handshake, in seconds.
    pub wait: u64,
}

impl Default for OnDemand {
    fn default() -> Self {
        Self { ask: None, allow: Vec::new(), rate: 10, names: 100, wait: 20 }
    }
}

/// Whether `url` may be an `ask` URL: `http` or `https`, with a host, printable, and
/// without a query or a fragment of its own, because we append `?domain=NAME`.
fn is_ask_url(url: &str) -> bool {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"));
    let plain = url.len() <= 512 && url.bytes().all(|byte| byte.is_ascii_graphic());
    plain
        && !url.contains(['?', '#'])
        && rest.is_some_and(|rest| !rest.split('/').next().unwrap_or_default().is_empty())
}

/// Reads a number of `on_demand` within `range`, or its default.
fn number(
    r: &mut ObjectReader<'_, '_>,
    key: &str,
    range: std::ops::RangeInclusive<u64>,
    default: u64,
) -> io::Result<u64> {
    let path = r.field_path(key);
    match field(r.take_u64(key))? {
        None => Ok(default),
        Some(value) if range.contains(&value) => Ok(value),
        Some(_) => Err(invalid(format!("{path}: expected {} to {}", range.start(), range.end()))),
    }
}

impl OnDemand {
    pub(crate) fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Self> {
        let defaults = Self::default();
        let path = r.field_path("ask");
        let ask = match field(r.take_str("ask"))? {
            None => None,
            Some(url) if is_ask_url(url) => Some(url.to_owned()),
            Some(_) => {
                return Err(invalid(format!(
                    "{path}: expected an http or https URL without a query"
                )));
            }
        };
        let path = r.field_path("allow");
        let allow = match field(r.take_array("allow"))? {
            None => Vec::new(),
            Some(items) if (1..=MAX_SUFFIXES).contains(&items.len()) => items
                .iter()
                .map(|item| {
                    let suffix = item.as_str().unwrap_or_default().trim_start_matches('.');
                    match crate::hello::valid_host(suffix) {
                        true => Ok(suffix.to_ascii_lowercase()),
                        false => Err(invalid(format!("{path}: expected DNS suffixes"))),
                    }
                })
                .collect::<io::Result<Vec<_>>>()?,
            Some(_) => {
                return Err(invalid(format!("{path}: expected 1 to {MAX_SUFFIXES} suffixes")));
            }
        };
        let rate = number(&mut r, "rate", 1..=1000, u64::from(defaults.rate))?;
        let names = number(&mut r, "names", 1..=10_000, defaults.names as u64)?;
        let wait = number(&mut r, "wait", 1..=120, defaults.wait)?;
        field(r.finish())?;
        Ok(Self {
            ask,
            allow,
            rate: u32::try_from(rate).unwrap_or(defaults.rate),
            names: usize::try_from(names).unwrap_or(defaults.names),
            wait,
        })
    }

    /// Whether the object has a guard: an `ask` URL or a list of suffixes. Without one
    /// the daemon refuses the file.
    pub fn is_guarded(&self) -> bool {
        self.ask.is_some() || !self.allow.is_empty()
    }

    /// Whether a handshake may ask for a certificate for `name`, by the guards that
    /// read no state: `name` is a host name in lower case of at most 253 bytes, not an
    /// address and not a wildcard, and a suffix of `allow` covers it when the list
    /// exists.
    pub fn admits(&self, name: &str) -> bool {
        let host = name.len() <= MAX_NAME
            && !super::is_address(name)
            && crate::hello::valid_host(name)
            && !name.bytes().any(|byte| byte.is_ascii_uppercase());
        let covered = |suffix: &String| {
            name.strip_suffix(suffix.as_str())
                .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
        };
        host && (self.allow.is_empty() || self.allow.iter().any(covered))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(allow: &[&str]) -> OnDemand {
        OnDemand { allow: allow.iter().map(|s| (*s).to_owned()).collect(), ..OnDemand::default() }
    }

    #[test]
    fn a_suffix_allows_its_name_and_the_names_below() {
        let guard = guard(&["example.org", "apps.test"]);
        for name in ["example.org", "a.example.org", "a.b.example.org", "x.apps.test"] {
            assert!(guard.admits(name), "{name}");
        }
        for name in ["badexample.org", "example.org.evil.com", "org", "test", "example.com"] {
            assert!(!guard.admits(name), "{name}");
        }
    }

    #[test]
    fn only_a_plain_host_name_is_admitted() {
        let open = guard(&[]);
        assert!(open.admits("a.example.org") && open.admits("localhost"));
        let long = format!("{}.example.org", "a".repeat(250));
        for name in ["*.example.org", "127.0.0.1", "::1", "A.example.org", "a..b", "", &long] {
            assert!(!open.admits(name), "{name}");
        }
        assert!(!open.is_guarded() && guard(&["example.org"]).is_guarded());
        assert!(OnDemand { ask: Some("http://127.0.0.1:1/ok".into()), ..open }.is_guarded());
    }

    #[test]
    fn an_ask_url_has_a_scheme_a_host_and_no_query() {
        for url in ["http://127.0.0.1:9000/check", "https://auth.example.org/tls", "http://a"] {
            assert!(is_ask_url(url), "{url}");
        }
        for url in ["ftp://a/b", "http://", "http:///x", "http://a/b?x=1", "http://a/#f", "a"] {
            assert!(!is_ask_url(url), "{url}");
        }
    }
}
