//! WebSocket rules of a frontend or route: who may open a tunnel, and how many.
//!
//! Sibuna judges the upgrade request and then relays bytes. Two checks need to know that
//! the request opens a tunnel. A browser sends the cookies of a site with a WebSocket
//! handshake from any page, so an application that authenticates by cookie must check
//! the `Origin` field. A tunnel holds a connection for hours, so one client must not hold
//! too many.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

use sibuna_json::ObjectReader;

use crate::config::{field, invalid};

/// The WebSocket rule of one frontend or route.
#[derive(Debug, Default)]
pub struct WebSocketRule {
    /// The origins that may open a tunnel, in lower case. Empty admits every origin.
    origins: Vec<String>,
    /// The most concurrent tunnels of one client address.
    max_per_ip: Option<u32>,
    tunnels: Mutex<HashMap<IpAddr, u32>>,
}

/// Why an upgrade was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelRefusal {
    /// The `Origin` field is absent or not listed: answer 403.
    Origin,
    /// The client holds its limit of tunnels: answer 429.
    Limit,
}

/// One tunnel counted against its client. Dropping it gives the place back.
#[derive(Debug)]
pub struct TunnelPermit {
    rule: Arc<WebSocketRule>,
    client: IpAddr,
}

impl WebSocketRule {
    /// A rule that admits the listed origins and at most `max_per_ip` tunnels per client.
    pub fn new(origins: Vec<String>, max_per_ip: Option<u32>) -> Self {
        let origins = origins.into_iter().map(|origin| origin.to_ascii_lowercase()).collect();
        Self { origins, max_per_ip, tunnels: Mutex::default() }
    }

    pub(crate) fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Arc<Self>> {
        let mut origins = Vec::new();
        for entry in field(r.take_array("origins"))?.unwrap_or_default() {
            let origin = entry.as_str().filter(|origin| is_origin(origin));
            let origin = origin.ok_or_else(|| {
                invalid(format!(
                    "{}: expected origins such as https://app.example.org",
                    r.field_path("origins")
                ))
            })?;
            origins.push(origin.to_owned());
        }
        if origins.len() > 64 {
            return Err(invalid(format!("{}: at most 64 origins", r.field_path("origins"))));
        }
        let max_per_ip = match field(r.take_u64("max_per_ip"))? {
            None => None,
            Some(count) if (1..=1_000_000).contains(&count) => Some(count as u32),
            Some(_) => {
                return Err(invalid(format!(
                    "{} must be in 1..=1000000",
                    r.field_path("max_per_ip")
                )));
            }
        };
        field(r.finish())?;
        Ok(Arc::new(Self::new(origins, max_per_ip)))
    }

    /// Judges an upgrade from `client` that carries the `Origin` field `origin`.
    ///
    /// # Errors
    ///
    /// The [`TunnelRefusal`] that names the check the request failed.
    pub fn admit(
        self: &Arc<Self>,
        origin: Option<&[u8]>,
        client: IpAddr,
    ) -> Result<TunnelPermit, TunnelRefusal> {
        if !self.origins.is_empty() {
            let listed = |origin: &[u8]| {
                self.origins.iter().any(|allowed| origin.eq_ignore_ascii_case(allowed.as_bytes()))
            };
            if !origin.is_some_and(listed) {
                return Err(TunnelRefusal::Origin);
            }
        }
        let mut tunnels = self.tunnels.lock().unwrap_or_else(PoisonError::into_inner);
        let held = tunnels.entry(client).or_insert(0);
        if self.max_per_ip.is_some_and(|limit| *held >= limit) {
            if *held == 0 {
                tunnels.remove(&client);
            }
            return Err(TunnelRefusal::Limit);
        }
        *held += 1;
        Ok(TunnelPermit { rule: Arc::clone(self), client })
    }

    /// The tunnels `client` holds now.
    pub fn tunnel_count(&self, client: IpAddr) -> u32 {
        let tunnels = self.tunnels.lock().unwrap_or_else(PoisonError::into_inner);
        tunnels.get(&client).copied().unwrap_or(0)
    }
}

impl Drop for TunnelPermit {
    fn drop(&mut self) {
        let mut tunnels = self.rule.tunnels.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(held) = tunnels.get_mut(&self.client) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                tunnels.remove(&self.client);
            }
        }
    }
}

/// A serialized origin (RFC 6454): a scheme, a host and an optional port, nothing more.
fn is_origin(text: &str) -> bool {
    let rest = text.strip_prefix("https://").or_else(|| text.strip_prefix("http://"));
    rest.is_some_and(|authority| {
        !authority.is_empty()
            && authority.len() <= 255
            && authority.bytes().all(|b| b.is_ascii_alphanumeric() || b"-.:[]".contains(&b))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_are_matched_whole_and_tunnels_are_counted_per_client() {
        let rule = Arc::new(WebSocketRule::new(vec!["https://App.example.org".into()], Some(2)));
        let client: IpAddr = "192.0.2.7".parse().unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let other: IpAddr = "192.0.2.8".parse().unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let good: Option<&[u8]> = Some(b"https://app.example.org");
        assert_eq!(rule.admit(None, client).err(), Some(TunnelRefusal::Origin));
        let evil: Option<&[u8]> = Some(b"https://app.example.org.evil.test");
        assert_eq!(rule.admit(evil, client).err(), Some(TunnelRefusal::Origin));
        let first = rule.admit(good, client);
        let second = rule.admit(Some(b"HTTPS://APP.EXAMPLE.ORG"), client);
        assert!(first.is_ok() && second.is_ok());
        assert_eq!(rule.admit(good, client).err(), Some(TunnelRefusal::Limit));
        assert!(rule.admit(good, other).is_ok());
        assert_eq!((rule.tunnel_count(client), rule.tunnel_count(other)), (2, 0));
        drop(first);
        assert!(rule.admit(good, client).is_ok());
        drop(second);
        assert_eq!(rule.tunnel_count(client), 0);
    }

    #[test]
    fn only_serialized_origins_are_accepted_in_a_rule() {
        assert!(is_origin("https://app.example.org") && is_origin("http://[::1]:8080"));
        assert!(!is_origin("app.example.org") && !is_origin("https://a/path"));
        assert!(!is_origin("https://") && !is_origin("wss://a"));
    }
}
