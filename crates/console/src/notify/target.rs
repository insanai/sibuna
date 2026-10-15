//! Notification targets (Zig's `notify_target.zig`): one rule, used when a destination is
//! saved (`api/notifications`) and again before every delivery.
//!
//! A webhook is `https://` to a public host on port 443 or 8443, or `http://` to a loopback
//! literal on a port of 1024 or more, without user information or a fragment. A syslog
//! receiver is `host:port`. A literal address must be public, or loopback where plain
//! delivery to the same host is allowed; private, link-local and metadata ranges never
//! are. Names are checked again after resolution, so a name cannot point at private space.
//!
//! Changes from Zig: plain HTTP is allowed only to a loopback literal (SID 0012); Zig also
//! accepted public literals. A host that is not an address literal may not contain a colon.

use std::fmt;
use std::net::IpAddr;

use sibuna_console_protocol::notifications::Kind;
use sibuna_crypto::sha256::Sha256;
use sibuna_net::outbound::{self, Policy};

/// The longest webhook URL, in bytes.
pub const MAX_URL: usize = 512;
/// The longest syslog address, in bytes.
pub const MAX_SYSLOG: usize = 255;

/// Bytes a webhook URL may not contain anywhere.
const URL_FORBIDDEN: [char; 9] = [' ', '\t', '\r', '\n', '"', '\'', '<', '>', '\\'];
/// Bytes a syslog host may not contain.
const SYSLOG_FORBIDDEN: [char; 8] = [' ', '\t', '\r', '\n', '/', '\\', '"', '\''];

/// A target that may not be stored or reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InvalidTarget;

impl fmt::Display for InvalidTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InvalidTarget")
    }
}

impl std::error::Error for InvalidTarget {}

/// The scheme of a webhook.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// HTTP over TLS.
    Https,
    /// Plain HTTP, only to a loopback literal.
    Http,
}

/// A validated webhook URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Webhook<'a> {
    /// The scheme.
    pub scheme: Scheme,
    /// The host, percent-decoded, IPv6 without brackets.
    pub host: String,
    /// The port, the scheme's default when none was written.
    pub port: u16,
    /// The request-target: the path and query of the URL, `/` when it has no path.
    pub path: &'a str,
}

impl Webhook<'_> {
    /// Returns the address policy the resolved host must pass: loopback for plain HTTP,
    /// public addresses only for HTTPS.
    pub fn policy(&self) -> Policy {
        match self.scheme {
            Scheme::Http => Policy::LoopbackAllowed,
            Scheme::Https => Policy::PublicOnly,
        }
    }

    /// Returns the origin text the client connects to: the scheme, the host (IPv6 in
    /// brackets) and the port.
    pub fn origin(&self) -> String {
        let scheme = if self.scheme == Scheme::Https { "https" } else { "http" };
        if self.host.contains(':') {
            format!("{scheme}://[{}]:{}", self.host, self.port)
        } else {
            format!("{scheme}://{}:{}", self.host, self.port)
        }
    }
}

/// A validated syslog address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Syslog<'a> {
    /// The host, IPv6 without brackets.
    pub host: &'a str,
    /// The port.
    pub port: u16,
}

/// Returns the subject a sealed secret is bound to: the first eight bytes, little-endian,
/// of SHA-256 over a domain and the destination's target. An envelope copied onto a row
/// with another target cannot be opened, and the subject is known before the row has an
/// id (Zig's `envelopeSubject`).
pub fn envelope_subject(target: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"sibuna-console-notify-target-v1");
    hasher.update(target.as_bytes());
    let digest = hasher.finalize();
    let mut first = [0u8; 8];
    first.copy_from_slice(digest.get(..8).unwrap_or(&[0; 8]));
    u64::from_le_bytes(first)
}

/// Returns the host of `target` when it may be stored for `kind`, or `None`. The host is
/// what storage keeps as `target_host` and audit summaries show.
pub fn target_host(kind: Kind, target: &str) -> Option<String> {
    match kind {
        Kind::Webhook => validate_webhook(target).ok().map(|webhook| webhook.host),
        Kind::Syslog => validate_syslog(target).ok().map(|syslog| syslog.host.to_owned()),
    }
}

/// Checks a webhook URL (Zig's `validateWebhook`). Borrows `url`; the returned path borrows
/// it too.
///
/// Fails with [`InvalidTarget`] for anything but `https://` to a name or a public literal
/// on port 443 or 8443, or `http://` to a loopback literal on port 1024 or above; for user
/// information, a fragment, quotes, angle brackets, backslashes or white space; and for a
/// URL longer than [`MAX_URL`] bytes.
pub fn validate_webhook(url: &str) -> Result<Webhook<'_>, InvalidTarget> {
    if url.len() > MAX_URL || url.contains(URL_FORBIDDEN) || url.contains('#') {
        return Err(InvalidTarget);
    }
    let (scheme, rest) = match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
        (Some(rest), _) => (Scheme::Https, rest),
        (None, Some(rest)) => (Scheme::Http, rest),
        _ => return Err(InvalidTarget),
    };
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, after) = rest.split_at(end);
    if authority.contains('@') {
        return Err(InvalidTarget);
    }
    let (raw_host, port) = split_host_port(authority).ok_or(InvalidTarget)?;
    let host = percent_decode(raw_host).ok_or(InvalidTarget)?;
    let port = match port {
        Some(text) => text.parse::<u16>().ok().filter(|&port| port != 0).ok_or(InvalidTarget)?,
        None if scheme == Scheme::Https => 443,
        None => 80,
    };
    let allowed = match host.parse::<IpAddr>() {
        Ok(address) => match scheme {
            Scheme::Https => is_address_allowed(address, false),
            Scheme::Http => address.is_loopback() && is_address_allowed(address, true),
        },
        Err(_) => scheme == Scheme::Https && !host.contains(':'),
    };
    let port_allowed = match scheme {
        Scheme::Https => port == 443 || port == 8443,
        Scheme::Http => port >= 1024,
    };
    if !allowed || !port_allowed || outbound::Host::new(&host).is_err() {
        return Err(InvalidTarget);
    }
    // As in Zig, a URL without a path posts to `/`, even when it has a query.
    let path = if after.starts_with('/') { after } else { "/" };
    Ok(Webhook { scheme, host, port, path })
}

/// Checks a syslog address `host:port` (Zig's `validateSyslog`). Borrows `text`; the
/// returned host borrows it too.
///
/// Fails with [`InvalidTarget`] for an empty or missing host, a port that is not 1 to
/// 65535, white space, quotes, slashes or backslashes in the host, a literal that is neither
/// public nor loopback, or more than [`MAX_SYSLOG`] bytes.
pub fn validate_syslog(text: &str) -> Result<Syslog<'_>, InvalidTarget> {
    if text.is_empty() || text.len() > MAX_SYSLOG {
        return Err(InvalidTarget);
    }
    let (host, port) = text.rsplit_once(':').ok_or(InvalidTarget)?;
    let host = host.strip_prefix('[').and_then(|bare| bare.strip_suffix(']')).unwrap_or(host);
    if host.is_empty() || host.contains(SYSLOG_FORBIDDEN) {
        return Err(InvalidTarget);
    }
    let port = port.parse::<u16>().ok().filter(|&port| port != 0).ok_or(InvalidTarget)?;
    if let Ok(address) = host.parse::<IpAddr>()
        && !is_address_allowed(address, true)
    {
        return Err(InvalidTarget);
    }
    Ok(Syslog { host, port })
}

/// Returns true for a public unicast address, or loopback when `loopback_ok` (plain
/// webhooks and syslog receivers on the same host). Private, link-local and metadata
/// ranges never are.
pub fn is_address_allowed(address: IpAddr, loopback_ok: bool) -> bool {
    let policy = if loopback_ok { Policy::LoopbackAllowed } else { Policy::PublicOnly };
    outbound::is_allowed(address, policy)
}

/// Splits `authority` into a host (brackets removed) and an optional port text.
fn split_host_port(authority: &str) -> Option<(&str, Option<&str>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':')?),
        };
        return (!host.is_empty()).then_some((host, port));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    (!host.is_empty()).then_some((host, port))
}

/// Decodes `%HH` escapes in a host, as Zig's URI parser did; a `%` without two hex digits
/// stays as it is. Returns `None` when the result is empty or not UTF-8.
fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        let escaped = bytes.get(index + 1..index + 3).and_then(|pair| {
            let text = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(text, 16).ok()
        });
        match (byte, escaped) {
            (b'%', Some(value)) => {
                out.push(value);
                index += 3;
            }
            _ => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).ok().filter(|host| !host.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    // notify_target.zig: "webhook targets are https to public hosts or http to loopback
    // literals".
    #[test]
    fn webhooks_are_https_to_public_hosts_or_http_to_loopback_literals() {
        let ok = validate_webhook("https://hooks.example/notify?team=ops").unwrap();
        assert_eq!(
            (ok.host.as_str(), ok.port, ok.path),
            ("hooks.example", 443, "/notify?team=ops")
        );
        assert_eq!(ok.policy(), Policy::PublicOnly);
        assert_eq!(ok.origin(), "https://hooks.example:443");
        let local = validate_webhook("http://127.0.0.1:8099/hook").unwrap();
        assert_eq!((local.scheme, local.port, local.path), (Scheme::Http, 8099, "/hook"));
        assert_eq!(local.policy(), Policy::LoopbackAllowed);
        let v6 = validate_webhook("https://[2606:4700::1]:8443/x").unwrap();
        assert_eq!(
            (v6.host.as_str(), v6.origin()),
            ("2606:4700::1", "https://[2606:4700::1]:8443".into())
        );
        assert_eq!(validate_webhook("https://hooks.example?x=1").unwrap().path, "/");
        for refused in [
            "http://hooks.example/x",
            "https://user@hooks.example/x",
            "https://10.0.0.1/x",
            "https://169.254.169.254/",
            "ftp://hooks.example/x",
            "https://hooks.example:22/x",
            "https://[fe80::1]/x",
            "https://hooks.example/x#frag",
            "",
            "https://hooks.example:9443/x",
            "http://127.0.0.1:80/hook",
            // Added in the port: SID 0012 allows plain HTTP to loopback only.
            "http://8.8.8.8:8080/hook",
            "https://hooks.example:0/x",
            "https://hooks example/x",
            "https://a:b:c/x",
            "https://[::1/x",
            "https:///x",
        ] {
            assert_eq!(validate_webhook(refused), Err(InvalidTarget), "{refused}");
        }
        assert_eq!(
            validate_webhook(&format!("https://h.example/{}", "a".repeat(512))).err(),
            Some(InvalidTarget)
        );
    }

    // notify_target.zig: "syslog endpoints need a host and port and never link-local space".
    #[test]
    fn syslog_endpoints_need_a_host_and_port_and_never_link_local_space() {
        let endpoint = validate_syslog("logs.example:514").unwrap();
        assert_eq!((endpoint.host, endpoint.port), ("logs.example", 514));
        assert_eq!(validate_syslog("[::1]:1514").unwrap().host, "::1");
        assert_eq!(validate_syslog("127.0.0.1:514").unwrap().host, "127.0.0.1");
        for refused in [
            "logs.example",
            ":514",
            "169.254.1.1:514",
            "a b:514",
            "x:0",
            "10.0.0.1:514",
            "a/b:514",
        ] {
            assert_eq!(validate_syslog(refused), Err(InvalidTarget), "{refused}");
        }
    }

    // notify_target.zig: "decoded webhook hostnames are owned after parsing".
    #[test]
    fn decoded_webhook_hostnames_are_owned_after_parsing() {
        let url = String::from("https://%68ooks.example/notify");
        let encoded = validate_webhook(&url).unwrap();
        let host = encoded.host.clone();
        drop(encoded);
        assert_eq!(host, "hooks.example");
        assert_eq!(percent_decode("a%zz%4"), Some("a%zz%4".into()));
        assert_eq!(percent_decode("%ff"), None);
        // A decoded loopback literal is a literal.
        assert_eq!(validate_webhook("http://%31%32%37.0.0.1:8099/").unwrap().host, "127.0.0.1");
    }

    #[test]
    fn hosts_and_subjects_follow_the_target() {
        assert_eq!(
            target_host(Kind::Webhook, "https://hooks.example/x").as_deref(),
            Some("hooks.example")
        );
        assert_eq!(target_host(Kind::Syslog, "[::1]:514").as_deref(), Some("::1"));
        assert_eq!(target_host(Kind::Webhook, "logs.example:514"), None);
        assert_ne!(
            envelope_subject("https://a.example/x"),
            envelope_subject("https://b.example/x")
        );
        assert_eq!(envelope_subject("x"), envelope_subject("x"));
    }
}
