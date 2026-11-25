//! The `global.acme.internal.server` object: the ACME server in front of the local
//! authority (SID 0021). Nothing here opens a socket or a file.
//!
//! ```text
//! "server": { "url": "https://ca.corp.internal/acme",
//!             "allow": ["corp.internal", "10.0.0.0/8"],
//!             "http_port": 80 }
//! ```

use std::io;
use std::net::IpAddr;

use sibuna_json::ObjectReader;

use super::internal::{canonical, range};
use crate::config::{field, invalid};

/// The most entries of `allow`.
const MAX_ALLOW: usize = 32;
/// The longest base URL.
const MAX_URL: usize = 255;

/// The `global.acme.internal.server` object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InternalServer {
    /// The base URL that clients are given, without a final slash. The directory is
    /// `URL/directory`.
    pub url: String,
    /// Whether the URL is an `https` URL. Then only a TLS frontend answers for it.
    pub secure: bool,
    /// The host of the URL in lower case, with its port when the URL has one.
    pub authority: String,
    /// The path of the URL: empty, or a path that starts with a slash.
    pub path: String,
    /// The DNS suffixes that a client may order names under, in lower case.
    pub names: Vec<String>,
    /// The address ranges that an HTTP-01 validation may connect into.
    pub ranges: Vec<(IpAddr, u8)>,
    /// The port that an HTTP-01 validation connects to.
    pub http_port: u16,
}

/// Whether `host` is a name or an address of this machine alone.
fn is_loopback(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost" || bare.parse::<IpAddr>().is_ok_and(|address| address.is_loopback())
}

/// Splits a base URL into whether it is secure, its authority and its path. `None`
/// when it is no `http` or `https` URL of plain characters, when it has a query, a
/// fragment, a user or a final slash, or when it is `http` for a host that is not
/// this machine.
fn split_url(url: &str) -> Option<(bool, String, String)> {
    let (secure, rest) = match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
        (Some(rest), _) => (true, rest),
        (None, Some(rest)) => (false, rest),
        (None, None) => return None,
    };
    let plain = |byte: u8| byte.is_ascii_graphic() && !b"\"\\?#@<>%".contains(&byte);
    if url.len() > MAX_URL || !url.bytes().all(plain) || url.ends_with('/') {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(slash) => rest.split_at(slash),
        None => (rest, ""),
    };
    let authority = authority.to_ascii_lowercase();
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !port.contains(']') => (host, Some(port)),
        _ => (authority.as_str(), None),
    };
    let port_is_good = port.is_none_or(|port| port.parse::<u16>().is_ok_and(|port| port != 0));
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let host_is_good = crate::hello::valid_host(host) || bare.parse::<IpAddr>().is_ok();
    if !port_is_good || !host_is_good || (!secure && !is_loopback(host)) {
        return None;
    }
    Some((secure, authority, path.to_owned()))
}

impl InternalServer {
    /// Reads the object. `constraints` are the name constraints of the root in their
    /// stored form: a suffix of `allow` must lie inside them, when there are any.
    pub(crate) fn parse(mut r: ObjectReader<'_, '_>, constraints: &[String]) -> io::Result<Self> {
        let path = r.field_path("url");
        let url = field(r.take_str("url"))?.ok_or_else(|| invalid(r.missing("url")))?;
        let Some((secure, authority, url_path)) = split_url(url) else {
            return Err(invalid(format!(
                "{path}: expected a URL such as \"https://ca.corp.internal/acme\" with no \
                 final slash; \"http\" is for localhost only"
            )));
        };
        let path = r.field_path("allow");
        let allow = field(r.take_array("allow"))?.ok_or_else(|| invalid(r.missing("allow")))?;
        if allow.len() > MAX_ALLOW {
            return Err(invalid(format!("{path}: expected at most {MAX_ALLOW} entries")));
        }
        let (mut names, mut ranges) = (Vec::new(), Vec::new());
        for item in allow {
            let entry = item.as_str().and_then(canonical).ok_or_else(|| {
                invalid(format!(
                    "{path}: expected DNS suffixes such as \"corp.internal\" and address \
                     ranges such as \"10.0.0.0/8\""
                ))
            })?;
            match range(&entry) {
                Some(found) => ranges.push(found),
                None => names.push(entry),
            }
        }
        if names.is_empty() || ranges.is_empty() {
            return Err(invalid(format!(
                "{path}: needs a DNS suffix that clients may order under and an address \
                 range that a validation may connect into"
            )));
        }
        let inside = |name: &String| {
            constraints.iter().filter(|entry| !entry.contains('/')).any(|suffix| {
                name.strip_suffix(suffix.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
            })
        };
        if let Some(name) = names.iter().find(|name| !constraints.is_empty() && !inside(name)) {
            return Err(invalid(format!(
                "{path}: `{name}` is outside global.acme.internal.constraints; the root \
                 cannot sign for it"
            )));
        }
        names.sort();
        names.dedup();
        let path = r.field_path("http_port");
        let http_port = match field(r.take_u64("http_port"))? {
            None => 80,
            Some(port) => u16::try_from(port)
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(|| invalid(format!("{path}: expected a port from 1 to 65535")))?,
        };
        field(r.finish())?;
        Ok(Self {
            url: url.to_owned(),
            secure,
            authority,
            path: url_path,
            names,
            ranges,
            http_port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str, constraints: &[&str]) -> io::Result<InternalServer> {
        let value = sibuna_json::parse(text.as_bytes()).map_err(invalid)?;
        let path = "global.acme.internal.server".to_owned();
        let reader = ObjectReader::with_path(&value, path).map_err(invalid)?;
        let constraints: Vec<String> =
            constraints.iter().map(|entry| (*entry).to_owned()).collect();
        InternalServer::parse(reader, &constraints)
    }

    #[test]
    fn the_object_is_read_into_its_parts() {
        let text = r#"{"url":"https://CA.Corp.Internal:8443/acme",
            "allow":["10.1.2.3/8",".Corp.Internal","fd00::/8","corp.internal"],"http_port":8080}"#;
        let server = read(text, &["internal"]).ok();
        let expected = InternalServer {
            url: "https://CA.Corp.Internal:8443/acme".to_owned(),
            secure: true,
            authority: "ca.corp.internal:8443".to_owned(),
            path: "/acme".to_owned(),
            names: vec!["corp.internal".to_owned()],
            ranges: vec![("10.0.0.0".parse().ok(), 8), ("fd00::".parse().ok(), 8)]
                .into_iter()
                .filter_map(|(address, prefix)| Some((address?, prefix)))
                .collect(),
            http_port: 8080,
        };
        assert_eq!(server, Some(expected));
        let plain =
            read(r#"{"url":"http://127.0.0.1:8080","allow":["localhost","::1"]}"#, &[]).ok();
        let plain = plain.map(|s| (s.secure, s.authority, s.path, s.http_port));
        assert_eq!(plain, Some((false, "127.0.0.1:8080".to_owned(), String::new(), 80)));
        assert!(
            read(r#"{"url":"http://[::1]:8080/a/b","allow":["localhost","::1"]}"#, &[]).is_ok()
        );
    }

    #[test]
    fn a_url_that_cannot_be_served_is_refused() {
        for url in [
            "ca.corp.internal",
            "ftp://ca.corp.internal",
            "http://ca.corp.internal",
            "https://ca.corp.internal/",
            "https://ca.corp.internal/acme/",
            "https://ca.corp.internal/acme?x=1",
            "https://ca.corp.internal/acme#x",
            "https://user@ca.corp.internal",
            "https://ca.corp.internal:0",
            "https://ca.corp.internal:99999",
            "https://ca corp",
            "https://",
            "https://ca.corp.internal/a\\\"b",
        ] {
            let text = format!(r#"{{"url":"{url}","allow":["corp.internal","10.0.0.0/8"]}}"#);
            let error = read(&text, &[]).err().map(|error| error.to_string()).unwrap_or_default();
            assert!(error.contains("server.url"), "{url}: {error}");
        }
        let long = format!("https://ca.corp.internal/{}", "a".repeat(MAX_URL));
        let text = format!(r#"{{"url":"{long}","allow":["corp.internal","10.0.0.0/8"]}}"#);
        assert!(read(&text, &[]).is_err());
    }

    #[test]
    fn allow_needs_names_and_ranges_inside_the_constraints() {
        let with = |allow: &str, constraints: &[&str]| {
            let text = format!(r#"{{"url":"https://ca.corp.internal","allow":{allow}}}"#);
            read(&text, constraints).err().map(|error| error.to_string()).unwrap_or_default()
        };
        assert!(with(r#"["corp.internal"]"#, &[]).contains("needs a DNS suffix"));
        assert!(with(r#"["10.0.0.0/8"]"#, &[]).contains("needs a DNS suffix"));
        assert!(with("[]", &[]).contains("needs a DNS suffix"));
        assert!(with(r#"["*.corp","10.0.0.0/8"]"#, &[]).contains("expected DNS suffixes"));
        assert!(with(r#"[7,"10.0.0.0/8"]"#, &[]).contains("expected DNS suffixes"));
        let outside = with(r#"["example.org","10.0.0.0/8"]"#, &["corp.internal"]);
        assert!(outside.contains("`example.org` is outside"), "{outside}");
        assert!(with(r#"["internal","10.0.0.0/8"]"#, &["corp.internal"]).contains("outside"));
        assert_eq!(with(r#"["a.corp.internal","10.0.0.0/8"]"#, &["corp.internal"]), "");
        // Constraints of ranges only close every name.
        assert!(with(r#"["corp.internal","10.0.0.0/8"]"#, &["10.0.0.0/8"]).contains("outside"));
        let many: Vec<String> = (0..=MAX_ALLOW).map(|n| format!("\"h{n}.internal\"")).collect();
        assert!(with(&format!("[{}]", many.join(",")), &[]).contains("at most 32"));
        let text =
            r#"{"url":"https://ca.corp.internal","allow":["a.internal","::1"],"http_port":0}"#;
        assert!(read(text, &[]).is_err());
        let text = r#"{"url":"https://ca.corp.internal","allow":["a.internal","::1"],"other":1}"#;
        assert!(read(text, &[]).is_err());
        assert!(read(r#"{"allow":["a.internal","::1"]}"#, &[]).is_err());
        assert!(read(r#"{"url":"https://ca.corp.internal"}"#, &[]).is_err());
    }
}
