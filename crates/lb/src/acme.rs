//! The configuration of automatic HTTPS (SID 0021): the `auto` names of a TLS frontend
//! and the `global.acme` object. Nothing here opens a socket or a file.

use std::collections::BTreeMap;
use std::io;

use sibuna_json::ObjectReader;

use crate::config::{Config, Protocol, field, invalid};

/// The production directory of Let's Encrypt, the default authority.
pub const LETSENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// The staging directory of Let's Encrypt, for tests.
pub const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
/// The most `auto` names of one frontend.
const MAX_NAMES: usize = 64;

/// Which challenge the daemon answers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AcmeChallenge {
    /// HTTP-01 when the file has a plain HTTP frontend, else TLS-ALPN-01. After a failed
    /// attempt the other type.
    #[default]
    Auto,
    /// HTTP-01 only.
    Http01,
    /// TLS-ALPN-01 only.
    TlsAlpn01,
}

/// The `global.acme` object. Every key has a default.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcmeOptions {
    /// The URL of the ACME directory.
    pub directory: String,
    /// The contact address of the account.
    pub email: Option<String>,
    /// The directory of the account key, the certificates and the locks.
    pub storage: String,
    /// The challenge to answer.
    pub challenge: AcmeChallenge,
    /// PEM roots for the connection to the authority. `None` uses the system trust store.
    pub ca_file: Option<String>,
    /// Redirect plain HTTP requests for managed names to HTTPS.
    pub redirect: bool,
}

impl Default for AcmeOptions {
    fn default() -> Self {
        Self {
            directory: LETSENCRYPT.to_owned(),
            email: None,
            storage: "/var/lib/sibuna/acme".to_owned(),
            challenge: AcmeChallenge::Auto,
            ca_file: None,
            redirect: true,
        }
    }
}

impl AcmeOptions {
    /// Whether the authority is one of the public directories that we know by name. A
    /// public authority is never asked for an internal name.
    pub fn is_public(&self) -> bool {
        self.directory == LETSENCRYPT || self.directory == LETSENCRYPT_STAGING
    }

    pub(crate) fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Self> {
        let defaults = Self::default();
        let directory = match field(r.take_str("directory"))? {
            None | Some("letsencrypt") => defaults.directory,
            Some("letsencrypt-staging") => LETSENCRYPT_STAGING.to_owned(),
            Some(url) if is_directory_url(url) => url.to_owned(),
            Some(_) => {
                return Err(invalid(
                    "global.acme.directory: expected \"letsencrypt\", \"letsencrypt-staging\" \
                     or an https URL (http is accepted for a loopback address only)",
                ));
            }
        };
        let email = match field(r.take_str("email"))? {
            None => None,
            Some(email) if is_email(email) => Some(email.to_owned()),
            Some(_) => return Err(invalid("global.acme.email: expected an e-mail address")),
        };
        let storage = match field(r.take_str("storage"))? {
            None => defaults.storage,
            Some("") => return Err(invalid("global.acme.storage must be a directory")),
            Some(path) => path.to_owned(),
        };
        let challenge = match field(r.take_str("challenge"))? {
            None | Some("auto") => AcmeChallenge::Auto,
            Some("http-01") => AcmeChallenge::Http01,
            Some("tls-alpn-01") => AcmeChallenge::TlsAlpn01,
            Some(_) => {
                return Err(invalid(
                    "global.acme.challenge: expected \"auto\", \"http-01\" or \"tls-alpn-01\"",
                ));
            }
        };
        let ca_file = field(r.take_str("ca_file"))?.map(str::to_owned);
        let redirect = field(r.take_bool("redirect"))?.unwrap_or(defaults.redirect);
        field(r.finish())?;
        Ok(Self { directory, email, storage, challenge, ca_file, redirect })
    }
}

/// Whether `url` may be an ACME directory: `https`, or `http` to this host.
fn is_directory_url(url: &str) -> bool {
    let printable = url.len() <= 512 && url.bytes().all(|byte| byte.is_ascii_graphic());
    let authority = |rest: &str| rest.split(['/', '?']).next().unwrap_or_default().to_owned();
    match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
        _ if !printable => false,
        (Some(rest), _) => !authority(rest).is_empty(),
        (_, Some(rest)) => {
            let authority = authority(rest);
            let host = authority.rsplit_once(':').map_or(authority.as_str(), |(host, _)| host);
            host == "localhost" || host == "[::1]" || host.starts_with("127.")
        }
        _ => false,
    }
}

fn is_email(text: &str) -> bool {
    let plain = text.len() <= 254 && text.bytes().all(|byte| byte.is_ascii_graphic());
    plain
        && text.split_once('@').is_some_and(|(user, host)| {
            !user.is_empty() && !host.contains('@') && crate::hello::valid_host(host)
        })
}

/// Whether a public authority cannot or must not validate `name`: `localhost`, a name of
/// one label, and the reserved endings of RFC 6761, RFC 6762 and RFC 8375.
pub fn is_internal_name(name: &str) -> bool {
    const ENDINGS: [&str; 8] =
        ["localhost", "local", "internal", "home.arpa", "test", "example", "invalid", "lan"];
    let name = name.to_ascii_lowercase();
    !name.contains('.')
        || ENDINGS.iter().any(|ending| {
            name.strip_suffix(ending).is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
        })
}

/// Reads `tls.auto`: one host name or a list of them, stored in lower case.
pub(crate) fn names(r: &mut ObjectReader<'_, '_>) -> io::Result<Vec<String>> {
    let path = r.field_path("auto");
    let listed: Vec<&str> = match r.take("auto") {
        None => return Ok(Vec::new()),
        Some(value) => match (value.as_str(), value.as_array()) {
            (Some(name), _) => vec![name],
            (_, Some(items)) if (1..=MAX_NAMES).contains(&items.len()) => items
                .iter()
                .map(|item| item.as_str())
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| invalid(format!("{path}: expected host names")))?,
            _ => {
                return Err(invalid(format!(
                    "{path}: expected a host name or a list of 1 to {MAX_NAMES} host names"
                )));
            }
        },
    };
    let mut names = Vec::with_capacity(listed.len());
    for name in listed {
        let name = name.to_ascii_lowercase();
        if name.starts_with("*.") {
            return Err(invalid(format!(
                "{path}: `{name}` is a wildcard, which needs the DNS challenge; list the \
                 host names, or serve the wildcard from a file with crt"
            )));
        }
        if name.parse::<std::net::IpAddr>().is_ok() || !crate::hello::valid_host(&name) {
            return Err(invalid(format!("{path}: `{name}` is not a DNS host name")));
        }
        if !names.contains(&name) {
            names.push(name);
        }
    }
    Ok(names)
}

/// What the daemon needs to run automatic HTTPS for a topology.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomaticHttps {
    /// The `global.acme` object, or its defaults.
    pub options: AcmeOptions,
    /// Every managed name with the port of its first TLS frontend, sorted by name.
    pub names: Vec<(String, u16)>,
    /// Whether the topology has an HTTP frontend without TLS, for HTTP-01 and the
    /// redirect.
    pub plain_frontend: bool,
}

impl Config {
    /// Automatic HTTPS of this topology, when a TLS frontend has an `auto` name.
    pub fn automatic_https(&self) -> Option<AutomaticHttps> {
        let mut names = BTreeMap::new();
        let mut plain_frontend = false;
        for ((protocol, addr), frontend) in &self.listeners {
            match &frontend.tls {
                Some(tls) => {
                    for name in &tls.auto {
                        names.entry(name.clone()).or_insert(addr.port());
                    }
                }
                None => plain_frontend |= *protocol == Protocol::Http,
            }
        }
        (!names.is_empty()).then(|| AutomaticHttps {
            options: self.acme.clone().unwrap_or_default(),
            names: names.into_iter().collect(),
            plain_frontend,
        })
    }

    /// Checks `global.acme` against the frontends: the object needs an `auto` name, and
    /// a public authority takes no internal name.
    pub(crate) fn check_automatic_https(&self) -> io::Result<()> {
        let Some(automatic) = self.automatic_https() else {
            return match self.acme {
                Some(_) => Err(invalid("global.acme requires a frontend with tls.auto names")),
                None => Ok(()),
            };
        };
        if !automatic.options.is_public() {
            return Ok(());
        }
        match automatic.names.iter().find(|(name, _)| is_internal_name(name)) {
            Some((name, _)) => Err(invalid(format!(
                "tls.auto: `{name}` is an internal name; a public certificate authority \
                 cannot validate it"
            ))),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(tls: &str, global: &str) -> io::Result<Config> {
        let document = format!(
            r#"{{{global}"frontends":{{"web":{{"binds":["0.0.0.0:443"],"tls":{tls}}},
                 "plain":{{"binds":["0.0.0.0:80"]}}}},
               "backends":{{"app":{{"servers":["10.0.0.1:80"]}}}}}}"#
        );
        Config::parse(document.as_bytes())
    }

    fn reason(tls: &str, global: &str) -> String {
        parse(tls, global).err().map(|error| error.to_string()).unwrap_or_default()
    }

    #[test]
    fn the_smallest_form_names_the_hosts_and_takes_every_default() {
        let config = parse(r#"{"auto":["Example.org","www.example.org","example.org"]}"#, "");
        let automatic = config.ok().and_then(|config| config.automatic_https());
        let expected = AutomaticHttps {
            options: AcmeOptions::default(),
            names: vec![("example.org".to_owned(), 443), ("www.example.org".to_owned(), 443)],
            plain_frontend: true,
        };
        assert_eq!(automatic, Some(expected));
        let defaults = AcmeOptions::default();
        assert_eq!(defaults.directory, LETSENCRYPT);
        assert_eq!(defaults.storage, "/var/lib/sibuna/acme");
        assert!(defaults.redirect && defaults.is_public() && defaults.email.is_none());
        let single = parse(r#"{"auto":"example.org"}"#, "").ok();
        assert_eq!(single.and_then(|c| c.automatic_https()).map(|a| a.names.len()), Some(1));
    }

    #[test]
    fn every_acme_key_is_read() {
        let global = r#""global":{"acme":{"directory":"https://ca.internal/dir",
            "email":"ops@example.org","storage":"/srv/acme","challenge":"tls-alpn-01",
            "ca_file":"/etc/ca.pem","redirect":false}},"#;
        let config = parse(r#"{"auto":["intranet.local"]}"#, global);
        let options = config.ok().and_then(|c| c.automatic_https()).map(|a| a.options);
        let expected = AcmeOptions {
            directory: "https://ca.internal/dir".to_owned(),
            email: Some("ops@example.org".to_owned()),
            storage: "/srv/acme".to_owned(),
            challenge: AcmeChallenge::TlsAlpn01,
            ca_file: Some("/etc/ca.pem".to_owned()),
            redirect: false,
        };
        assert_eq!(options, Some(expected));
        let staging = r#""global":{"acme":{"directory":"letsencrypt-staging"}},"#;
        let config = parse(r#"{"auto":["example.org"]}"#, staging);
        let options = config.ok().and_then(|c| c.automatic_https()).map(|a| a.options);
        assert_eq!(options.map(|o| o.directory).as_deref(), Some(LETSENCRYPT_STAGING));
    }

    #[test]
    fn internal_names_are_refused_for_a_public_authority_only() {
        for name in ["localhost", "intranet", "a.local", "db.internal", "x.home.arpa", "a.test"] {
            assert!(is_internal_name(name), "{name}");
            let text = reason(&format!(r#"{{"auto":["{name}"]}}"#), "");
            assert!(text.contains("is an internal name"), "{name}: {text}");
        }
        for name in ["example.org", "local.example.org", "mylocal.org", "internal.io"] {
            assert!(!is_internal_name(name), "{name}");
        }
        let private = r#""global":{"acme":{"directory":"http://127.0.0.1:14000/dir"}},"#;
        assert!(parse(r#"{"auto":["localhost"]}"#, private).is_ok());
    }

    #[test]
    fn mistakes_are_named() {
        let auto = |value: &str| reason(&format!(r#"{{"auto":{value}}}"#), "");
        assert!(auto(r#"["*.example.org"]"#).contains("wildcard"));
        assert!(auto(r#"["192.0.2.1"]"#).contains("not a DNS host name"));
        assert!(auto(r#"["bad_name.example.org"]"#).contains("not a DNS host name"));
        assert!(auto("[]").contains("1 to 64 host names"));
        assert!(auto("[7]").contains("expected host names"));
        assert!(reason("{}", "").contains("or auto (host names)"));
        let acme = |members: &str| {
            reason(
                r#"{"auto":["example.org"]}"#,
                &format!(r#""global":{{"acme":{{{members}}}}},"#),
            )
        };
        assert!(acme(r#""directory":"http://ca.example/dir""#).contains("loopback"));
        assert!(acme(r#""directory":"ftp://x""#).contains("https URL"));
        assert!(acme(r#""email":"nobody""#).contains("e-mail"));
        assert!(acme(r#""challenge":"dns-01""#).contains("http-01"));
        assert!(acme(r#""storage":"""#).contains("directory"));
        assert!(acme(r#""staging":true"#).contains("staging"));
        let unused = r#""global":{"acme":{}},"#;
        let text = reason(r#"{"crt":"site.pem"}"#, unused);
        assert!(text.contains("requires a frontend with tls.auto"), "{text}");
    }

    #[test]
    fn a_topology_without_a_plain_frontend_says_so() {
        let document = r#"{"frontends":{"web":{"binds":["0.0.0.0:8443"],
            "tls":{"auto":["example.org"],"crt":"site.pem"}}},
            "backends":{"app":{"servers":["10.0.0.1:80"]}}}"#;
        let automatic = Config::parse(document.as_bytes()).ok().and_then(|c| c.automatic_https());
        assert_eq!(automatic.as_ref().map(|a| a.plain_frontend), Some(false));
        assert_eq!(automatic.map(|a| a.names), Some(vec![("example.org".to_owned(), 8443)]));
    }
}
