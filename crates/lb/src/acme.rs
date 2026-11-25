//! The configuration of automatic HTTPS (SID 0021): the `auto` names of a TLS frontend
//! and the `global.acme` object. Nothing here opens a socket or a file.

mod authority;
mod demand;
mod dns;
mod internal;
mod server;

use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;

use sibuna_json::ObjectReader;

pub use self::authority::{Authority, Eab};
pub use self::demand::OnDemand;
pub use self::dns::{DnsConfig, DnsProvider};
pub use self::internal::{INTERNAL_LIFETIME, Internal};
pub use self::server::InternalServer;
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
    /// DNS-01 for every name. A wildcard uses DNS-01 whatever this says.
    Dns01,
}

/// `global.acme.key`: the kind of the key of a new certificate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CertificateKey {
    /// ECDSA on P-256.
    #[default]
    P256,
    /// ECDSA on P-384.
    P384,
    /// RSA with 2048 bits. The daemon makes it with the `openssl` program.
    Rsa2048,
    /// RSA with 3072 bits.
    Rsa3072,
    /// RSA with 4096 bits.
    Rsa4096,
}

impl CertificateKey {
    /// Whether the key is an RSA key, which the `openssl` program makes.
    pub fn is_rsa(self) -> bool {
        matches!(self, Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096)
    }
}

/// Reads `global.acme.key`.
fn certificate_key(r: &mut ObjectReader<'_, '_>) -> io::Result<CertificateKey> {
    let path = r.field_path("key");
    match field(r.take_str("key"))? {
        None | Some("p256") => Ok(CertificateKey::P256),
        Some("p384") => Ok(CertificateKey::P384),
        Some("rsa2048") => Ok(CertificateKey::Rsa2048),
        Some("rsa3072") => Ok(CertificateKey::Rsa3072),
        Some("rsa4096") => Ok(CertificateKey::Rsa4096),
        Some(_) => Err(invalid(format!(
            "{path}: expected \"p256\", \"p384\", \"rsa2048\", \"rsa3072\" or \"rsa4096\""
        ))),
    }
}

/// `tls.issuer`: who issues the certificates of the `auto` names of a frontend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmeIssuer {
    /// The ACME authority of `global.acme`.
    Acme,
    /// The local authority that the daemon keeps in its storage directory.
    Internal,
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
    /// The provider of the DNS-01 challenge. A wildcard from an ACME authority needs it.
    pub dns: Option<DnsConfig>,
    /// The local authority: the lifetime of its certificates and the name constraints
    /// of its root.
    pub internal: Internal,
    /// The guards of issuance on demand. A frontend with `tls.on_demand` needs them.
    pub on_demand: Option<OnDemand>,
    /// The external account binding of the first authority.
    pub eab: Option<Eab>,
    /// The authorities that are asked when the first one fails, in this order.
    pub fallback: Vec<Authority>,
    /// Ask the authority when to renew a certificate (RFC 9773).
    pub ari: bool,
    /// Staple an OCSP response when a certificate names a responder.
    pub ocsp: bool,
    /// The kind of the key of a new certificate, from either source.
    pub key: CertificateKey,
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
            dns: None,
            internal: Internal::default(),
            on_demand: None,
            eab: None,
            fallback: Vec::new(),
            ari: true,
            ocsp: true,
            key: CertificateKey::P256,
        }
    }
}

impl AcmeOptions {
    /// Every authority in the order in which an attempt asks them: the first one, then
    /// those of `fallback`.
    pub fn authorities(&self) -> Vec<Authority> {
        let first = Authority {
            directory: self.directory.clone(),
            email: self.email.clone(),
            ca_file: self.ca_file.clone(),
            eab: self.eab.clone(),
        };
        std::iter::once(first).chain(self.fallback.iter().cloned()).collect()
    }

    /// Whether a listed authority is one of the public directories that we know by
    /// name. A public authority is never asked for an internal name.
    pub fn is_public(&self) -> bool {
        self.authorities().iter().any(Authority::is_public)
    }

    /// The managed name that a handshake on a frontend with `issuer` and the TLS port
    /// `port` may ask for on demand. `None` when the guards that read no state refuse
    /// `name`, or when no authority of ours can issue for it: issuance on demand is
    /// off, the name is not a plain host name, no suffix of `allow` covers it, or the
    /// frontend sends an internal name to a public authority, or the constraints of
    /// the local root do not permit a name of the local authority.
    pub fn demanded(&self, name: &str, port: u16, issuer: Option<AcmeIssuer>) -> Option<AutoName> {
        let guards = self.on_demand.as_ref()?;
        let local = is_local(name, issuer, self);
        let refused_by_authority = match local {
            true => !self.internal.permits(name),
            false => self.is_public() && is_internal_name(name),
        };
        (guards.admits(name) && !refused_by_authority).then(|| AutoName {
            name: name.to_owned(),
            port,
            local,
        })
    }

    pub(crate) fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Self> {
        let defaults = Self::default();
        let Authority { directory, email, ca_file, eab } = Authority::take(&mut r)?;
        let fallback = authority::fallback(&mut r, &directory)?;
        let ari = field(r.take_bool("ari"))?.unwrap_or(defaults.ari);
        let ocsp = field(r.take_bool("ocsp"))?.unwrap_or(defaults.ocsp);
        let storage = match field(r.take_str("storage"))? {
            None => defaults.storage,
            Some("") => return Err(invalid("global.acme.storage must be a directory")),
            Some(path) => path.to_owned(),
        };
        let challenge = match field(r.take_str("challenge"))? {
            None | Some("auto") => AcmeChallenge::Auto,
            Some("http-01") => AcmeChallenge::Http01,
            Some("tls-alpn-01") => AcmeChallenge::TlsAlpn01,
            Some("dns-01") => AcmeChallenge::Dns01,
            Some(_) => {
                return Err(invalid(
                    "global.acme.challenge: expected \"auto\", \"http-01\", \"tls-alpn-01\" \
                     or \"dns-01\"",
                ));
            }
        };
        let redirect = field(r.take_bool("redirect"))?.unwrap_or(defaults.redirect);
        let dns = field(r.take_object("dns"))?.map(DnsConfig::parse).transpose()?;
        let internal = Internal::take(&mut r)?;
        let key = certificate_key(&mut r)?;
        let on_demand = field(r.take_object("on_demand"))?.map(OnDemand::parse).transpose()?;
        field(r.finish())?;
        Ok(Self {
            directory,
            email,
            storage,
            challenge,
            ca_file,
            redirect,
            dns,
            internal,
            on_demand,
            eab,
            fallback,
            ari,
            ocsp,
            key,
        })
    }
}

/// Reads `tls.issuer`.
pub(crate) fn issuer(r: &mut ObjectReader<'_, '_>) -> io::Result<Option<AcmeIssuer>> {
    let path = r.field_path("issuer");
    match field(r.take_str("issuer"))? {
        None => Ok(None),
        Some("acme") => Ok(Some(AcmeIssuer::Acme)),
        Some("internal") => Ok(Some(AcmeIssuer::Internal)),
        Some(_) => Err(invalid(format!("{path}: expected \"acme\" or \"internal\""))),
    }
}

/// The address that an `auto` name spells, with or without the brackets of IPv6.
fn address(name: &str) -> Option<IpAddr> {
    let bare = name.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')).unwrap_or(name);
    bare.parse().ok()
}

/// Whether an `auto` name is an IP address.
pub fn is_address(name: &str) -> bool {
    name.parse::<IpAddr>().is_ok()
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

/// Reads `tls.auto`: one name or a list of them. A name is a host name, a wildcard
/// `*.NAME` or an IP address. Host names are stored in lower case and addresses in
/// their usual text form.
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
        let name = match address(name) {
            Some(address) => address.to_string(),
            None => name.to_ascii_lowercase(),
        };
        let host = name.strip_prefix("*.").unwrap_or(&name);
        if !is_address(&name) && !crate::hello::valid_host(host) {
            return Err(invalid(format!(
                "{path}: `{name}` is not a host name, a wildcard `*.NAME` or an IP address"
            )));
        }
        if !names.contains(&name) {
            names.push(name);
        }
    }
    Ok(names)
}

/// One managed name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutoName {
    /// The host name, the wildcard `*.NAME` or the IP address.
    pub name: String,
    /// The port of the first TLS frontend that lists the name.
    pub port: u16,
    /// Whether the local authority issues the certificate, and not the ACME authority.
    pub local: bool,
}

/// What the daemon needs to run automatic HTTPS for a topology.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomaticHttps {
    /// The `global.acme` object, or its defaults.
    pub options: AcmeOptions,
    /// Every managed name, sorted by name.
    pub names: Vec<AutoName>,
    /// Whether the topology has an HTTP frontend without TLS, for HTTP-01 and the
    /// redirect.
    pub plain_frontend: bool,
    /// Whether a TLS frontend obtains certificates on demand.
    pub on_demand: bool,
}

/// Whether the local authority issues for `name` on a frontend with `issuer`: when the
/// frontend says so, and else for an address and for an internal name that the public
/// authority would refuse.
fn is_local(name: &str, issuer: Option<AcmeIssuer>, options: &AcmeOptions) -> bool {
    match issuer {
        Some(AcmeIssuer::Internal) => true,
        Some(AcmeIssuer::Acme) => false,
        None => is_address(name) || (options.is_public() && is_internal_name(name)),
    }
}

impl Config {
    /// Whether a TLS frontend has `on_demand`.
    fn has_on_demand(&self) -> bool {
        self.listeners.values().any(|frontend| frontend.tls.as_ref().is_some_and(|t| t.on_demand))
    }

    /// Every `auto` name of every TLS frontend with its port and its issuer, and
    /// whether the topology has a plain HTTP frontend.
    fn auto_names(&self) -> (Vec<AutoName>, bool) {
        let options = self.acme.clone().unwrap_or_default();
        let mut names = Vec::new();
        let mut plain_frontend = false;
        for ((protocol, addr), frontend) in &self.listeners {
            match &frontend.tls {
                Some(tls) => names.extend(tls.auto.iter().map(|name| AutoName {
                    name: name.clone(),
                    port: addr.port(),
                    local: is_local(name, tls.issuer, &options),
                })),
                None => plain_frontend |= *protocol == Protocol::Http,
            }
        }
        (names, plain_frontend)
    }

    /// Automatic HTTPS of this topology, when a TLS frontend has an `auto` name.
    pub fn automatic_https(&self) -> Option<AutomaticHttps> {
        let (listed, plain_frontend) = self.auto_names();
        let mut names = BTreeMap::new();
        for entry in listed {
            names.entry(entry.name.clone()).or_insert(entry);
        }
        let on_demand = self.has_on_demand();
        (!names.is_empty() || on_demand).then(|| AutomaticHttps {
            options: self.acme.clone().unwrap_or_default(),
            names: names.into_values().collect(),
            plain_frontend,
            on_demand,
        })
    }

    /// Checks `global.acme` against the frontends: the object needs an `auto` name, a
    /// name has one issuer, a public authority takes no internal name, and a wildcard
    /// from an ACME authority needs a DNS provider.
    pub(crate) fn check_automatic_https(&self) -> io::Result<()> {
        let (names, _) = self.auto_names();
        let options = self.acme.clone().unwrap_or_default();
        if self.has_on_demand() {
            if !options.on_demand.as_ref().is_some_and(OnDemand::is_guarded) {
                return Err(invalid(
                    "tls.on_demand needs a guard; set global.acme.on_demand.ask or \
                     global.acme.on_demand.allow",
                ));
            }
        } else if names.is_empty() {
            return match self.acme {
                Some(_) => Err(invalid("global.acme requires a frontend with tls.auto names")),
                None => Ok(()),
            };
        }
        for entry in &names {
            let name = &entry.name;
            if names.iter().any(|other| other.name == *name && other.local != entry.local) {
                return Err(invalid(format!(
                    "tls.auto: `{name}` has two issuers; give its frontends the same \
                     tls.issuer"
                )));
            }
            if entry.local && !options.internal.permits(name) {
                return Err(invalid(format!(
                    "tls.auto: `{name}` is outside global.acme.internal.constraints; the \
                     root of the local authority may not sign for it"
                )));
            }
            if entry.local {
                continue;
            }
            if is_address(name) {
                return Err(invalid(format!(
                    "tls.auto: the IP address `{name}` is an internal name; an ACME \
                     certificate authority is not asked for it"
                )));
            }
            if options.is_public() && is_internal_name(name) {
                return Err(invalid(format!(
                    "tls.auto: `{name}` is an internal name; a public certificate authority \
                     cannot validate it"
                )));
            }
            if name.starts_with("*.") && options.dns.is_none() {
                return Err(invalid(format!(
                    "tls.auto: `{name}` is a wildcard, which needs the DNS challenge; set \
                     global.acme.dns"
                )));
            }
            if options.challenge == AcmeChallenge::Dns01 && options.dns.is_none() {
                return Err(invalid("global.acme.challenge: \"dns-01\" needs global.acme.dns"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    fn parse(tls: &str, global: &str) -> io::Result<Config> {
        let document = format!(
            r#"{{{global}"frontends":{{"web":{{"binds":["0.0.0.0:443"],"tls":{tls}}},
                 "plain":{{"binds":["0.0.0.0:80"]}}}},
               "backends":{{"app":{{"servers":["10.0.0.1:80"]}}}}}}"#
        );
        Config::parse(document.as_bytes())
    }

    fn public(name: &str, port: u16) -> AutoName {
        AutoName { name: name.to_owned(), port, local: false }
    }

    fn names(tls: &str, global: &str) -> Vec<(String, bool)> {
        let automatic = parse(tls, global).ok().and_then(|config| config.automatic_https());
        let names = automatic.map(|automatic| automatic.names).unwrap_or_default();
        names.into_iter().map(|entry| (entry.name, entry.local)).collect()
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
            names: vec![public("example.org", 443), public("www.example.org", 443)],
            plain_frontend: true,
            on_demand: false,
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
            ..AcmeOptions::default()
        };
        assert_eq!(options, Some(expected));
        let staging = r#""global":{"acme":{"directory":"letsencrypt-staging"}},"#;
        let config = parse(r#"{"auto":["example.org"]}"#, staging);
        let options = config.ok().and_then(|c| c.automatic_https()).map(|a| a.options);
        assert_eq!(options.map(|o| o.directory).as_deref(), Some(LETSENCRYPT_STAGING));
    }

    #[test]
    fn the_issuer_follows_the_name() {
        for name in ["localhost", "intranet", "a.local", "db.internal", "x.home.arpa", "a.test"] {
            assert!(is_internal_name(name), "{name}");
        }
        for name in ["example.org", "local.example.org", "mylocal.org", "internal.io"] {
            assert!(!is_internal_name(name), "{name}");
        }
        // With no setting: a public name goes to ACME, an internal name and an address
        // to the local authority.
        let auto = r#"{"auto":["example.org","localhost","*.Internal","127.0.0.1","[::1]"]}"#;
        let expected = [
            ("*.internal", true),
            ("127.0.0.1", true),
            ("::1", true),
            ("example.org", false),
            ("localhost", true),
        ];
        let found = names(auto, "");
        let found: Vec<_> = found.iter().map(|(name, local)| (name.as_str(), *local)).collect();
        assert_eq!(found, expected);
        // A directory of the operator's own takes internal names. An address stays local.
        let private = r#""global":{"acme":{"directory":"http://127.0.0.1:14000/dir"}},"#;
        let found = names(r#"{"auto":["localhost","10.0.0.1"]}"#, private);
        assert_eq!(found, [("10.0.0.1".to_owned(), true), ("localhost".to_owned(), false)]);
        // The override, both ways.
        let forced = names(r#"{"auto":["example.org"],"issuer":"internal"}"#, "");
        assert_eq!(forced, [("example.org".to_owned(), true)]);
        let text = reason(r#"{"auto":["localhost"],"issuer":"acme"}"#, "");
        assert!(text.contains("`localhost` is an internal name"), "{text}");
        let text = reason(r#"{"auto":["192.0.2.1"],"issuer":"acme"}"#, private);
        assert!(text.contains("IP address `192.0.2.1` is an internal name"), "{text}");
        assert!(
            names(r#"{"auto":["db.internal"],"issuer":"acme"}"#, private)
                == [("db.internal".to_owned(), false)]
        );
        let text = reason(r#"{"auto":["a.example"],"issuer":"local"}"#, "");
        assert!(text.contains("expected \"acme\" or \"internal\""), "{text}");
        assert!(
            reason(r#"{"crt":"a.pem","issuer":"internal"}"#, "").contains("issuer needs auto")
        );
    }

    #[test]
    fn a_name_on_two_frontends_has_one_issuer() {
        let document = r#"{"frontends":{
            "a":{"binds":["0.0.0.0:443"],"tls":{"auto":["example.org"]}},
            "b":{"binds":["0.0.0.0:8443"],"tls":{"auto":["example.org"],"issuer":"internal"}}},
            "backends":{"app":{"servers":["10.0.0.1:80"]}}}"#;
        let text = Config::parse(document.as_bytes()).err().map(|e| e.to_string());
        assert!(text.unwrap_or_default().contains("has two issuers"));
    }

    #[test]
    fn the_key_of_a_certificate_is_on_one_of_two_curves() {
        let key = |global: &str| {
            let config = parse(r#"{"auto":["example.org"]}"#, global).ok();
            config.and_then(|c| c.automatic_https()).map(|a| a.options.key)
        };
        assert_eq!(key(""), Some(CertificateKey::P256));
        assert_eq!(key(r#""global":{"acme":{"key":"p256"}},"#), Some(CertificateKey::P256));
        assert_eq!(key(r#""global":{"acme":{"key":"p384"}},"#), Some(CertificateKey::P384));
        let text = reason(r#"{"auto":["example.org"]}"#, r#""global":{"acme":{"key":"rsa"}},"#);
        assert!(
            text.contains("global.acme.key: expected \"p256\", \"p384\", \"rsa2048\""),
            "{text}"
        );
        for (word, kind) in [
            ("rsa2048", CertificateKey::Rsa2048),
            ("rsa3072", CertificateKey::Rsa3072),
            ("rsa4096", CertificateKey::Rsa4096),
        ] {
            let global = format!(r#""global":{{"acme":{{"key":"{word}"}}}},"#);
            assert_eq!(key(&global), Some(kind));
            assert!(kind.is_rsa() && !CertificateKey::P384.is_rsa());
        }
    }

    #[test]
    fn the_local_root_signs_inside_its_constraints_only() {
        let global = r#""global":{"acme":{"internal":{"lifetime":600,
            "constraints":[".Corp.Internal","10.9.8.7/8","localhost","corp.internal"]}}},"#;
        let config = parse(r#"{"auto":["a.corp.internal","10.1.2.3","localhost"]}"#, global);
        let options = config.ok().and_then(|c| c.automatic_https()).map(|a| a.options.internal);
        let expected = Internal {
            lifetime: 600,
            constraints: vec!["10.0.0.0/8".into(), "corp.internal".into(), "localhost".into()],
            server: None,
        };
        assert_eq!(options, Some(expected));
        for outside in ["db.internal", "192.168.1.1", "*.internal"] {
            let text = reason(&format!(r#"{{"auto":["{outside}"]}}"#), global);
            assert!(text.contains("is outside global.acme.internal.constraints"), "{text}");
        }
        // A public name of the ACME authority is none of the root's business. With the
        // override it is.
        assert_eq!(names(r#"{"auto":["example.org"]}"#, global).len(), 1);
        let text = reason(r#"{"auto":["example.org"],"issuer":"internal"}"#, global);
        assert!(text.contains("`example.org` is outside"), "{text}");
        for (bad, wanted) in [
            (r#"["a b"]"#, "expected DNS suffixes"),
            (r#"["10.0.0.0/40"]"#, "expected DNS suffixes"),
            (r#"[7]"#, "expected DNS suffixes"),
            ("[]", "expected 1 to 32 entries"),
        ] {
            let global = format!(r#""global":{{"acme":{{"internal":{{"constraints":{bad}}}}}}},"#);
            let text = reason(r#"{"auto":["localhost"]}"#, &global);
            assert!(text.contains("global.acme.internal.constraints") && text.contains(wanted));
        }
        // On demand: a local name outside the list is not asked for.
        let global = r#""global":{"acme":{"on_demand":{"allow":["internal"]},
            "internal":{"constraints":["corp.internal"]}}},"#;
        let config = parse(r#"{"on_demand":true}"#, global).ok();
        let options = config.and_then(|c| c.automatic_https()).map(|a| a.options);
        let demanded = |name: &str| options.as_ref().and_then(|o| o.demanded(name, 443, None));
        assert!(demanded("a.corp.internal").is_some_and(|name| name.local));
        assert_eq!(demanded("db.internal"), None);
    }

    #[test]
    fn a_wildcard_needs_a_dns_provider_unless_it_is_local() {
        let text = reason(r#"{"auto":["*.example.org"]}"#, "");
        assert!(text.contains("is a wildcard, which needs the DNS challenge"), "{text}");
        assert_eq!(names(r#"{"auto":["*.example.org"],"issuer":"internal"}"#, "").len(), 1);
        assert_eq!(names(r#"{"auto":["*.corp.internal"]}"#, "").len(), 1);
        let hook = r#""global":{"acme":{"dns":{"hook":"/etc/sibuna/dns-hook"}}},"#;
        let config = parse(r#"{"auto":["*.example.org"]}"#, hook).ok();
        let dns = config.and_then(|c| c.automatic_https()).and_then(|a| a.options.dns);
        let expected = DnsConfig {
            provider: DnsProvider::Hook("/etc/sibuna/dns-hook".to_owned()),
            check: true,
            timeout: 120,
            wait: 0,
            resolver: None,
            servers: Vec::new(),
            follow_cname: true,
        };
        assert_eq!(dns, Some(expected));
        let text =
            reason(r#"{"auto":["example.org"]}"#, r#""global":{"acme":{"challenge":"dns-01"}},"#);
        assert!(text.contains("\"dns-01\" needs global.acme.dns"), "{text}");
    }

    #[test]
    fn every_dns_key_is_read() {
        let global = r#""global":{"acme":{"challenge":"dns-01","internal":{"lifetime":600},
            "dns":{"rfc2136":{"server":"192.0.2.53:53","key_name":"Sibuna.","key_file":"/k",
            "zone":"Example.org."},"check":false,"timeout":30,"wait":5,
            "resolver":"[2001:db8::1]:53","servers":["192.0.2.1:53","192.0.2.2:5353"]}}},"#;
        let options = parse(r#"{"auto":["example.org"]}"#, global).ok().and_then(|c| c.acme);
        let options = options.unwrap_or_default();
        let dns = options.dns.clone().map(|dns| (dns.provider, dns.check, dns.timeout, dns.wait));
        let provider = DnsProvider::Rfc2136 {
            server: SocketAddr::from(([192, 0, 2, 53], 53)),
            key: Some(("Sibuna.".to_owned(), "/k".to_owned())),
            zone: Some("example.org".to_owned()),
        };
        assert_eq!(dns, Some((provider, false, 30, 5)));
        let dns = options.dns.unwrap_or_else(|| unreachable!());
        assert_eq!(dns.resolver.map(|r| r.port()), Some(53));
        assert_eq!(dns.servers.len(), 2);
        assert_eq!((options.challenge, options.internal.lifetime), (AcmeChallenge::Dns01, 600));
        let wrong = |members: &str| {
            let global = format!(r#""global":{{"acme":{{{members}}}}},"#);
            reason(r#"{"auto":["example.org"]}"#, &global)
        };
        assert!(wrong(r#""dns":{}"#).contains("expected one provider"));
        assert!(
            wrong(r#""dns":{"hook":"/h","rfc2136":{"server":"1.2.3.4:53"}}"#)
                .contains("one provider")
        );
        assert!(wrong(r#""dns":{"rfc2136":{}}"#).contains("needs the \"IP:PORT\""));
        // An update without a key is accepted for this host, and elsewhere when the
        // file says so.
        let unsigned = wrong(r#""dns":{"rfc2136":{"server":"192.0.2.53:53"}}"#);
        assert!(unsigned.contains("without a TSIG key is not signed"), "{unsigned}");
        assert!(unsigned.contains("global.acme.dns.rfc2136"), "{unsigned}");
        for accepted in [
            r#""dns":{"rfc2136":{"server":"127.0.0.1:53"}}"#,
            r#""dns":{"rfc2136":{"server":"[::1]:53"}}"#,
            r#""dns":{"rfc2136":{"server":"192.0.2.53:53","unsigned":true}}"#,
        ] {
            assert_eq!(wrong(accepted), "", "{accepted}");
        }
        let both = r#""dns":{"rfc2136":{"server":"192.0.2.53:53","key_name":"k.",
            "key_file":"/k","unsigned":true}}"#;
        assert!(wrong(both).contains("unsigned contradicts"));
        assert!(wrong(r#""dns":{"rfc2136":{"server":"ns.example.org"}}"#).contains("IP:PORT"));
        assert!(
            wrong(r#""dns":{"rfc2136":{"server":"1.2.3.4:53","key_name":"k"}}"#)
                .contains("go together")
        );
        assert!(wrong(r#""dns":{"hook":"/h","timeout":0}"#).contains("1 to 3600"));
        assert!(wrong(r#""dns":{"hook":"/h","wait":3601}"#).contains("0 to 3600"));
        assert!(wrong(r#""dns":{"hook":"/h","servers":[]}"#).contains("1 to 8 servers"));
        assert!(wrong(r#""dns":{"hook":"/h","token":"x"}"#).contains("token"));
        assert!(wrong(r#""internal":{"lifetime":5}"#).contains("10 to 172800"));
    }

    #[test]
    fn the_cloudflare_provider_takes_a_token_file_and_a_loopback_api_only() {
        let read = |members: &str| {
            let global = format!(r#""global":{{"acme":{{"dns":{{{members}}}}}}},"#);
            let options = parse(r#"{"auto":["*.example.org"]}"#, &global).ok()?.acme?;
            options.dns
        };
        let wrong = |members: &str| {
            let global = format!(r#""global":{{"acme":{{"dns":{{{members}}}}}}},"#);
            reason(r#"{"auto":["*.example.org"]}"#, &global)
        };
        let dns = read(r#""cloudflare":{"token_file":"/etc/sibuna/cf-token"}"#);
        let dns = dns.unwrap_or_else(|| unreachable!());
        let plain = DnsProvider::Cloudflare {
            token_file: "/etc/sibuna/cf-token".to_owned(),
            zone: None,
            api: None,
        };
        assert_eq!((dns.provider, dns.follow_cname), (plain, true));
        let dns = read(
            r#""cloudflare":{"token_file":"/t","zone":"Example.ORG.",
               "api":"http://127.0.0.1:20443/client/v4"},"follow_cname":false"#,
        );
        let dns = dns.unwrap_or_else(|| unreachable!());
        let full = DnsProvider::Cloudflare {
            token_file: "/t".to_owned(),
            zone: Some("example.org".to_owned()),
            api: Some("http://127.0.0.1:20443/client/v4".to_owned()),
        };
        assert_eq!((dns.provider, dns.follow_cname), (full, false));
        assert!(read(r#""cloudflare":{"token_file":"/t","api":"http://[::1]:1/v4"}"#).is_some());
        // The token goes to the host of `api`: only a loopback address is taken.
        for api in [
            "https://api.cloudflare.com/client/v4",
            "https://127.0.0.1:20443/",
            "http://api.cloudflare.com/client/v4",
            "http://localhost:20443/",
            "http://192.0.2.1:80/",
            "http://127.0.0.1@evil.example/",
            "http://evil.example:80@127.0.0.1/",
            "http://127.0.0.1.evil.example/",
            "http://evil.example/127.0.0.1:1",
            "http://",
            "",
        ] {
            let text = wrong(&format!(r#""cloudflare":{{"token_file":"/t","api":"{api}"}}"#));
            assert!(text.contains("global.acme.dns.cloudflare.api"), "{api}: {text}");
            assert!(text.contains("an http URL on a loopback address"), "{api}: {text}");
        }
        assert!(wrong(r#""cloudflare":{}"#).contains("needs the file of an API token"));
        assert!(wrong(r#""cloudflare":{"token_file":""}"#).contains("API token"));
        assert!(wrong(r#""cloudflare":{"token_file":"/t","zone":"a b"}"#).contains("DNS name"));
        assert!(wrong(r#""cloudflare":{"token_file":"/t","token":"x"}"#).contains("token"));
        let two = r#""cloudflare":{"token_file":"/t"},"hook":"/h""#;
        assert!(wrong(two).contains("expected one provider"));
        let two = r#""cloudflare":{"token_file":"/t"},"rfc2136":{"server":"1.2.3.4:53"}"#;
        assert!(wrong(two).contains("expected one provider"));
        assert!(wrong(r#""hook":"/h","follow_cname":1"#).contains("follow_cname"));
    }

    #[test]
    fn mistakes_are_named() {
        let auto = |value: &str| reason(&format!(r#"{{"auto":{value}}}"#), "");
        assert!(auto(r#"["*.example.org"]"#).contains("wildcard"));
        assert!(auto(r#"["a.*.example.org"]"#).contains("is not a host name"));
        assert!(auto(r#"["*"]"#).contains("is not a host name"));
        assert!(auto(r#"["bad_name.example.org"]"#).contains("is not a host name"));
        assert!(auto("[]").contains("1 to 64 host names"));
        assert!(auto("[7]").contains("expected host names"));
        assert!(reason("{}", "").contains("auto (host names) or on_demand"));
        let acme = |members: &str| {
            reason(
                r#"{"auto":["example.org"]}"#,
                &format!(r#""global":{{"acme":{{{members}}}}},"#),
            )
        };
        assert!(acme(r#""directory":"http://ca.example/dir""#).contains("loopback"));
        assert!(acme(r#""directory":"ftp://x""#).contains("https URL"));
        assert!(acme(r#""email":"nobody""#).contains("e-mail"));
        assert!(acme(r#""challenge":"dns""#).contains("http-01"));
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
        assert_eq!(automatic.map(|a| a.names), Some(vec![public("example.org", 8443)]));
    }

    #[test]
    fn on_demand_needs_a_guard_and_reads_its_keys() {
        let demand = r#"{"on_demand":true}"#;
        let unguarded = [
            String::new(),
            r#""global":{"acme":{}},"#.to_owned(),
            r#""global":{"acme":{"on_demand":{"rate":5}}},"#.to_owned(),
        ];
        for global in &unguarded {
            assert!(reason(demand, global).contains("tls.on_demand needs a guard"), "{global}");
        }
        let global = r#""global":{"acme":{"on_demand":{"ask":"http://127.0.0.1:9000/ok",
            "allow":[".Example.org","apps.test"],"rate":5,"names":7,"wait":3}}},"#;
        let automatic = parse(demand, global).ok().and_then(|config| config.automatic_https());
        let automatic = automatic.unwrap_or_else(|| panic!("{}", reason(demand, global)));
        assert!(automatic.on_demand && automatic.names.is_empty());
        let expected = OnDemand {
            ask: Some("http://127.0.0.1:9000/ok".to_owned()),
            allow: vec!["example.org".to_owned(), "apps.test".to_owned()],
            rate: 5,
            names: 7,
            wait: 3,
        };
        assert_eq!(automatic.options.on_demand, Some(expected));
        let defaults = OnDemand::default();
        assert_eq!((defaults.rate, defaults.names, defaults.wait), (10, 100, 20));
        let bad = |members: &str| {
            reason(demand, &format!(r#""global":{{"acme":{{"on_demand":{{{members}}}}}}},"#))
        };
        assert!(bad(r#""ask":"ftp://x""#).contains("http or https URL"));
        assert!(bad(r#""allow":[]"#).contains("1 to 64 suffixes"));
        assert!(bad(r#""allow":["a b"]"#).contains("DNS suffixes"));
        assert!(bad(r#""allow":["a.test"],"rate":0"#).contains("1 to 1000"));
        assert!(bad(r#""allow":["a.test"],"names":10001"#).contains("1 to 10000"));
        assert!(bad(r#""allow":["a.test"],"wait":121"#).contains("1 to 120"));
    }

    #[test]
    fn a_demanded_name_gets_the_issuer_of_a_listed_one() {
        let guards =
            OnDemand { allow: vec!["example.org".into(), "test".into()], ..OnDemand::default() };
        let options = AcmeOptions { on_demand: Some(guards), ..AcmeOptions::default() };
        let demanded = |name: &str, issuer| options.demanded(name, 443, issuer).map(|n| n.local);
        assert_eq!(demanded("a.example.org", None), Some(false));
        assert_eq!(demanded("a.example.org", Some(AcmeIssuer::Internal)), Some(true));
        assert_eq!(demanded("app.test", None), Some(true));
        // A public authority is not asked for an internal name, and nothing outside the
        // suffixes is admitted.
        assert_eq!(demanded("app.test", Some(AcmeIssuer::Acme)), None);
        assert_eq!(demanded("a.example.com", None), None);
        assert_eq!(demanded("*.example.org", None), None);
        assert_eq!(AcmeOptions::default().demanded("a.example.org", 443, None), None);
    }
}
