//! The authorities of `global.acme` (SID 0021): the first one, which the keys
//! `directory`, `email`, `ca_file` and `eab` describe, and the ones of `fallback`.
//! Nothing here opens a socket or a file.

use std::io;

use sibuna_json::ObjectReader;

use super::{LETSENCRYPT, LETSENCRYPT_STAGING, is_directory_url, is_email};
use crate::config::{field, invalid};

/// The most authorities of `fallback`.
pub(super) const MAX_FALLBACK: usize = 3;
/// The longest key identifier of a binding.
const MAX_KID: usize = 256;

/// `eab`: the external account binding of an authority (RFC 8555, section 7.3.4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Eab {
    /// The key identifier that the authority gave.
    pub kid: String,
    /// The file that holds the MAC key in base64url.
    pub key_file: String,
}

/// One certificate authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authority {
    /// The URL of the ACME directory.
    pub directory: String,
    /// The contact address of the account.
    pub email: Option<String>,
    /// PEM roots for the connection to the authority. `None` uses the system trust store.
    pub ca_file: Option<String>,
    /// The external account binding of a new account.
    pub eab: Option<Eab>,
}

impl Authority {
    /// Whether the authority is one of the public directories that we know by name.
    pub fn is_public(&self) -> bool {
        self.directory == LETSENCRYPT || self.directory == LETSENCRYPT_STAGING
    }

    /// Reads the keys `directory`, `email`, `ca_file` and `eab` of `r` and leaves the
    /// other keys. Without `directory` the authority is Let's Encrypt.
    pub(super) fn take(r: &mut ObjectReader<'_, '_>) -> io::Result<Self> {
        let path = r.field_path("directory");
        let directory = match field(r.take_str("directory"))? {
            None | Some("letsencrypt") => LETSENCRYPT.to_owned(),
            Some("letsencrypt-staging") => LETSENCRYPT_STAGING.to_owned(),
            Some(url) if is_directory_url(url) => url.to_owned(),
            Some(_) => {
                return Err(invalid(format!(
                    "{path}: expected \"letsencrypt\", \"letsencrypt-staging\" \
                     or an https URL (http is accepted for a loopback address only)"
                )));
            }
        };
        let path = r.field_path("email");
        let email = match field(r.take_str("email"))? {
            None => None,
            Some(email) if is_email(email) => Some(email.to_owned()),
            Some(_) => return Err(invalid(format!("{path}: expected an e-mail address"))),
        };
        let ca_file = field(r.take_str("ca_file"))?.map(str::to_owned);
        let eab = field(r.take_object("eab"))?.map(Eab::parse).transpose()?;
        Ok(Self { directory, email, ca_file, eab })
    }
}

impl Eab {
    fn parse(mut r: ObjectReader<'_, '_>) -> io::Result<Self> {
        let kid = field(r.take_str("kid"))?.unwrap_or_default();
        let key_file = field(r.take_str("key_file"))?.unwrap_or_default();
        let kid_ok = (1..=MAX_KID).contains(&kid.len())
            && kid.bytes().all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\');
        if !kid_ok || key_file.is_empty() {
            return Err(invalid(format!(
                "{}: expected kid (the key identifier of the authority, printable, at most \
                 {MAX_KID} bytes) and key_file (the file with the base64url key)",
                r.path()
            )));
        }
        field(r.finish())?;
        Ok(Self { kid: kid.to_owned(), key_file: key_file.to_owned() })
    }
}

/// Reads `fallback`: one to three authorities that are asked, in this order, when the
/// first one fails. `first` is the directory of the first authority. No directory is
/// listed twice.
pub(super) fn fallback(r: &mut ObjectReader<'_, '_>, first: &str) -> io::Result<Vec<Authority>> {
    let path = r.field_path("fallback");
    let items = match field(r.take_array("fallback"))? {
        None => return Ok(Vec::new()),
        Some(items) if (1..=MAX_FALLBACK).contains(&items.len()) => items,
        Some(_) => {
            return Err(invalid(format!("{path}: expected 1 to {MAX_FALLBACK} authorities")));
        }
    };
    let mut listed: Vec<Authority> = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let at = format!("{path}[{index}]");
        let mut reader = field(ObjectReader::with_path(item, at.clone()))?;
        if reader.take("directory").is_none() {
            return Err(invalid(format!("{at}.directory: a fallback authority names its URL")));
        }
        let mut reader = field(ObjectReader::with_path(item, at.clone()))?;
        let authority = Authority::take(&mut reader)?;
        field(reader.finish())?;
        let known = |other: &str| other == authority.directory;
        if known(first) || listed.iter().any(|other| known(&other.directory)) {
            return Err(invalid(format!("{at}.directory: the authority is listed twice")));
        }
        listed.push(authority);
    }
    Ok(listed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AcmeOptions, Config};

    fn options(acme: &str) -> io::Result<AcmeOptions> {
        let document = format!(
            r#"{{"global":{{"acme":{acme}}},
               "frontends":{{"web":{{"binds":["0.0.0.0:443"],"tls":{{"auto":["example.org"]}}}}}},
               "backends":{{"app":{{"servers":["10.0.0.1:80"]}}}}}}"#
        );
        let config = Config::parse(document.as_bytes())?;
        Ok(config.automatic_https().map(|automatic| automatic.options).unwrap_or_default())
    }

    fn reason(acme: &str) -> String {
        options(acme).err().map(|error| error.to_string()).unwrap_or_default()
    }

    #[test]
    fn the_binding_and_the_fallback_are_read() {
        let found = options(
            r#"{"directory":"https://one.example/dir","email":"a@example.org",
                "eab":{"kid":"kid-1","key_file":"/etc/one.key"},"ari":false,
                "fallback":[{"directory":"letsencrypt-staging"},
                            {"directory":"https://two.example/dir","email":"b@example.org",
                             "ca_file":"/etc/two.pem",
                             "eab":{"kid":"kid-2","key_file":"/etc/two.key"}}]}"#,
        );
        let found = found.unwrap_or_default();
        let eab =
            |kid: &str, file: &str| Some(Eab { kid: kid.to_owned(), key_file: file.to_owned() });
        let expected = [
            Authority {
                directory: "https://one.example/dir".to_owned(),
                email: Some("a@example.org".to_owned()),
                ca_file: None,
                eab: eab("kid-1", "/etc/one.key"),
            },
            Authority {
                directory: LETSENCRYPT_STAGING.to_owned(),
                email: None,
                ca_file: None,
                eab: None,
            },
            Authority {
                directory: "https://two.example/dir".to_owned(),
                email: Some("b@example.org".to_owned()),
                ca_file: Some("/etc/two.pem".to_owned()),
                eab: eab("kid-2", "/etc/two.key"),
            },
        ];
        assert_eq!(found.authorities(), expected);
        assert!(!found.ari);
        // One public directory in the list makes internal names local.
        assert!(found.is_public());
        let defaults = AcmeOptions::default();
        assert!(defaults.ari && defaults.eab.is_none() && defaults.fallback.is_empty());
        assert_eq!(defaults.authorities().len(), 1);
        let private = options(r#"{"directory":"https://one.example/dir"}"#).unwrap_or_default();
        assert!(!private.is_public());
    }

    #[test]
    fn a_malformed_list_is_refused_with_its_path() {
        let cases = [
            (r#"{"fallback":[]}"#, "global.acme.fallback: expected 1 to 3 authorities"),
            (
                r#"{"fallback":[{"directory":"https://a.example/d"},
                    {"directory":"https://b.example/d"},{"directory":"https://c.example/d"},
                    {"directory":"https://d.example/d"}]}"#,
                "global.acme.fallback: expected 1 to 3 authorities",
            ),
            (r#"{"fallback":[{}]}"#, "global.acme.fallback[0].directory: a fallback"),
            (r#"{"fallback":[{"directory":"letsencrypt"}]}"#, "fallback[0].directory: the auth"),
            (
                r#"{"fallback":[{"directory":"https://a.example/d"},
                    {"directory":"https://a.example/d"}]}"#,
                "fallback[1].directory: the authority is listed twice",
            ),
            (r#"{"fallback":[{"directory":"http://a.example/d"}]}"#, "fallback[0].directory"),
            (r#"{"fallback":[{"directory":"https://a.example/d","email":"x"}]}"#, "[0].email"),
            (r#"{"fallback":[{"directory":"https://a.example/d","storage":"/x"}]}"#, "storage"),
            (r#"{"fallback":["letsencrypt"]}"#, "global.acme.fallback[0]"),
            (r#"{"eab":{"kid":"k"}}"#, "global.acme.eab: expected kid"),
            (r#"{"eab":{"kid":"","key_file":"/k"}}"#, "global.acme.eab: expected kid"),
            (r#"{"eab":{"kid":"a b","key_file":"/k"}}"#, "global.acme.eab: expected kid"),
            (r#"{"eab":{"kid":"k","key_file":"/k","mac":"x"}}"#, "mac"),
            (r#"{"ari":"yes"}"#, "ari"),
        ];
        for (acme, expected) in cases {
            let text = reason(acme);
            assert!(text.contains(expected), "{acme}: {text}");
        }
    }
}
