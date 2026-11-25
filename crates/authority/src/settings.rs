//! The `authority` section of a node file: which database, under which name, how often.

use std::path::PathBuf;
use std::time::Duration;

use sibuna_json::{ObjectReader, Value};
use sibuna_storage::Target;

use crate::document::{self, SECTION};
use crate::error::Error;

/// The name of a node that states none and uses SQLite.
pub const LOCAL_NODE: &str = "local";
/// The time between two looks at the head when the file states none.
pub const DEFAULT_POLL: Duration = Duration::from_secs(5);
/// The longest name of a node, in bytes.
pub const MAX_NODE: usize = 64;

/// Where the revisions are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Location {
    /// A SQLite file on this host.
    Sqlite(PathBuf),
    /// A file that holds a PostgreSQL URL, readable by its owner alone.
    PostgresUrlFile(PathBuf),
}

/// The `authority` section. Create one with [`Settings::parse`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Where the revisions are.
    pub location: Location,
    /// The name under which the node reports.
    pub node: String,
    /// Whether the file states the name. PostgreSQL needs a stated name to serve.
    pub node_stated: bool,
    /// The time between two looks at the head.
    pub poll: Duration,
    /// The file that keeps the last served revision, if the node has one.
    pub cache: Option<PathBuf>,
}

fn fault(message: impl std::fmt::Display) -> Error {
    Error::Settings(message.to_string())
}

/// Reads a duration such as `500ms`, `5s`, `2m` or `1h`.
fn duration(text: &str) -> Option<Duration> {
    let (digits, unit) = match text {
        _ if text.ends_with("ms") => (&text[..text.len() - 2], 1),
        _ if text.ends_with('s') => (&text[..text.len() - 1], 1000),
        _ if text.ends_with('m') => (&text[..text.len() - 1], 60_000),
        _ if text.ends_with('h') => (&text[..text.len() - 1], 3_600_000),
        _ => return None,
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()?.checked_mul(unit).map(Duration::from_millis)
}

fn is_node_name(name: &str) -> bool {
    (1..=MAX_NODE).contains(&name.len()) && name.bytes().all(|byte| byte.is_ascii_graphic())
}

impl Settings {
    /// Reads the `authority` section of the evaluated node file `file`. It borrows the
    /// file for the call. Fails with [`Error::Settings`] when the file has no such
    /// section, names no database or two, or holds a value out of its range.
    pub fn parse(file: &[u8]) -> Result<Settings, Error> {
        let value = document::parse(file, "the file of the node")?;
        let section = value.as_object().and_then(|root| root.get(SECTION));
        let Some(section) = section else {
            return Err(fault("the file has no `authority` section"));
        };
        let mut reader = ObjectReader::with_path(section, SECTION.to_owned()).map_err(fault)?;
        let sqlite = reader.take_str("sqlite").map_err(fault)?;
        let postgres = reader.take_str("postgres_url_file").map_err(fault)?;
        let location = match (sqlite, postgres) {
            (Some(path), None) if !path.is_empty() => Location::Sqlite(path.into()),
            (None, Some(path)) if !path.is_empty() => Location::PostgresUrlFile(path.into()),
            _ => {
                return Err(fault(
                    "authority names exactly one of `sqlite` and `postgres_url_file`, a path",
                ));
            }
        };
        let stated = reader.take_str("node").map_err(fault)?;
        if stated.is_some_and(|name| !is_node_name(name)) {
            return Err(fault(format!(
                "authority.node must have 1 to {MAX_NODE} printable ASCII bytes and no space"
            )));
        }
        let poll = match reader.take_str("poll").map_err(fault)? {
            None => DEFAULT_POLL,
            Some(text) => duration(text)
                .filter(|poll| (100..=3_600_000).contains(&poll.as_millis()))
                .ok_or_else(|| fault("authority.poll must be a duration from 100ms to 1h"))?,
        };
        let cache = match reader.take_str("cache").map_err(fault)? {
            Some("") => return Err(fault("authority.cache must be a path")),
            path => path.map(PathBuf::from),
        };
        // `compose` reads the binds. Here they only count as a known key.
        let _: Option<&Value<'_>> = reader.take("binds");
        reader.finish().map_err(fault)?;
        Ok(Settings {
            location,
            node: stated.unwrap_or(LOCAL_NODE).to_owned(),
            node_stated: stated.is_some(),
            poll,
            cache,
        })
    }

    /// Fails when the node cannot serve under these settings: a node of a PostgreSQL
    /// database must state its name, because all its nodes report into one table.
    pub fn check_node(&self) -> Result<(), Error> {
        match self.location {
            Location::PostgresUrlFile(_) if !self.node_stated => Err(fault(
                "authority.node is required with `postgres_url_file`: every node reports \
                 under a name of its own",
            )),
            _ => Ok(()),
        }
    }

    /// The database to open. For PostgreSQL it reads the URL file now, so a new
    /// password is used at the next connection. Fails with [`Error::Settings`] when the
    /// URL file is missing, readable by others or malformed. The message never holds
    /// the URL.
    pub fn target(&self) -> Result<Target, Error> {
        match &self.location {
            Location::Sqlite(path) => Ok(Target::Sqlite(path.clone())),
            Location::PostgresUrlFile(path) => {
                sibuna_storage::read_database_url_file(path).map(Target::Postgres).map_err(fault)
            }
        }
    }

    /// The store in words, without a secret: `sqlite PATH` or `postgres (url file PATH)`.
    pub fn describe(&self) -> String {
        match &self.location {
            Location::Sqlite(path) => format!("sqlite {}", path.display()),
            Location::PostgresUrlFile(path) => {
                format!("postgres (url file {})", path.display())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(section: &str) -> Result<Settings, Error> {
        Settings::parse(format!(r#"{{"authority":{section}}}"#).as_bytes())
    }

    #[test]
    fn the_section_names_one_database() {
        let settings = parse(r#"{"sqlite":"/var/lib/sibuna/a.db"}"#).unwrap();
        assert_eq!(settings.location, Location::Sqlite("/var/lib/sibuna/a.db".into()));
        assert_eq!(settings.node, LOCAL_NODE);
        assert_eq!(settings.poll, DEFAULT_POLL);
        assert_eq!(settings.cache, None);
        assert!(settings.check_node().is_ok());
        assert_eq!(settings.describe(), "sqlite /var/lib/sibuna/a.db");
        let full = r#"{"postgres_url_file":"/etc/u","node":"fra-1","poll":"250ms",
            "cache":"/var/c","binds":{"web":["10.0.0.1:80"]}}"#;
        let settings = parse(full).unwrap();
        assert_eq!(settings.location, Location::PostgresUrlFile("/etc/u".into()));
        assert_eq!((settings.node.as_str(), settings.poll.as_millis()), ("fra-1", 250));
        assert_eq!(settings.cache, Some("/var/c".into()));
        assert!(settings.check_node().is_ok());
        assert!(!settings.describe().contains("postgres://"));
    }

    #[test]
    fn a_wrong_section_is_refused_with_its_key() {
        let code = |section: &str| parse(section).unwrap_err();
        assert!(code("{}").to_string().contains("exactly one"));
        assert!(code(r#"{"sqlite":"a","postgres_url_file":"b"}"#).to_string().contains("one"));
        assert!(code(r#"{"sqlite":""}"#).to_string().contains("one"));
        assert!(code(r#"{"sqlite":"a","node":"two words"}"#).to_string().contains("node"));
        assert!(code(r#"{"sqlite":"a","poll":"50ms"}"#).to_string().contains("poll"));
        assert!(code(r#"{"sqlite":"a","poll":"2h"}"#).to_string().contains("poll"));
        assert!(code(r#"{"sqlite":"a","poll":"soon"}"#).to_string().contains("poll"));
        assert!(code(r#"{"sqlite":"a","cache":""}"#).to_string().contains("cache"));
        assert!(code(r#"{"sqlite":"a","pol":"5s"}"#).to_string().contains("pol"));
        assert_eq!(code("{}").code(), "DBA005");
        assert_eq!(Settings::parse(b"{}").unwrap_err().code(), "DBA005");
        let unnamed = parse(r#"{"postgres_url_file":"/etc/u"}"#).unwrap();
        assert!(unnamed.check_node().unwrap_err().to_string().contains("authority.node"));
    }

    #[test]
    fn a_url_file_that_cannot_be_read_gives_no_target() {
        let settings = parse(r#"{"postgres_url_file":"/nonexistent/sibuna/url"}"#).unwrap();
        assert_eq!(settings.target().unwrap_err().code(), "DBA005");
    }
}
