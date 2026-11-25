//! The documents of the two owners (SID 0028): what a source publishes, what a node
//! composes from its file and a revision, and the canonical text that a digest names.
//!
//! ```text
//!   source  --publish-->  frontends, backends, http   (the revision, canonical)
//!   node file: global, mesh, observability, authority.binds
//!   node file + revision  --compose-->  the document that the node checks and serves
//! ```
//!
//! Nothing here performs I/O or knows what a frontend means. The caller checks a
//! composition with the topology checker.

use std::fmt::Write as _;

use sibuna_crypto::sha256::Sha256;
use sibuna_json::{Limits, Object, Value};

use crate::error::Error;

/// The bounds of every document read here. They are the bounds of an edge file.
pub const LIMITS: Limits = Limits {
    max_input_bytes: 256 * 1024,
    max_values: 32768,
    max_string_bytes: 512,
    max_depth: 16,
};

/// The sections that the database owns.
pub const PUBLISHED: [&str; 3] = ["backends", "frontends", "http"];

/// The sections that the file of a node owns.
pub const LOCAL: [&str; 3] = ["global", "mesh", "observability"];

/// The section of a node file that names the database.
pub const SECTION: &str = "authority";

/// Parses `bytes` within [`LIMITS`]. `what` names the text in the message.
pub(crate) fn parse<'a>(bytes: &'a [u8], what: &str) -> Result<Value<'a>, Error> {
    sibuna_json::parse_with_limits(bytes, &LIMITS)
        .map_err(|error| Error::Rejected(format!("{what}: {error}")))
}

/// The members of the object at the root of `value`.
fn root<'v, 'a>(value: &'v Value<'a>, what: &str) -> Result<&'v Object<'a>, Error> {
    value.as_object().ok_or_else(|| Error::Rejected(format!("{what}: expected an object")))
}

/// The members of `object` with their keys in order.
fn sorted<'v, 'a>(object: &'v Object<'a>) -> Vec<(&'v str, &'v Value<'a>)> {
    let mut members: Vec<_> = object.iter().collect();
    members.sort_by(|left, right| left.0.cmp(right.0));
    members
}

/// Writes `value` with the keys of every object in order and no white space. The
/// parser bounded the nesting, so the recursion is bounded.
fn write_canonical(out: &mut String, value: &Value<'_>) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => out.push_str(number.as_str()),
        Value::String(text) => {
            let _ = sibuna_json::write_string(out, text);
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(out, item);
            }
            out.push(']');
        }
        Value::Object(object) => {
            out.push('{');
            for (index, (key, item)) in sorted(object).into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                let _ = sibuna_json::write_string(out, key);
                out.push(':');
                write_canonical(out, item);
            }
            out.push('}');
        }
    }
}

/// The canonical text of `value`: the keys of every object in order, no white space,
/// numbers as they were written. Two equal documents have the same text.
pub fn canonical(value: &Value<'_>) -> String {
    let mut out = String::new();
    write_canonical(&mut out, value);
    out
}

fn write_pretty(out: &mut String, value: &Value<'_>, depth: usize) {
    let indent = |out: &mut String, depth: usize| {
        out.push('\n');
        (0..depth).for_each(|_| out.push_str("  "));
    };
    match value {
        Value::Array(items) if !items.is_empty() => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                indent(out, depth + 1);
                write_pretty(out, item, depth + 1);
            }
            indent(out, depth);
            out.push(']');
        }
        Value::Object(object) if !object.is_empty() => {
            out.push('{');
            for (index, (key, item)) in sorted(object).into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                indent(out, depth + 1);
                let _ = sibuna_json::write_string(out, key);
                out.push_str(": ");
                write_pretty(out, item, depth + 1);
            }
            indent(out, depth);
            out.push('}');
        }
        scalar => write_canonical(out, scalar),
    }
}

/// The text of `document` for a reader: one member on each line, two spaces of indent,
/// keys in order, and a line feed at the end. Publishing it gives `document` again.
/// Fails with [`Error::Damaged`] when `document` is not JSON within [`LIMITS`].
pub fn pretty(document: &str) -> Result<String, Error> {
    let value = sibuna_json::parse_with_limits(document.as_bytes(), &LIMITS)
        .map_err(|error| Error::Damaged(format!("the stored document is not JSON: {error}")))?;
    let mut out = String::with_capacity(document.len() * 2);
    write_pretty(&mut out, &value, 0);
    out.push('\n');
    Ok(out)
}

/// The SHA-256 digest of `bytes` in 64 hexadecimal digits.
pub fn digest(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    let mut text = String::with_capacity(hash.len() * 2);
    for byte in hash {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Whether `bytes` is the file of a node in persistent mode: a JSON object with the
/// section `authority`. Text that does not parse is no node file. Its reader reports
/// the fault.
pub fn is_node_file(bytes: &[u8]) -> bool {
    let parsed = sibuna_json::parse_with_limits(bytes, &LIMITS);
    parsed.is_ok_and(|value| value.as_object().is_some_and(|root| root.contains_key(SECTION)))
}

/// What a source publishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Publication {
    /// The canonical text of the sections that the database owns.
    pub document: String,
    /// The digest of `document`.
    pub digest: String,
    /// The sections of the source that stay with the file of each node, in order.
    pub left_out: Vec<String>,
}

/// Takes from the evaluated `source` the sections that the database owns. Fails with
/// [`Error::Rejected`] when the source is not a JSON object, names a section that no
/// owner has, or names `authority`, which belongs to a node file.
pub fn publish(source: &[u8]) -> Result<Publication, Error> {
    let value = parse(source, "the source")?;
    let mut published = Object::new();
    let mut left_out = Vec::new();
    for (key, member) in sorted(root(&value, "the source")?) {
        if PUBLISHED.contains(&key) {
            published.insert(key.to_owned(), member.clone());
        } else if LOCAL.contains(&key) {
            left_out.push(key.to_owned());
        } else if key == SECTION {
            return Err(Error::Rejected(
                "the source holds `authority`, which belongs to the file of a node".to_owned(),
            ));
        } else {
            return Err(Error::Rejected(format!(
                "the source holds the section `{key}`. The sections are {}, {} and {}",
                PUBLISHED.join(", "),
                LOCAL[..2].join(", "),
                LOCAL[2]
            )));
        }
    }
    let document = canonical(&Value::Object(published));
    let digest = digest(document.as_bytes());
    Ok(Publication { document, digest, left_out })
}

/// What a node serves: its file composed with a revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Composition {
    /// The canonical text of the whole topology, for the topology checker.
    pub document: String,
    /// The names under `authority.binds` that no published frontend has, in order.
    pub unused_binds: Vec<String>,
}

/// The `binds` object of the `authority` section, if the file has one.
fn local_binds<'v, 'a>(file: &'v Object<'a>) -> Result<Option<&'v Object<'a>>, Error> {
    let Some(binds) = file.get(SECTION).and_then(Value::as_object).and_then(|s| s.get("binds"))
    else {
        return Ok(None);
    };
    let fault = || Error::Settings("authority.binds must map a frontend to its binds".to_owned());
    let binds = binds.as_object().ok_or_else(fault)?;
    for (_, addresses) in binds {
        let addresses = addresses.as_array().ok_or_else(fault)?;
        if addresses.is_empty() || addresses.iter().any(|address| address.as_str().is_none()) {
            return Err(fault());
        }
    }
    Ok(Some(binds))
}

/// The frontends of a revision with the binds of this host in the place of theirs.
fn rebind<'a>(
    frontends: &Value<'a>,
    binds: Option<&Object<'a>>,
    unused: &mut Vec<String>,
) -> Value<'a> {
    let (Some(binds), Some(published)) = (binds, frontends.as_object()) else {
        unused.extend(binds.iter().flat_map(|binds| binds.iter()).map(|(name, _)| name.into()));
        return frontends.clone();
    };
    let mut rebound = Object::new();
    for (name, frontend) in published {
        let local = binds.get(name).zip(frontend.as_object());
        let frontend = match local {
            Some((addresses, members)) => {
                let mut members = members.clone();
                members.insert("binds", addresses.clone());
                Value::Object(members)
            }
            None => frontend.clone(),
        };
        rebound.insert(name.to_owned(), frontend);
    }
    let missing = binds.iter().filter(|(name, _)| !published.contains_key(name));
    unused.extend(missing.map(|(name, _)| name.to_owned()));
    unused.sort();
    Value::Object(rebound)
}

/// Composes the evaluated file of a node with the document of a revision: the sections
/// of the file, the sections of the revision, and `authority.binds` in the place of the
/// binds that the revision gives a frontend.
///
/// Fails with [`Error::Settings`] when the file holds a section of the database or a
/// malformed `authority.binds`, with [`Error::Rejected`] when the file is not a JSON
/// object, and with [`Error::Damaged`] when `published` is not the document of a
/// revision.
pub fn compose<'a>(node_file: &'a [u8], published: &'a str) -> Result<Composition, Error> {
    let file = parse(node_file, "the file of the node")?;
    let file = root(&file, "the file of the node")?;
    let damaged = |why: String| Error::Damaged(format!("the stored document {why}"));
    let revision = sibuna_json::parse_with_limits(published.as_bytes(), &LIMITS)
        .map_err(|error| damaged(format!("is not JSON: {error}")))?;
    let revision = revision.as_object().ok_or_else(|| damaged("is not an object".to_owned()))?;
    let binds = local_binds(file)?;
    let mut whole = Object::new();
    for (key, member) in file {
        if PUBLISHED.contains(&key) {
            return Err(Error::Settings(format!(
                "the file of a node holds `{key}`, and the database owns it. Move it to the \
                 source and apply the source"
            )));
        }
        if key != SECTION {
            whole.insert(key.to_owned(), member.clone());
        }
    }
    let mut unused_binds = Vec::new();
    for (key, member) in revision {
        if !PUBLISHED.contains(&key) {
            return Err(damaged(format!("holds the section `{key}`")));
        }
        let member = match key {
            "frontends" => rebind(member, binds, &mut unused_binds),
            _ => member.clone(),
        };
        whole.insert(key.to_owned(), member);
    }
    if !revision.contains_key("frontends") {
        rebind(&Value::Null, binds, &mut unused_binds);
    }
    Ok(Composition { document: canonical(&Value::Object(whole)), unused_binds })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = r#"{
        "global": {"workers": 2},
        "frontends": {"web": {"proto": "tcp", "binds": ["0.0.0.0:80"]},
                      "dns": {"proto": "udp", "binds": ["192.0.2.1:53"]}},
        "backends": {"app": {"mode": "tcp", "servers": [{"name": "a", "addr": "10.0.0.1:80"}]}}
    }"#;

    #[test]
    fn the_canonical_text_ignores_order_and_white_space() {
        let first = publish(br#"{"frontends":{"b":1,"a":[1, 2]},"backends":{}}"#).unwrap();
        let second = publish(b"{ \"backends\": {},\n \"frontends\": {\"a\": [1,2], \"b\": 1} }");
        let second = second.unwrap();
        assert_eq!(first.document, r#"{"backends":{},"frontends":{"a":[1,2],"b":1}}"#);
        assert_eq!(first, second);
        assert_eq!(first.digest.len(), 64);
        // The digest of the empty text is the known SHA-256 value.
        assert!(digest(b"").starts_with("e3b0c44298fc1c14"));
    }

    #[test]
    fn a_source_publishes_three_sections_and_names_the_rest() {
        let publication = publish(SOURCE.as_bytes()).unwrap();
        assert_eq!(publication.left_out, ["global"]);
        assert!(publication.document.starts_with(r#"{"backends":"#));
        assert!(!publication.document.contains("workers"));
        let misspelled = publish(br#"{"fronteds":{}}"#).unwrap_err();
        assert_eq!(misspelled.code(), "DBA001");
        assert!(misspelled.to_string().contains("fronteds"));
        assert_eq!(publish(br#"{"authority":{}}"#).unwrap_err().code(), "DBA001");
        assert_eq!(publish(b"[]").unwrap_err().code(), "DBA001");
        assert_eq!(publish(b"{").unwrap_err().code(), "DBA001");
    }

    #[test]
    fn a_dump_publishes_the_same_document() {
        let publication = publish(SOURCE.as_bytes()).unwrap();
        let dump = pretty(&publication.document).unwrap();
        assert!(dump.contains("\n  \"backends\": {\n"));
        assert!(dump.ends_with("}\n"));
        assert_eq!(publish(dump.as_bytes()).unwrap().document, publication.document);
        assert_eq!(pretty("{}").unwrap(), "{}\n");
        assert_eq!(pretty("{").unwrap_err().code(), "DBA008");
    }

    #[test]
    fn a_node_composes_its_file_with_the_revision() {
        let published = publish(SOURCE.as_bytes()).unwrap().document;
        let file = br#"{"global":{"admin_socket":"s"},
            "authority":{"sqlite":"x.db","binds":{"dns":["10.9.9.9:53"],"gone":["1.1.1.1:1"]}}}"#;
        assert!(is_node_file(file));
        assert!(!is_node_file(SOURCE.as_bytes()));
        assert!(!is_node_file(b"{"));
        let composed = compose(file, &published).unwrap();
        assert_eq!(composed.unused_binds, ["gone"]);
        let document = composed.document;
        assert!(document.contains(r#""global":{"admin_socket":"s"}"#), "{document}");
        assert!(document.contains(r#""binds":["10.9.9.9:53"]"#), "{document}");
        assert!(document.contains(r#""binds":["0.0.0.0:80"]"#), "{document}");
        assert!(!document.contains("192.0.2.1"), "{document}");
        assert!(!document.contains("authority"), "{document}");
        assert!(!document.contains("workers"), "the global of the source stays out");
    }

    #[test]
    fn a_node_file_may_not_hold_what_the_database_owns() {
        let published = publish(SOURCE.as_bytes()).unwrap().document;
        let owns = compose(br#"{"authority":{},"frontends":{}}"#, &published).unwrap_err();
        assert_eq!(owns.code(), "DBA005");
        assert!(owns.to_string().contains("frontends"));
        let binds = compose(br#"{"authority":{"binds":{"web":"0.0.0.0:1"}}}"#, &published);
        assert_eq!(binds.unwrap_err().code(), "DBA005");
        let empty = compose(br#"{"authority":{"binds":{"web":[]}}}"#, &published);
        assert_eq!(empty.unwrap_err().code(), "DBA005");
        let damaged = compose(br#"{"authority":{}}"#, r#"{"global":{}}"#).unwrap_err();
        assert_eq!(damaged.code(), "DBA008");
        assert_eq!(compose(br#"{"authority":{}}"#, "[").unwrap_err().code(), "DBA008");
    }
}
