//! The policy set commands (Zig's `console_command_policies.zig`). `policies export` walks
//! the catalog and prints every managed rule document as one JSON array; `policies import`
//! sends such an array as one `policies/import` request (SID 0013) against the revision
//! observed just before, so a concurrent edit is refused instead of overwritten.

use std::io::{Read, Write};

use sibuna_console_protocol::workflows::{
    MAX_IMPORT_BYTES, MAX_IMPORT_DOCUMENT, MAX_IMPORT_DOCUMENTS,
};
use sibuna_json::Value;

use super::args::{Args, Kind};
use super::{CommandError, Field, Session, body, emit, reply};

/// The largest policy set file read.
pub const MAX_FILE: usize = 640 * 1024;
/// The longest rule id or catalog cursor.
const MAX_ID: usize = 128;

/// Runs `policies export` or `policies import`.
///
/// Fails with the session's error, [`CommandError::InvalidResponse`] for a reply that
/// breaks its contract, and for an import [`CommandError::PolicyFile`] or
/// [`CommandError::InvalidPolicySet`].
pub fn run(session: &Session, args: &Args<'_>, out: &mut dyn Write) -> Result<(), CommandError> {
    if args.kind == Kind::PoliciesExport {
        return export(session, out);
    }
    import(session, args.file, out)
}

/// Returns the string member `name` of the object `value`.
fn text<'v>(value: &'v Value<'_>, name: &str) -> Option<&'v str> {
    value.as_object()?.get(name)?.as_str()
}

/// Collects the whole set before printing, so a failed walk prints nothing.
fn export(session: &Session, out: &mut dyn Write) -> Result<(), CommandError> {
    let invalid = || CommandError::InvalidResponse;
    let mut output = String::from("[");
    let mut documents = 0;
    let mut after = String::new();
    loop {
        let request = body(&[("kind", Field::Text("catalog")), ("after", Field::Text(&after))]);
        let page = session.post("/console/api/policies/read", request.as_bytes())?;
        let page = sibuna_json::parse(&page.body).map_err(|_| invalid())?;
        let rows = page.as_object().and_then(|page| page.get("rows")?.as_array());
        for row in rows.ok_or_else(invalid)? {
            let id = text(row, "id").filter(|id| !id.is_empty() && id.len() <= MAX_ID);
            let id = id.ok_or_else(invalid)?;
            documents += 1;
            if documents > MAX_IMPORT_DOCUMENTS {
                return Err(invalid());
            }
            let request = body(&[("kind", Field::Text("document")), ("id", Field::Text(id))]);
            let reply = session.post("/console/api/policies/read", request.as_bytes())?;
            let reply = sibuna_json::parse(&reply.body).map_err(|_| invalid())?;
            let document = text(&reply, "document").ok_or_else(invalid)?;
            // The document is printed as it is stored; it must be one JSON object.
            let parsed = sibuna_json::parse(document.as_bytes()).map_err(|_| invalid())?;
            if parsed.as_object().is_none() {
                return Err(invalid());
            }
            if documents > 1 {
                output.push(',');
            }
            output.push_str(document);
        }
        match page.as_object().and_then(|page| page.get("next")) {
            None | Some(Value::Null) => break,
            Some(next) => {
                let next = next.as_str().filter(|next| !next.is_empty() && next.len() <= MAX_ID);
                after = next.ok_or_else(invalid)?.to_owned();
            }
        }
    }
    output.push(']');
    emit(out, output.as_bytes())
}

/// Reads the set file and returns its compact documents.
///
/// Fails with [`CommandError::PolicyFile`] when the file cannot be read and with
/// [`CommandError::InvalidPolicySet`] for a file over 640 KiB or a set that is not an array
/// of 1 to 128 objects, each at most 4 KiB compact and 256 KiB together.
fn read_set(path: &str) -> Result<Vec<String>, CommandError> {
    let file = std::fs::File::open(path).map_err(|_| CommandError::PolicyFile)?;
    let mut text = Vec::new();
    let limit = MAX_FILE as u64 + 1;
    file.take(limit).read_to_end(&mut text).map_err(|_| CommandError::PolicyFile)?;
    if text.len() > MAX_FILE {
        return Err(CommandError::InvalidPolicySet);
    }
    let root = sibuna_json::parse(&text).map_err(|_| CommandError::InvalidPolicySet)?;
    let items = root.as_array().ok_or(CommandError::InvalidPolicySet)?;
    if items.is_empty() || items.len() > MAX_IMPORT_DOCUMENTS {
        return Err(CommandError::InvalidPolicySet);
    }
    let mut documents = Vec::with_capacity(items.len());
    let mut total = 0;
    for item in items {
        if item.as_object().is_none() {
            return Err(CommandError::InvalidPolicySet);
        }
        let document = item.to_string();
        total += document.len();
        if document.len() > MAX_IMPORT_DOCUMENT || total > MAX_IMPORT_BYTES {
            return Err(CommandError::InvalidPolicySet);
        }
        documents.push(document);
    }
    Ok(documents)
}

/// Imports the set in `path` against the committed revision read just before.
fn import(session: &Session, path: &str, out: &mut dyn Write) -> Result<(), CommandError> {
    let documents = read_set(path)?;
    let page = session.post("/console/api/policies/query", b"{}")?;
    let page = sibuna_json::parse(&page.body).map_err(|_| CommandError::InvalidResponse)?;
    let committed = page.as_object().and_then(|page| page.get("committed"));
    let committed = match committed {
        Some(Value::String(text)) => text.to_string(),
        Some(Value::Number(number)) => number.as_str().to_owned(),
        _ => return Err(CommandError::InvalidResponse),
    };
    let texts: Vec<&str> = documents.iter().map(String::as_str).collect();
    let request = body(&[
        ("expected_revision", Field::Text(&committed)),
        ("documents", Field::Texts(&texts)),
    ]);
    let reply = session.post("/console/api/policies/import", request.as_bytes())?;
    reply::import(&reply.body)?;
    emit(out, &reply.body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(name: &str, text: &str) -> Result<Vec<String>, CommandError> {
        let path =
            std::env::temp_dir().join(format!("sibuna-u2-set-{}-{name}", std::process::id()));
        std::fs::write(&path, text).unwrap();
        let read = read_set(path.to_str().unwrap());
        let _ = std::fs::remove_file(&path);
        read
    }

    #[test]
    fn policy_sets_are_bounded_arrays_of_objects() {
        let documents =
            set("valid", "[ {\"id\": \"a\"},\n {\"id\":\"b\", \"name\": \"B\"} ]").unwrap();
        assert_eq!(documents, ["{\"id\":\"a\"}", "{\"id\":\"b\",\"name\":\"B\"}"]);
        for invalid in ["[]", "{}", "[1]", "not json", "[{}]x"] {
            assert!(matches!(set("invalid", invalid), Err(CommandError::InvalidPolicySet)));
        }
        let many = format!("[{}]", vec!["{}"; 129].join(","));
        assert!(matches!(set("many", &many), Err(CommandError::InvalidPolicySet)));
        let long = format!("[{{\"name\":\"{}\"}}]", "x".repeat(4096));
        assert!(matches!(set("long", &long), Err(CommandError::InvalidPolicySet)));
        assert!(matches!(read_set("/nonexistent/set.json"), Err(CommandError::PolicyFile)));
    }
}
