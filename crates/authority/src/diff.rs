//! The difference between two revisions, by the path of what changed.
//!
//! Objects are compared member by member. A list whose members are objects with
//! distinct names, such as the servers of a pool, is compared by name, so adding a
//! server shows as one added member and not as a changed list.

use std::fmt::Write as _;

use sibuna_json::{Object, Value};

use crate::document::{self, LIMITS};
use crate::error::Error;

/// The most lines that [`render`] prints.
pub const MAX_LINES: usize = 200;
/// The most bytes of a value that [`render`] prints.
const MAX_VALUE: usize = 120;

/// One difference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// Where: `backends.app.servers[web2].weight`.
    pub path: String,
    /// The canonical text of the value before, or `None` when it was added.
    pub before: Option<String>,
    /// The canonical text of the value after, or `None` when it was removed.
    pub after: Option<String>,
}

fn parse(text: &str) -> Result<Value<'_>, Error> {
    sibuna_json::parse_with_limits(text.as_bytes(), &LIMITS)
        .map_err(|error| Error::Damaged(format!("a document is not JSON: {error}")))
}

/// The differences between the documents `before` and `after`, in the order of their
/// paths. `before` is `None` for the first revision. Fails with [`Error::Damaged`] when
/// a document is not JSON.
pub fn diff(before: Option<&str>, after: &str) -> Result<Vec<Change>, Error> {
    let empty = Value::Object(Object::new());
    let before = before.map(parse).transpose()?;
    let after = parse(after)?;
    let mut changes = Vec::new();
    walk(&mut changes, "", before.as_ref().unwrap_or(&empty), &after);
    Ok(changes)
}

/// The name of a member of a list, when the member is an object with a `name`.
fn name<'v>(member: &'v Value<'_>) -> Option<&'v str> {
    member.as_object()?.get("name")?.as_str()
}

/// Whether every member of `items` has a name and no two share one.
fn is_named(items: &[Value<'_>]) -> bool {
    let mut names: Vec<&str> = items.iter().filter_map(name).collect();
    if names.len() != items.len() {
        return false;
    }
    names.sort_unstable();
    names.windows(2).all(|pair| pair[0] != pair[1])
}

/// The members of a list with their names.
fn named<'v, 'a>(items: &'v [Value<'a>]) -> impl Iterator<Item = (&'v str, &'v Value<'a>)> {
    items.iter().filter_map(|member| Some((name(member)?, member)))
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() { key.to_owned() } else { format!("{path}.{key}") }
}

/// Compares two sets of members that are told apart by a key, in the order of the keys.
fn members<'v, 'a: 'v>(
    changes: &mut Vec<Change>,
    before: impl Iterator<Item = (&'v str, &'v Value<'a>)>,
    after: impl Iterator<Item = (&'v str, &'v Value<'a>)>,
    path_of: impl Fn(&str) -> String,
) {
    let mut before: Vec<_> = before.collect();
    let mut after: Vec<_> = after.collect();
    before.sort_by(|left, right| left.0.cmp(right.0));
    after.sort_by(|left, right| left.0.cmp(right.0));
    let (mut old, mut new) = (before.into_iter().peekable(), after.into_iter().peekable());
    loop {
        let order = match (old.peek(), new.peek()) {
            (None, None) => return,
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (Some(left), Some(right)) => left.0.cmp(right.0),
        };
        match order {
            std::cmp::Ordering::Less => {
                let Some((key, value)) = old.next() else { return };
                let before = Some(document::canonical(value));
                changes.push(Change { path: path_of(key), before, after: None });
            }
            std::cmp::Ordering::Greater => {
                let Some((key, value)) = new.next() else { return };
                let after = Some(document::canonical(value));
                changes.push(Change { path: path_of(key), before: None, after });
            }
            std::cmp::Ordering::Equal => {
                let (Some((key, left)), Some((_, right))) = (old.next(), new.next()) else {
                    return;
                };
                walk(changes, &path_of(key), left, right);
            }
        }
    }
}

/// Adds the differences between `before` and `after`, which both live at `path`. The
/// parser bounded the nesting, so the recursion is bounded.
fn walk(changes: &mut Vec<Change>, path: &str, before: &Value<'_>, after: &Value<'_>) {
    if before == after {
        return;
    }
    match (before, after) {
        (Value::Object(old), Value::Object(new)) => {
            members(changes, old.iter(), new.iter(), |key| join(path, key));
        }
        (Value::Array(old), Value::Array(new)) if is_named(old) && is_named(new) => {
            members(changes, named(old), named(new), |key| format!("{path}[{key}]"));
        }
        _ => changes.push(Change {
            path: path.to_owned(),
            before: Some(document::canonical(before)),
            after: Some(document::canonical(after)),
        }),
    }
}

/// At most [`MAX_VALUE`] bytes of `text`, cut at a character.
fn short(text: &str) -> String {
    if text.len() <= MAX_VALUE {
        return text.to_owned();
    }
    let mut end = MAX_VALUE;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

/// Writes one line for each change: `+ PATH: VALUE` for an addition, `- PATH` for a
/// removal and `~ PATH: BEFORE -> AFTER` for a change. After [`MAX_LINES`] lines it
/// says how many it left out. No change gives no text.
pub fn render(changes: &[Change]) -> String {
    let mut out = String::new();
    for change in changes.iter().take(MAX_LINES) {
        let path = &change.path;
        let _ = match (&change.before, &change.after) {
            (None, Some(after)) => writeln!(out, "+ {path}: {}", short(after)),
            (Some(_), None) => writeln!(out, "- {path}"),
            (Some(before), Some(after)) => {
                writeln!(out, "~ {path}: {} -> {}", short(before), short(after))
            }
            (None, None) => Ok(()),
        };
    }
    if changes.len() > MAX_LINES {
        let _ = writeln!(out, "... and {} more", changes.len() - MAX_LINES);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const BEFORE: &str = r#"{"backends":{"app":{"servers":[
        {"name":"web1","addr":"10.0.0.1:80"},{"name":"web2","addr":"10.0.0.2:80","weight":1}]}},
        "frontends":{"old":{"binds":["0.0.0.0:1"]},"web":{"binds":["0.0.0.0:80"]}}}"#;
    const AFTER: &str = r#"{"backends":{"app":{"servers":[
        {"name":"web2","addr":"10.0.0.2:80","weight":3},{"name":"web3","addr":"10.0.0.3:80"},
        {"name":"web1","addr":"10.0.0.1:80"}]}},
        "frontends":{"web":{"binds":["0.0.0.0:80","0.0.0.0:81"]}}}"#;

    #[test]
    fn the_difference_names_paths_and_compares_servers_by_name() {
        let changes = diff(Some(BEFORE), AFTER).unwrap();
        let text = render(&changes);
        let expected = [
            r#"~ backends.app.servers[web2].weight: 1 -> 3"#,
            r#"+ backends.app.servers[web3]: {"addr":"10.0.0.3:80","name":"web3"}"#,
            r#"- frontends.old"#,
            r#"~ frontends.web.binds: ["0.0.0.0:80"] -> ["0.0.0.0:80","0.0.0.0:81"]"#,
        ];
        assert_eq!(text.lines().collect::<Vec<_>>(), expected);
        assert!(diff(Some(BEFORE), BEFORE).unwrap().is_empty());
        assert_eq!(render(&[]), "");
    }

    #[test]
    fn the_first_revision_adds_its_sections() {
        let changes = diff(None, r#"{"backends":{},"frontends":{"web":{}}}"#).unwrap();
        assert_eq!(render(&changes), "+ backends: {}\n+ frontends: {\"web\":{}}\n");
    }

    #[test]
    fn a_list_with_a_repeated_or_missing_name_is_compared_whole() {
        let before = r#"{"l":[{"name":"a"},{"name":"a"}]}"#;
        let after = r#"{"l":[{"name":"a"}]}"#;
        let changes = diff(Some(before), after).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "l");
        let scalars = diff(Some(r#"{"l":[1,2]}"#), r#"{"l":[2,1]}"#).unwrap();
        assert_eq!(render(&scalars), "~ l: [1,2] -> [2,1]\n");
    }

    #[test]
    fn long_values_and_long_differences_are_cut() {
        let long = format!(r#"{{"k":"{}"}}"#, "x".repeat(400));
        let text = render(&diff(None, &long).unwrap());
        assert!(text.len() < 160 && text.trim_end().ends_with("..."), "{text}");
        let many: Vec<String> = (0..300).map(|index| format!(r#""k{index}":1"#)).collect();
        let many = format!("{{{}}}", many.join(","));
        let text = render(&diff(None, &many).unwrap());
        assert_eq!(text.lines().count(), MAX_LINES + 1);
        assert!(text.ends_with("... and 100 more\n"));
        assert_eq!(diff(None, "{").unwrap_err().code(), "DBA008");
    }
}
