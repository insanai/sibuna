//! Request fragments shared with the policy crate's differential test: addresses, paths,
//! queries, User-Agents, header names and values, content types, bodies and attack
//! payloads (SQL injection, cross-site scripting, command injection, traversal), and the
//! policy crate's bot signature tables.

/// The fragment file of `sibuna-policy`, embedded so the corpus does not depend on the
/// working directory.
const FRAGMENTS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/policy/tests/data/differential/fragments.txt"
));

/// The policy crate's built-in bot signatures, read as data so the tool does not compile
/// the policy library (a parity run tests built daemons, not the library in the tree).
const BOTS: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../crates/policy/src/bots.rs"));

/// The string elements of the table `pub const <name>: [&str; N] = [...];` in the policy
/// crate's `bots.rs`; empty when there is no such table.
pub fn bot_table(name: &str) -> Vec<&'static str> {
    let opening = format!("pub const {name}: [&str;");
    let Some(start) = BOTS.find(&opening) else { return Vec::new() };
    let rest = &BOTS[start..];
    // The elements start at the first `[` after the `=`, on the same line or the next.
    let Some(equals) = rest.find('=') else { return Vec::new() };
    let Some(open) = rest[equals..].find('[') else { return Vec::new() };
    let body = &rest[equals + open + 1..];
    let body = &body[..body.find("];").unwrap_or(body.len())];
    body.split('"').skip(1).step_by(2).collect()
}

/// The fragment lists, unescaped.
#[derive(Debug, Default)]
pub struct Fragments {
    /// Paths, some with traversal and percent-encodings.
    pub paths: Vec<Vec<u8>>,
    /// Query strings, some with attack payloads.
    pub queries: Vec<Vec<u8>>,
    /// User-Agent values of browsers, libraries and crawlers.
    pub user_agents: Vec<Vec<u8>>,
    /// Header names the policy rules look at.
    pub header_names: Vec<Vec<u8>>,
    /// Header values, some hostile.
    pub header_values: Vec<Vec<u8>>,
    /// Content types, `(none)` meaning the header is absent.
    pub content_types: Vec<Vec<u8>>,
    /// Request bodies, some multipart and some with payloads.
    pub bodies: Vec<Vec<u8>>,
    /// Attack payloads and benign look-alikes.
    pub payloads: Vec<Vec<u8>>,
}

impl Fragments {
    /// Parses the embedded fragment file. Sections the corpus does not use are skipped.
    pub fn load() -> Fragments {
        parse(FRAGMENTS)
    }
}

/// Parses fragment text: `[section]` lines open a list, every other non-empty line is one
/// escaped entry of the open list.
pub fn parse(text: &str) -> Fragments {
    let mut fragments = Fragments::default();
    let mut section = "";
    for line in text.lines().filter(|line| !line.is_empty()) {
        if let Some(name) = line.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
            section = name;
            continue;
        }
        let list = match section {
            "paths" => &mut fragments.paths,
            "queries" => &mut fragments.queries,
            "user_agents" => &mut fragments.user_agents,
            "header_names" => &mut fragments.header_names,
            "header_values" => &mut fragments.header_values,
            "content_types" => &mut fragments.content_types,
            "bodies" => &mut fragments.bodies,
            "payloads" => &mut fragments.payloads,
            _ => continue,
        };
        list.push(unescape(line.as_bytes()));
    }
    fragments
}

/// Reverses the escaping of the fragment file (`\r`, `\n`, `\t`, `\\`, `\xHH`); `(empty)`
/// is the empty string. An unknown or cut escape stays as written.
pub fn unescape(line: &[u8]) -> Vec<u8> {
    if line == b"(empty)" {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(line.len());
    let mut rest = line;
    while let Some((&byte, tail)) = rest.split_first() {
        rest = tail;
        if byte != b'\\' {
            out.push(byte);
            continue;
        }
        // The decoded byte and how many bytes after the backslash it used; an unknown escape
        // keeps its backslash and leaves the next byte to the loop.
        let (value, used) = match rest {
            [b'r', ..] => (b'\r', 1),
            [b'n', ..] => (b'\n', 1),
            [b't', ..] => (b'\t', 1),
            [b'\\', ..] => (b'\\', 1),
            [b'x', digits @ ..] => hex_byte(digits).map_or((b'\\', 0), |value| (value, 3)),
            _ => (b'\\', 0),
        };
        out.push(value);
        rest = rest.get(used..).unwrap_or_default();
    }
    out
}

/// The byte written by the first two hexadecimal digits of `text`.
fn hex_byte(text: &[u8]) -> Option<u8> {
    let digits = std::str::from_utf8(text.get(..2)?).ok()?;
    u8::from_str_radix(digits, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_are_reversed() {
        assert_eq!(unescape(b"a\\r\\n\\t\\\\b"), b"a\r\n\t\\b");
        assert_eq!(unescape(b"x\\x00y\\x7f"), b"x\x00y\x7f");
        assert_eq!(unescape(b"(empty)"), b"");
        assert_eq!(unescape(b"..\\\\windows"), b"..\\windows");
        assert_eq!(unescape(b"cut\\x4"), b"cut\\x4");
        assert_eq!(unescape(b"end\\"), b"end\\");
    }

    #[test]
    fn the_bot_tables_are_read_from_the_policy_crate() {
        let ai = bot_table("AI_SCRAPERS");
        assert!(ai.len() >= 10 && ai.contains(&"GPTBot") && ai.contains(&"ClaudeBot"), "{ai:?}");
        assert!(bot_table("SCRAPER_LIBRARIES").contains(&"python-requests"));
        assert!(bot_table("SEARCH_CRAWLERS").contains(&"Googlebot"));
        assert!(bot_table("NO_SUCH_TABLE").is_empty());
    }

    #[test]
    fn the_embedded_file_has_every_section() {
        let fragments = Fragments::load();
        for list in [
            &fragments.paths,
            &fragments.queries,
            &fragments.user_agents,
            &fragments.header_names,
            &fragments.header_values,
            &fragments.content_types,
            &fragments.bodies,
            &fragments.payloads,
        ] {
            assert!(list.len() > 5);
        }
        assert!(fragments.payloads.iter().any(|p| p.as_slice() == b"<script>alert(1)</script>"));
    }
}
