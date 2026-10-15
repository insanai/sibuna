//! Single-pass structural detectors, gated by the byte classes.
//!
//! Strong signatures alone cannot catch `id=5' or 1=1` without also catching prose, so each
//! category has a small deterministic recogniser that fires only on structure: a quote next
//! to SQL keywords, a `literal = literal` or `literal > literal` tautology, `union` and
//! `select` joined by parentheses, a script-capable tag together with an event-handler
//! attribute or any tag carrying one, a shell separator followed by a command name, or a
//! NUL byte.
//!
//! Every loop here does work proportional to its input: each literal search starts just
//! after an opening quote and stops at the next quote of the same kind, so no stretch of
//! text is searched more than twice.

use super::Violation;
use super::classes::Classes;
use super::tables::{SHELL_COMMANDS, XSS_TAGS};
use crate::bytes::{contains, find_byte, starts_with_ignore_case};
use crate::waf::AttackCategory;

/// Bytes of SQL words: ASCII letters, digits and `_`.
const WORD: [bool; 256] = {
    let mut table = [false; 256];
    let mut byte = 0;
    while byte < 256 {
        let b = byte as u8;
        table[byte] = b.is_ascii_alphanumeric() || b == b'_';
        byte += 1;
    }
    table
};

#[inline]
fn is_word_byte(byte: u8) -> bool {
    WORD[usize::from(byte)]
}

/// A NUL byte, or the escape `%00`, can truncate application text.
pub(crate) fn null_byte(text: &[u8], classes: Classes) -> Option<Violation> {
    let escaped = classes.percent() && contains(text, b"%00");
    (classes.nul() || escaped).then_some(Violation::new(AttackCategory::PathTraversal, "%00"))
}

/// Returns the canonical keyword equal to `word` (already lower case), if any.
fn keyword_name(word: &[u8]) -> Option<&'static str> {
    Some(match word {
        b"select" => "select",
        b"union" => "union",
        b"insert" => "insert",
        b"update" => "update",
        b"delete" => "delete",
        b"drop" => "drop",
        b"from" => "from",
        b"where" => "where",
        b"having" => "having",
        b"order" => "order",
        b"group" => "group",
        b"exec" => "exec",
        b"declare" => "declare",
        b"cast" => "cast",
        b"concat" => "concat",
        b"char" => "char",
        b"convert" => "convert",
        b"table" => "table",
        b"values" => "values",
        b"limit" => "limit",
        b"offset" => "offset",
        _ => return None,
    })
}

fn skip_spaces(text: &[u8], start: usize) -> usize {
    let rest = text.get(start..).unwrap_or_default();
    start + rest.iter().take_while(|&&b| b == b' ' || b == b'\t').count()
}

/// Consumes one SQL literal (a digit run or a quoted string) at `start` and returns the
/// index just past it, or `None` when no literal starts there.
fn skip_literal(text: &[u8], start: usize) -> Option<usize> {
    let &first = text.get(start)?;
    if first.is_ascii_digit() {
        let rest = &text[start..];
        return Some(start + rest.iter().take_while(|b| b.is_ascii_digit()).count());
    }
    if first == b'\'' || first == b'"' {
        let close = find_byte(text, start + 1, first)?;
        crate::steps::count((close - start) as u64);
        return Some(close + 1);
    }
    None
}

/// Returns the index just past a comparison operator at `start`: `=`, `==`, `<`, `>`,
/// `<=`, `>=`, `<>` or `!=`.
fn skip_comparison(text: &[u8], start: usize) -> Option<usize> {
    let first = *text.get(start)?;
    let second = text.get(start + 1).copied();
    match (first, second) {
        (b'=' | b'<' | b'>' | b'!', Some(b'=')) | (b'<', Some(b'>')) => Some(start + 2),
        (b'=' | b'<' | b'>', _) => Some(start + 1),
        _ => None,
    }
}

/// A boolean tautology is `or`/`and`, a space, then `literal op literal` for a comparison
/// operator, as in `or 1=1`, `and 'a'='a'` or `or 2>1`. Identifiers on either side
/// (`or b=2`) are ordinary filter syntax.
fn tautology_after(text: &[u8], word_end: usize) -> bool {
    let left_start = skip_spaces(text, word_end);
    if left_start == word_end {
        return false;
    }
    let Some(left_end) = skip_literal(text, left_start) else { return false };
    let Some(operator_end) = skip_comparison(text, skip_spaces(text, left_end)) else {
        return false;
    };
    skip_literal(text, skip_spaces(text, operator_end)).is_some()
}

/// The word that ends at `end` once spaces and tabs before `end` are skipped, with the
/// index where it starts. The word is empty when none ends there.
fn previous_word(text: &[u8], end: usize) -> (usize, &[u8]) {
    let head = text.get(..end).unwrap_or_default();
    let spaces = head.iter().rev().take_while(|&&b| b == b' ' || b == b'\t').count();
    let word_end = head.len() - spaces;
    let len = head[..word_end].iter().rev().take_while(|&&b| is_word_byte(b)).count();
    crate::steps::count((spaces + len) as u64);
    (word_end - len, &head[word_end - len..word_end])
}

/// True when the word before `end` is `union`, or `all` or `distinct` after `union`.
fn union_before(text: &[u8], end: usize) -> bool {
    let (start, word) = previous_word(text, end);
    if word.eq_ignore_ascii_case(b"all") || word.eq_ignore_ascii_case(b"distinct") {
        return previous_word(text, start).1.eq_ignore_ascii_case(b"union");
    }
    word.eq_ignore_ascii_case(b"union")
}

/// `union` and `select` joined by parentheses, as in `union(select` or
/// `union all ((select`, which the signature `union select` misses. Each `(` that follows
/// `union` is examined once, and the scan resumes after the parentheses it skipped.
fn union_select(text: &[u8]) -> bool {
    let mut position = 0;
    while let Some(paren) = find_byte(text, position, b'(') {
        position = paren + 1;
        if !union_before(text, paren) {
            continue;
        }
        let skipped =
            text[position..].iter().take_while(|&&b| matches!(b, b'(' | b' ' | b'\t')).count();
        crate::steps::count(skipped as u64);
        position += skipped;
        if starts_with_ignore_case(&text[position..], b"select")
            && text.get(position + 6).is_none_or(|&b| !is_word_byte(b))
        {
            return true;
        }
    }
    false
}

#[derive(Default)]
struct SqlScan {
    keyword_hits: u32,
    first_keyword: &'static str,
    tautology: bool,
}

/// One pass over the words of `text`: words of at most seven bytes are looked up in the
/// keyword table, and `or`/`and` words are checked for a tautology. The scan stops at the
/// first tautology, because a tautology decides the field on its own.
fn scan_sql(text: &[u8]) -> SqlScan {
    let mut scan = SqlScan::default();
    let mut index = 0;
    while index < text.len() {
        if !is_word_byte(text[index]) {
            index += 1;
            continue;
        }
        let start = index;
        index += text[index..].iter().take_while(|&&b| is_word_byte(b)).count();
        let word = &text[start..index];
        if word.len() > 7 {
            continue;
        }
        let mut lower = [0u8; 7];
        let lower = &mut lower[..word.len()];
        lower.copy_from_slice(word);
        lower.make_ascii_lowercase();
        if let Some(name) = keyword_name(lower) {
            if scan.keyword_hits == 0 {
                scan.first_keyword = name;
            }
            scan.keyword_hits += 1;
        } else if (lower == b"or" || lower == b"and") && tautology_after(text, index) {
            scan.tautology = true;
            return scan;
        }
    }
    scan
}

fn has_sql_comment(text: &[u8]) -> bool {
    contains(text, b"--") || contains(text, b"/*") || find_byte(text, 0, b'#').is_some()
}

/// SQL injection scoring. A tautology fires alone. Otherwise a quote is mandatory and the
/// evidence must reach four points: the quote, up to two keywords, a comment marker and an
/// `=` each add one. `it's a group order from the shop` scores three and passes.
pub(crate) fn sqli(text: &[u8], classes: Classes) -> Option<Violation> {
    if classes.paren_and_u() && union_select(text) {
        return Some(Violation::new(AttackCategory::Sqli, "union(select"));
    }
    let (quote, equals) = (classes.quote(), classes.equals());
    // Without a quote or a comparison no structure can exist.
    if !quote && !equals && !classes.less() && !classes.greater() {
        return None;
    }
    let scan = scan_sql(text);
    if scan.tautology {
        return Some(Violation::new(AttackCategory::Sqli, "tautology"));
    }
    if !quote {
        return None;
    }
    // A closing quote followed by a comment is the classic `admin'--` termination.
    if contains(text, b"'--") || contains(text, b"'/*") || contains(text, b"'#") {
        return Some(Violation::new(AttackCategory::Sqli, "'--"));
    }
    let score =
        1 + scan.keyword_hits.min(2) + u32::from(has_sql_comment(text)) + u32::from(equals);
    (score >= 4 && scan.keyword_hits > 0)
        .then_some(Violation::new(AttackCategory::Sqli, scan.first_keyword))
}

/// True when `text` holds `<tag` followed by a space, tab, `/` or `>`, for a tag that can
/// host script.
fn has_html_tag(text: &[u8]) -> bool {
    let mut position = 0;
    while let Some(less) = find_byte(text, position, b'<') {
        let rest = &text[less + 1..];
        if let Some(&first) = rest.first() {
            let first = first.to_ascii_lowercase();
            for tag in XSS_TAGS.iter().filter(|tag| tag.as_bytes()[0] == first) {
                crate::steps::count(1);
                let tag = tag.as_bytes();
                if rest.len() > tag.len()
                    && starts_with_ignore_case(rest, tag)
                    && matches!(rest[tag.len()], b' ' | b'/' | b'>' | b'\t')
                {
                    return true;
                }
            }
        }
        position = less + 1;
    }
    false
}

/// HTML white space, which may separate an attribute name from its `=`.
fn is_html_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0c)
}

/// True when an `on<event>=` attribute appears in attribute position: preceded by white
/// space, a slash or a quote, with optional white space before the `=` (`onerror =`).
/// `onboarding=1` in a query string does not count.
fn has_event_handler(text: &[u8]) -> bool {
    // `window[1..3]` is `on` in any case; `window[0]` is the byte before it. A byte `b` has
    // `b | 0x20 == b'o'` exactly when it is `o` or `O` (and likewise for `n`).
    for (index, window) in text.windows(3).enumerate() {
        let is_on = window[1] | 0x20 == b'o' && window[2] | 0x20 == b'n';
        if !is_on || !(is_html_space(window[0]) || matches!(window[0], b'/' | b'"' | b'\'')) {
            continue;
        }
        let rest = &text[index + 3..];
        let letters = rest.iter().take_while(|b| b.is_ascii_alphabetic()).count();
        let spaces = rest[letters..].iter().take_while(|&&b| is_html_space(b)).count();
        crate::steps::count((letters + spaces) as u64);
        if letters > 0 && rest.get(letters + spaces) == Some(&b'=') {
            return true;
        }
    }
    false
}

/// True when a tag of any name (`<` and a letter) carries an event-handler attribute before
/// its `>` (or the end of the text). Custom and unlisted elements run handlers too. The
/// scan resumes after each tag, so no text is searched twice.
fn tag_with_event_handler(text: &[u8]) -> bool {
    let mut position = 0;
    while let Some(less) = find_byte(text, position, b'<') {
        if !text.get(less + 1).is_some_and(u8::is_ascii_alphabetic) {
            position = less + 1;
            continue;
        }
        let end = find_byte(text, less + 1, b'>').unwrap_or(text.len());
        if has_event_handler(&text[less..end]) {
            return true;
        }
        position = end;
    }
    false
}

/// XSS: a tag that can host script together with an event-handler attribute anywhere in the
/// field (the Zig rule), or a tag of any name with an event-handler attribute inside it.
pub(crate) fn xss(text: &[u8], classes: Classes) -> Option<Violation> {
    let found = classes.less()
        && ((has_html_tag(text) && has_event_handler(text)) || tag_with_event_handler(text));
    found.then_some(Violation::new(AttackCategory::Xss, "on*="))
}

/// True when the letters of `scheme` end just before `end`, ignoring case and any tabs and
/// line breaks among them.
fn scheme_ends_at(text: &[u8], end: usize, scheme: &[u8]) -> bool {
    let mut index = end;
    for &letter in scheme.iter().rev() {
        loop {
            let Some(previous) = index.checked_sub(1) else { return false };
            index = previous;
            crate::steps::count(1);
            match text[index] {
                b'\t' | b'\n' | b'\r' => continue,
                byte if byte.to_ascii_lowercase() == letter => break,
                _ => return false,
            }
        }
    }
    true
}

/// XSS: a `javascript:` or `vbscript:` scheme with tabs or line breaks among its letters
/// (`jav&#x09;ascript:`), which browsers remove from a URL. Meant for the decoded form,
/// before folding turns them into spaces; the plain schemes are strong signatures.
pub(crate) fn split_script_scheme(text: &[u8]) -> Option<Violation> {
    let mut position = 0;
    while let Some(colon) = find_byte(text, position, b':') {
        position = colon + 1;
        if scheme_ends_at(text, colon, b"javascript") {
            return Some(Violation::new(AttackCategory::Xss, "javascript:"));
        }
        if scheme_ends_at(text, colon, b"vbscript") {
            return Some(Violation::new(AttackCategory::Xss, "vbscript:"));
        }
    }
    None
}

/// True when `text`, after spaces and tabs, starts with a shell command name that is not
/// followed by a word byte.
fn starts_with_shell_command(text: &[u8]) -> bool {
    let start = skip_spaces(text, 0);
    crate::steps::count(start as u64);
    let rest = &text[start..];
    let Some(&first) = rest.first() else { return false };
    let first = first.to_ascii_lowercase();
    SHELL_COMMANDS.iter().filter(|command| command.as_bytes()[0] == first).any(|command| {
        let command = command.as_bytes();
        starts_with_ignore_case(rest, command)
            && rest.get(command.len()).is_none_or(|&next| !is_word_byte(next))
    })
}

/// Command injection: a shell separator (`;`, `|`, `||`, `&`, `&&`, `$(`, backtick, LF)
/// followed by a known command name. A bare `;` or `|` is punctuation; `;wget` is not.
pub(crate) fn rce(text: &[u8], classes: Classes) -> Option<Violation> {
    if !classes.shell() {
        return None;
    }
    for (index, &byte) in text.iter().enumerate() {
        let next = text.get(index + 1).copied();
        let after = match (byte, next) {
            (b'$', Some(b'(')) | (b'&', Some(b'&')) | (b'|', Some(b'|')) => index + 2,
            (b';' | b'|' | b'`' | b'\n' | b'&', _) => index + 1,
            _ => continue,
        };
        if after < text.len() && starts_with_shell_command(&text[after..]) {
            return Some(Violation::new(AttackCategory::Rce, "shell-separator"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::classes::scan;

    #[test]
    fn keyword_table_and_lookup_agree() {
        for keyword in crate::waf::tables::SQL_KEYWORDS {
            assert_eq!(keyword_name(keyword.as_bytes()), Some(keyword));
        }
        assert_eq!(keyword_name(b"selects"), None);
    }

    #[test]
    fn tautology_needs_literals_on_both_sides() {
        assert!(sqli(b"id=1 or 1=1", scan(b"id=1 or 1=1")).is_some());
        assert!(sqli(b"id=5 or b=2", scan(b"id=5 or b=2")).is_none());
        assert!(sqli(b"x or '1' = \"1\"", scan(b"x or '1' = \"1\"")).is_some());
        assert!(sqli(b"x or'1'='1'", scan(b"x or'1'='1'")).is_none());
    }

    #[test]
    fn event_handler_needs_attribute_position() {
        assert!(has_event_handler(b"<img src=x onerror=alert(1)>"));
        assert!(has_event_handler(b"<svg/onload=x>"));
        assert!(!has_event_handler(b"onboarding=1"));
        assert!(!has_event_handler(b"x on=1"));
        assert!(!has_event_handler(b"x ON1=1"));
        assert!(!has_event_handler(b"onX=1"));
        assert!(has_event_handler(b"'onX="));
        assert!(!has_event_handler(b"'onX"));
        assert!(has_event_handler(b"<img src=1 onerror =alert(1)>"));
        assert!(has_event_handler(b"<img\nonerror\t\n=alert(1)>"));
        assert!(!has_event_handler(b"x onerror alert"));
    }

    #[test]
    fn any_tag_with_an_event_handler_inside_it_is_xss() {
        let found = |text: &[u8]| xss(text, scan(text)).is_some();
        assert!(found(b"<x onclick=alert(1)>"));
        assert!(found(b"<custom-el onfocus = alert(1) autofocus>"));
        assert!(found(b"<x title='<' onclick=alert(1)>"));
        assert!(!found(b"<b>bold</b> onboarding=1"));
        assert!(!found(b"a < b onclick"));
        assert!(!found(b"if a<3 then x onclick=1"));
    }

    #[test]
    fn split_script_schemes_are_found_in_decoded_text() {
        assert!(split_script_scheme(b"<a href=jav\tascript:alert(1)>").is_some());
        assert!(split_script_scheme(b"j\na\rv\tascript:x").is_some());
        assert!(split_script_scheme(b"VB\tScript:msgbox").is_some());
        assert!(split_script_scheme(b"java script:x").is_none());
        assert!(split_script_scheme(b"https://example.com:443/script:").is_none());
    }

    #[test]
    fn comparison_tautologies_and_parenthesised_union_select_are_sqli() {
        let found = |text: &[u8]| sqli(text, scan(text)).is_some();
        assert!(found(b"id=1 or 2>1"));
        assert!(found(b"1 or 2 > 1"));
        assert!(found(b"x' or 'b'<>'a'"));
        assert!(found(b"id=1 or 1 != 2"));
        assert!(!found(b"x or y>1"));
        assert!(found(b"1 union(select password from users)"));
        assert!(found(b"1 UNION ALL ((SELECT 1"));
        assert!(found(b"1 union distinct (select 1"));
        assert!(!found(b"European Union (selected members)"));
        assert!(!found(b"labour union (see select committee)"));
        assert!(!found(b"Mozilla/5.0 (X11; Linux x86_64)"));
    }
}
