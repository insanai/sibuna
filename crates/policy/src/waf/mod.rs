//! The semantic web application firewall: zero-allocation inspection of paths, queries,
//! headers and bodies for SQL injection, cross-site scripting, path traversal and command
//! injection.
//!
//! Detection is contextual rather than a flat substring list: a lone SQL comment marker or
//! `alert(` never fires on its own, because those bytes appear in ordinary browser traffic
//! (`Accept: */*`, JavaScript bodies). Each category combines strong signatures, one hit of
//! which suffices, with structural detectors that need co-occurring evidence.
//!
//! A field is inspected as received and then, when the byte classes show it could change,
//! canonicalised (see `normalizer::canonicalize`) and inspected again. Every field the
//! daemon hands over is canonicalised whole: header values up to the 16 KiB head bound,
//! body fields within the 8 KiB body prefix. On the way, the decoded form (before
//! whitespace folding) is searched for a line feed that separates shell commands and for a
//! `javascript:` scheme split by tabs or line breaks.
//!
//! Deliberate changes from Zig, each with a regression test:
//!
//! - Zig canonicalised into an 8 KiB stack buffer and inspected a longer field raw only, so
//!   a header, query or cookie padded beyond 8 KiB could hide a percent-encoded payload.
//!   Fields longer than 2 KiB are now canonicalised in a 16 KiB buffer that each thread
//!   allocates once and reuses.
//! - Zig folded a decoded `%0a` into a space before the command-injection detector saw it.
//! - Canonicalisation also decodes JSON string escapes and HTML character references, and
//!   keeps the text of MySQL executable comments (`/*!50000select*/`).
//! - The detectors also find `onerror =` (white space before `=`), an event handler on a
//!   tag of any name, tautologies with `<`, `>`, `<>` and `!=` (`or 2>1`), and `union` and
//!   `select` joined by parentheses (`union(select`).

mod canonical;
mod classes;
mod structure;
mod tables;

use std::fmt;

use sibuna_patterns::{Automaton, Options};

use crate::body_fields::{self, Fields};
use crate::request::RequestView;
use canonical::{Canonical, Decoded, with_canonical};
use classes::{Classes, scan};

pub use body_fields::MAX_PREFIX as MAX_BODY_INSPECT;

/// Longest field whose canonical form is inspected whole: the daemon's request head bound
/// (16 KiB), so no path, query or header value escapes the second pass. Body fields come
/// from the `MAX_BODY_INSPECT` prefix and are shorter. Of a longer field, which only other
/// callers can pass, the first `MAX_CANONICAL` bytes of the canonical form are inspected.
pub const MAX_CANONICAL: usize = 16 * 1024;

/// The attack categories, in the order mixed-mode inspection visits them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttackCategory {
    /// Path traversal, local file inclusion and NUL truncation.
    PathTraversal,
    /// SQL injection.
    Sqli,
    /// Cross-site scripting.
    Xss,
    /// Command and template injection.
    Rce,
}

impl AttackCategory {
    /// Every category in inspection order.
    pub const ALL: [AttackCategory; 4] = [
        AttackCategory::PathTraversal,
        AttackCategory::Sqli,
        AttackCategory::Xss,
        AttackCategory::Rce,
    ];

    /// Returns the category's position in `ALL` (0 to 3), also its signature tag.
    pub fn index(self) -> usize {
        self as usize
    }

    /// Returns the category name: `path_traversal`, `sqli`, `xss` or `rce`.
    pub fn name(self) -> &'static str {
        match self {
            AttackCategory::PathTraversal => "path_traversal",
            AttackCategory::Sqli => "sqli",
            AttackCategory::Xss => "xss",
            AttackCategory::Rce => "rce",
        }
    }

    /// Returns the rule name a denial carries: `waf:path-traversal`, `waf:sqli`, `waf:xss`
    /// or `waf:rce`.
    pub fn rule_name(self) -> &'static str {
        match self {
            AttackCategory::PathTraversal => "waf:path-traversal",
            AttackCategory::Sqli => "waf:sqli",
            AttackCategory::Xss => "waf:xss",
            AttackCategory::Rce => "waf:rce",
        }
    }
}

impl fmt::Display for AttackCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One finding: the category and the signature or structural rule that fired.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Violation {
    /// The attack category.
    pub category: AttackCategory,
    /// The signature as listed (`union select`), or the structural rule (`tautology`,
    /// `'--`, a keyword, `on*=`, `shell-separator`, `%00`).
    pub pattern: &'static str,
}

impl Violation {
    pub(crate) fn new(category: AttackCategory, pattern: &'static str) -> Violation {
        Violation { category, pattern }
    }

    /// Returns the rule name of the category, as in `AttackCategory::rule_name`.
    pub fn rule_name(self) -> &'static str {
        self.category.rule_name()
    }
}

/// Returns the signature table of `category`.
fn table(category: AttackCategory) -> &'static [&'static str] {
    match category {
        AttackCategory::PathTraversal => &tables::TRAVERSAL,
        AttackCategory::Sqli => &tables::SQLI,
        AttackCategory::Xss => &tables::XSS,
        AttackCategory::Rce => &tables::RCE,
    }
}

/// All strong signatures of every category in one case-insensitive automaton, so a field is
/// scanned once whatever the number of signatures. Immutable once built; build it once and
/// share it.
#[derive(Clone, Debug)]
pub struct Signatures {
    automaton: Automaton,
}

impl Default for Signatures {
    fn default() -> Signatures {
        Signatures::new()
    }
}

impl Signatures {
    /// Builds the automaton from the built-in tables. Pattern ids follow the tables in
    /// category order, so a match maps back to its static signature.
    pub fn new() -> Signatures {
        let pairs = AttackCategory::ALL.into_iter().flat_map(|category| {
            table(category).iter().map(move |pattern| (pattern.as_bytes(), category.index() as u8))
        });
        let total: usize = AttackCategory::ALL
            .iter()
            .map(|&c| table(c).iter().map(|p| p.len()).sum::<usize>())
            .sum();
        let options =
            Options { ascii_case_insensitive: true, max_states: 1 + total, max_patterns: total };
        match Automaton::from_patterns(options, pairs) {
            Ok(automaton) => Signatures { automaton },
            // The tables are constants within the capacity above; the unit tests build them.
            Err(error) => unreachable!("built-in WAF signatures do not compile: {error}"),
        }
    }

    /// Returns the heap bytes of the automaton.
    pub fn heap_bytes(&self) -> usize {
        self.automaton.heap_bytes()
    }

    fn violation(&self, index: usize) -> Option<Violation> {
        let mut index = index;
        for category in AttackCategory::ALL {
            let patterns = table(category);
            match patterns.get(index) {
                Some(pattern) => return Some(Violation::new(category, pattern)),
                None => index -= patterns.len(),
            }
        }
        None
    }

    /// The signature that ends first in `text` (the longest one ending there).
    #[inline]
    fn find_first(&self, text: &[u8]) -> Option<Violation> {
        let found = self.automaton.find_first(text)?;
        self.violation(found.pattern.index())
    }

    /// The first signature of `category` in `text`, ignoring other categories.
    fn find_first_in(&self, text: &[u8], category: AttackCategory) -> Option<Violation> {
        let found = self.automaton.find_first_tagged(text, category.index() as u8)?;
        self.violation(found.pattern.index())
    }

    /// The categories with a signature in `text`, as bits `1 << index`.
    fn categories(&self, text: &[u8]) -> u8 {
        // Tags are category indices below 4, so the set fits in the low four bits.
        (self.automaton.tags(text).bits & 0xf) as u8
    }
}

fn first_match(text: &[u8], patterns: &[&'static str]) -> Option<&'static str> {
    patterns
        .iter()
        .copied()
        .find(|pattern| crate::rule::contains_ignore_case(text, pattern.as_bytes()))
}

/// Path traversal by sequential signature search, then NUL bytes; for callers without an
/// automaton (tools, tests).
pub fn check_path_traversal(text: &[u8]) -> Option<Violation> {
    if let Some(pattern) = first_match(text, &tables::TRAVERSAL) {
        return Some(Violation::new(AttackCategory::PathTraversal, pattern));
    }
    structure::null_byte(text, scan(text))
}

/// SQL injection by sequential signature search, then the structural detector.
pub fn check_sqli(text: &[u8]) -> Option<Violation> {
    if let Some(pattern) = first_match(text, &tables::SQLI) {
        return Some(Violation::new(AttackCategory::Sqli, pattern));
    }
    structure::sqli(text, scan(text))
}

/// Cross-site scripting by sequential signature search, then the structural detector.
pub fn check_xss(text: &[u8]) -> Option<Violation> {
    if let Some(pattern) = first_match(text, &tables::XSS) {
        return Some(Violation::new(AttackCategory::Xss, pattern));
    }
    structure::xss(text, scan(text))
}

/// Command injection by sequential signature search, then the structural detector.
pub fn check_rce(text: &[u8]) -> Option<Violation> {
    if let Some(pattern) = first_match(text, &tables::RCE) {
        return Some(Violation::new(AttackCategory::Rce, pattern));
    }
    structure::rce(text, scan(text))
}

fn inspect_sequential(text: &[u8]) -> Option<Violation> {
    check_path_traversal(text)
        .or_else(|| check_sqli(text))
        .or_else(|| check_xss(text))
        .or_else(|| check_rce(text))
}

/// Inspects one field without an automaton, raw then canonicalised; for tools and tests.
pub fn inspect_text(text: &[u8]) -> Option<Violation> {
    if text.is_empty() {
        return None;
    }
    if let Some(violation) = inspect_sequential(text) {
        return Some(violation);
    }
    if !scan(text).needs_canonical() {
        return None;
    }
    with_canonical(text, |canonical: Canonical<'_>| {
        let decoded = canonical.decoded;
        inspect_sequential(canonical.text).or(decoded.xss).or(decoded.rce)
    })
}

/// The first signature in `text`, else the first structural finding in category order.
fn inspect_raw(signatures: &Signatures, text: &[u8], classes: Classes) -> Option<Violation> {
    if let Some(violation) = signatures.find_first(text) {
        return Some(violation);
    }
    structure::null_byte(text, classes)
        .or_else(|| structure::sqli(text, classes))
        .or_else(|| structure::xss(text, classes))
        .or_else(|| structure::rce(text, classes))
}

/// Inspects one field for every category: the first signature in the text, else the
/// structural detectors in category order; then the same on the canonical form when the
/// byte classes show canonicalisation can change the field (see `MAX_CANONICAL` for fields
/// longer than 16 KiB).
pub fn inspect_text_with(signatures: &Signatures, text: &[u8]) -> Option<Violation> {
    if text.is_empty() {
        return None;
    }
    let classes = scan(text);
    if let Some(violation) = inspect_raw(signatures, text, classes) {
        return Some(violation);
    }
    if !classes.needs_canonical() {
        return None;
    }
    // The decoded form's findings come last: they matter only when the canonical form
    // shows nothing. Keeping them out of `inspect_raw` keeps the raw pass, which every
    // field takes, as lean as it was.
    with_canonical(text, |canonical| {
        let decoded = canonical.decoded;
        inspect_raw(signatures, canonical.text, scan(canonical.text))
            .or(decoded.xss)
            .or(decoded.rce)
    })
}

/// The findings of one field for the categories in `wanted` (bits `1 << index`); `decoded`
/// adds what the decoded form showed (nothing for a raw field).
fn raw_findings(
    signatures: &Signatures,
    text: &[u8],
    wanted: u8,
    decoded: Decoded,
) -> [Option<Violation>; 4] {
    let classes = scan(text);
    let found = signatures.categories(text);
    let mut findings = [None; 4];
    for category in AttackCategory::ALL {
        let bit = 1 << category.index();
        if wanted & bit == 0 {
            continue;
        }
        findings[category.index()] = if found & bit != 0 {
            signatures.find_first_in(text, category)
        } else {
            structural(category, text, classes, decoded)
        };
    }
    findings
}

/// The structural finding of `category` in `text`, else the one the decoded form showed.
fn structural(
    category: AttackCategory,
    text: &[u8],
    classes: Classes,
    decoded: Decoded,
) -> Option<Violation> {
    let found = match category {
        AttackCategory::PathTraversal => structure::null_byte(text, classes),
        AttackCategory::Sqli => structure::sqli(text, classes),
        AttackCategory::Xss => structure::xss(text, classes),
        AttackCategory::Rce => structure::rce(text, classes),
    };
    found.or(decoded.finding(category))
}

/// Inspects one field for the categories in `wanted` (bits `1 << index`) separately, each
/// raw and then canonicalised, so that a finding of one category can never hide another.
/// Returns the finding of each wanted category, indexed by `AttackCategory::index`.
pub(crate) fn inspect_categories(
    signatures: &Signatures,
    text: &[u8],
    wanted: u8,
) -> [Option<Violation>; 4] {
    if text.is_empty() || wanted == 0 {
        return [None; 4];
    }
    let mut findings = raw_findings(signatures, text, wanted, Decoded::default());
    let missing = AttackCategory::ALL
        .iter()
        .filter(|c| findings[c.index()].is_none())
        .fold(0u8, |bits, c| bits | (1 << c.index()))
        & wanted;
    if missing == 0 || !scan(text).needs_canonical() {
        return findings;
    }
    let canonical = with_canonical(text, |canonical| {
        Some(raw_findings(signatures, canonical.text, missing, canonical.decoded))
    });
    if let Some(canonical) = canonical {
        for category in AttackCategory::ALL {
            if missing & (1 << category.index()) != 0 {
                findings[category.index()] = canonical[category.index()];
            }
        }
    }
    findings
}

/// Inspects one field for one category only, raw then canonicalised. Mixed inspection
/// modes use this so that an audited finding of one category cannot hide a denial.
pub fn inspect_category(
    signatures: &Signatures,
    category: AttackCategory,
    text: &[u8],
) -> Option<Violation> {
    inspect_categories(signatures, text, 1 << category.index())[category.index()]
}

/// Returns true for headers whose values are content negotiation and are never inspected
/// (`Accept`, `Content-Type`, `Sec-Fetch-*` and the like), compared without regard to case.
pub fn is_structural_header(name: &[u8]) -> bool {
    tables::STRUCTURAL_HEADERS.iter().any(|header| name.eq_ignore_ascii_case(header.as_bytes()))
}

/// Calls `visit` on each inspected field of `request` in order (path, query, User-Agent,
/// non-structural header values, body fields) until it returns `Some`.
pub(crate) fn visit_fields<R>(
    request: &RequestView<'_>,
    mut visit: impl FnMut(&[u8]) -> Option<R>,
) -> Option<R> {
    for text in [request.path, request.query, request.user_agent] {
        if let Some(result) = visit(text) {
            return Some(result);
        }
    }
    for header in request.headers {
        if is_structural_header(header.name) {
            continue;
        }
        if let Some(result) = visit(header.value) {
            return Some(result);
        }
    }
    Fields::new(request.headers, request.body).find_map(visit)
}

/// Inspects every field of `request` for every category and returns the first finding.
/// Bodies are inspected over their first 8 KiB, split into form, JSON or multipart fields
/// as `body_fields` describes; file contents stay opaque.
pub fn inspect_request(signatures: &Signatures, request: &RequestView<'_>) -> Option<Violation> {
    visit_fields(request, |text| inspect_text_with(signatures, text))
}

#[cfg(test)]
mod tests;
