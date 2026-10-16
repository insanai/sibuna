//! Declarative policy rules: actions, proof-of-work algorithms, header, CIDR and JA4
//! matchers, and the pattern grammar shared by paths, user agents and header values.
//!
//! A rule is a conjunction of optional criteria. Its action is ALLOW, DENY, CHALLENGE or
//! WEIGH; a challenge may override the difficulty and the algorithm, and a WEIGH rule adds a
//! signed weight to the request's score instead of deciding.

use std::fmt;

use sibuna_cidr::Prefix;

use crate::ja4;
use crate::limits::Limits;
use crate::request::RequestView;

/// Most header matchers one rule may hold.
pub const MAX_RULE_HEADERS: usize = 4;
/// Most CIDR matchers one rule may hold.
pub const MAX_RULE_CIDRS: usize = 8;

/// What a rule (or the engine) decides for a request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Action {
    /// Forward the request.
    #[default]
    Allow,
    /// Refuse the request.
    Deny,
    /// Demand a proof of work first.
    Challenge,
    /// Add the rule's weight to the score and continue (rules only).
    Weigh,
}

impl Action {
    /// Every action, in the order of their numeric tags (0 to 3).
    pub const ALL: [Action; 4] = [Action::Allow, Action::Deny, Action::Challenge, Action::Weigh];

    /// Parses an action name without regard to ASCII case (`DENY`, `deny`, `Deny`).
    ///
    /// Returns `None` for any other text.
    pub fn parse(text: &[u8]) -> Option<Action> {
        Action::ALL.into_iter().find(|action| text.eq_ignore_ascii_case(action.name().as_bytes()))
    }

    /// Returns the lowercase name of the action.
    pub fn name(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Challenge => "challenge",
            Action::Weigh => "weigh",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Proof-of-work mechanism a challenge rule may select; `None` inherits the daemon default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// SHA-256 hashcash.
    Hashcash,
    /// Cohen-Pietrzak proof of sequential work.
    Posw,
}

impl Algorithm {
    /// Every algorithm, in the order of their numeric tags (0 and 1).
    pub const ALL: [Algorithm; 2] = [Algorithm::Hashcash, Algorithm::Posw];

    /// Parses `hashcash` (or its alias `sha256`) or `posw` without regard to ASCII case.
    ///
    /// Returns `None` for any other text.
    pub fn parse(text: &[u8]) -> Option<Algorithm> {
        if text.eq_ignore_ascii_case(b"hashcash") || text.eq_ignore_ascii_case(b"sha256") {
            return Some(Algorithm::Hashcash);
        }
        if text.eq_ignore_ascii_case(b"posw") {
            return Some(Algorithm::Posw);
        }
        None
    }

    /// Returns the lowercase name of the algorithm.
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Hashcash => "hashcash",
            Algorithm::Posw => "posw",
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One request header as the engine sees it; both slices borrow the request buffer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header<'a> {
    /// The field name as sent; compared without regard to ASCII case.
    pub name: &'a [u8],
    /// The field value.
    pub value: &'a [u8],
}

/// A header criterion: the first request header named `name` must match `pattern`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderMatcher {
    /// The header name, compared without regard to ASCII case.
    pub name: String,
    /// A pattern in the grammar of `pattern_matches`, applied to the header value.
    pub pattern: String,
}

impl HeaderMatcher {
    /// Returns true when the first header in `headers` named like this matcher has a value
    /// that matches the pattern. Later headers of the same name are not consulted, and a
    /// missing header never matches.
    pub fn matches(&self, headers: &[Header<'_>]) -> bool {
        headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(self.name.as_bytes()))
            .is_some_and(|header| pattern_matches(self.pattern.as_bytes(), header.value))
    }
}

/// One declarative rule. Every present criterion must match (a conjunction); absent criteria
/// match anything.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyRule {
    /// The rule's name, reported in decisions: 1 to 128 bytes without control bytes.
    pub name: String,
    /// The rule's action.
    pub action: Action,
    /// Path pattern (see `pattern_matches`), if any.
    pub path_pattern: Option<String>,
    /// User-Agent pattern, if any.
    pub ua_pattern: Option<String>,
    /// Header criteria, at most `MAX_RULE_HEADERS`.
    pub headers: Vec<HeaderMatcher>,
    /// Client address criteria, at most `MAX_RULE_CIDRS`; the client must lie in one.
    pub cidrs: Vec<Prefix>,
    /// JA4 fingerprint criterion (SID 0014), if any; a request without a fingerprint never
    /// matches it.
    pub ja4: Option<ja4::Pattern>,
    /// Challenge difficulty override in work bits.
    pub difficulty: Option<u32>,
    /// Challenge algorithm override.
    pub algorithm: Option<Algorithm>,
    /// Score contributed by a WEIGH rule; negative values vouch for a client.
    pub weight: i32,
    /// Request quota attached to a terminal rule.
    pub limits: Option<Limits>,
    /// Stable identity of a managed rule (see `limits::managed_identity`); 0 means the
    /// engine derives one from the name and position, as for file rules.
    pub limit_identity: u64,
    /// The quota's bucket scope; the engine computes it when the rule is added with limits.
    pub limit_scope: u64,
}

impl PolicyRule {
    /// Returns a rule named `name` with `action` and no criteria.
    pub fn new(name: &str, action: Action) -> PolicyRule {
        PolicyRule { name: name.to_owned(), action, ..PolicyRule::default() }
    }

    /// Returns true when every criterion of the rule matches `request`. A client that is
    /// not an address ([`RequestView::address`]) matches no CIDR criterion.
    ///
    /// The engine evaluates compiled forms of these criteria with the same results; this
    /// direct form serves management checks and tests.
    pub fn matches(&self, request: &RequestView<'_>) -> bool {
        if let Some(pattern) = &self.path_pattern
            && !pattern_matches(pattern.as_bytes(), request.path)
        {
            return false;
        }
        if let Some(pattern) = &self.ua_pattern
            && !pattern_matches(pattern.as_bytes(), request.user_agent)
        {
            return false;
        }
        if !self.headers.iter().all(|matcher| matcher.matches(request.headers)) {
            return false;
        }
        if self.ja4.as_ref().is_some_and(|pattern| !pattern.matches(request.ja4)) {
            return false;
        }
        if self.cidrs.is_empty() {
            return true;
        }
        match request.address() {
            Some(address) => self.cidrs.iter().any(|prefix| prefix.contains(address)),
            None => false,
        }
    }
}

/// Matches `text` against a rule pattern.
///
/// The grammar: an empty pattern, `.*` or `*` match anything; `^...$` anchors an exact match
/// (and `^...*$` a prefix); a trailing `*`, `/*` or `.*` is a prefix match; a pattern that
/// starts with `/` is an exact path; anything else is a substring that ignores ASCII case,
/// the common form for user-agent rules. Exact and prefix matches respect case.
pub fn pattern_matches(pattern: &[u8], text: &[u8]) -> bool {
    if pattern.is_empty() || pattern == b".*" || pattern == b"*" {
        return true;
    }
    if let [b'^', inner @ .., b'$'] = pattern {
        if inner.ends_with(b"*") {
            return prefix_wildcard_matches(inner, text);
        }
        return inner == text;
    }
    prefix_wildcard_matches(pattern, text)
}

fn prefix_wildcard_matches(pattern: &[u8], text: &[u8]) -> bool {
    if let Some(prefix) = pattern.strip_suffix(b".*") {
        return text.starts_with(prefix);
    }
    if let Some(prefix) = pattern.strip_suffix(b"*") {
        return text.starts_with(prefix);
    }
    if pattern.starts_with(b"/") {
        return pattern == text;
    }
    contains_ignore_case(text, pattern)
}

/// Returns true when `needle` occurs in `haystack` without regard to ASCII case. An empty
/// needle occurs everywhere.
pub(crate) fn contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack.windows(needle.len()).any(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_pattern_matches_paths_uas_and_wildcards() {
        assert!(pattern_matches(b".*", b"anything"));
        assert!(pattern_matches(b"^bot$", b"bot"));
        assert!(!pattern_matches(b"^bot$", b"robot"));
        assert!(pattern_matches(b"^/favicon.ico$", b"/favicon.ico"));
        assert!(!pattern_matches(b"^/favicon.ico$", b"/favicon.ico2"));
        assert!(pattern_matches(b"^/.well-known/.*$", b"/.well-known/acme"));
        assert!(pattern_matches(b"/api/*", b"/api/v1/users"));
        assert!(pattern_matches(b"Amazonbot", b"Mozilla/5.0 Amazonbot/0.1"));
        assert!(!pattern_matches(b"Amazonbot", b"Mozilla/5.0 Chrome/120.0"));
    }

    #[test]
    fn pattern_edge_forms_follow_the_grammar() {
        assert!(pattern_matches(b"", b"x"));
        assert!(pattern_matches(b"^$", b""));
        assert!(!pattern_matches(b"^$", b"x"));
        assert!(pattern_matches(b"^*$", b"anything"));
        assert!(pattern_matches(b"^", b"a^b"));
        assert!(!pattern_matches(b"/Api/*", b"/api/x"));
        assert!(pattern_matches(b"mozilla", b"MOZILLA/5.0"));
    }

    fn from(client_ip: &[u8]) -> RequestView<'_> {
        RequestView::new(b"/", client_ip, b"")
    }

    #[test]
    fn cidr_matcher_verifies_ipv4_and_ipv6_subnets() {
        let mut rule = PolicyRule::new("net", Action::Allow);
        rule.cidrs.push(sibuna_cidr::parse_cidr(b"192.168.1.0/24").unwrap());
        assert!(rule.matches(&from(b"192.168.1.50")));
        assert!(!rule.matches(&from(b"192.168.2.1")));
        rule.cidrs = vec![sibuna_cidr::parse_cidr(b"2a02:1234::/32").unwrap()];
        assert!(rule.matches(&from(b"2a02:1234:5::9")));
        assert!(!rule.matches(&from(b"2a02:1235::1")));
        assert!(!rule.matches(&from(b"192.168.1.50")));
        assert!(!rule.matches(&from(b"bogus")));
        assert!(sibuna_cidr::parse_cidr(b"bogus").is_err());
    }

    #[test]
    fn ja4_criterion_needs_a_matching_fingerprint() {
        let rule = PolicyRule {
            ja4: ja4::Pattern::parse(b"t13d*"),
            ..PolicyRule::new("tls13", Action::Deny)
        };
        let chrome = ja4::Fingerprint::parse(b"t13d1516h2_8daaf6152771_02713d6af862");
        let old = ja4::Fingerprint::parse(b"t12d1516h2_8daaf6152771_02713d6af862");
        assert!(rule.matches(&RequestView { ja4: chrome, ..from(b"192.0.2.1") }));
        assert!(!rule.matches(&RequestView { ja4: old, ..from(b"192.0.2.1") }));
        assert!(!rule.matches(&from(b"192.0.2.1")), "no fingerprint matches no criterion");
    }

    #[test]
    fn policy_rule_multi_criteria_conjunction() {
        let rule = PolicyRule {
            path_pattern: Some("/api/*".into()),
            ua_pattern: Some("curl".into()),
            headers: vec![HeaderMatcher { name: "x-token".into(), pattern: "test".into() }],
            difficulty: Some(8),
            ..PolicyRule::new("protect-api", Action::Challenge)
        };
        let ok = [Header { name: b"X-Token", value: b"test-123" }];
        let bad = [Header { name: b"X-Token", value: b"wrong" }];
        let request = |path, headers| RequestView {
            headers,
            ..RequestView::new(path, b"1.1.1.1", b"curl/8.0")
        };
        assert!(rule.matches(&request(b"/api/data", &ok)));
        assert!(!rule.matches(&request(b"/api/data", &bad)));
        assert!(!rule.matches(&request(b"/home", &ok)));
    }

    #[test]
    fn header_matcher_consults_only_the_first_header_of_a_name() {
        let matcher = HeaderMatcher { name: "x-a".into(), pattern: "^yes$".into() };
        let first_no =
            [Header { name: b"X-A", value: b"no" }, Header { name: b"x-a", value: b"yes" }];
        assert!(!matcher.matches(&first_no));
        assert!(!matcher.matches(&[]));
    }

    #[test]
    fn action_and_algorithm_names_parse_without_case() {
        assert_eq!(Action::parse(b"DENY"), Some(Action::Deny));
        assert_eq!(Action::parse(b"Weigh"), Some(Action::Weigh));
        assert_eq!(Action::parse(b"DNEY"), None);
        assert_eq!(Algorithm::parse(b"SHA256"), Some(Algorithm::Hashcash));
        assert_eq!(Algorithm::parse(b"PoSW"), Some(Algorithm::Posw));
        assert_eq!(Algorithm::parse(b"argon2"), None);
        assert_eq!(Action::Challenge.to_string(), "challenge");
    }
}
