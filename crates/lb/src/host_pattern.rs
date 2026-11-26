//! Host patterns of HTTP routes and SNI rules (SID 0036): an exact host name or a
//! wildcard `*.SUFFIX`, the matcher, and the coverage relation of the configuration check.
//!
//! A wildcard matches every name under its suffix, at any depth, and never the suffix
//! itself. It is kept as the suffix with its leading dot, so a match is one comparison of
//! the end of the host. `docs/sid/assets/host-wildcards.lean` proves that this comparison
//! is the definition, and that what [`HostPattern::covers`] reports is sound.

use std::fmt;
use std::io;

use sibuna_json::Value;

use crate::config::invalid;
use crate::hello::valid_host;

/// The most patterns in one `hosts` list.
pub(crate) const MAX_HOSTS: usize = 16;
/// The longest pattern, a wildcard with its `*.` included, as long as a host name.
const MAX_NAME: usize = 253;

/// An exact host name or a wildcard, in lower case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HostPattern {
    /// Matches this name, without regard to ASCII case.
    Exact(Box<str>),
    /// Matches a name that ends with this suffix, which begins with a dot, and is longer.
    Wild(Box<str>),
}

impl HostPattern {
    /// Reads the pattern `text` of the field `path`.
    ///
    /// # Errors
    ///
    /// `InvalidData` with a hint when `text` is neither a host name nor a wildcard of a
    /// leading `*.` label before a host name whose last label is not all digits.
    pub(crate) fn parse(text: &str, path: &str) -> io::Result<Self> {
        let lower = text.to_ascii_lowercase();
        if lower == "*" {
            return Err(invalid(format!(
                "{path}: `*` alone is not a host. Hint: a route without `host` matches \
                 every host and a frontend's default pool takes every server name; to match \
                 the names under a domain, write a wildcard such as `*.example.org`."
            )));
        }
        if let Some(suffix) = lower.strip_prefix("*.")
            && !suffix.contains('*')
            && valid_host(suffix)
            && lower.len() <= MAX_NAME
        {
            if ends_in_number(suffix) {
                return Err(invalid(format!(
                    "{path}: `{text}` ends in a number, so it could only match IP addresses. \
                     Hint: a wildcard names a domain, such as `*.example.org`; route an \
                     address with its exact text."
                )));
            }
            return Ok(Self::Wild(format!(".{suffix}").into()));
        }
        if !lower.contains('*') && valid_host(&lower) {
            return Ok(Self::Exact(lower.into()));
        }
        Err(invalid(format!("{path}: `{text}` is not a host name or a wildcard.{}", hint(&lower))))
    }

    /// Reads the `host` or the `hosts` of `path`, at most one of the two. `hosts` holds 1
    /// to [`MAX_HOSTS`] patterns, none twice and none that another one covers when either
    /// is a wildcard. Returns `None` when neither is present.
    ///
    /// # Errors
    ///
    /// `InvalidData` for both fields, an empty, long or repeating list, and a pattern
    /// that [`HostPattern::parse`] refuses.
    pub(crate) fn parse_hosts(
        host: Option<&str>,
        hosts: Option<&[Value<'_>]>,
        path: &str,
    ) -> io::Result<Option<Box<[Self]>>> {
        match (host, hosts) {
            (None, None) => Ok(None),
            (Some(_), Some(_)) => Err(invalid(format!(
                "{path}: give `host` or `hosts`, not both. Hint: put every name in `hosts`."
            ))),
            (Some(text), None) => {
                Ok(Some(Box::new([Self::parse(text, &format!("{path}.host"))?])))
            }
            (None, Some(items)) => list(items, &format!("{path}.hosts")).map(Some),
        }
    }

    /// True when `host` matches. `host` is a request host without port and trailing dot,
    /// or the server name of a ClientHello. An empty host matches no pattern.
    pub(crate) fn matches(&self, host: &[u8]) -> bool {
        match self {
            Self::Exact(name) => host.eq_ignore_ascii_case(name.as_bytes()),
            Self::Wild(suffix) => {
                let suffix = suffix.as_bytes();
                host.len() > suffix.len()
                    && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
            }
        }
    }

    /// True when `self` matches every host that `other` matches.
    pub(crate) fn covers(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Exact(name), Self::Exact(other)) => name == other,
            (Self::Exact(_), Self::Wild(_)) => false,
            (Self::Wild(_), Self::Exact(name)) => self.matches(name.as_bytes()),
            // `*.t` lies under `*.s` when `t` is `s` or a name under `s`.
            (Self::Wild(suffix), Self::Wild(other)) => {
                suffix == other || self.matches(other[1..].as_bytes())
            }
        }
    }

    /// True for a wildcard.
    pub(crate) fn is_wild(&self) -> bool {
        matches!(self, Self::Wild(_))
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(name) => f.write_str(name),
            Self::Wild(suffix) => write!(f, "*{suffix}"),
        }
    }
}

/// True when some pattern of `patterns` matches `host`. `None` matches every host.
pub(crate) fn any_matches(patterns: Option<&[HostPattern]>, host: &[u8]) -> bool {
    patterns.is_none_or(|patterns| patterns.iter().any(|pattern| pattern.matches(host)))
}

/// The pattern of `covering` that covers `pattern`, where one of the two is a wildcard.
/// `None` for `covering` stands for every host, which covers a wildcard here.
pub(crate) fn hiding<'a>(
    covering: Option<&'a [HostPattern]>,
    pattern: &HostPattern,
) -> Option<Option<&'a HostPattern>> {
    let Some(covering) = covering else { return pattern.is_wild().then_some(None) };
    covering
        .iter()
        .find(|earlier| (earlier.is_wild() || pattern.is_wild()) && earlier.covers(pattern))
        .map(Some)
}

fn list(items: &[Value<'_>], path: &str) -> io::Result<Box<[HostPattern]>> {
    if !(1..=MAX_HOSTS).contains(&items.len()) {
        return Err(invalid(format!(
            "{path}: expected 1 to {MAX_HOSTS} host patterns. Hint: split a longer list over \
             several routes to the same backend."
        )));
    }
    let mut patterns: Vec<HostPattern> = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let at = format!("{path}[{index}]");
        let text = item.as_str().ok_or_else(|| invalid(format!("{at}: expected a string")))?;
        let pattern = HostPattern::parse(text, &at)?;
        if let Some(earlier) = patterns.iter().find(|earlier| {
            **earlier == pattern
                || ((earlier.is_wild() || pattern.is_wild()) && covers(earlier, &pattern))
        }) {
            return Err(invalid(format!(
                "{at}: `{pattern}` and `{earlier}` in the same list overlap: one matches \
                 every name that the other matches. Hint: keep the one that covers the other."
            )));
        }
        patterns.push(pattern);
    }
    Ok(patterns.into_boxed_slice())
}

/// True when the last label of `name` is all digits, which no top-level domain is.
fn ends_in_number(name: &str) -> bool {
    name.rsplit('.').next().is_some_and(|last| last.bytes().all(|b| b.is_ascii_digit()))
}

/// True when either pattern covers the other.
fn covers(a: &HostPattern, b: &HostPattern) -> bool {
    a.covers(b) || b.covers(a)
}

/// The hint of a malformed pattern, with a suggestion: `*.` and the labels after the last
/// label that holds a `*`, when they make a host name.
fn hint(lower: &str) -> String {
    let mut text = String::from(
        " Hint: a wildcard is one leading `*.` before a host name, such as `*.example.org`; \
         it matches every name under example.org and not example.org itself.",
    );
    let labels: Vec<&str> = lower.split('.').collect();
    if let Some(last) = labels.iter().rposition(|label| label.contains('*')) {
        let rest = labels[last + 1..].join(".");
        if valid_host(&rest) && !ends_in_number(&rest) && rest.len() + 2 <= MAX_NAME {
            text.push_str(&format!(" Did you mean `*.{rest}`?"));
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(text: &str) -> HostPattern {
        HostPattern::parse(text, "routes[0].host").unwrap()
    }

    fn refusal(text: &str) -> String {
        HostPattern::parse(text, "routes[0].host").unwrap_err().to_string()
    }

    #[test]
    fn a_wildcard_matches_names_under_its_domain_at_any_depth_and_not_the_domain() {
        let wild = pattern("*.Example.org");
        assert_eq!(wild, HostPattern::Wild(".example.org".into()));
        assert!(wild.matches(b"a.example.org"));
        assert!(wild.matches(b"A.B.EXAMPLE.org"));
        assert!(!wild.matches(b"example.org"));
        assert!(!wild.matches(b".example.org"));
        assert!(!wild.matches(b"badexample.org"));
        assert!(!wild.matches(b"a.example.org.evil.net"));
        assert!(!wild.matches(b""));
        assert!(!wild.matches(b"[2001:db8::1]"));
        let exact = pattern("API.example.org");
        assert!(exact.matches(b"api.EXAMPLE.org"));
        assert!(!exact.matches(b"x.api.example.org"));
        assert!(pattern("*.org").matches(b"example.org"));
        assert!(pattern("192.0.2.7").matches(b"192.0.2.7"));
    }

    #[test]
    fn malformed_wildcards_are_refused_with_a_hint_and_a_suggestion() {
        let alone = refusal("*");
        assert!(alone.contains("a route without `host` matches"), "{alone}");
        for text in ["*api.example.org", "api.*.example.org", "**.example.org"] {
            let message = refusal(text);
            assert!(message.contains("Hint: a wildcard is one leading"), "{message}");
            assert!(message.contains("Did you mean `*.example.org`?"), "{message}");
        }
        assert!(!refusal("*.org.*").contains("Did you mean"));
        assert!(refusal("foo*.org").contains("Did you mean `*.org`?"));
        assert!(!refusal("x*.0.2.7").contains("Did you mean"));
        let numeric = refusal("*.0.2.7");
        assert!(numeric.contains("ends in a number"), "{numeric}");
        assert!(refusal("*.example.org.").contains("not a host name"));
        assert!(refusal("*.-bad.org").contains("not a host name"));
        assert!(refusal("bücher.example").contains("not a host name"));
        // A name of 253 characters is valid alone and too long behind `*.`.
        let name =
            format!("{}.{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61));
        assert_eq!(name.len(), 253);
        assert!(HostPattern::parse(&name, "host").is_ok());
        assert!(refusal(&format!("*.{name}")).contains("not a host name"));
        let shorter = &name[2..];
        assert!(HostPattern::parse(&format!("*.{shorter}"), "host").is_ok());
    }

    #[test]
    fn coverage_follows_the_definition() {
        let (wild, deeper) = (pattern("*.example.org"), pattern("*.a.example.org"));
        let (name, apex) = (pattern("b.a.example.org"), pattern("example.org"));
        assert!(wild.covers(&wild));
        assert!(wild.covers(&deeper));
        assert!(!deeper.covers(&wild));
        assert!(wild.covers(&name) && deeper.covers(&name));
        assert!(!wild.covers(&apex));
        assert!(!name.covers(&deeper));
        assert!(apex.covers(&apex));
        assert!(!pattern("*.bexample.org").covers(&pattern("*.example.org")));
        assert!(!pattern("*.example.org").covers(&pattern("*.badexample.org")));
    }

    #[test]
    fn a_host_list_refuses_repeats_and_patterns_its_wildcards_cover() {
        let parse = |json: &str| {
            let value = sibuna_json::parse(json.as_bytes()).unwrap();
            HostPattern::parse_hosts(None, value.as_array(), "routes[0]").map(|h| h.unwrap())
        };
        let hosts = parse(r#"["*.example.org", "example.org"]"#).unwrap();
        assert!(any_matches(Some(&hosts), b"example.org"));
        assert!(any_matches(Some(&hosts), b"x.example.org"));
        assert!(!any_matches(Some(&hosts), b"example.net"));
        assert!(any_matches(None, b"anything"));
        for json in [
            r#"[]"#,
            r#"["a.org", "A.org"]"#,
            r#"["*.example.org", "a.example.org"]"#,
            r#"["a.example.org", "*.example.org"]"#,
            r#"["*.a.example.org", "*.example.org"]"#,
        ] {
            assert!(parse(json).is_err(), "{json}");
        }
        let many = format!(
            "[{}]",
            (0..17).map(|i| format!("\"h{i}.org\"")).collect::<Vec<_>>().join(",")
        );
        assert!(parse(&many).unwrap_err().to_string().contains("1 to 16"));
        let both = HostPattern::parse_hosts(Some("a.org"), Some(&[]), "routes[0]");
        assert!(both.unwrap_err().to_string().contains("not both"));
    }

    #[test]
    fn hiding_needs_a_wildcard_on_one_side() {
        let earlier = [pattern("*.example.org")];
        assert!(hiding(Some(&earlier), &pattern("a.example.org")).is_some());
        assert!(hiding(Some(&earlier), &pattern("example.org")).is_none());
        let exact = [pattern("a.example.org")];
        assert!(hiding(Some(&exact), &pattern("a.example.org")).is_none());
        assert_eq!(hiding(None, &pattern("*.example.org")), Some(None));
        assert_eq!(hiding(None, &pattern("a.example.org")), None);
    }
}
