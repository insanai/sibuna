//! Per-category inspection modes and the findings of one request.
//!
//! Each WAF category is enforced (a finding denies the request), audited (a finding is
//! recorded and the request continues) or disabled (its detectors never run). The modes
//! belong to an immutable engine snapshot.

use std::fmt;

use crate::request::RequestView;
use crate::waf::{self, AttackCategory, Signatures, Violation};

/// What a finding of one category does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Mode {
    /// The category's detectors do not run.
    Disabled,
    /// A finding is recorded in `Decision::audited`; the request continues.
    Audit,
    /// A finding denies the request.
    #[default]
    Enforce,
}

impl Mode {
    /// Every mode, in the order of their numeric tags (0 to 2).
    pub const ALL: [Mode; 3] = [Mode::Disabled, Mode::Audit, Mode::Enforce];

    /// Returns the mode's name: `disabled`, `audit` or `enforce`.
    pub fn name(self) -> &'static str {
        match self {
            Mode::Disabled => "disabled",
            Mode::Audit => "audit",
            Mode::Enforce => "enforce",
        }
    }

    /// Parses a mode name exactly (lower case), as stored by the daemon.
    pub fn parse(text: &[u8]) -> Option<Mode> {
        Mode::ALL.into_iter().find(|mode| mode.name().as_bytes() == text)
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The mode of each category; every category is enforced by default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Modes {
    /// Path traversal.
    pub path_traversal: Mode,
    /// SQL injection.
    pub sqli: Mode,
    /// Cross-site scripting.
    pub xss: Mode,
    /// Command injection.
    pub rce: Mode,
}

impl Modes {
    /// Returns the mode of `category`.
    pub fn mode(self, category: AttackCategory) -> Mode {
        match category {
            AttackCategory::PathTraversal => self.path_traversal,
            AttackCategory::Sqli => self.sqli,
            AttackCategory::Xss => self.xss,
            AttackCategory::Rce => self.rce,
        }
    }

    /// Returns a mutable reference to the mode of `category`.
    pub fn mode_mut(&mut self, category: AttackCategory) -> &mut Mode {
        match category {
            AttackCategory::PathTraversal => &mut self.path_traversal,
            AttackCategory::Sqli => &mut self.sqli,
            AttackCategory::Xss => &mut self.xss,
            AttackCategory::Rce => &mut self.rce,
        }
    }

    /// Returns true when every category is enforced (the single-pass fast path).
    pub fn is_all_enforcing(self) -> bool {
        AttackCategory::ALL.iter().all(|&category| self.mode(category) == Mode::Enforce)
    }

    /// Returns true when every category is disabled.
    pub fn is_all_disabled(self) -> bool {
        AttackCategory::ALL.iter().all(|&category| self.mode(category) == Mode::Disabled)
    }
}

/// What inspecting one request found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Findings {
    /// The enforced finding that denies the request, if any.
    pub denied: Option<Violation>,
    /// Audited categories with a finding, as `bit(category)` bits; at most one per
    /// category per request, whatever the number of fields.
    pub audited: u8,
}

/// Returns the bit of `category` in `Findings::audited` and `Decision::audited`.
pub fn bit(category: AttackCategory) -> u8 {
    1 << category.index()
}

/// Returns the event name of an audited finding: `audit:path-traversal`, `audit:sqli`,
/// `audit:xss` or `audit:rce`.
pub fn audit_name(category: AttackCategory) -> &'static str {
    match category {
        AttackCategory::PathTraversal => "audit:path-traversal",
        AttackCategory::Sqli => "audit:sqli",
        AttackCategory::Xss => "audit:xss",
        AttackCategory::Rce => "audit:rce",
    }
}

/// Inspects `request` under `modes`.
///
/// When every category is enforced this is one pass per field (`waf::inspect_request`).
/// Otherwise each field is inspected per category, raw and canonicalised, so that an audited
/// finding cannot hide an enforced one in the same or a later field; inspection stops at
/// the first enforced finding.
pub fn inspect(signatures: &Signatures, modes: Modes, request: &RequestView<'_>) -> Findings {
    if modes.is_all_enforcing() {
        return Findings { denied: waf::inspect_request(signatures, request), audited: 0 };
    }
    let mut findings = Findings::default();
    if modes.is_all_disabled() {
        return findings;
    }
    findings.denied = waf::visit_fields(request, |text| {
        inspect_field(signatures, modes, text, &mut findings.audited)
    });
    findings
}

/// Inspects one field for the categories that are not disabled and not yet audited, in
/// category order, and returns the first enforced finding.
fn inspect_field(
    signatures: &Signatures,
    modes: Modes,
    text: &[u8],
    audited: &mut u8,
) -> Option<Violation> {
    let wanted = AttackCategory::ALL
        .iter()
        .filter(|&&category| {
            modes.mode(category) != Mode::Disabled && *audited & bit(category) == 0
        })
        .fold(0u8, |bits, &category| bits | bit(category));
    if wanted == 0 {
        return None;
    }
    let found = waf::inspect_categories(signatures, text, wanted);
    for category in AttackCategory::ALL {
        let Some(violation) = found[category.index()] else { continue };
        match modes.mode(category) {
            Mode::Audit => *audited |= bit(category),
            Mode::Enforce => return Some(violation),
            Mode::Disabled => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::Header;

    #[test]
    fn audit_findings_do_not_hide_enforcing_categories_in_the_same_or_later_fields() {
        let signatures = Signatures::new();
        let modes =
            Modes { sqli: Mode::Audit, path_traversal: Mode::Disabled, ..Modes::default() };
        let request = RequestView {
            path: b"/",
            query: b"union select 1; %3Cscript%3E",
            ..RequestView::default()
        };
        let mixed = inspect(&signatures, modes, &request);
        assert_eq!(mixed.denied.unwrap().category, AttackCategory::Xss);
        assert_eq!(mixed.audited, bit(AttackCategory::Sqli));
        let request = RequestView {
            path: b"/../../etc/passwd",
            query: b"union select",
            body: b"; /bin/sh",
            ..RequestView::default()
        };
        let later = inspect(&signatures, modes, &request);
        assert_eq!(later.denied.unwrap().category, AttackCategory::Rce);
        assert_eq!(later.audited, bit(AttackCategory::Sqli));
        let request = RequestView { path: b"/", query: b"union select", ..RequestView::default() };
        let ignored =
            inspect(&signatures, Modes { sqli: Mode::Disabled, ..Modes::default() }, &request);
        assert_eq!(ignored, Findings::default());
    }

    #[test]
    fn mixed_category_modes_inspect_multipart_fields_after_an_opaque_file() {
        let signatures = Signatures::new();
        let body = b"--b\r\nContent-Disposition: form-data; name=\"f\"; \
            filename=\"x\"\r\n\r\nbinary\x00file\r\n--b\r\nContent-Disposition: form-data; \
            name=\"text\"\r\n\r\n1 UNION SELECT password <script>alert(1)</script>\r\n--b--\r\n";
        let headers =
            [Header { name: b"Content-Type", value: b"multipart/form-data; boundary=b" }];
        let request =
            RequestView { path: b"/upload", headers: &headers, body, ..RequestView::default() };
        let result =
            inspect(&signatures, Modes { sqli: Mode::Audit, ..Modes::default() }, &request);
        assert_eq!(result.audited, bit(AttackCategory::Sqli));
        assert_eq!(result.denied.unwrap().category, AttackCategory::Xss);
    }

    #[test]
    fn mode_names_round_trip() {
        for mode in Mode::ALL {
            assert_eq!(Mode::parse(mode.name().as_bytes()), Some(mode));
        }
        assert_eq!(Mode::parse(b"Audit"), None);
        assert_eq!(audit_name(AttackCategory::Xss), "audit:xss");
    }
}
