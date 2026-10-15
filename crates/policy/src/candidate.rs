//! A private engine composed before a management change commits: the policy file, the
//! managed documents (ordered by priority, name, id, and placed ahead of the file's rules)
//! and the reputation snapshot. No publication or storage happens here; the caller applies
//! any further settings (inspection overrides) and evaluates or publishes the result.

use std::fmt;

use crate::engine::{Engine, MAX_RULES, RuleError};
use crate::loader::{Diagnostic, LoadError};
use crate::management::{self, Document, ManagementError};
use crate::rule::Action;

/// Largest policy file a candidate accepts, in bytes.
pub const MAX_FILE_BYTES: usize = 256 * 1024;
/// Most reputation entries (the trie's node capacity).
pub const MAX_REPUTATIONS: usize = sibuna_cidr::DEFAULT_MAX_NODES as usize;

/// How to compose a candidate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options<'a> {
    /// The daemon's default difficulty.
    pub default_difficulty: u32,
    /// Whether the WAF runs (before the file's `waf` key).
    pub waf: bool,
    /// The startup policy file, if any.
    pub file: Option<&'a [u8]>,
}

/// One reputation row of the caller's revision-bound snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reputation<'a> {
    /// The address or prefix.
    pub cidr: &'a [u8],
    /// `Allow` or `Deny`.
    pub action: Action,
}

/// Why a candidate could not be composed. The names are Zig's error names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateError {
    /// More than 128 documents.
    TooManyDocuments,
    /// More reputation rows than the trie has nodes.
    TooManyReputations,
    /// A policy file above `MAX_FILE_BYTES`.
    FileTooLarge,
    /// The policy file was rejected.
    File(LoadError),
    /// A document was rejected.
    Document(ManagementError),
    /// Two documents share an id.
    DuplicateId,
    /// Enabled documents and file rules together exceed 128.
    TooManyRules,
    /// A document's rule was refused by the engine.
    Rule(RuleError),
    /// A reputation action other than `Allow` or `Deny`.
    InvalidReputationAction,
    /// A reputation prefix that does not parse.
    InvalidCidr,
    /// The reputation rows exceed the trie's capacity.
    TrieFull,
}

impl CandidateError {
    /// Returns the Zig error name.
    pub fn name(self) -> &'static str {
        match self {
            CandidateError::TooManyDocuments => "TooManyDocuments",
            CandidateError::TooManyReputations => "TooManyReputations",
            CandidateError::FileTooLarge => "FileTooLarge",
            CandidateError::File(error) => error.name(),
            CandidateError::Document(error) => error.name(),
            CandidateError::DuplicateId => "DuplicateId",
            CandidateError::TooManyRules => "TooManyRules",
            CandidateError::Rule(error) => error.name(),
            CandidateError::InvalidReputationAction => "InvalidReputationAction",
            CandidateError::InvalidCidr => "InvalidCidr",
            CandidateError::TrieFull => "TrieFull",
        }
    }
}

impl fmt::Display for CandidateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl std::error::Error for CandidateError {}

/// Composes a candidate engine: `Engine::new`, the WAF switch, the file, the enabled
/// documents ahead of the file's rules (disabled ones are still validated), then the
/// reputation rows. Every string is copied; the inputs may be released afterwards.
///
/// Fails with the first `CandidateError`.
pub fn compose(
    options: &Options<'_>,
    sources: &[&[u8]],
    reputation: &[Reputation<'_>],
) -> Result<Engine, CandidateError> {
    if sources.len() > MAX_RULES {
        return Err(CandidateError::TooManyDocuments);
    }
    if reputation.len() > MAX_REPUTATIONS {
        return Err(CandidateError::TooManyReputations);
    }
    if options.file.is_some_and(|file| file.len() > MAX_FILE_BYTES) {
        return Err(CandidateError::FileTooLarge);
    }
    let mut engine = Engine::new(options.default_difficulty);
    engine.waf_enabled = options.waf;
    if let Some(file) = options.file {
        engine.apply_json(file, &mut Diagnostic::default()).map_err(CandidateError::File)?;
    }
    insert_documents(&mut engine, sources)?;
    for entry in reputation {
        if !matches!(entry.action, Action::Allow | Action::Deny) {
            return Err(CandidateError::InvalidReputationAction);
        }
        engine.insert_reputation(entry.cidr, entry.action).map_err(|error| match error {
            sibuna_cidr::TrieError::Full => CandidateError::TrieFull,
            sibuna_cidr::TrieError::InvalidCidr(_) => CandidateError::InvalidCidr,
        })?;
    }
    Ok(engine)
}

fn insert_documents(engine: &mut Engine, sources: &[&[u8]]) -> Result<(), CandidateError> {
    let mut documents: Vec<Document> = Vec::with_capacity(sources.len());
    for source in sources {
        let document = management::parse(source).map_err(CandidateError::Document)?;
        if documents.iter().any(|previous| previous.id == document.id) {
            return Err(CandidateError::DuplicateId);
        }
        documents.push(document);
    }
    documents.sort_by(|left, right| {
        (left.priority, left.rule.name.as_bytes(), left.id.as_bytes()).cmp(&(
            right.priority,
            right.rule.name.as_bytes(),
            right.id.as_bytes(),
        ))
    });
    let enabled = documents.iter().filter(|document| document.enabled).count();
    if enabled + engine.rule_count() > MAX_RULES {
        return Err(CandidateError::TooManyRules);
    }
    // Managed rules go ahead of the file's, in order, keeping the file's own order after.
    let enabled_rules = documents.into_iter().filter(|document| document.enabled);
    for (index, document) in enabled_rules.enumerate() {
        engine.insert_rule(index, document.rule).map_err(CandidateError::Rule)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RequestView;
    use crate::inspection::{Mode, bit};
    use crate::waf::AttackCategory;

    fn options(file: Option<&[u8]>) -> Options<'_> {
        Options { default_difficulty: 16, waf: true, file }
    }

    #[test]
    fn private_candidates_retain_file_inspection_modes_and_reject_invalid_settings() {
        let file = br#"{"inspection":{"sqli":"audit","xss":"disabled"}}"#;
        let engine = compose(&options(Some(file)), &[], &[]).unwrap();
        let request = RequestView {
            query: b"union select <script>",
            ..RequestView::new(b"/robots.txt", b"8.8.8.8", b"")
        };
        let decision = engine.evaluate(&request);
        assert_eq!(
            (decision.action, decision.audited),
            (Action::Allow, bit(AttackCategory::Sqli))
        );
        assert_eq!(engine.inspection_modes.xss, Mode::Disabled);
        let gate = compose(&Options { waf: false, ..options(Some(file)) }, &[], &[]).unwrap();
        let request = RequestView {
            query: b"union select",
            ..RequestView::new(b"/robots.txt", b"8.8.8.8", b"")
        };
        assert_eq!(gate.evaluate(&request).audited, 0);
        let unknown = compose(&options(Some(br#"{"inspection":{"sql":"audit"}}"#)), &[], &[]);
        assert_eq!(unknown.unwrap_err().name(), "UnknownField");
        let invalid = compose(&options(Some(br#"{"inspection":{"sqli":"ignore"}}"#)), &[], &[]);
        assert_eq!(invalid.unwrap_err().name(), "InvalidEnumTag");
    }

    #[test]
    fn candidate_owns_inputs_and_composes_ordered_rules_file_settings_and_reputation() {
        let document =
            br#"{"id":"deny","name":"Deny","action":"deny","path":"/private"}"#.to_vec();
        let file = b"{\"default_action\":\"ALLOW\",\"rules\":[{\"name\":\"File\",\"action\":\"ALL\
            OW\",\"path\":\"/from-file\"}]}"
            .to_vec();
        let options = Options { default_difficulty: 17, waf: false, file: Some(&file) };
        let reputation = [Reputation { cidr: b"8.8.4.0/24", action: Action::Deny }];
        let engine = compose(&options, &[&document], &reputation).unwrap();
        drop((document, file));
        let names: Vec<&str> = engine.rules().iter().map(|rule| rule.name.as_str()).collect();
        assert_eq!(names, ["Deny", "File"]);
        assert_eq!(
            (engine.default_action, engine.default_difficulty, engine.waf_enabled),
            (Action::Allow, 17, false)
        );
        assert_eq!(
            engine.evaluate(&RequestView::new(b"/other", b"8.8.4.4", b"human")).action,
            Action::Deny
        );
    }

    #[test]
    fn candidate_refuses_duplicates_and_capacity_overflow() {
        let source: &[u8] = br#"{"id":"same","name":"Same","action":"deny"}"#;
        assert_eq!(
            compose(&options(None), &[source, source], &[]).unwrap_err(),
            CandidateError::DuplicateId
        );
        let sources = vec![source; MAX_RULES + 1];
        assert_eq!(
            compose(&options(None), &sources, &[]).unwrap_err(),
            CandidateError::TooManyDocuments
        );
        let bad = [Reputation { cidr: b"bad", action: Action::Deny }];
        assert_eq!(compose(&options(None), &[], &bad).unwrap_err(), CandidateError::InvalidCidr);
        let challenge = [Reputation { cidr: b"1.2.3.4", action: Action::Challenge }];
        assert_eq!(
            compose(&options(None), &[], &challenge).unwrap_err(),
            CandidateError::InvalidReputationAction
        );
    }

    #[test]
    fn candidate_counts_fallbacks_against_capacity_and_validates_disabled_documents() {
        let texts: Vec<String> = (0..MAX_RULES)
            .map(|i| format!(r#"{{"id":"r{i}","name":"Rule","action":"deny"}}"#))
            .collect();
        let sources: Vec<&[u8]> = texts.iter().map(|text| text.as_bytes()).collect();
        assert_eq!(
            compose(&options(None), &sources, &[]).unwrap_err(),
            CandidateError::TooManyRules
        );
        let disabled: &[u8] =
            br#"{"id":"off","name":"Off","action":"allow","enabled":false,"cidrs":["invalid"]}"#;
        assert_eq!(compose(&options(None), &[disabled], &[]).unwrap_err().name(), "InvalidCidr");
    }

    #[test]
    fn candidate_ordering_uses_priority_then_name_then_identity_and_excludes_disabled_rules() {
        let a: &[u8] = br#"{"id":"a","name":"Same","priority":10,"action":"deny"}"#;
        let b: &[u8] = br#"{"id":"b","name":"Same","priority":10,"action":"allow"}"#;
        let c: &[u8] = br#"{"id":"c","name":"First","priority":10,"action":"weigh"}"#;
        let d: &[u8] = br#"{"id":"d","name":"Priority","priority":0,"action":"weigh"}"#;
        let off: &[u8] = br#"{"id":"off","name":"Off","action":"deny","enabled":false}"#;
        let engine = compose(&options(Some(br#"{"rules":[]}"#)), &[b, off, a, c, d], &[]).unwrap();
        let rules = engine.rules();
        assert_eq!(rules.len(), 4);
        assert_eq!((rules[0].name.as_str(), rules[1].name.as_str()), ("Priority", "First"));
        assert_eq!((rules[2].action, rules[3].action), (Action::Deny, Action::Allow));
    }

    #[test]
    fn candidate_refuses_a_reputation_set_that_exhausts_the_shared_trie() {
        let texts: Vec<String> = (1..=128).map(|i| format!("{i:x}::1/128")).collect();
        let entries: Vec<Reputation<'_>> = texts
            .iter()
            .map(|text| Reputation { cidr: text.as_bytes(), action: Action::Deny })
            .collect();
        assert_eq!(compose(&options(None), &[], &entries).unwrap_err(), CandidateError::TrieFull);
    }
}
