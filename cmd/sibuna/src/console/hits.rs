//! Rule-hit counters of a published engine and the identity of their generation (Zig's
//! `policy_hit_state.zig` and the publication half of `console_policy_hits.zig`; SID 0007,
//! "Rule observations").
//!
//! Every engine the storage thread publishes while the console runs carries a fresh
//! [`RuleHits`]: zeroed counters and a [`Generation`] naming the node, the boot, a number
//! that grows with each publication, the policy revision, the publication time and the
//! identity of each rule in match-index order. A refused snapshot publishes nothing, so the
//! live counters are never reset by a failed rebuild. Request threads record into the
//! counters of the engine that evaluated them; the console's collector reads them once a
//! second through `Node::sample_rule_hits`.
//!
//! Zig prepared a spare slot's counters in place and reset them; here each publication
//! allocates its counters once, off the request path, and the old ones are freed with the
//! old engine.

use std::fmt;
use std::num::NonZeroU64;
use std::sync::Arc;

use sibuna_console::{Clock, RuleHitSample};
use sibuna_console_protocol::rule_hits::{self, Generation, Identity, Key, MAX_RULES, Name};
use sibuna_crypto::sha256::Sha256;
use sibuna_policy::{Engine, RuleMatches};
use sibuna_store::rule_hits::{Counters, Matches};

/// The longest rule identity source kept readable; a longer one is hashed.
const MAX_READABLE: usize = 128;

/// The counters of one published engine and the generation they count.
pub struct RuleHits {
    counters: Counters<MAX_RULES>,
    generation: Generation,
}

impl fmt::Debug for RuleHits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleHits")
            .field("number", &self.generation.number)
            .field("revision", &self.generation.revision)
            .field("rules", &self.generation.rules.len())
            .finish_non_exhaustive()
    }
}

impl RuleHits {
    /// Returns the generation these counters belong to.
    pub fn generation(&self) -> &Generation {
        &self.generation
    }

    /// Adds one hit to each of the first `rule_count` rules set in `matches`. Allocates
    /// nothing; called on the request path.
    #[inline]
    pub fn record(&self, matches: &RuleMatches, rule_count: usize) {
        if matches.count() == 0 {
            return;
        }
        let mut set = Matches::new();
        for index in (0..rule_count.min(MAX_RULES)).filter(|&index| matches.is_set(index)) {
            set.set(index);
        }
        self.counters.record(&set);
    }

    /// Fills `sample` with the counter values and the generation, reusing its storage.
    pub fn sample(&self, sample: &mut RuleHitSample) {
        sample.generation.clone_from(&self.generation);
        self.counters.read(&mut sample.counts);
    }
}

/// Why a generation could not be numbered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenerationsExhausted;

impl fmt::Display for GenerationsExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuleGenerationExhausted")
    }
}

impl std::error::Error for GenerationsExhausted {}

/// Numbers and stamps the rule-hit generations of one boot; owned by the publish hook.
pub struct Generations {
    node: u32,
    boot: [u8; 16],
    clock: Arc<dyn Clock>,
    last: u64,
}

impl fmt::Debug for Generations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Generations").field("node", &self.node).field("last", &self.last).finish()
    }
}

impl Generations {
    /// Starts numbering at 1 for node `node` in boot `boot`, stamping with `clock`.
    pub fn new(node: u32, boot: [u8; 16], clock: Arc<dyn Clock>) -> Generations {
        Generations { node, boot, clock, last: 0 }
    }

    /// Returns zeroed counters for `engine`, built from policy `revision`, whose first rules
    /// are the managed rules with the stored ids `managed` in order and whose other rules
    /// came from the policy file. Call it only for an engine about to be published: the
    /// number is spent.
    ///
    /// Fails with [`GenerationsExhausted`] after 2^63 - 1 generations, as Zig did.
    pub fn next(
        &mut self,
        engine: &Engine,
        revision: u64,
        managed: &[&str],
    ) -> Result<RuleHits, GenerationsExhausted> {
        let number = self.last.checked_add(1).filter(|&n| n <= i64::MAX as u64);
        let number = number.and_then(NonZeroU64::new).ok_or(GenerationsExhausted)?;
        let rules = engine.rules().iter().take(MAX_RULES).enumerate().map(|(index, rule)| {
            match managed.get(index) {
                Some(id) => identify(&rule.name, Some(id), 0),
                None => identify(&rule.name, None, index.saturating_sub(managed.len())),
            }
        });
        let generation = Generation {
            node: self.node,
            boot: self.boot,
            number: number.get(),
            revision,
            born: rule_hits::Clock {
                utc: self.clock.unix_seconds(),
                ms: self.clock.monotonic_ms(),
            },
            rules: rules.collect(),
        };
        self.last = number.get();
        Ok(RuleHits { counters: Counters::new(number), generation })
    }
}

/// The identity of the rule named `name`: a managed rule is keyed by its stored id
/// (`m:<id>`), a file rule by its position among the file's rules and its name
/// (`f:<index>:<name>`). A source that is longer than 128 bytes or holds a control
/// character is keyed by its SHA-256 instead (`mh:`, `fh:`), so telemetry never refuses a
/// policy the data plane accepted. The display name is the name cut to 128 bytes.
fn identify(name: &str, id: Option<&str>, file_index: usize) -> Identity {
    let source = id.unwrap_or(name);
    let readable = source.len() <= MAX_READABLE && !source.contains(['\0', '\r', '\n', '\t']);
    let digest;
    let shown = if readable {
        source
    } else {
        digest = sibuna_encoding::hex::encode(&Sha256::digest(source.as_bytes()));
        digest.as_str()
    };
    let key = match (id.is_some(), readable) {
        (true, true) => format!("m:{shown}"),
        (true, false) => format!("mh:{shown}"),
        (false, true) => format!("f:{file_index}:{shown}"),
        (false, false) => format!("fh:{file_index}:{shown}"),
    };
    // Both fit: a key is at most "fh:" or "f:", a 20-digit index, ":" and 128 bytes or 64
    // hexadecimal digits (153 bytes); a label is cut to 128 bytes.
    Identity {
        key: Key::from_string(key).unwrap_or_default(),
        name: Name::new(label(name)).unwrap_or_default(),
    }
}

/// `name` cut to at most 128 bytes at a character boundary.
fn label(name: &str) -> &str {
    let mut end = name.len().min(MAX_READABLE);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name.get(..end).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use sibuna_console::ManualClock;
    use sibuna_policy::{Action, PolicyRule};

    use super::*;

    // policy_hit_state.zig: "observation metadata preserves accepted long and opaque file
    // rule identities". Rust names are always UTF-8, so the `[invalid text]` label of a
    // name with invalid bytes has no counterpart.
    #[test]
    fn identities_keep_long_and_opaque_file_rules_apart() {
        let long = format!("{}{}", "x".repeat(127), "\u{e9}".repeat(10));
        let first = identify(&long, None, 0);
        assert_eq!(first.name.as_str(), "x".repeat(127));
        assert!(first.key.as_str().starts_with("fh:0:"));
        let other = identify(&format!("{long}different"), None, 0);
        assert_ne!(first.key, other.key);
        assert!(identify("a\0b", None, 0).key.as_str().starts_with("fh:0:"));
        assert_eq!(identify("Tracked", Some("tracked"), 0).key.as_str(), "m:tracked");
        assert_eq!(identify("Open", None, 3).key.as_str(), "f:3:Open");
        let opaque = identify("Name", Some("id\nwith newline"), 0);
        assert!(opaque.key.as_str().starts_with("mh:") && opaque.key.as_str().len() == 67);
        assert_eq!(opaque.name.as_str(), "Name");
    }

    #[test]
    fn generations_number_publications_and_count_only_matched_rules() {
        let clock = Arc::new(ManualClock::new(1_000, 5));
        let mut generations = Generations::new(3, [7; 16], clock);
        let mut engine = Engine::new(8);
        engine.insert_rule(0, PolicyRule::new("Managed", Action::Deny)).unwrap();
        engine.insert_rule(1, PolicyRule::new("From file", Action::Allow)).unwrap();
        let hits = generations.next(&engine, 9, &["managed"]).unwrap();
        let generation = hits.generation();
        assert_eq!((generation.node, generation.number, generation.revision), (3, 1, 9));
        assert_eq!((generation.born.utc, generation.born.ms), (1_000, 5));
        assert_eq!(generation.rules[0].key.as_str(), "m:managed");
        assert_eq!(generation.rules[1].key.as_str(), "f:0:From file");
        let mut matches = RuleMatches::new();
        matches.set(1);
        matches.set(100);
        hits.record(&matches, engine.rule_count());
        let mut sample = RuleHitSample::default();
        hits.sample(&mut sample);
        assert_eq!(&sample.counts.values[..3], &[0, 1, 0]);
        assert_eq!(sample.counts.values[100], 0);
        assert_eq!(sample.generation.number, 1);
        assert_eq!(generations.next(&engine, 10, &[]).unwrap().generation().number, 2);
        generations.last = i64::MAX as u64;
        assert_eq!(generations.next(&engine, 11, &[]).map(drop), Err(GenerationsExhausted));
    }
}
