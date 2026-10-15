//! The policy evaluation engine.
//!
//! A request is evaluated, in order, against: the semantic WAF; reputation verdicts that
//! admit or ban outright; the declarative rules (the first terminal match wins, WEIGH rules
//! accumulate a score); the accumulated score; the static bypass paths; a reputation
//! challenge verdict; the bot-signature automaton; and the default action.
//!
//! An `Engine` is a self-contained value. Its owner configures it off the hot path (rules,
//! reputation, modes, pages), then publishes it, typically in an `Arc`, after which it is
//! only read. Evaluation borrows the engine and the request and allocates nothing.

use std::fmt;
use std::net::IpAddr;

use sibuna_cidr::{Prefix, PrefixTrie, TrieError};

use crate::bots::BotMatcher;
use crate::inspection::{self, Findings, Modes};
use crate::limits::{Limits, file_identity};
use crate::pages::Pages;
use crate::pattern::TextMatcher;
use crate::request::RequestView;
use crate::rule::{Action, Algorithm, Header, MAX_RULE_CIDRS, MAX_RULE_HEADERS, PolicyRule};
use crate::waf::{self, Signatures};

/// Most declarative rules an engine holds.
pub const MAX_RULES: usize = 128;
/// Longest rule name, in bytes.
pub const MAX_RULE_NAME: usize = 128;

/// The outcome of evaluating one request. `rule_name` borrows the engine (or is static).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision<'e> {
    /// What to do with the request.
    pub action: Action,
    /// The rule that decided: a rule name, `waf:<category>`, `ip/cidr-trie`,
    /// `bypass/static`, a bot signature, `default/allow` or `default/challenge`.
    pub rule_name: &'e str,
    /// Challenge difficulty in work bits; zero when not challenging.
    pub difficulty: u32,
    /// The deciding rule's algorithm override, if any.
    pub algorithm: Option<Algorithm>,
    /// The accumulated WEIGH score when the decision was made.
    pub score: i32,
    /// Audited WAF categories with a finding, as `inspection::bit` bits; independent of
    /// the action.
    pub audited: u8,
    /// The deciding rule's quota, if any.
    pub limits: Option<Limits>,
    /// The quota's bucket scope (0 without a quota).
    pub limit_scope: u64,
}

impl<'e> Decision<'e> {
    fn new(action: Action, rule_name: &'e str, difficulty: u32, score: i32) -> Decision<'e> {
        Decision {
            action,
            rule_name,
            difficulty,
            algorithm: None,
            score,
            audited: 0,
            limits: None,
            limit_scope: 0,
        }
    }
}

/// WEIGH scoring: negative totals vouch for a client and allow it; totals at or above
/// `challenge_at` demand a challenge whose difficulty grows by one bit per `bits_step`
/// points (at most `max_extra_bits`); totals at or above `deny_at` are denied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WeighThresholds {
    /// Score at which a challenge is demanded.
    pub challenge_at: i32,
    /// Score at which the request is denied.
    pub deny_at: i32,
    /// Points per extra bit of difficulty.
    pub bits_step: i32,
    /// Most extra bits.
    pub max_extra_bits: u32,
}

impl Default for WeighThresholds {
    fn default() -> WeighThresholds {
        WeighThresholds { challenge_at: 10, deny_at: 40, bits_step: 5, max_extra_bits: 6 }
    }
}

/// The declarative rules that matched during one evaluation, WEIGH rules included, as one
/// bit per rule index. Indices belong to the engine that was evaluated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RuleMatches {
    bits: [u64; MAX_RULES / 64],
}

impl RuleMatches {
    /// Returns an empty set.
    pub fn new() -> RuleMatches {
        RuleMatches::default()
    }

    /// Returns true when rule `index` matched. Indices of `MAX_RULES` or more never match.
    pub fn is_set(&self, index: usize) -> bool {
        self.bits.get(index / 64).is_some_and(|word| word >> (index % 64) & 1 == 1)
    }

    /// Records that rule `index` matched; indices of `MAX_RULES` or more are ignored.
    pub fn set(&mut self, index: usize) {
        if let Some(word) = self.bits.get_mut(index / 64) {
            *word |= 1 << (index % 64);
        }
    }

    /// Returns the number of rules that matched.
    pub fn count(&self) -> usize {
        self.bits.iter().map(|word| word.count_ones() as usize).sum()
    }

    /// Returns the indices of the rules that matched, in increasing order.
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        (0..MAX_RULES).filter(|&index| self.is_set(index))
    }

    /// Removes every index.
    pub fn clear(&mut self) {
        self.bits = [0; MAX_RULES / 64];
    }
}

/// Why a rule was refused by `Engine::add_rule`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RuleError {
    /// The engine already holds `MAX_RULES` rules.
    TooManyRules,
    /// The name is empty, longer than `MAX_RULE_NAME`, or holds a control byte.
    InvalidRuleName,
    /// A WEIGH rule with limits, or limits out of range.
    InvalidRuleLimit,
    /// More than `MAX_RULE_HEADERS` header matchers.
    TooManyHeaders,
    /// More than `MAX_RULE_CIDRS` CIDR matchers.
    TooManyCidrs,
}

impl RuleError {
    /// Returns the error's name as the Zig engine reported it (`TooManyRules`, ...).
    pub fn name(self) -> &'static str {
        match self {
            RuleError::TooManyRules => "TooManyRules",
            RuleError::InvalidRuleName => "InvalidRuleName",
            RuleError::InvalidRuleLimit => "InvalidRuleLimit",
            RuleError::TooManyHeaders => "TooManyHeaders",
            RuleError::TooManyCidrs => "TooManyCidrs",
        }
    }
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl std::error::Error for RuleError {}

/// A rule's criteria compiled for evaluation.
#[derive(Clone, Debug)]
struct CompiledRule {
    path: Option<TextMatcher>,
    user_agent: Option<TextMatcher>,
    headers: Box<[(Box<[u8]>, TextMatcher)]>,
    cidrs: Box<[Prefix]>,
}

impl CompiledRule {
    fn new(rule: &PolicyRule) -> CompiledRule {
        let compile =
            |pattern: &Option<String>| pattern.as_ref().map(|p| TextMatcher::new(p.as_bytes()));
        CompiledRule {
            path: compile(&rule.path_pattern),
            user_agent: compile(&rule.ua_pattern),
            headers: rule
                .headers
                .iter()
                .map(|h| (h.name.as_bytes().into(), TextMatcher::new(h.pattern.as_bytes())))
                .collect(),
            cidrs: rule.cidrs.as_slice().into(),
        }
    }

    /// Returns true when every criterion matches; `address` is the parsed client address.
    #[inline]
    fn matches(&self, request: &RequestView<'_>, address: Option<IpAddr>) -> bool {
        if self.path.as_ref().is_some_and(|m| !m.matches(request.path)) {
            return false;
        }
        if self.user_agent.as_ref().is_some_and(|m| !m.matches(request.user_agent)) {
            return false;
        }
        let headers_match = self.headers.iter().all(|(name, matcher)| {
            first_header(request.headers, name).is_some_and(|value| matcher.matches(value))
        });
        if !headers_match {
            return false;
        }
        self.cidrs.is_empty()
            || address.is_some_and(|address| self.cidrs.iter().any(|p| p.contains(address)))
    }

    fn heap_bytes(&self) -> usize {
        let matcher = |m: &Option<TextMatcher>| m.as_ref().map_or(0, TextMatcher::heap_bytes);
        matcher(&self.path)
            + matcher(&self.user_agent)
            + self
                .headers
                .iter()
                .map(|(n, m)| size_of::<(Box<[u8]>, TextMatcher)>() + n.len() + m.heap_bytes())
                .sum::<usize>()
            + size_of_val(&*self.cidrs)
    }
}

fn first_header<'a>(headers: &[Header<'a>], name: &[u8]) -> Option<&'a [u8]> {
    headers.iter().find(|header| header.name.eq_ignore_ascii_case(name)).map(|header| header.value)
}

/// Receives the index of each rule that matches; `()` ignores them.
trait Observer {
    fn matched(&mut self, index: usize);
}

impl Observer for () {
    #[inline(always)]
    fn matched(&mut self, _index: usize) {}
}

impl Observer for RuleMatches {
    #[inline(always)]
    fn matched(&mut self, index: usize) {
        self.set(index);
    }
}

/// The policy engine: settings, rules, reputation, response pages and the WAF and bot
/// automata.
///
/// Settings are public fields; rules and reputation entries go through methods that
/// validate and compile them. Evaluation takes `&self`.
#[derive(Clone, Debug)]
pub struct Engine {
    /// The action for requests no rule decides. Unmatched clients are challenged by
    /// default: a scraper that presents no known signature must still pay for admission.
    pub default_action: Action,
    /// Difficulty in work bits of challenges without an override.
    pub default_difficulty: u32,
    /// WEIGH scoring thresholds.
    pub thresholds: WeighThresholds,
    /// Whether the semantic WAF runs at all (the Shield surface).
    pub waf_enabled: bool,
    /// Per-category WAF modes.
    pub inspection_modes: Modes,
    /// The response pages published with this engine.
    pub pages: Pages,
    rules: Vec<PolicyRule>,
    compiled: Vec<CompiledRule>,
    reputation: PrefixTrie<Action>,
    bots: BotMatcher,
    signatures: Signatures,
}

impl Engine {
    /// Returns an engine with the built-in rules (well-known paths, favicon, robots.txt,
    /// Sibuna's own paths, a Cloudflare-Workers denial, Amazonbot denial and a challenge for
    /// browser user agents), the WAF enforcing every category, the default challenge, the
    /// built-in pages, and an empty reputation trie.
    pub fn new(default_difficulty: u32) -> Engine {
        let mut engine = Engine {
            default_action: Action::Challenge,
            default_difficulty,
            thresholds: WeighThresholds::default(),
            waf_enabled: true,
            inspection_modes: Modes::default(),
            pages: Pages::builtin(),
            rules: Vec::new(),
            compiled: Vec::new(),
            reputation: PrefixTrie::new(),
            bots: BotMatcher::new(),
            signatures: Signatures::new(),
        };
        for rule in builtin_rules() {
            // Seven valid rules into an empty 128-slot table cannot fail.
            if let Err(error) = engine.add_rule(rule) {
                unreachable!("built-in rule refused: {error}");
            }
        }
        engine
    }

    /// Returns the declarative rules in evaluation order.
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    /// Returns the number of declarative rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Removes every declarative rule (the built-in ones included).
    pub fn clear_rules(&mut self) {
        self.rules.clear();
        self.compiled.clear();
    }

    /// Appends `rule`; see `insert_rule`.
    pub fn add_rule(&mut self, rule: PolicyRule) -> Result<(), RuleError> {
        self.insert_rule(self.rules.len(), rule)
    }

    /// Inserts `rule` at `index` (clamped to the rule count), shifting later rules down.
    ///
    /// A rule with limits gets its bucket scope here: from its `limit_identity`, or, when
    /// that is 0, from its name and `index`, as Zig derived it for file rules.
    ///
    /// Fails with `TooManyRules`, `InvalidRuleName` (empty, longer than 128 bytes, or a
    /// control byte), `InvalidRuleLimit` (limits on a WEIGH rule or out of range),
    /// `TooManyHeaders` or `TooManyCidrs`; the engine is then unchanged.
    pub fn insert_rule(&mut self, index: usize, mut rule: PolicyRule) -> Result<(), RuleError> {
        if self.rules.len() >= MAX_RULES {
            return Err(RuleError::TooManyRules);
        }
        let name = rule.name.as_bytes();
        if name.is_empty()
            || name.len() > MAX_RULE_NAME
            || name.iter().any(|&b| b < 32 || b == 127)
        {
            return Err(RuleError::InvalidRuleName);
        }
        let index = index.min(self.rules.len());
        if let Some(limits) = rule.limits {
            if rule.action == Action::Weigh || limits.validate().is_err() {
                return Err(RuleError::InvalidRuleLimit);
            }
            let identity = match rule.limit_identity {
                0 => file_identity(name, index),
                identity => identity,
            };
            rule.limit_scope = limits.scope(identity);
        }
        if rule.headers.len() > MAX_RULE_HEADERS {
            return Err(RuleError::TooManyHeaders);
        }
        if rule.cidrs.len() > MAX_RULE_CIDRS {
            return Err(RuleError::TooManyCidrs);
        }
        self.compiled.insert(index, CompiledRule::new(&rule));
        self.rules.insert(index, rule);
        Ok(())
    }

    /// Associates the reputation `action` with the CIDR `text` (`10.0.0.0/8`,
    /// `2001:db8::/32`, or a bare address), replacing an earlier entry for the same prefix.
    ///
    /// Fails with `TrieError::InvalidCidr` or `TrieError::Full` (8,192 trie nodes).
    pub fn insert_reputation(&mut self, text: &[u8], action: Action) -> Result<(), TrieError> {
        self.reputation.insert_cidr(text, action).map(|_| ())
    }

    /// Removes every reputation entry.
    pub fn clear_reputation(&mut self) {
        self.reputation.clear();
    }

    /// Returns the reputation verdict for the address `text`, if any.
    pub fn reputation(&self, text: &[u8]) -> Option<Action> {
        self.reputation.lookup_str(text).copied()
    }

    /// Returns the WAF signature automaton, for inspection outside evaluation.
    pub fn signatures(&self) -> &Signatures {
        &self.signatures
    }

    /// Returns true for the static paths that are always admitted: `/favicon.ico`,
    /// `/robots.txt`, `/.well-known/...` and `/__sibuna/...`.
    pub fn is_bypass_path(path: &[u8]) -> bool {
        path == b"/favicon.ico"
            || path == b"/robots.txt"
            || path.starts_with(b"/.well-known/")
            || path.starts_with(b"/__sibuna/")
    }

    /// Returns the heap memory the engine holds, in bytes (automata, rules, reputation
    /// trie and pages).
    pub fn heap_bytes(&self) -> usize {
        let rules: usize = self
            .rules
            .iter()
            .map(|rule| {
                let pattern = |p: &Option<String>| p.as_ref().map_or(0, String::capacity);
                rule.name.capacity()
                    + pattern(&rule.path_pattern)
                    + pattern(&rule.ua_pattern)
                    + rule
                        .headers
                        .iter()
                        .map(|h| h.name.capacity() + h.pattern.capacity())
                        .sum::<usize>()
                    + rule.headers.capacity() * size_of::<crate::rule::HeaderMatcher>()
                    + rule.cidrs.capacity() * size_of::<Prefix>()
            })
            .sum();
        let compiled: usize = self.compiled.iter().map(CompiledRule::heap_bytes).sum();
        rules
            + compiled
            + self.rules.capacity() * size_of::<PolicyRule>()
            + self.compiled.capacity() * size_of::<CompiledRule>()
            + self.reputation.node_count() * size_of::<([u32; 2], Option<Action>)>()
            + self.bots.heap_bytes()
            + self.signatures.heap_bytes()
            + self.pages.heap_bytes()
    }

    /// Evaluates `request`. Allocates nothing.
    pub fn evaluate<'e>(&'e self, request: &RequestView<'_>) -> Decision<'e> {
        self.evaluate_observed(request, &mut ())
    }

    /// Evaluates `request` and records in `matches` (cleared first) every declarative rule
    /// that matched, WEIGH rules included. The decision equals `evaluate`'s.
    pub fn evaluate_with_matches<'e>(
        &'e self,
        request: &RequestView<'_>,
        matches: &mut RuleMatches,
    ) -> Decision<'e> {
        matches.clear();
        self.evaluate_observed(request, matches)
    }

    #[inline(always)]
    fn evaluate_observed<'e>(
        &'e self,
        request: &RequestView<'_>,
        observer: &mut impl Observer,
    ) -> Decision<'e> {
        let mut findings = Findings::default();
        if self.waf_enabled {
            findings = self.inspect(request);
            if let Some(violation) = findings.denied {
                let mut decision = Decision::new(Action::Deny, violation.rule_name(), 0, 0);
                decision.audited = findings.audited;
                return decision;
            }
        }
        let mut decision = self.evaluate_admission(request, observer);
        decision.audited = findings.audited;
        decision
    }

    fn inspect(&self, request: &RequestView<'_>) -> Findings {
        if self.inspection_modes.is_all_enforcing() {
            return Findings {
                denied: waf::inspect_request(&self.signatures, request),
                audited: 0,
            };
        }
        inspection::inspect(&self.signatures, self.inspection_modes, request)
    }

    fn evaluate_admission<'e>(
        &'e self,
        request: &RequestView<'_>,
        observer: &mut impl Observer,
    ) -> Decision<'e> {
        let address = request.address();
        let verdict = address.and_then(|address| self.reputation.lookup(address).copied());
        if let Some(action @ (Action::Deny | Action::Allow)) = verdict {
            return self.reputation_decision(action, 0);
        }
        let mut score: i32 = 0;
        let mut weigh_rule = "weigh";
        for (index, (rule, compiled)) in self.rules.iter().zip(&self.compiled).enumerate() {
            if !compiled.matches(request, address) {
                continue;
            }
            observer.matched(index);
            if rule.action == Action::Weigh {
                score = score.saturating_add(rule.weight);
                weigh_rule = &rule.name;
                continue;
            }
            return self.rule_decision(rule, score);
        }
        if score != 0
            && let Some(decision) = self.weigh_decision(score, weigh_rule)
        {
            return decision;
        }
        if Engine::is_bypass_path(request.path) {
            return Decision::new(Action::Allow, "bypass/static", 0, score);
        }
        if let Some(action) = verdict {
            return self.reputation_decision(action, score);
        }
        if let Some(bot) = self.bots.find_first(request.user_agent) {
            return Decision::new(Action::Challenge, bot, self.default_difficulty, score);
        }
        let name = if self.default_action == Action::Allow {
            "default/allow"
        } else {
            "default/challenge"
        };
        Decision::new(self.default_action, name, self.challenge_bits(self.default_action), score)
    }

    fn challenge_bits(&self, action: Action) -> u32 {
        if action == Action::Challenge { self.default_difficulty } else { 0 }
    }

    fn reputation_decision(&self, action: Action, score: i32) -> Decision<'static> {
        Decision::new(action, "ip/cidr-trie", self.challenge_bits(action), score)
    }

    fn rule_decision<'e>(&self, rule: &'e PolicyRule, score: i32) -> Decision<'e> {
        let difficulty = match rule.action {
            Action::Challenge => rule.difficulty.unwrap_or(self.default_difficulty),
            _ => 0,
        };
        Decision {
            algorithm: rule.algorithm,
            limits: rule.limits,
            limit_scope: rule.limit_scope,
            ..Decision::new(rule.action, &rule.name, difficulty, score)
        }
    }

    /// Turns an accumulated WEIGH score into a terminal decision, or `None` below the
    /// challenge threshold. The arithmetic is widened so that extreme managed weights and
    /// difficulties saturate instead of overflowing.
    fn weigh_decision<'e>(&self, score: i32, rule_name: &'e str) -> Option<Decision<'e>> {
        let thresholds = self.thresholds;
        if score < 0 {
            return Some(Decision::new(Action::Allow, rule_name, 0, score));
        }
        if score >= thresholds.deny_at {
            return Some(Decision::new(Action::Deny, rule_name, 0, score));
        }
        if score < thresholds.challenge_at {
            return None;
        }
        let excess = i64::from(score) - i64::from(thresholds.challenge_at);
        let extra = excess / i64::from(thresholds.bits_step.max(1));
        let extra = extra.min(i64::from(thresholds.max_extra_bits)) as u32;
        let difficulty = self.default_difficulty.saturating_add(extra);
        Some(Decision::new(Action::Challenge, rule_name, difficulty, score))
    }
}

/// The rules every engine starts with.
fn builtin_rules() -> [PolicyRule; 7] {
    let path = |name: &str, pattern: &str| PolicyRule {
        path_pattern: Some(pattern.to_owned()),
        ..PolicyRule::new(name, Action::Allow)
    };
    let user_agent = |name: &str, pattern: &str, action| PolicyRule {
        ua_pattern: Some(pattern.to_owned()),
        ..PolicyRule::new(name, action)
    };
    [
        path("well-known", "^/.well-known/.*$"),
        path("favicon", "^/favicon.ico$"),
        path("robots-txt", "^/robots.txt$"),
        path("sibuna-internal", "/__sibuna/*"),
        PolicyRule {
            headers: vec![crate::rule::HeaderMatcher {
                name: "CF-Worker".into(),
                pattern: ".*".into(),
            }],
            ..PolicyRule::new("cloudflare-workers", Action::Deny)
        },
        user_agent("amazonbot", "Amazonbot", Action::Deny),
        user_agent("generic-browser", "Mozilla", Action::Challenge),
    ]
}

#[cfg(test)]
mod tests;
