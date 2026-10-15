//! Sibuna's declarative policy engine and semantic web application firewall.
//!
//! Every request the daemon serves is classified here. An [`Engine`] holds the declarative
//! rules, the IP reputation trie, the bot-signature automaton, the WAF signature automaton
//! and the response pages. It is configured off the hot path (from a policy file with
//! [`Engine::load_json`], from management documents with [`candidate::compose`], or
//! programmatically), published (typically in an `Arc`), and then only read:
//! [`Engine::evaluate`] borrows the engine and a [`RequestView`] of the connection buffer and
//! allocates nothing.
//!
//! ```
//! use sibuna_policy::{Action, Engine, Header, RequestView};
//!
//! let engine = Engine::new(16);
//! let browser = RequestView::new(b"/index.html", b"192.0.2.7", b"Mozilla/5.0 (X11; Linux)");
//! let decision = engine.evaluate(&browser);
//! assert_eq!((decision.action, decision.rule_name), (Action::Challenge, "generic-browser"));
//!
//! let headers = [Header { name: b"X-Search", value: b"1' UNION SELECT password FROM users--" }];
//! let attack = RequestView { headers: &headers, ..browser };
//! assert_eq!(engine.evaluate(&attack).rule_name, "waf:sqli");
//! ```
//!
//! Evaluation order (SID 0003): the semantic WAF of the Shield surface ([`waf`], with
//! per-category modes in [`inspection`]; the Gate surface sets `waf_enabled` to false);
//! reputation trie verdicts that admit or ban outright; the declarative rules in order (the
//! first terminal match wins, WEIGH rules accumulate a score); the score against the
//! thresholds; the static bypass paths; a reputation challenge verdict; the bot signatures
//! ([`bots`]); the default action.
//!
//! The WAF (SID 0004) runs a byte-class pre-scan, one tagged Aho-Corasick pass over every
//! strong signature, the structural tokenizers for SQL injection, cross-site scripting,
//! command injection and NUL truncation, and, when the byte classes show it can matter, the
//! same again on the canonicalised field ([`normalizer`]). Bodies are inspected over their
//! first 8 KiB, split into fields by [`body_fields`] and [`mime`]. Every loop does work
//! linear in its input; the fuzz tests assert a work budget proportional to the length.
//!
//! # Changes from the Zig version
//!
//! `libs/policy/src` of the Zig daemon is the specification: decisions, WAF findings, loader
//! acceptance, diagnostics, explanations, rule hashes, quota scopes and embeddings are the
//! same. A differential test replays thousands of generated requests, payloads, mutated
//! policy files and management documents against output of the Zig 0.16 library. The port
//! differs deliberately as follows.
//!
//! - The reputation trie comes from `sibuna-cidr`, which fixed a Zig bug: the prefix
//!   `0.0.0.0/0` (and `::ffff:0:0/96`) in `ip_rules` now matches every IPv4 client, where
//!   Zig accepted the entry and silently never matched it.
//! - WEIGH arithmetic is widened, so extreme managed weights and difficulties saturate
//!   where Zig would trap on overflow.
//! - A number in an integer field whose integrality depends on binary128 rounding (more
//!   than about 34 significant digits) is judged exactly; Zig could round it to an integer.
//! - Errors are enums per module carrying Zig's error names (`name()`); a JSON-level loader
//!   error also reports its byte offset in the `Diagnostic`.
//! - The candidate engine is bounded by its inputs (a 256 KiB file, 128 documents of 4 KiB,
//!   8,192 reputation rows) instead of a 2 MiB arena that could run out on a valid file.
//! - `Pages::defaults` reports a challenge page that does not compile instead of trapping.
//!
//! # Zig machinery that Rust replaced
//!
//! - `Engine.initInPlace` over several megabytes of fixed arrays (853,728 bytes per engine
//!   value, kept in static or heap storage and re-initialised for every rebuild): an owned
//!   `Engine` built once by `Engine::new`, about 200 KiB of compact heap tables
//!   (`Engine::heap_bytes`), published behind an `Arc` and freed by `Drop`.
//! - Fixed rule, header and CIDR arrays with counts and `undefined` slots: `Vec`s whose
//!   bounds `Engine::insert_rule` checks.
//! - Loader arenas whose lifetime the engine's borrowed strings depended on, and the
//!   comments saying so: owned `String`s copied once when a rule is added.
//! - `Candidate` with its allocator, memory block and `deinit`: `candidate::compose`
//!   returns an owned `Engine`.
//! - The comptime `observed` flag that specialised evaluation: a generic observer that
//!   compiles to nothing when rule matches are not recorded.
//! - Re-interpreting rule patterns (and rebuilding a substring search table) on every
//!   request: patterns compiled once into exact, prefix or Horspool matchers.
//! - `catch unreachable` around the built-in tables: construction that the unit tests prove
//!   cannot fail, behind `unreachable!` with the reason.
//! - The 8 KiB `undefined` canonicalisation buffer: a stack buffer sized to the field.
//! - Per-category automaton scans in mixed inspection modes: one scan for every category's
//!   tags, then a tagged search only for the categories present.
//! - `std.json.parseFromSliceLeaky` with reflection over Zig structs: a streaming reader
//!   (`json`) that consumes tokens in Zig's order, so the first error in document order wins.
//!   It is local to this crate because `sibuna-json` parses whole documents first and would
//!   report a late syntax error ahead of an earlier unknown key.

pub mod body_fields;
pub mod bots;
pub mod candidate;
pub mod embedding;
pub mod engine;
pub mod inspection;
pub mod json;
pub mod limits;
pub mod loader;
pub mod management;
pub mod matchers;
pub mod mime;
pub mod normalizer;
pub mod pages;
pub mod request;
pub mod rule;
pub mod waf;

mod bytes;
mod pattern;
mod steps;

pub use engine::{
    Decision, Engine, MAX_RULE_NAME, MAX_RULES, RuleError, RuleMatches, WeighThresholds,
};
pub use inspection::{Mode, Modes};
pub use limits::Limits;
pub use loader::{Diagnostic, Explanation, LoadError, explain};
pub use request::RequestView;
pub use rule::{Action, Algorithm, Header, HeaderMatcher, PolicyRule, pattern_matches};

#[cfg(test)]
mod fuzz_tests;
