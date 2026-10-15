//! Tagged Aho-Corasick automata over bytes.
//!
//! We match hundreds of literal patterns against a field in one linear pass (Aho and
//! Corasick, CACM 1975). Each pattern carries a small tag (a WAF category, a bot class), so
//! one pass returns both the match and its class. The automaton is built once, off the hot
//! path, with a `Builder`; it is then immutable and every scan runs without allocation.
//!
//! ```
//! use sibuna_patterns::{Automaton, Options};
//!
//! let options = Options { ascii_case_insensitive: true, ..Options::default() };
//! let pairs: [(&[u8], u8); 3] = [(b"union select", 1), (b"<script", 2), (b"../", 0)];
//! let automaton = Automaton::from_patterns(options, pairs).unwrap();
//! let field = b"q=1 UNION SELECT null--";
//! let found = automaton.find_first(field).unwrap();
//! assert_eq!((found.tag, found.start, found.end), (1, 4, 16));
//! assert!(automaton.tags(field).contains(1));
//! assert_eq!(automaton.find_first_tagged(field, 2), None);
//! ```
//!
//! # Design
//!
//! The table is dense: one `u32` successor per (state, byte class), with failure links folded
//! in, so a scan is exactly one dependent load per input byte and never follows a failure
//! chain. Bytes that occur in no pattern share one class, and with case folding both cases of
//! a letter share a class too, so a row is as wide as the number of distinct pattern bytes
//! plus one rather than 256. Match states are numbered after all other states, so the inner
//! loop detects a match with one comparison. Construction is `O(m * c)` time and space for
//! patterns of total length `m` and `c` classes; a scan is `O(n)` for a haystack of length
//! `n`, plus the matches reported.
//!
//! The scans are:
//!
//! - `is_match`: does any pattern occur;
//! - `find_first`: the occurrence that ends first;
//! - `find_first_tagged`: the first occurrence of a pattern with a given tag;
//! - `tags`: the set of tags of all patterns that occur;
//! - `matches`: an iterator over every occurrence.
//!
//! # Changes from the Zig version
//!
//! The Zig `Automaton(max_states)` in `libs/policy/src/aho_corasick.zig` is the
//! specification. The port differs deliberately as follows.
//!
//! - Capacity is a run-time `Options` value instead of a compile-time parameter, with the
//!   same failures (`EmptyPattern`, `TooManyStates`, `TooManyPatterns`). A failed `add`
//!   leaves the builder unchanged; Zig kept the states it had created.
//! - Case folding is an option; Zig always folded ASCII letters. Sibuna's callers turn it on.
//! - Tags run from 0 to 63 (Zig allowed 0 to 255) so that a tag set is one `u64`;
//!   `TagOutOfRange` reports a larger tag. Sibuna's tags are below 4.
//! - The table holds `u32` row offsets over byte classes instead of `u16` state numbers over
//!   256 bytes; the signature sets need several times less memory.
//! - Patterns equal under folding are all kept and reported by `matches`; elsewhere the one
//!   added first wins. Zig overwrote the earlier one, so its scans reported only the last.
//!   Sibuna's signature tables contain no such duplicates.
//! - A match carries its pattern id and offsets; `Automaton::pattern` returns the bytes
//!   that Zig returned as the match name. `matches` and `tags` are new.
//! - `Builder::build` consumes the builder, so adding after building is a compile error
//!   rather than a debug assertion.
//!
//! The Sibuna signature tables themselves (bot names, WAF signatures) live in
//! `sibuna-policy`, which builds its automata with this crate.

mod automaton;
mod builder;
mod tags;

pub use automaton::{Automaton, Match, Matches};
pub use builder::{BuildError, Builder, Options, PatternId, STATE_LIMIT};
pub use tags::{MAX_TAG, TagSet};

#[cfg(test)]
mod tests;
