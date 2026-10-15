//! The compiled automaton and its scans.
//!
//! The transition table is one flat slice of `u32`. A state is stored as its row offset
//! (state number times the stride), so a step is one add and one load:
//! `state = table[state + class[byte]]`. Failure links are folded into the table, so a scan
//! never follows one. States are numbered so that every match state comes after every other
//! state; detecting a match is then one comparison against `first_match`, with no second
//! table to load in the inner loop.
//!
//! ```text
//!   byte --classes--> class        table (stride = class count)
//!                       |          +---------------------------+
//!   state (row offset) -+--------> | row 0: root               |
//!                                  | ...   non-match states    |
//!                       first_match| ...   match states        |
//!                                  +---------------------------+
//! ```

use crate::builder::PatternId;
use crate::tags::TagSet;

/// Marks the absence of a dictionary link in `MatchState::next`.
pub(crate) const NO_STATE: u32 = u32::MAX;

/// Where a pattern's bytes live in `Automaton::pattern_bytes`, and its tag.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PatternInfo {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) tag: u8,
}

/// Output data of one match state.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MatchState {
    /// The patterns that end exactly at this state (all as long as the state is deep), in
    /// insertion order, as a range of `Automaton::output_ids`. Empty when the state only
    /// inherits outputs through its failure chain.
    pub(crate) outputs_start: u32,
    pub(crate) outputs_end: u32,
    /// Index of the next match state along the failure chain that has outputs of its own
    /// (the dictionary suffix link), or `NO_STATE`.
    pub(crate) next: u32,
    /// Tags of every pattern ending at this state, along the whole failure chain.
    pub(crate) tags: TagSet,
}

/// The pieces `Builder::build` hands over.
pub(crate) struct Parts {
    pub(crate) table: Box<[u32]>,
    pub(crate) classes: [u8; 256],
    pub(crate) stride: usize,
    pub(crate) first_match: usize,
    pub(crate) match_states: Box<[MatchState]>,
    pub(crate) output_ids: Box<[u32]>,
    pub(crate) patterns: Box<[PatternInfo]>,
    pub(crate) pattern_bytes: Box<[u8]>,
    pub(crate) ascii_case_insensitive: bool,
}

/// One occurrence of a pattern in a haystack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Match {
    /// The pattern that occurs.
    pub pattern: PatternId,
    /// The pattern's tag.
    pub tag: u8,
    /// Offset of the first byte of the occurrence.
    pub start: usize,
    /// Offset one past the last byte of the occurrence.
    pub end: usize,
}

/// A compiled Aho-Corasick automaton: immutable, shareable between threads, and scanned
/// without allocation. Built by `Builder::build` or `Automaton::from_patterns`.
///
/// Every scan reads each haystack byte once and does a constant amount of work per byte, plus
/// work per reported match. Matches may overlap.
#[derive(Clone, Debug)]
pub struct Automaton {
    table: Box<[u32]>,
    classes: [u8; 256],
    stride: usize,
    first_match: usize,
    match_states: Box<[MatchState]>,
    output_ids: Box<[u32]>,
    patterns: Box<[PatternInfo]>,
    pattern_bytes: Box<[u8]>,
    all_tags: TagSet,
    ascii_case_insensitive: bool,
}

impl Automaton {
    pub(crate) fn from_parts(parts: Parts) -> Automaton {
        let all_tags = parts.match_states.iter().fold(TagSet::EMPTY, |tags, s| tags | s.tags);
        Automaton {
            table: parts.table,
            classes: parts.classes,
            stride: parts.stride,
            first_match: parts.first_match,
            match_states: parts.match_states,
            output_ids: parts.output_ids,
            patterns: parts.patterns,
            pattern_bytes: parts.pattern_bytes,
            all_tags,
            ascii_case_insensitive: parts.ascii_case_insensitive,
        }
    }

    /// Builds an automaton from (pattern, tag) pairs in one call. Pattern ids follow the
    /// order of `patterns`.
    ///
    /// Fails with the first error `Builder::add` reports.
    pub fn from_patterns<'p>(
        options: crate::Options,
        patterns: impl IntoIterator<Item = (&'p [u8], u8)>,
    ) -> Result<Automaton, crate::BuildError> {
        let mut builder = crate::Builder::new(options);
        for (pattern, tag) in patterns {
            builder.add(pattern, tag)?;
        }
        Ok(builder.build())
    }

    /// Returns the number of patterns.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Returns the number of states, the root included.
    pub fn state_count(&self) -> usize {
        self.table.len() / self.stride
    }

    /// Returns the number of byte classes, the width of one table row.
    pub fn class_count(&self) -> usize {
        self.stride
    }

    /// Returns the heap memory the automaton holds, in bytes.
    pub fn heap_bytes(&self) -> usize {
        size_of_val(&*self.table)
            + size_of_val(&*self.match_states)
            + size_of_val(&*self.output_ids)
            + size_of_val(&*self.patterns)
            + self.pattern_bytes.len()
    }

    /// Returns true when the automaton matches ASCII letters without regard to case.
    pub fn is_ascii_case_insensitive(&self) -> bool {
        self.ascii_case_insensitive
    }

    /// Returns the bytes of pattern `id` as they were added (not case-folded).
    ///
    /// Panics if `id` comes from a different automaton with more patterns.
    pub fn pattern(&self, id: PatternId) -> &[u8] {
        let info = self.patterns[id.index()];
        &self.pattern_bytes[info.start..info.end]
    }

    /// Returns the tag of pattern `id`.
    ///
    /// Panics if `id` comes from a different automaton with more patterns.
    pub fn tag(&self, id: PatternId) -> u8 {
        self.patterns[id.index()].tag
    }

    /// Returns the union of the tags of all patterns.
    pub fn all_tags(&self) -> TagSet {
        self.all_tags
    }

    /// Advances from `state` (a row offset) over `byte`.
    #[inline(always)]
    fn step(&self, state: usize, byte: u8) -> usize {
        self.table[state + usize::from(self.classes[usize::from(byte)])] as usize
    }

    /// Returns the output data of match state `state` (a row offset at or after
    /// `first_match`).
    #[inline]
    fn match_state(&self, state: usize) -> &MatchState {
        &self.match_states[(state - self.first_match) / self.stride]
    }

    fn report(&self, id: u32, end: usize) -> Match {
        let info = self.patterns[id as usize];
        Match { pattern: PatternId(id), tag: info.tag, start: end - (info.end - info.start), end }
    }

    /// Returns the first pattern id among the outputs of `state` whose tag is in `wanted`,
    /// walking the dictionary links. The caller checked that one exists.
    fn first_output_in<'a>(&'a self, mut state: &'a MatchState, wanted: TagSet) -> Option<u32> {
        loop {
            let own = &self.output_ids[state.outputs_start as usize..state.outputs_end as usize];
            let tags = &self.patterns;
            if let Some(&id) = own.iter().find(|&&id| wanted.contains(tags[id as usize].tag)) {
                return Some(id);
            }
            state = self.match_states.get(state.next as usize)?;
        }
    }

    /// Returns true when some pattern occurs in `haystack`. Stops at the first occurrence.
    pub fn is_match(&self, haystack: &[u8]) -> bool {
        let mut state = 0;
        for &byte in haystack {
            state = self.step(state, byte);
            if state >= self.first_match {
                return true;
            }
        }
        false
    }

    /// Returns the occurrence that ends first; when several patterns end at that offset, the
    /// longest one, and among equal patterns the one added first. Stops scanning there.
    pub fn find_first(&self, haystack: &[u8]) -> Option<Match> {
        let mut state = 0;
        for (index, &byte) in haystack.iter().enumerate() {
            state = self.step(state, byte);
            if state >= self.first_match {
                let id = self.first_output_in(self.match_state(state), self.all_tags)?;
                return Some(self.report(id, index + 1));
            }
        }
        None
    }

    /// Returns the first occurrence, in the order of `find_first`, of a pattern tagged `tag`,
    /// ignoring patterns with other tags, including ones that end at the same offset.
    pub fn find_first_tagged(&self, haystack: &[u8], tag: u8) -> Option<Match> {
        if !self.all_tags.contains(tag) {
            return None;
        }
        let wanted = TagSet { bits: 1 << tag };
        let mut state = 0;
        for (index, &byte) in haystack.iter().enumerate() {
            state = self.step(state, byte);
            if state >= self.first_match {
                let found = self.match_state(state);
                if found.tags.contains(tag) {
                    let id = self.first_output_in(found, wanted)?;
                    return Some(self.report(id, index + 1));
                }
            }
        }
        None
    }

    /// Returns the tags of every pattern that occurs in `haystack`. Stops early once every
    /// tag of the automaton has been seen.
    pub fn tags(&self, haystack: &[u8]) -> TagSet {
        let mut found = TagSet::EMPTY;
        let mut state = 0;
        for &byte in haystack {
            state = self.step(state, byte);
            if state >= self.first_match {
                found |= self.match_state(state).tags;
                if found == self.all_tags {
                    break;
                }
            }
        }
        found
    }

    /// Returns an iterator over every occurrence of every pattern, overlapping ones
    /// included, ordered by end offset, then from longest to shortest, then by insertion
    /// order. It borrows `haystack` and allocates nothing.
    pub fn matches<'a>(&'a self, haystack: &'a [u8]) -> Matches<'a> {
        Matches { automaton: self, haystack, position: 0, state: 0, pending: None }
    }
}

/// Iterator over all occurrences in a haystack; see `Automaton::matches`.
#[derive(Clone, Debug)]
pub struct Matches<'a> {
    automaton: &'a Automaton,
    haystack: &'a [u8],
    /// Offset of the next byte to scan; never beyond the end of the haystack.
    position: usize,
    state: usize,
    /// Outputs at `position` not yet reported: (match state index, next output in its own
    /// range).
    pending: Option<(u32, u32)>,
}

impl Matches<'_> {
    /// Returns the next pending output at the current position, if any, and advances the
    /// cursor past it along the output list and the dictionary links.
    fn next_pending(&mut self) -> Option<u32> {
        let automaton = self.automaton;
        while let Some((index, cursor)) = self.pending {
            let state = &automaton.match_states[index as usize];
            if cursor < state.outputs_end {
                self.pending = Some((index, cursor + 1));
                return Some(automaton.output_ids[cursor as usize]);
            }
            self.pending = automaton
                .match_states
                .get(state.next as usize)
                .map(|next| (state.next, next.outputs_start));
        }
        None
    }
}

impl Iterator for Matches<'_> {
    type Item = Match;

    fn next(&mut self) -> Option<Match> {
        let automaton = self.automaton;
        loop {
            if let Some(id) = self.next_pending() {
                return Some(automaton.report(id, self.position));
            }
            let rest = &self.haystack[self.position..];
            let mut state = self.state;
            let found = rest.iter().position(|&byte| {
                state = automaton.step(state, byte);
                state >= automaton.first_match
            });
            self.state = state;
            let Some(offset) = found else {
                self.position = self.haystack.len();
                return None;
            };
            self.position += offset + 1;
            let index = ((state - automaton.first_match) / automaton.stride) as u32;
            self.pending = Some((index, automaton.match_states[index as usize].outputs_start));
        }
    }
}
