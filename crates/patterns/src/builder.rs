//! Building an automaton: a pattern trie grown by `Builder::add`, then compiled into the dense
//! table of `Automaton` by `Builder::build`.
//!
//! Construction runs once, off the hot path, so it favours clarity over speed: the trie keeps
//! a small edge list per node, and `build` derives the byte classes, the failure links and the
//! output lists in a few linear passes.

use std::collections::VecDeque;
use std::fmt;

use crate::automaton::{Automaton, MatchState, NO_STATE, PatternInfo};
use crate::tags::{MAX_TAG, TagSet};

/// Hard ceiling on the number of states, whatever `Options::max_states` says. It keeps every
/// premultiplied state offset (at most `states * 256`) inside a `u32`.
pub const STATE_LIMIT: usize = 1 << 24;

/// Configuration of a `Builder`.
///
/// The limits make construction from untrusted pattern lists bounded: `add` refuses a pattern
/// that would exceed them instead of growing without limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// Match ASCII letters without regard to case (`GPTBot` matches `gptbot`). Other bytes,
    /// including non-ASCII ones, always match exactly.
    pub ascii_case_insensitive: bool,
    /// Largest number of states, the root included. Values above `STATE_LIMIT` act as
    /// `STATE_LIMIT`. A set of patterns needs at most one plus their total length.
    pub max_states: usize,
    /// Largest number of patterns.
    pub max_patterns: usize,
}

impl Default for Options {
    /// Case-sensitive matching with room for 16,384 states and 16,384 patterns.
    fn default() -> Options {
        Options { ascii_case_insensitive: false, max_states: 16_384, max_patterns: 16_384 }
    }
}

/// Why `Builder::add` refused a pattern. The builder is unchanged after an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// The pattern has no bytes; it would match everywhere.
    EmptyPattern,
    /// The tag is above `MAX_TAG`.
    TagOutOfRange(u8),
    /// The pattern needs more states than `Options::max_states` allows.
    TooManyStates,
    /// The automaton already holds `Options::max_patterns` patterns.
    TooManyPatterns,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::EmptyPattern => f.write_str("a pattern must have at least one byte"),
            BuildError::TagOutOfRange(tag) => {
                write!(f, "tag {tag} is out of range; tags run from 0 to {MAX_TAG}")
            }
            BuildError::TooManyStates => f.write_str("the patterns need more states than allowed"),
            BuildError::TooManyPatterns => f.write_str("too many patterns"),
        }
    }
}

impl std::error::Error for BuildError {}

/// Identifies a pattern by the order in which it was added, starting at zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PatternId(pub(crate) u32);

impl PatternId {
    /// Returns the position of the pattern in insertion order.
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// One node of the pattern trie. `edges` holds (folded byte, child) pairs; `outputs` the
/// patterns that end here, in insertion order (more than one only for duplicates).
#[derive(Default)]
struct TrieNode {
    edges: Vec<(u8, u32)>,
    outputs: Vec<u32>,
}

impl TrieNode {
    fn child(&self, byte: u8) -> Option<u32> {
        self.edges.iter().find(|(edge, _)| *edge == byte).map(|(_, child)| *child)
    }
}

/// Collects (pattern, tag) pairs and compiles them into an `Automaton`.
///
/// ```
/// use sibuna_patterns::{Builder, Options};
///
/// let mut builder = Builder::new(Options { ascii_case_insensitive: true, ..Options::default() });
/// builder.add(b"GPTBot", 1).unwrap();
/// builder.add(b"curl/", 2).unwrap();
/// let automaton = builder.build();
/// let found = automaton.find_first(b"Mozilla/5.0 (compatible; gptbot/1.2)").unwrap();
/// assert_eq!(automaton.pattern(found.pattern), b"GPTBot");
/// assert_eq!(found.tag, 1);
/// ```
pub struct Builder {
    options: Options,
    nodes: Vec<TrieNode>,
    patterns: Vec<PatternInfo>,
    pattern_bytes: Vec<u8>,
}

impl Builder {
    /// Returns an empty builder with the given options.
    pub fn new(options: Options) -> Builder {
        Builder {
            options,
            nodes: vec![TrieNode::default()],
            patterns: Vec::new(),
            pattern_bytes: Vec::new(),
        }
    }

    /// Returns the number of patterns added so far.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Returns the number of states the patterns added so far need, the root included.
    pub fn state_count(&self) -> usize {
        self.nodes.len()
    }

    /// Adds `pattern` with `tag` and returns its id. The bytes are copied.
    ///
    /// Adding a pattern twice (or two patterns equal under case folding) is allowed; both
    /// are reported by `Automaton::matches`, and the first one added wins elsewhere.
    ///
    /// Fails with `EmptyPattern`, `TagOutOfRange`, `TooManyPatterns` or `TooManyStates`;
    /// the builder is unchanged after a failure.
    pub fn add(&mut self, pattern: &[u8], tag: u8) -> Result<PatternId, BuildError> {
        if pattern.is_empty() {
            return Err(BuildError::EmptyPattern);
        }
        if tag > MAX_TAG {
            return Err(BuildError::TagOutOfRange(tag));
        }
        if self.patterns.len() >= self.options.max_patterns.min(u32::MAX as usize) {
            return Err(BuildError::TooManyPatterns);
        }
        let (mut node, shared) = self.longest_existing_prefix(pattern);
        let max_states = self.options.max_states.min(STATE_LIMIT);
        if self.nodes.len() + (pattern.len() - shared) > max_states {
            return Err(BuildError::TooManyStates);
        }
        for &byte in &pattern[shared..] {
            let child = self.nodes.len() as u32;
            self.nodes.push(TrieNode::default());
            let folded = self.fold(byte);
            self.nodes[node as usize].edges.push((folded, child));
            node = child;
        }
        let id = self.patterns.len() as u32;
        self.nodes[node as usize].outputs.push(id);
        let start = self.pattern_bytes.len();
        self.pattern_bytes.extend_from_slice(pattern);
        self.patterns.push(PatternInfo { start, end: self.pattern_bytes.len(), tag });
        Ok(PatternId(id))
    }

    /// Compiles the patterns into an automaton. An empty builder gives an automaton that
    /// never matches.
    pub fn build(self) -> Automaton {
        let classes = self.byte_classes();
        let stride = usize::from(classes.iter().copied().max().unwrap_or(0)) + 1;
        let mut table = self.goto_table(&classes, stride);
        let order = breadth_first_order(&table, stride);
        let fail = fold_failure_links(&mut table, stride, &order);
        self.assemble(classes, stride, &table, &order, &fail)
    }

    /// Walks the trie along `pattern` and returns the deepest node reached and its depth.
    fn longest_existing_prefix(&self, pattern: &[u8]) -> (u32, usize) {
        let mut node = 0u32;
        for (depth, &byte) in pattern.iter().enumerate() {
            match self.nodes[node as usize].child(self.fold(byte)) {
                Some(child) => node = child,
                None => return (node, depth),
            }
        }
        (node, pattern.len())
    }

    fn fold(&self, byte: u8) -> u8 {
        if self.options.ascii_case_insensitive { byte.to_ascii_lowercase() } else { byte }
    }

    /// Maps every byte to an equivalence class. Each folded byte that occurs in a pattern
    /// gets a class of its own; all other bytes behave alike (they lead back to the root
    /// from every state) and share one class. Case folding is free here: both cases of a
    /// letter map to the same class, so the scan never folds.
    fn byte_classes(&self) -> [u8; 256] {
        let mut used = [false; 256];
        for node in &self.nodes {
            for &(byte, _) in &node.edges {
                used[usize::from(byte)] = true;
            }
        }
        let mut class_of_byte: [Option<u8>; 256] = [None; 256];
        let mut other: Option<u8> = None;
        let mut next_class: u16 = 0;
        let mut classes = [0u8; 256];
        for (byte, class) in (0..=255u8).zip(classes.iter_mut()) {
            let folded = usize::from(self.fold(byte));
            let slot = if used[folded] { &mut class_of_byte[folded] } else { &mut other };
            // At most 256 distinct slots exist (one per used byte, or "other" when some byte
            // is unused), so `next_class` never exceeds 255 when it is assigned.
            *class = *slot.get_or_insert_with(|| {
                next_class += 1;
                (next_class - 1) as u8
            });
        }
        classes
    }

    /// Returns the trie as a dense table of `nodes * stride` plain state numbers, where 0
    /// (the root, which is never a child) marks a missing edge.
    fn goto_table(&self, classes: &[u8; 256], stride: usize) -> Vec<u32> {
        let mut table = vec![0u32; self.nodes.len() * stride];
        for (row, node) in table.chunks_exact_mut(stride).zip(&self.nodes) {
            for &(byte, child) in &node.edges {
                row[usize::from(classes[usize::from(byte)])] = child;
            }
        }
        table
    }

    /// Turns the folded table into the final automaton: renumbers the states so that every
    /// match state comes after every other state, premultiplies state numbers by the stride,
    /// and lays out the output lists.
    fn assemble(
        self,
        classes: [u8; 256],
        stride: usize,
        table: &[u32],
        order: &[u32],
        fail: &[u32],
    ) -> Automaton {
        let outputs = OutputLinks::compute(&self.nodes, &self.patterns, order, fail);
        let state_count = self.nodes.len();
        let mut renumber = vec![0u32; state_count];
        let mut next = 0u32;
        let root_first = std::iter::once(0).chain(order.iter().copied());
        for state in root_first.filter(|&s| !outputs.is_match[s as usize]) {
            renumber[state as usize] = next;
            next += 1;
        }
        let first_match_state = next;
        let mut match_states = Vec::with_capacity(state_count - next as usize);
        let mut output_ids = Vec::with_capacity(self.patterns.len());
        for state in order.iter().copied().filter(|&s| outputs.is_match[s as usize]) {
            renumber[state as usize] = next;
            next += 1;
            let own = &self.nodes[state as usize].outputs;
            match_states.push(MatchState {
                outputs_start: output_ids.len() as u32,
                outputs_end: (output_ids.len() + own.len()) as u32,
                next: outputs.link[state as usize],
                tags: outputs.tags[state as usize],
            });
            output_ids.extend_from_slice(own);
        }
        // Dictionary links still name old states; translate them to match-state indices.
        for state in &mut match_states {
            if state.next != NO_STATE {
                state.next = renumber[state.next as usize] - first_match_state;
            }
        }
        let mut final_table = vec![0u32; table.len()];
        for (old, row) in table.chunks_exact(stride).enumerate() {
            let start = renumber[old] as usize * stride;
            for (slot, &target) in final_table[start..start + stride].iter_mut().zip(row) {
                *slot = renumber[target as usize] * stride as u32;
            }
        }
        Automaton::from_parts(crate::automaton::Parts {
            table: final_table.into_boxed_slice(),
            classes,
            stride,
            first_match: first_match_state as usize * stride,
            match_states: match_states.into_boxed_slice(),
            output_ids: output_ids.into_boxed_slice(),
            patterns: self.patterns.into_boxed_slice(),
            pattern_bytes: self.pattern_bytes.into_boxed_slice(),
            ascii_case_insensitive: self.options.ascii_case_insensitive,
        })
    }
}

/// Returns every state except the root in breadth-first order of the goto table.
fn breadth_first_order(table: &[u32], stride: usize) -> Vec<u32> {
    let state_count = table.len() / stride;
    let mut order = Vec::with_capacity(state_count.saturating_sub(1));
    let mut queue: VecDeque<u32> = table[..stride].iter().copied().filter(|&c| c != 0).collect();
    while let Some(state) = queue.pop_front() {
        order.push(state);
        let row = &table[state as usize * stride..][..stride];
        queue.extend(row.iter().copied().filter(|&c| c != 0));
    }
    order
}

/// Computes the failure links breadth-first and folds them into the table, so that scanning
/// never follows a failure chain: a missing edge of a state becomes the edge of its failure
/// state, which lies closer to the root and is therefore complete already. Returns the
/// failure link of every state (the root's is the root).
fn fold_failure_links(table: &mut [u32], stride: usize, order: &[u32]) -> Vec<u32> {
    let mut fail = vec![0u32; table.len() / stride];
    for &state in order {
        let fail_row = fail[state as usize] as usize * stride;
        let row = state as usize * stride;
        for class in 0..stride {
            let next = table[row + class];
            let fallback = table[fail_row + class];
            if next == 0 {
                table[row + class] = fallback;
            } else {
                fail[next as usize] = fallback;
            }
        }
    }
    // The root is not in `order`, so its children keep the initial link 0, which is correct.
    fail
}

/// Output structure derived from the failure links.
struct OutputLinks {
    /// True when some pattern ends at the state (its own, or one along its failure chain).
    is_match: Vec<bool>,
    /// Nearest state along the failure chain that has patterns of its own, or `NO_STATE`.
    link: Vec<u32>,
    /// Tags of every pattern ending at the state.
    tags: Vec<TagSet>,
}

impl OutputLinks {
    fn compute(nodes: &[TrieNode], patterns: &[PatternInfo], order: &[u32], fail: &[u32]) -> Self {
        let count = nodes.len();
        let mut links = OutputLinks {
            is_match: vec![false; count],
            link: vec![NO_STATE; count],
            tags: vec![TagSet::EMPTY; count],
        };
        for &state in order {
            let state = state as usize;
            let suffix = fail[state] as usize;
            let own = &nodes[state].outputs;
            let mut tags = links.tags[suffix];
            for &id in own {
                tags.bits |= 1u64 << patterns[id as usize].tag;
            }
            links.tags[state] = tags;
            links.is_match[state] = !own.is_empty() || links.is_match[suffix];
            links.link[state] =
                if nodes[suffix].outputs.is_empty() { links.link[suffix] } else { suffix as u32 };
        }
        links
    }
}
