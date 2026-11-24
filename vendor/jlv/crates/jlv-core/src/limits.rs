//! Bounds on untrusted input (JDD 0004, "Limits and diagnostics").

/// The nonzero bounds one invocation selects. A project may lower them in its
/// `[limits]` table; exceeding one is a structured `budget_exhausted` problem, never a
/// panic, a partial result or an unbounded allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Bytes of one source module.
    pub module_bytes: usize,
    /// Modules in one source closure.
    pub modules: usize,
    /// Nesting depth of expressions, types and blocks.
    pub depth: usize,
    /// Nesting depth of the types the checker forms, such as `List<List<Text>>`.
    pub type_depth: usize,
    /// Nesting depth of lists, maps and opaque values.
    pub value_depth: usize,
    /// Active nested calls during evaluation.
    pub call_depth: usize,
    /// Normalized evaluation steps (JDD 0004's semantic fuel).
    pub evaluation_steps: u64,
    /// Elements of one list or map.
    pub container_len: usize,
    /// Bytes of one text or byte string.
    pub string_bytes: usize,
    /// Resources one stack declares.
    pub resources: usize,
    /// Dependency edges between resources.
    pub edges: usize,
    /// Actions one plan or recipe contains.
    pub actions: usize,
}

impl Default for Limits {
    /// The defaults of JDD 0003's example `jlv.toml`, with conservative bounds for the
    /// values it does not name.
    fn default() -> Limits {
        Limits {
            module_bytes: 1 << 20,
            modules: 4096,
            depth: 64,
            type_depth: 64,
            // The canonical encoding gives a map three JSON levels, and a plan wraps a
            // value in a few more, within the JSON reader's 127 (JDD 0013).
            value_depth: 32,
            call_depth: 64,
            evaluation_steps: 10_000_000,
            container_len: 100_000,
            string_bytes: 16 << 20,
            resources: 10_000,
            edges: 50_000,
            actions: 100_000,
        }
    }
}
