//! Bounds on the work and memory one document may cost.

/// Bounds on the work and memory a document may cost. Exceeding one is an error.
///
/// The tree parser and the [`PullReader`](crate::PullReader) check the same limits at the
/// same places, before the work they bound.
///
/// ```
/// let limits = sibuna_json::Limits { max_depth: 8, ..Default::default() };
/// assert!(sibuna_json::parse_with_limits(b"[[[[[[[[[1]]]]]]]]]", &limits).is_err());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Limits {
    /// The longest input accepted, in bytes. Default: 16 MiB.
    pub max_input_bytes: usize,
    /// The deepest nesting of arrays and objects. Default: 64. Dropping and writing a
    /// value recurse once per level, so very large values risk the thread's stack.
    pub max_depth: usize,
    /// The most values (scalars, arrays and objects, not counting keys) in the document.
    /// Default: 1,000,000.
    pub max_values: usize,
    /// The longest decoded string or key, in bytes. Default: 1 MiB.
    pub max_string_bytes: usize,
}

impl Limits {
    /// Limits that never trigger: every resource is then bounded by the input's length
    /// alone, since each value, nesting level and string byte takes at least one input
    /// byte. For callers that bound the input themselves.
    pub const UNBOUNDED: Limits = Limits {
        max_input_bytes: usize::MAX,
        max_depth: usize::MAX,
        max_values: usize::MAX,
        max_string_bytes: usize::MAX,
    };
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_input_bytes: 16 << 20,
            max_depth: 64,
            max_values: 1_000_000,
            max_string_bytes: 1 << 20,
        }
    }
}
