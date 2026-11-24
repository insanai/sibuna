//! Byte spans in captured source files.

/// A source file within one compilation, numbered in the order the closure lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct SourceId(pub u32);

/// Bytes `start..end` of one source file. Spans are diagnostic data: they never enter a
/// canonical graph or plan identity (JDD 0003, "Typed intermediate representation").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Span {
    /// The file.
    pub source: SourceId,
    /// The first byte.
    pub start: u32,
    /// One past the last byte.
    pub end: u32,
}

impl Span {
    /// The span of bytes `start..end` in `source`.
    pub fn new(source: SourceId, start: usize, end: usize) -> Span {
        let clamp = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        Span { source, start: clamp(start), end: clamp(end.max(start)) }
    }

    /// The smallest span covering both; both must be in the same file.
    pub fn to(self, other: Span) -> Span {
        Span {
            source: self.source,
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }

    /// The span as a byte range.
    pub fn range(self) -> std::ops::Range<usize> {
        self.start as usize..self.end as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joined_spans_cover_both() {
        let a = Span::new(SourceId(1), 4, 7);
        let b = Span::new(SourceId(1), 2, 5);
        assert_eq!(a.to(b).range(), 2..7);
        assert_eq!(Span::new(SourceId(0), 5, 3).range(), 5..5);
    }
}
