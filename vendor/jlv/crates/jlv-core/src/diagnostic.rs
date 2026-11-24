//! Problems located by byte spans, before the source text is at hand.
//!
//! The language kernel and compiler know where a problem lies as a [`Span`] but do not
//! own the file text; [`Diagnostic::into_problem`] attaches the excerpt once a
//! [`Sources`] table can supply it.

use crate::{Problem, SourceId, Span};

/// The source files of one compilation, for turning spans into excerpts.
pub trait Sources {
    /// The display path and text of `source`, if it is known.
    fn file(&self, source: SourceId) -> Option<(&str, &str)>;
}

/// A problem with the span it concerns and related spans.
#[derive(Debug, Clone, PartialEq)]
pub struct Diagnostic {
    /// The problem, without a location.
    pub problem: Problem,
    /// Where it lies, if anywhere.
    pub span: Option<Span>,
    /// Other places that explain it, such as a first definition.
    pub related: Vec<Span>,
}

impl Diagnostic {
    /// A diagnostic for `problem` at `span`.
    pub fn at(problem: Problem, span: Span) -> Diagnostic {
        Diagnostic { problem, span: Some(span), related: Vec::new() }
    }

    /// A diagnostic without a position.
    pub fn unplaced(problem: Problem) -> Diagnostic {
        Diagnostic { problem, span: None, related: Vec::new() }
    }

    /// Adds a related span.
    pub fn related(mut self, span: Span) -> Diagnostic {
        self.related.push(span);
        self
    }

    /// The stable code of the problem.
    pub fn code(&self) -> &str {
        &self.problem.code
    }

    /// The problem with its location and related locations filled from `sources`.
    pub fn into_problem(self, sources: &dyn Sources) -> Problem {
        let mut problem = self.problem;
        if let Some(span) = self.span
            && let Some((path, text)) = sources.file(span.source)
        {
            problem = problem.at(path, text, span.start as usize, span.end as usize);
        }
        for span in self.related {
            if let Some((path, text)) = sources.file(span.source) {
                problem = problem.related(path, text, span.start as usize, span.end as usize);
            }
        }
        problem
    }
}

impl From<Problem> for Diagnostic {
    fn from(problem: Problem) -> Diagnostic {
        Diagnostic::unplaced(problem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct One(&'static str);

    impl Sources for One {
        fn file(&self, _: SourceId) -> Option<(&str, &str)> {
            Some(("deploy.jlv", self.0))
        }
    }

    #[test]
    fn a_span_becomes_a_location() {
        let problem = Problem::new("type_mismatch", "TYPE MISMATCH", "No.").hint("Fix it.");
        let diagnostic = Diagnostic::at(problem, Span::new(SourceId(0), 4, 7));
        let located = diagnostic.into_problem(&One("let\nabc = 1;\n"));
        let location = located.location.unwrap();
        assert_eq!((location.line, location.column), (2, 1));
    }
}
