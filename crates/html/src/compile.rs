//! The template compiler: it parses and checks a snippet exactly as the Zig renderer did
//! at comptime and keeps the result as literal runs and placeholder slots.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Range;

use crate::diagnostic::{Diagnostic, ErrorKind, locate};
use crate::names;
use crate::value::{Value, escape, write_value};

/// The largest snippet source in bytes (32 KiB); larger sources fail with `HTML001`.
pub const SOURCE_LIMIT: usize = 32 * 1024;

/// The most placeholders one snippet may hold; one more fails with `HTML005`.
pub const PLACEHOLDER_LIMIT: usize = 128;

/// The bytes trimmed from both ends of a placeholder name, as Zig's `std.mem.trim`.
const NAME_PADDING: &[char] = &[' ', '\r', '\n', '\t'];

/// One piece of a compiled template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Part {
    /// Source bytes written as they are.
    Literal(Range<usize>),
    /// A placeholder: the index of its field and the byte range of its name.
    Slot { field: usize, name: Range<usize> },
}

/// A compiled snippet: its source split into literal runs and placeholder slots.
///
/// `compile` makes one; `generate` turns templates into Rust source, and `render`
/// interprets one directly. A template owns a copy of its name and source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    name: String,
    stem: String,
    source: String,
    parts: Vec<Part>,
    /// The byte range of each distinct field name, in order of first appearance.
    fields: Vec<Range<usize>>,
}

/// Compiles the snippet `source`, named `name` (its path or file name) in diagnostics.
///
/// The file name in `name` (after the last `/` or `\`) must be a lowercase letter
/// followed by lowercase letters, digits, `-` and `_`, then optional extensions; its stem
/// names the generated items. The checks and their order match the Zig renderer:
/// `HTML001` for a source over 32 KiB, `HTML002` for `{%` or `{#` anywhere, then for each
/// `{{` in order `HTML003` (no `}}`), `HTML006` (empty, invalid or Rust-reserved name) and
/// `HTML005` (the 129th placeholder). `HTML008` reports an unusable file name first.
///
/// Work is bounded: a source over the limit is rejected after examining at most the
/// limit, and an accepted template holds at most 128 slots.
pub fn compile(name: &str, source: &str) -> Result<Template, Diagnostic> {
    let fail = |kind, location| Diagnostic { kind, snippet: String::from(name), location };
    let Some(stem) = names::snippet_stem(name) else {
        return Err(fail(ErrorKind::InvalidSnippetName, None));
    };
    if source.len() > SOURCE_LIMIT {
        let location = locate(source, SOURCE_LIMIT, 1);
        return Err(fail(ErrorKind::SnippetTooLarge, Some(location)));
    }
    if let Some(offset) = unsupported_tag(source) {
        return Err(fail(ErrorKind::UnsupportedTag, Some(locate(source, offset, 2))));
    }
    let mut template = Template {
        name: String::from(name),
        stem: String::from(stem),
        source: String::from(source),
        parts: Vec::new(),
        fields: Vec::new(),
    };
    template
        .split()
        .map_err(|(kind, offset, length)| fail(kind, Some(locate(source, offset, length))))?;
    Ok(template)
}

/// Returns the offset of the first `{%` or `{#`, the template tags Zig rejected.
fn unsupported_tag(source: &str) -> Option<usize> {
    source.as_bytes().windows(2).position(|pair| matches!(pair, [b'{', b'%' | b'#']))
}

/// Returns the offset of `pattern` in `source` at or after `from`.
fn find(source: &str, from: usize, pattern: &str) -> Option<usize> {
    source.get(from..)?.find(pattern).map(|index| index + from)
}

/// A failed check: the kind, the byte offset and the byte length to mark.
type Failure = (ErrorKind, usize, usize);

impl Template {
    /// Splits the source into parts, applying the per-placeholder checks in Zig's order.
    fn split(&mut self) -> Result<(), Failure> {
        let source = self.source.as_str();
        let mut cursor = 0;
        let mut slots = 0;
        while let Some(start) = find(source, cursor, "{{") {
            let end =
                find(source, start + 2, "}}").ok_or((ErrorKind::UnclosedPlaceholder, start, 2))?;
            let name = trimmed(source, start + 2..end);
            check_name(source, &name, start, end + 2 - start)?;
            slots += 1;
            if slots > PLACEHOLDER_LIMIT {
                return Err((ErrorKind::TooManyPlaceholders, start, end + 2 - start));
            }
            if cursor < start {
                self.parts.push(Part::Literal(cursor..start));
            }
            let text = source.get(name.clone()).unwrap_or_default();
            let field =
                match self.fields.iter().position(|seen| source.get(seen.clone()) == Some(text)) {
                    Some(index) => index,
                    None => {
                        self.fields.push(name.clone());
                        self.fields.len() - 1
                    }
                };
            self.parts.push(Part::Slot { field, name });
            cursor = end + 2;
        }
        if cursor < source.len() {
            self.parts.push(Part::Literal(cursor..source.len()));
        }
        Ok(())
    }

    /// Returns the snippet name as given to `compile`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the snippet source.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns the number of placeholders, counting repeats.
    pub fn placeholder_count(&self) -> usize {
        self.parts.iter().filter(|part| matches!(part, Part::Slot { .. })).count()
    }

    /// Returns the number of distinct placeholder names, which is the number of fields
    /// in the generated values struct.
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// Returns the distinct placeholder names in order of first appearance; this is the
    /// field order of the generated values struct.
    pub fn field_names(&self) -> impl Iterator<Item = &str> {
        self.fields.iter().map(|range| self.source.get(range.clone()).unwrap_or_default())
    }

    /// Returns the name of the generated function, such as `render_audit_detail` for
    /// `audit-detail.html`.
    pub fn function_name(&self) -> String {
        names::function_name(&self.stem)
    }

    /// Returns the name of the generated values struct, such as `AuditDetailValues` for
    /// `audit-detail.html`.
    pub fn struct_name(&self) -> String {
        names::struct_name(&self.stem)
    }

    /// Returns the file name shown in generated documentation, such as `field.html`.
    pub(crate) fn file_name(&self) -> &str {
        names::file_name(&self.name)
    }

    pub(crate) fn parts(&self) -> &[Part] {
        &self.parts
    }

    /// Renders the template into `out`, looking each placeholder up by name in `values`.
    ///
    /// This interprets the template instead of running generated code; it suits tools and
    /// tests, while applications call the generated `render_*` functions. Every value is
    /// looked up before anything is written, so a missing name (`HTML004`, reported for
    /// the first such placeholder) leaves `out` untouched. The first pair with a name
    /// wins and unused pairs are ignored. It borrows everything for the call and
    /// allocates only to build a diagnostic.
    ///
    /// # Errors
    ///
    /// `RenderError::Missing` for a placeholder without a value, `RenderError::Write`
    /// when `out` fails (the output is then partial).
    pub fn render(
        &self,
        out: &mut (impl fmt::Write + ?Sized),
        values: &[(&str, &dyn Value)],
    ) -> Result<(), RenderError> {
        let lookup = |field: usize| {
            let wanted = self.fields.get(field).and_then(|range| self.source.get(range.clone()));
            values.iter().find(|(name, _)| Some(*name) == wanted).map(|(_, value)| *value)
        };
        if let Some(field) = (0..self.fields.len()).find(|&field| lookup(field).is_none()) {
            return Err(RenderError::Missing(self.missing(field)));
        }
        for part in &self.parts {
            match part {
                Part::Literal(range) => {
                    out.write_str(self.source.get(range.clone()).unwrap_or_default())?;
                }
                Part::Slot { field, .. } => match lookup(*field) {
                    Some(value) => write_value(out, value)?,
                    None => escape(out, "")?,
                },
            }
        }
        Ok(())
    }

    /// Builds the `HTML004` diagnostic for `field`, located at its first placeholder.
    fn missing(&self, field: usize) -> Diagnostic {
        let range = self.fields.get(field).cloned().unwrap_or_default();
        let name = String::from(self.source.get(range.clone()).unwrap_or_default());
        Diagnostic {
            kind: ErrorKind::MissingValue { name },
            snippet: self.name.clone(),
            location: Some(locate(&self.source, range.start, range.len())),
        }
    }
}

/// Returns `range` of `source` without the padding Zig trims from placeholder names.
fn trimmed(source: &str, range: Range<usize>) -> Range<usize> {
    let inner = source.get(range.clone()).unwrap_or_default();
    let start = range.start + (inner.len() - inner.trim_start_matches(NAME_PADDING).len());
    let end = range.end - (inner.len() - inner.trim_end_matches(NAME_PADDING).len());
    start..end.max(start)
}

/// Checks a placeholder name as Zig's `validateName` did, then against Rust's reserved
/// names. `start` and `length` cover the whole placeholder.
fn check_name(
    source: &str,
    name: &Range<usize>,
    start: usize,
    length: usize,
) -> Result<(), Failure> {
    let text = source.get(name.clone()).unwrap_or_default();
    if text.is_empty() {
        return Err((ErrorKind::EmptyPlaceholder, start, length));
    }
    let valid = text.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_alphabetic() || byte == b'_' || (index != 0 && byte.is_ascii_digit())
    });
    if !valid {
        return Err((ErrorKind::InvalidPlaceholder, name.start, name.len()));
    }
    if names::is_reserved(text) {
        let kind = ErrorKind::ReservedPlaceholder { name: String::from(text) };
        return Err((kind, name.start, name.len()));
    }
    Ok(())
}

/// Why `Template::render` failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenderError {
    /// No value was supplied for a placeholder (`HTML004`); nothing was written.
    Missing(Diagnostic),
    /// The output sink failed; the output is partial and must be discarded.
    Write,
}

impl From<fmt::Error> for RenderError {
    fn from(_: fmt::Error) -> Self {
        Self::Write
    }
}

impl fmt::Display for RenderError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(diagnostic) => diagnostic.fmt(out),
            Self::Write => out.write_str("the output sink failed; discard the partial output"),
        }
    }
}

impl core::error::Error for RenderError {}

#[cfg(test)]
mod tests;
