//! Operator-editable response pages.
//!
//! A template is validated and split into literal segments and placeholder slots when it
//! enters an engine snapshot; the request path only copies segments and escapes values into
//! a writer. Validation refuses script, frames, event handlers, external resources, unknown
//! placeholders and placeholders inside tags.

mod markup;

use std::fmt;
use std::io::{self, Write};

pub use markup::{MarkupError, validate as validate_markup};

/// Longest template source, in bytes.
pub const MAX_BYTES: usize = 16 * 1024;
/// Most segments (literals and slots) a template may have.
pub const MAX_SEGMENTS: usize = 32;

/// The response pages an operator can edit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// The proof-of-work interstitial.
    Challenge,
    /// A policy or WAF denial.
    Denied,
    /// A rate-limit rejection.
    RateLimited,
    /// A banned address.
    Banned,
    /// The daemon is overloaded.
    Overloaded,
}

impl Kind {
    /// Every kind, in storage order.
    pub const ALL: [Kind; 5] =
        [Kind::Challenge, Kind::Denied, Kind::RateLimited, Kind::Banned, Kind::Overloaded];

    /// Returns the stored name: `challenge`, `denied`, `rate_limited`, `banned` or
    /// `overloaded`.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Challenge => "challenge",
            Kind::Denied => "denied",
            Kind::RateLimited => "rate_limited",
            Kind::Banned => "banned",
            Kind::Overloaded => "overloaded",
        }
    }

    /// Parses a stored name exactly.
    pub fn parse(text: &[u8]) -> Option<Kind> {
        Kind::ALL.into_iter().find(|kind| kind.name().as_bytes() == text)
    }
}

/// A value slot in a template.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Placeholder {
    /// The HTTP status code.
    Status,
    /// The reason text, escaped.
    Reason,
    /// Seconds before a retry.
    RetryAfter,
    /// The request reference, escaped.
    RequestId,
    /// The cluster node number.
    Node,
    /// The fixed solver block (challenge pages only), not escaped.
    Challenge,
}

impl Placeholder {
    const ALL: [Placeholder; 6] = [
        Placeholder::Status,
        Placeholder::Reason,
        Placeholder::RetryAfter,
        Placeholder::RequestId,
        Placeholder::Node,
        Placeholder::Challenge,
    ];

    /// Returns the name written between `{{` and `}}`.
    pub fn name(self) -> &'static str {
        match self {
            Placeholder::Status => "status",
            Placeholder::Reason => "reason",
            Placeholder::RetryAfter => "retry_after",
            Placeholder::RequestId => "request_id",
            Placeholder::Node => "node",
            Placeholder::Challenge => "challenge",
        }
    }

    fn parse(text: &[u8]) -> Option<Placeholder> {
        Placeholder::ALL.into_iter().find(|slot| slot.name().as_bytes() == text)
    }
}

/// Why a template was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PageError {
    /// The source exceeds `MAX_BYTES`.
    TooLarge,
    /// The source is not UTF-8 or holds a NUL byte.
    InvalidUtf8,
    /// A forbidden element, scheme, comment or malformed tag.
    ForbiddenContent,
    /// A forbidden or malformed attribute.
    ForbiddenAttribute,
    /// A URL that is not a literal local path or fragment.
    ExternalReference,
    /// An unknown or unterminated placeholder.
    UnknownPlaceholder,
    /// A placeholder inside a tag or raw-text element.
    PlaceholderInTag,
    /// More than `MAX_SEGMENTS` segments.
    TooManySegments,
    /// A challenge page without exactly one `{{ challenge }}`.
    ChallengeSlotRequired,
    /// `{{ challenge }}` outside a challenge page.
    ChallengeSlotForbidden,
}

impl PageError {
    /// Returns the error's name as the Zig daemon reported it (`ForbiddenContent`, ...).
    pub fn name(self) -> &'static str {
        match self {
            PageError::TooLarge => "TooLarge",
            PageError::InvalidUtf8 => "InvalidUtf8",
            PageError::ForbiddenContent => "ForbiddenContent",
            PageError::ForbiddenAttribute => "ForbiddenAttribute",
            PageError::ExternalReference => "ExternalReference",
            PageError::UnknownPlaceholder => "UnknownPlaceholder",
            PageError::PlaceholderInTag => "PlaceholderInTag",
            PageError::TooManySegments => "TooManySegments",
            PageError::ChallengeSlotRequired => "ChallengeSlotRequired",
            PageError::ChallengeSlotForbidden => "ChallengeSlotForbidden",
        }
    }
}

impl fmt::Display for PageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl std::error::Error for PageError {}

impl From<MarkupError> for PageError {
    fn from(error: MarkupError) -> PageError {
        match error {
            MarkupError::ForbiddenContent => PageError::ForbiddenContent,
            MarkupError::ForbiddenAttribute => PageError::ForbiddenAttribute,
            MarkupError::ExternalReference => PageError::ExternalReference,
            MarkupError::PlaceholderInTag => PageError::PlaceholderInTag,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Segment {
    /// Bytes `start..end` of the source.
    Literal {
        start: u16,
        end: u16,
    },
    Slot(Placeholder),
}

/// A compiled template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    source: Box<str>,
    segments: Box<[Segment]>,
    /// The stored revision the template came from; 0 for a built-in page.
    pub revision: u64,
    /// True for an operator's page, false for a built-in default.
    pub customized: bool,
    /// True when a stored page failed to compile and this default stands in for it.
    pub fallback: bool,
}

/// The values a page renders. Text values borrow the caller's storage.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Values<'a> {
    /// The HTTP status code.
    pub status: u16,
    /// The reason text; HTML-escaped when written.
    pub reason: &'a str,
    /// Seconds before a retry.
    pub retry_after: u32,
    /// The request reference; HTML-escaped when written.
    pub request_id: &'a str,
    /// The cluster node number.
    pub node: u32,
    /// The fixed solver block for challenge pages; written as it is, never escaped, so it
    /// must never come from an operator or a client.
    pub challenge: &'a str,
}

impl Template {
    /// Validates `source` as a page of `kind` and splits it into segments.
    ///
    /// Fails with `TooLarge`, `InvalidUtf8`, a markup error (`ForbiddenContent`,
    /// `ForbiddenAttribute`, `ExternalReference`, `PlaceholderInTag`), `UnknownPlaceholder`,
    /// `TooManySegments`, `ChallengeSlotForbidden` or `ChallengeSlotRequired`.
    pub fn compile(kind: Kind, source: &[u8]) -> Result<Template, PageError> {
        if source.len() > MAX_BYTES {
            return Err(PageError::TooLarge);
        }
        let text = std::str::from_utf8(source).map_err(|_| PageError::InvalidUtf8)?;
        if source.contains(&0) {
            return Err(PageError::InvalidUtf8);
        }
        markup::validate(source)?;
        let mut segments = Vec::new();
        let mut challenge_slots = 0;
        let mut literal_start = 0;
        let mut cursor = 0;
        while let Some(open) = crate::bytes::find(source, cursor, b"{{") {
            let close = crate::bytes::find(source, open + 2, b"}}")
                .ok_or(PageError::UnknownPlaceholder)?;
            let name = crate::bytes::trim_spaces(&source[open + 2..close]);
            let slot = Placeholder::parse(name).ok_or(PageError::UnknownPlaceholder)?;
            if inside_tag(&source[..open]) {
                return Err(PageError::PlaceholderInTag);
            }
            if slot == Placeholder::Challenge {
                if kind != Kind::Challenge {
                    return Err(PageError::ChallengeSlotForbidden);
                }
                challenge_slots += 1;
            }
            push_literal(&mut segments, literal_start, open)?;
            push(&mut segments, Segment::Slot(slot))?;
            cursor = close + 2;
            literal_start = cursor;
        }
        push_literal(&mut segments, literal_start, source.len())?;
        if kind == Kind::Challenge && challenge_slots != 1 {
            return Err(PageError::ChallengeSlotRequired);
        }
        Ok(Template {
            source: text.into(),
            segments: segments.into(),
            revision: 0,
            customized: true,
            fallback: false,
        })
    }

    /// Returns the template's source text.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Writes the page with `values` into `out`: literals as they are, text values
    /// HTML-escaped, numbers in decimal. Allocates nothing.
    ///
    /// Fails only when `out` fails.
    pub fn write<W: Write + ?Sized>(&self, out: &mut W, values: &Values<'_>) -> io::Result<()> {
        for segment in self.segments.iter() {
            match *segment {
                Segment::Literal { start, end } => {
                    let range = usize::from(start)..usize::from(end);
                    out.write_all(self.source.as_bytes().get(range).unwrap_or_default())?;
                }
                Segment::Slot(slot) => write_slot(out, slot, values)?,
            }
        }
        Ok(())
    }

    /// Returns the number of bytes `write` would produce for `values` (for a
    /// `Content-Length` written before the body).
    pub fn measure(&self, values: &Values<'_>) -> usize {
        let mut counter = Counter(0);
        // A counter never fails.
        let _ = self.write(&mut counter, values);
        counter.0
    }
}

struct Counter(usize);

impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_slot<W: Write + ?Sized>(
    out: &mut W,
    slot: Placeholder,
    values: &Values<'_>,
) -> io::Result<()> {
    match slot {
        Placeholder::Status => write!(out, "{}", values.status),
        Placeholder::Reason => escape(out, values.reason.as_bytes()),
        Placeholder::RetryAfter => write!(out, "{}", values.retry_after),
        Placeholder::RequestId => escape(out, values.request_id.as_bytes()),
        Placeholder::Node => write!(out, "{}", values.node),
        Placeholder::Challenge => out.write_all(values.challenge.as_bytes()),
    }
}

fn escape<W: Write + ?Sized>(out: &mut W, text: &[u8]) -> io::Result<()> {
    let mut start = 0;
    for (index, &byte) in text.iter().enumerate() {
        let entity: &[u8] = match byte {
            b'&' => b"&amp;",
            b'<' => b"&lt;",
            b'>' => b"&gt;",
            b'"' => b"&quot;",
            b'\'' => b"&#39;",
            _ => continue,
        };
        out.write_all(&text[start..index])?;
        out.write_all(entity)?;
        start = index + 1;
    }
    out.write_all(&text[start..])
}

fn push_literal(segments: &mut Vec<Segment>, start: usize, end: usize) -> Result<(), PageError> {
    if end == start {
        return Ok(());
    }
    // The source is at most MAX_BYTES (16 KiB), so both offsets fit in a u16.
    let (start, end) = (start as u16, end as u16);
    push(segments, Segment::Literal { start, end })
}

fn push(segments: &mut Vec<Segment>, segment: Segment) -> Result<(), PageError> {
    if segments.len() == MAX_SEGMENTS {
        return Err(PageError::TooManySegments);
    }
    segments.push(segment);
    Ok(())
}

/// True when the last `<` before the end of `before` comes after its last `>`.
fn inside_tag(before: &[u8]) -> bool {
    match before.iter().rposition(|&b| b == b'<') {
        None => false,
        Some(open) => before.iter().rposition(|&b| b == b'>').is_none_or(|close| open > close),
    }
}

/// The library's own challenge page: the solver slot inside a minimal document. The daemon
/// replaces it with its interstitial.
pub const DEFAULT_CHALLENGE_MINIMAL: &str = "<!doctype html><html lang=\"en\"><head><meta \
    charset=\"utf-8\"><title>Checking your browser</title></head><body><h1>Checking your \
    browser</h1>{{ challenge }}</body></html>";
/// The built-in denial page.
pub const DEFAULT_DENIED: &str = "<!doctype html><html lang=\"en\"><head><meta \
    charset=\"utf-8\"><title>Request blocked</title></head><body><h1>Request \
    blocked</h1><p>Sibuna refused this request ({{ status }}): {{ reason }}.</p><p>Reference \
    {{ request_id }} on node {{ node }}.</p></body></html>";
/// The built-in rate-limit page.
pub const DEFAULT_RATE_LIMITED: &str = "<!doctype html><html lang=\"en\"><head><meta \
    charset=\"utf-8\"><title>Slow down</title></head><body><h1>Too many requests</h1><p>Retry \
    after {{ retry_after }} seconds.</p><p>Reference {{ request_id }} on node \
    {{ node }}.</p></body></html>";
/// The built-in ban page.
pub const DEFAULT_BANNED: &str = "<!doctype html><html lang=\"en\"><head><meta \
    charset=\"utf-8\"><title>Access denied</title></head><body><h1>Access denied</h1><p>This \
    address is temporarily banned ({{ reason }}).</p><p>Reference {{ request_id }} on node \
    {{ node }}.</p></body></html>";
/// The built-in overload page.
pub const DEFAULT_OVERLOADED: &str = "<!doctype html><html lang=\"en\"><head><meta \
    charset=\"utf-8\"><title>Service busy</title></head><body><h1>Service unavailable</h1><p>{{ \
    reason }}. Retry after {{ retry_after }} seconds.</p></body></html>";

/// Returns the built-in source of `kind`, with `challenge` as the challenge page.
pub fn default_source(kind: Kind, challenge: &str) -> &str {
    match kind {
        Kind::Challenge => challenge,
        Kind::Denied => DEFAULT_DENIED,
        Kind::RateLimited => DEFAULT_RATE_LIMITED,
        Kind::Banned => DEFAULT_BANNED,
        Kind::Overloaded => DEFAULT_OVERLOADED,
    }
}

/// One template per page kind, published with an engine snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pages {
    entries: [Template; 5],
}

impl Pages {
    /// Compiles the built-in pages with `challenge` as the challenge page (the daemon
    /// supplies its interstitial). Every entry is marked as not customized, revision 0.
    ///
    /// Fails with the challenge page's `PageError`; the other built-in pages always compile.
    pub fn defaults(challenge: &str) -> Result<Pages, PageError> {
        let compile = |kind: Kind| -> Result<Template, PageError> {
            let mut template =
                Template::compile(kind, default_source(kind, challenge).as_bytes())?;
            template.customized = false;
            Ok(template)
        };
        Ok(Pages {
            entries: [
                compile(Kind::Challenge)?,
                compile(Kind::Denied)?,
                compile(Kind::RateLimited)?,
                compile(Kind::Banned)?,
                compile(Kind::Overloaded)?,
            ],
        })
    }

    /// Returns the library's built-in pages (with `DEFAULT_CHALLENGE_MINIMAL`).
    pub fn builtin() -> Pages {
        match Pages::defaults(DEFAULT_CHALLENGE_MINIMAL) {
            Ok(pages) => pages,
            // Every built-in source is a constant that the unit tests compile.
            Err(error) => unreachable!("built-in pages do not compile: {error}"),
        }
    }

    /// Returns the template of `kind`.
    pub fn page(&self, kind: Kind) -> &Template {
        &self.entries[kind as usize]
    }

    /// Replaces the template of `kind`.
    pub fn set(&mut self, kind: Kind, template: Template) {
        self.entries[kind as usize] = template;
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        self.entries.iter().map(|t| t.source.len() + t.segments.len() * size_of::<Segment>()).sum()
    }
}

impl Default for Pages {
    fn default() -> Pages {
        Pages::builtin()
    }
}

#[cfg(test)]
mod tests;
