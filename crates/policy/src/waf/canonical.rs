//! The second pass of inspection: the buffers a field is canonicalised in, and the findings
//! that only its decoded form shows.

use std::cell::Cell;

use super::{AttackCategory, MAX_CANONICAL, Violation, structure};
use crate::bytes::find_byte;
use crate::normalizer::{decode, finish};
use crate::waf::classes::scan;

/// Fields up to this length are canonicalised in a stack buffer; longer ones in the
/// thread's reused buffer of `MAX_CANONICAL` bytes.
const MAX_STACK_CANONICAL: usize = 2048;

thread_local! {
    /// The canonicalisation buffer of long fields. A thread allocates it on the first long
    /// field it canonicalises and reuses it afterwards, so inspection allocates at most once
    /// per thread (per connection in the daemon) and never per request; nor does it clear
    /// 16 KiB of stack per field.
    pub(super) static LONG_BUFFER: Cell<Option<Box<[u8]>>> = const { Cell::new(None) };
}

/// Findings that only the decoded form of a field shows, taken before whitespace folding
/// turns line feeds and tabs into spaces.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Decoded {
    /// A `javascript:` or `vbscript:` scheme split by tabs or line breaks.
    pub(super) xss: Option<Violation>,
    /// A command after a decoded line feed (`%0a`, `\n`, `&#10;`).
    pub(super) rce: Option<Violation>,
}

impl Decoded {
    /// Searches `decoded`; the command-injection detector runs only when a line feed is
    /// present, since the canonical form shows every other separator.
    fn of(decoded: &[u8]) -> Decoded {
        let rce = match find_byte(decoded, 0, b'\n') {
            Some(_) => structure::rce(decoded, scan(decoded)),
            None => None,
        };
        Decoded { xss: structure::split_script_scheme(decoded), rce }
    }

    fn is_empty(self) -> bool {
        self.xss.is_none() && self.rce.is_none()
    }

    /// Returns the finding of `category`, if the decoded form showed one.
    pub(super) fn finding(self, category: AttackCategory) -> Option<Violation> {
        match category {
            AttackCategory::Xss => self.xss,
            AttackCategory::Rce => self.rce,
            AttackCategory::PathTraversal | AttackCategory::Sqli => None,
        }
    }
}

/// A field's canonical form and what its decoded form showed.
#[derive(Clone, Copy, Debug)]
pub(super) struct Canonical<'a> {
    /// The canonical form.
    pub(super) text: &'a [u8],
    /// The findings of the decoded form.
    pub(super) decoded: Decoded,
}

/// Runs `inspect` on the canonical form of `text`, when canonicalisation changes it or the
/// decoded form shows a finding.
///
/// A short field uses a stack buffer sized to its tier, so it does not pay for clearing a
/// large one; a long field uses the thread's buffer. Every buffer holds the whole canonical
/// form of a field of at most `MAX_CANONICAL` bytes, because the form is never longer than
/// its input; of a longer field it holds the first `MAX_CANONICAL` bytes.
pub(super) fn with_canonical<R>(
    text: &[u8],
    inspect: impl FnOnce(Canonical<'_>) -> Option<R>,
) -> Option<R> {
    fn run<R>(
        buffer: &mut [u8],
        text: &[u8],
        inspect: impl FnOnce(Canonical<'_>) -> Option<R>,
    ) -> Option<R> {
        let len = decode(text, buffer).len();
        let decoded = buffer.get(..len).map(Decoded::of).unwrap_or_default();
        let normalized = finish(buffer, len);
        let unchanged = normalized.is_empty() || normalized == text;
        if unchanged && decoded.is_empty() {
            None
        } else {
            inspect(Canonical { text: normalized, decoded })
        }
    }
    if text.len() <= 256 {
        run(&mut [0u8; 256], text, inspect)
    } else if text.len() <= MAX_STACK_CANONICAL {
        run(&mut [0u8; MAX_STACK_CANONICAL], text, inspect)
    } else {
        with_long_buffer(|buffer| run(buffer, text, inspect))
    }
}

/// Lends the thread's long-field buffer to `use_buffer`.
///
/// The buffer is taken out of its cell for the call rather than borrowed, so a nested call
/// or a call during thread teardown finds the cell empty and works in a fresh buffer of the
/// same bounded size instead of panicking. Neither happens in the request path, where the
/// inspection closures never canonicalise again.
pub(super) fn with_long_buffer<R>(use_buffer: impl FnOnce(&mut [u8]) -> R) -> R {
    let mut buffer = LONG_BUFFER
        .try_with(Cell::take)
        .ok()
        .flatten()
        .unwrap_or_else(|| vec![0u8; MAX_CANONICAL].into_boxed_slice());
    let result = use_buffer(&mut buffer);
    // During teardown the cell is gone and the buffer is simply dropped.
    let _ = LONG_BUFFER.try_with(|cell| cell.set(Some(buffer)));
    result
}
