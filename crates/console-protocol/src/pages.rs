//! Operator page templates: bounded HTML with a fixed placeholder set. The owner validates
//! a template before staging it; the request path renders segments from the snapshot.
//!
//! Zig moved template bytes in a heap block whose owner had to free it explicitly
//! (`releaseRequest`, `releaseResult`); here the template is an owned value inside the
//! request or result and is dropped with it.

use crate::error::{MAX_I64, ValidationError, limit};
use crate::text::Text;
use crate::users;

/// The largest template, in bytes.
pub const MAX_BYTES: usize = 16 * 1024;

/// A template's HTML.
pub type Html = Text<MAX_BYTES>;

/// Which page a template renders.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Kind {
    /// The challenge page.
    #[default]
    Challenge,
    /// The denial page.
    Denied,
    /// The rate-limit page.
    RateLimited,
    /// The ban page.
    Banned,
    /// The overload page.
    Overloaded,
}

/// Reads a template.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Read {
    /// The reader's credential.
    pub auth: users::Auth,
    /// The page.
    pub kind: Kind,
}

/// Replaces or resets a template; `html` is present exactly when `reset` is false.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Edit {
    /// The operator's credential.
    pub auth: users::Auth,
    /// The page.
    pub kind: Kind,
    /// The revision the operator saw.
    pub expected_revision: u64,
    /// Restore the built-in template.
    pub reset: bool,
    /// The new template.
    pub html: Option<Html>,
}

/// A stored template.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Document {
    /// The page.
    pub kind: Kind,
    /// The template revision.
    pub revision: u64,
    /// The operator replaced the built-in template.
    pub customized: bool,
    /// SHA-256 of the template as hex.
    pub sha256: Text<64>,
    /// The template.
    pub html: Html,
}

/// Checks a template edit.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for an oversized revision, HTML with a reset or no
/// HTML without one, or an empty template.
pub fn validate_edit(input: &Edit) -> Result<(), ValidationError> {
    limit(input.expected_revision >= MAX_I64 || input.reset != input.html.is_none())?;
    limit(input.html.as_ref().is_some_and(Text::is_empty))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_carry_html_exactly_without_a_reset() {
        let edit = Edit { html: Some(Html::new("<p>hi</p>").unwrap()), ..Edit::default() };
        assert_eq!(validate_edit(&edit), Ok(()));
        assert!(validate_edit(&Edit { reset: true, ..edit.clone() }).is_err());
        assert!(validate_edit(&Edit { html: Some(Html::default()), ..edit }).is_err());
        assert_eq!(validate_edit(&Edit { reset: true, ..Edit::default() }), Ok(()));
        assert!(Html::new(&"x".repeat(MAX_BYTES + 1)).is_err());
    }
}
