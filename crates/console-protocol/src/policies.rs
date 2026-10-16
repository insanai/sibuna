//! Policy documents: catalog reads, the private policy tester and edits.

use crate::error::{MAX_I64, ValidationError, limit};
use crate::ja4;
use crate::text::Text;

/// The largest policy document.
pub const MAX_DOCUMENT: usize = 4096;
/// The most headers a test request carries.
pub const MAX_HEADERS: usize = 8;

/// A policy catalog page.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Query {
    /// SHA-256 of the session cookie or bearer token.
    pub session_digest: [u8; 32],
    /// The route requires an enrolled second factor.
    pub require_totp: bool,
    /// Rules to skip, at most 128.
    pub offset: u8,
    /// The applied revision the reader knows.
    pub applied: Option<u64>,
}

/// One request header of a test.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// The header name.
    pub name: Text<64>,
    /// The header value.
    pub value: Text<256>,
}

/// Evaluates a request against the committed policy or a private draft. Private tests do
/// not increment rule-hit counters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Test {
    /// The reader's credential and position.
    pub query: Query,
    /// The request path.
    pub path: Text<512>,
    /// The query string.
    pub query_string: Text<512>,
    /// The client address.
    pub ip: Text<48>,
    /// The User-Agent.
    pub user_agent: Text<256>,
    /// The JA4 fingerprint a trusted ingress would forward (SID 0014); empty for none.
    pub ja4: Text<{ ja4::FINGERPRINT_LEN }>,
    /// The body.
    pub body: Text<2048>,
    /// At most [`MAX_HEADERS`] headers.
    pub headers: Vec<Header>,
    /// A draft document; present exactly when `committed` is.
    pub draft: Option<Text<MAX_DOCUMENT>>,
    /// The committed revision the draft replaces.
    pub committed: Option<u64>,
}

/// Replaces the policy document, fenced by its revision.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Edit {
    /// SHA-256 of the session cookie.
    pub session_digest: [u8; 32],
    /// SHA-256 of the CSRF token.
    pub csrf_digest: [u8; 32],
    /// The route requires an enrolled second factor.
    pub require_totp: bool,
    /// The revision the editor saw.
    pub expected_revision: u64,
    /// The new document, 1 to [`MAX_DOCUMENT`] bytes.
    pub document: Text<MAX_DOCUMENT>,
    /// The client address; empty when unknown.
    pub client: Text<48>,
}

/// What a policy read returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selection {
    /// Catalog entries after this rule id (empty for the first page).
    Catalog(Text<128>),
    /// One rule's document. With `previous`, the newest recorded revision below
    /// `revision` for this rule.
    Document {
        /// The rule id.
        id: Text<128>,
        /// The revision, or `None` for the current one.
        revision: Option<u64>,
        /// Read the revision before `revision`.
        previous: bool,
    },
    /// One rule's revision history.
    History {
        /// The rule id.
        id: Text<128>,
        /// Revisions before this one.
        before: Option<u64>,
    },
}

/// A policy read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Read {
    /// SHA-256 of the session cookie or bearer token.
    pub session_digest: [u8; 32],
    /// The route requires an enrolled second factor.
    pub require_totp: bool,
    /// The committed revision the reader knows.
    pub committed: Option<u64>,
    /// What to read.
    pub selection: Selection,
}

/// A policy document and its revision.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Document {
    /// The revision.
    pub revision: u64,
    /// The document.
    pub document: Text<MAX_DOCUMENT>,
}

/// Checks a policy read. Identifier lengths are guaranteed by the field types.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for an oversized revision or an empty rule id.
pub fn validate_read(input: &Read) -> Result<(), ValidationError> {
    limit(input.committed.unwrap_or(0) > MAX_I64)?;
    match &input.selection {
        Selection::Catalog(_) => Ok(()),
        Selection::Document { id, revision, .. } => {
            limit(id.is_empty() || revision.unwrap_or(0) > MAX_I64)
        }
        Selection::History { id, before } => limit(id.is_empty() || before.unwrap_or(0) > MAX_I64),
    }
}

/// Checks a catalog query.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for an offset above 128 or an oversized revision.
pub fn validate(query: &Query) -> Result<(), ValidationError> {
    limit(query.offset > 128 || query.applied.unwrap_or(0) > MAX_I64)
}

/// Checks a policy test.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for an invalid query, an empty path or address, too
/// many headers, a JA4 value that is neither empty nor a fingerprint, a draft without a
/// committed revision (or the reverse), an oversized revision or an empty draft.
pub fn validate_test(input: &Test) -> Result<(), ValidationError> {
    validate(&input.query)?;
    limit(input.path.is_empty() || input.ip.is_empty() || input.headers.len() > MAX_HEADERS)?;
    limit(!input.ja4.is_empty() && !ja4::is_fingerprint(input.ja4.as_str()))?;
    limit(input.draft.is_some() != input.committed.is_some())?;
    limit(input.committed.unwrap_or(0) > MAX_I64)?;
    limit(input.draft.as_ref().is_some_and(Text::is_empty))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tests_need_a_request_and_a_complete_draft() {
        let test = Test {
            path: Text::new("/").unwrap(),
            ip: Text::new("::1").unwrap(),
            ..Test::default()
        };
        assert_eq!(validate_test(&test), Ok(()));
        let draft = Test { draft: Some(Text::default()), committed: Some(1), ..test.clone() };
        assert_eq!(validate_test(&draft), Err(ValidationError::InvalidLimit));
        let half = Test { committed: Some(1), ..test.clone() };
        assert_eq!(validate_test(&half), Err(ValidationError::InvalidLimit));
        let headers = Test { headers: vec![Header::default(); 9], ..test.clone() };
        assert_eq!(validate_test(&headers), Err(ValidationError::InvalidLimit));
        let fingerprint = |text: &str| Test { ja4: Text::new(text).unwrap(), ..test.clone() };
        assert_eq!(validate_test(&fingerprint("t13d1516h2_8daaf6152771_02713d6af862")), Ok(()));
        let prefix = fingerprint("t13d*");
        assert_eq!(validate_test(&prefix), Err(ValidationError::InvalidLimit));
        let read = Read {
            session_digest: [0; 32],
            require_totp: false,
            committed: None,
            selection: Selection::History { id: Text::default(), before: None },
        };
        assert_eq!(validate_read(&read), Err(ValidationError::InvalidLimit));
        assert_eq!(
            validate(&Query { offset: 129, ..Query::default() }),
            Err(ValidationError::InvalidLimit)
        );
    }
}
