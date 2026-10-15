//! Retained ranking archives: one immutable archive per page, newest first, with a
//! descending minute and digest cursor.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::codec::{
    Decode, DecodeError, DecodeErrorKind, Encode, Fields, Path, counter_field, field,
    zig_byte_string_value,
};
use crate::error::{MAX_I64, ValidationError, limit};
use crate::ranking_storage;
use crate::text::Text;

/// A response body: the hex archive plus bounded metadata.
pub const RESPONSE_BYTES: usize = ranking_storage::MAX_BYTES * 2 + 1024;
/// A browser event: the response plus the event envelope.
pub const EVENT_BYTES: usize = RESPONSE_BYTES + 3072;
/// The longest window, in minutes.
const MAX_WINDOW_MINUTES: u64 = 90 * 1440;

/// A position in the descending archive scan: minute, then digest.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Cursor {
    /// The archived minute.
    pub minute: u64,
    /// The archive's SHA-256 as 64 lowercase hex digits.
    pub digest: Text<64>,
}

impl Encode for Cursor {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        counter_field(json, "minute", self.minute)?;
        field(json, "digest", &self.digest)?;
        json.end_object()
    }
}

impl Decode for Cursor {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Cursor, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let cursor =
            Cursor { minute: fields.required("minute")?, digest: fields.required("digest")? };
        fields.finish()?;
        Ok(cursor)
    }
}

/// A history request as the browser posts it. Its cursor's minute is a plain number, as
/// Zig's default serializer wrote the anonymous form struct.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Form {
    /// The first minute.
    pub from_minute: u64,
    /// The last minute.
    pub until_minute: u64,
    /// One node, or `None` for all.
    pub node: Option<u32>,
    /// Continue before this position.
    pub before: Option<Cursor>,
}

impl Encode for Form {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "from_minute", &self.from_minute)?;
        field(json, "until_minute", &self.until_minute)?;
        field(json, "node", &self.node)?;
        json.key("before")?;
        match &self.before {
            Some(cursor) => {
                json.begin_object()?;
                field(json, "minute", &cursor.minute)?;
                field(json, "digest", &cursor.digest)?;
                json.end_object()?;
            }
            None => json.null()?,
        }
        json.end_object()
    }
}

impl Decode for Form {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Form, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = Form {
            from_minute: fields.required("from_minute")?,
            until_minute: fields.required("until_minute")?,
            node: fields.or_default("node")?,
            before: fields.or_with("before", None, decode_form_cursor)?,
        };
        fields.finish()?;
        Ok(form)
    }
}

/// Reads a form cursor as Zig's typed parse read its anonymous struct, whose digest was a
/// `[]const u8`; a digest longer than 64 bytes is refused.
fn decode_form_cursor(value: &Value<'_>, path: Path<'_>) -> Result<Option<Cursor>, DecodeError> {
    if value.is_null() {
        return Ok(None);
    }
    let mut fields = Fields::new(value, path)?;
    let minute = fields.required("minute")?;
    let digest = fields.required_with("digest", zig_byte_string_value)?;
    fields.finish()?;
    let digest = Text::from_string(digest)
        .map_err(|_| DecodeError::new(path.key("digest"), DecodeErrorKind::TooLong { max: 64 }))?;
    Ok(Some(Cursor { minute, digest }))
}

/// A history request as storage receives it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Request {
    /// The first minute.
    pub from_minute: u64,
    /// The last minute.
    pub until_minute: u64,
    /// One node, or `None` for all (node 0 includes retired nodes).
    pub node: Option<u32>,
    /// Continue before this position.
    pub before: Option<Cursor>,
}

impl From<Form> for Request {
    fn from(form: Form) -> Request {
        Request {
            from_minute: form.from_minute,
            until_minute: form.until_minute,
            node: form.node,
            before: form.before,
        }
    }
}

/// A history query.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Query {
    /// SHA-256 of the session cookie or bearer token.
    pub session_digest: [u8; 32],
    /// The route requires an enrolled second factor.
    pub require_totp: bool,
    /// The frozen range boundary, in Unix seconds.
    pub observed_at: u64,
    /// The scope.
    pub request: Request,
}

/// One archive page. The receiver owns the payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Page {
    /// The first minute.
    pub from_minute: u64,
    /// The last minute.
    pub until_minute: u64,
    /// The retention in force, in days.
    pub retention_days: u16,
    /// The frozen range boundary, in Unix seconds.
    pub observed_at: u64,
    /// The archive's position.
    pub cursor: Option<Cursor>,
    /// Where the next page continues.
    pub next: Option<Cursor>,
    /// The archive bytes, at most [`ranking_storage::MAX_BYTES`].
    pub payload: Vec<u8>,
}

/// Checks a history query: a closed, ended window of less than 90 days, a node other than
/// zero when given, and a cursor inside the window with a lowercase hex digest.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] otherwise.
pub fn validate(query: &Query) -> Result<(), ValidationError> {
    let input = &query.request;
    limit(
        query.observed_at > MAX_I64
            || input.from_minute > input.until_minute
            || input.until_minute >= query.observed_at / 60
            || input.until_minute - input.from_minute >= MAX_WINDOW_MINUTES
            || input.node == Some(0),
    )?;
    let Some(cursor) = &input.before else { return Ok(()) };
    limit(
        cursor.minute < input.from_minute
            || cursor.minute > input.until_minute
            || cursor.digest.len() != 64
            || !cursor
                .digest
                .as_bytes()
                .iter()
                .all(|&b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
    )
}

/// Returns true when `a` comes strictly before `b`: by minute, then digest bytes.
pub fn precedes(a: &Cursor, b: &Cursor) -> bool {
    (a.minute, a.digest.as_bytes()) < (b.minute, b.digest.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_json, to_json};

    fn cursor(minute: u64, digit: char) -> Cursor {
        Cursor { minute, digest: Text::new(&digit.to_string().repeat(64)).unwrap() }
    }

    #[test]
    fn queries_are_closed_bounded_windows() {
        let request = Request {
            from_minute: 1,
            until_minute: 2,
            node: Some(1),
            before: Some(cursor(2, 'a')),
        };
        let query = Query { observed_at: 180, request, ..Query::default() };
        assert_eq!(validate(&query), Ok(()));
        let mut open = query.clone();
        open.observed_at = 179;
        assert!(validate(&open).is_err());
        let mut upper = query.clone();
        upper.request.before = Some(cursor(2, 'A'));
        assert!(validate(&upper).is_err());
        let mut zero = query;
        zero.request.node = Some(0);
        assert!(validate(&zero).is_err());
        assert!(precedes(&cursor(1, 'f'), &cursor(2, '0')));
        assert!(precedes(&cursor(2, '0'), &cursor(2, '1')));
    }

    #[test]
    fn forms_write_plain_minutes() {
        let form =
            Form { from_minute: 1, until_minute: 2, node: None, before: Some(cursor(2, 'b')) };
        let text = to_json(&form);
        assert_eq!(
            text,
            format!(
                "{{\"from_minute\":1,\"until_minute\":2,\"node\":null,\"before\":{{\"minute\":2,\
                 \"digest\":\"{}\"}}}}",
                "b".repeat(64)
            )
        );
        assert_eq!(from_json::<Form>(text.as_bytes()), Ok(form.clone()));
        assert_eq!(Request::from(form).before, Some(cursor(2, 'b')));
    }
}
