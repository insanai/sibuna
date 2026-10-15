//! Audit views: recorded metadata and redacted summaries only.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::access::Role;
use crate::codec::{
    Decode, DecodeError, DecodeErrorKind, Encode, Fields, Path, counter_field, field,
};
use crate::error::{MAX_I64, ValidationError, limit};
use crate::text::Text;
use crate::users;

/// Rows per audit page.
pub const PAGE_ROWS: usize = 8;
/// The largest audit id.
pub const LAST_ID: u64 = MAX_I64;

/// A page of audit rows, newest first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    /// The administrator's credential.
    pub auth: users::Auth,
    /// Rows with smaller ids.
    pub before: u64,
    /// One actor, or `None` for all.
    pub actor: Option<u64>,
    /// One action ([`valid_action`]), or empty for all.
    pub action: Text<48>,
    /// The earliest time, in Unix seconds.
    pub since: u64,
    /// The latest time, in Unix seconds.
    pub until: u64,
    /// An audited export rather than a view.
    pub export_page: bool,
}

impl Default for Query {
    fn default() -> Query {
        Query {
            auth: users::Auth::default(),
            before: LAST_ID,
            actor: None,
            action: Text::default(),
            since: 0,
            until: LAST_ID,
            export_page: false,
        }
    }
}

/// Reads one row with its before and after summaries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Read {
    /// The administrator's credential.
    pub auth: users::Auth,
    /// The row id, 1 to [`LAST_ID`].
    pub id: u64,
}

/// One audit row.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Row {
    /// The row id.
    pub id: u64,
    /// The acting account; zero for the system.
    pub actor: u64,
    /// The changed object's id or revision.
    pub subject: u64,
    /// When it was recorded, in Unix seconds.
    pub recorded_at: u64,
    /// The action, such as `policy.edit`.
    pub action: Text<48>,
    /// The changed object's name.
    pub target: Option<Text<128>>,
    /// The actor's role at the time.
    pub actor_role: Option<Role>,
    /// The client address for sign-in, sign-out, refused sign-in and management mutations;
    /// `None` for rows written without a request.
    pub client_ip: Option<Text<48>>,
}

/// A policy revision an audit row may link to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyRevision {
    /// The rule id.
    pub id: Text<128>,
    /// The revision.
    pub revision: u64,
}

impl Row {
    /// Returns the policy revision this row links to: only a `policy.edit` row with a valid
    /// revision and a complete identifier of ASCII letters, digits, `-` and `_`. The result
    /// owns its bytes, so changing the selected row cannot retarget a request.
    pub fn policy_revision(&self) -> Option<PolicyRevision> {
        if self.action != "policy.edit" || self.subject == 0 || self.subject > LAST_ID {
            return None;
        }
        let target = self.target.as_ref().filter(|target| !target.is_empty())?;
        let plain = |byte: &u8| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_';
        if !target.as_bytes().iter().all(plain) {
            return None;
        }
        Some(PolicyRevision { id: target.clone(), revision: self.subject })
    }
}

impl Encode for Row {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        counter_field(json, "id", self.id)?;
        counter_field(json, "actor", self.actor)?;
        counter_field(json, "subject", self.subject)?;
        counter_field(json, "recorded_at", self.recorded_at)?;
        field(json, "action", &self.action)?;
        field(json, "target", &self.target)?;
        field(json, "actor_role", &self.actor_role)?;
        field(json, "client_ip", &self.client_ip)?;
        json.end_object()
    }
}

impl Decode for Row {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Row, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let row = Row {
            id: fields.or_default("id")?,
            actor: fields.or_default("actor")?,
            subject: fields.or_default("subject")?,
            recorded_at: fields.or_default("recorded_at")?,
            action: fields.or_default("action")?,
            target: fields.or_default("target")?,
            actor_role: fields.or_default("actor_role")?,
            client_ip: fields.or_default("client_ip")?,
        };
        fields.finish()?;
        Ok(row)
    }
}

/// A page of audit rows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Page {
    /// At most [`PAGE_ROWS`] rows.
    pub rows: Vec<Row>,
    /// The id to continue before, if more rows exist.
    pub next: Option<u64>,
}

impl Encode for Page {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        users::encode_page(json, &self.rows, self.next)
    }
}

impl Decode for Page {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Page, DecodeError> {
        let (rows, next) = users::decode_page(value, path, PAGE_ROWS)?;
        Ok(Page { rows, next })
    }
}

/// One row with its redacted before and after summaries (version 1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Detail {
    /// The row.
    pub row: Row,
    /// The summary before the change.
    pub before: Option<Text<1024>>,
    /// The summary after the change.
    pub after: Option<Text<1024>>,
    /// The before summary was truncated.
    pub before_truncated: bool,
    /// The after summary was truncated.
    pub after_truncated: bool,
    /// Secrets were redacted from the before summary.
    pub before_redacted: bool,
    /// Secrets were redacted from the after summary.
    pub after_redacted: bool,
}

impl Encode for Detail {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "version", &1u8)?;
        field(json, "row", &self.row)?;
        field(json, "before", &self.before)?;
        field(json, "before_truncated", &self.before_truncated)?;
        field(json, "before_redacted", &self.before_redacted)?;
        field(json, "after", &self.after)?;
        field(json, "after_truncated", &self.after_truncated)?;
        field(json, "after_redacted", &self.after_redacted)?;
        json.end_object()
    }
}

impl Decode for Detail {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Detail, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        if fields.required::<u8>("version")? != 1 {
            let path = path.key("version");
            return Err(DecodeError::new(path, DecodeErrorKind::Invalid("the version must be 1")));
        }
        let detail = Detail {
            row: fields.required("row")?,
            before: fields.required("before")?,
            before_truncated: fields.required("before_truncated")?,
            before_redacted: fields.required("before_redacted")?,
            after: fields.required("after")?,
            after_truncated: fields.required("after_truncated")?,
            after_redacted: fields.required("after_redacted")?,
        };
        fields.finish()?;
        Ok(detail)
    }
}

/// Checks an audit query.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for an oversized cursor, actor or time, an inverted
/// range, or an invalid action.
pub fn validate(input: &Query) -> Result<(), ValidationError> {
    limit(input.before > LAST_ID || input.since > input.until || input.until > LAST_ID)?;
    limit(input.actor.is_some_and(|actor| actor > LAST_ID))?;
    limit(!valid_action(input.action.as_str()))
}

/// Returns true for an action filter of at most 48 lowercase ASCII letters, digits, `.`
/// and `_`; the empty filter is valid.
pub fn valid_action(value: &str) -> bool {
    value.len() <= 48
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'_'
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_json, to_json};

    // Port of audit.zig "audit navigation requires an exact policy action, complete
    // identifier and valid revision".
    #[test]
    fn audit_navigation_requires_an_exact_policy_action_complete_identifier_and_valid_revision() {
        let mut row = Row {
            action: Text::new("policy.edit").unwrap(),
            target: Some(Text::new(&format!("policy-{}", "a".repeat(121))).unwrap()),
            subject: LAST_ID,
            ..Row::default()
        };
        let reference = row.policy_revision().unwrap();
        row.target.as_mut().unwrap().set("different").unwrap();
        assert_eq!(reference.id.len(), 128);
        assert_eq!(reference.revision, LAST_ID);
        row.action.set("user.update").unwrap();
        assert!(row.policy_revision().is_none());
        row.action.set("policy.edit").unwrap();
        row.subject = 0;
        assert!(row.policy_revision().is_none());
        row.subject = 1;
        row.target.as_mut().unwrap().set("<script>").unwrap();
        assert!(row.policy_revision().is_none());
    }

    #[test]
    fn details_round_trip() {
        let detail = Detail {
            row: Row {
                id: 4,
                action: Text::new("login").unwrap(),
                actor_role: Some(Role::Admin),
                client_ip: Some(Text::new("192.0.2.9").unwrap()),
                ..Row::default()
            },
            before: None,
            after: Some(Text::new("{\"name\":\"x\"}").unwrap()),
            after_redacted: true,
            ..Detail::default()
        };
        let text = to_json(&detail);
        assert_eq!(
            text,
            "{\"version\":1,\"row\":{\"id\":4,\"actor\":0,\"subject\":0,\"recorded_at\":0,\
             \"action\":\"login\",\"target\":null,\"actor_role\":\"admin\",\
             \"client_ip\":\"192.0.2.9\"},\"before\":null,\"before_truncated\":false,\
             \"before_redacted\":false,\"after\":\"{\\\"name\\\":\\\"x\\\"}\",\
             \"after_truncated\":false,\"after_redacted\":true}"
        );
        assert_eq!(from_json::<Detail>(text.as_bytes()), Ok(detail));
        assert_eq!(validate(&Query::default()), Ok(()));
        let bad = Query { action: Text::new("Policy").unwrap(), ..Query::default() };
        assert_eq!(validate(&bad), Err(ValidationError::InvalidLimit));
    }
}
