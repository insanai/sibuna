//! Account management. Password plaintext never crosses the storage mailbox.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::access::{Role, valid_username};
use crate::codec::{
    Decode, DecodeError, DecodeErrorKind, Encode, Fields, Path, counter_field, decode_list, field,
    optional_counter, optional_counter_field,
};
use crate::error::{MAX_I64, ValidationError, limit};
use crate::text::Text;

/// The most accounts storage keeps.
pub const CAPACITY: usize = 1024;
/// Rows per account page.
pub const PAGE_ROWS: usize = 8;
/// How long a temporary password stays valid, in seconds.
pub const TEMPORARY_SECONDS: u64 = 3600;

/// The credential of a management request, checked again when storage executes it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Auth {
    /// SHA-256 of the session cookie or bearer token.
    pub session_digest: [u8; 32],
    /// SHA-256 of the CSRF token; zeros for reads.
    pub csrf_digest: [u8; 32],
    /// The route requires an enrolled second factor.
    pub require_totp: bool,
    /// Address presenting the credential for this request; empty when not captured.
    pub client: Text<48>,
}

/// A page of accounts after `after`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    /// The administrator's credential.
    pub auth: Auth,
    /// The last id of the previous page; zero for the first page.
    pub after: u64,
    /// Rows wanted, 1 to [`PAGE_ROWS`].
    pub limit: u8,
}

impl Default for Query {
    fn default() -> Query {
        Query { auth: Auth::default(), after: 0, limit: PAGE_ROWS as u8 }
    }
}

/// A new account.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Create {
    /// The administrator's credential.
    pub auth: Auth,
    /// The sign-in name ([`valid_username`]).
    pub username: Text<64>,
    /// The account's role.
    pub role: Role,
    /// The Argon2id PHC string; never the password.
    pub password_hash: Text<255>,
}

/// What an account change does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    /// Sets the role and the disabled flag.
    Access {
        /// The new role.
        role: Role,
        /// Disable sign-in.
        disabled: bool,
    },
    /// Sets a temporary password (its PHC string).
    Password(Text<255>),
    /// Ends every session of the account.
    Revoke,
}

/// A change to one account, fenced by its revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// The administrator's credential.
    pub auth: Auth,
    /// The account id.
    pub target: u64,
    /// The revision the administrator saw.
    pub expected_revision: u64,
    /// What to change.
    pub operation: Operation,
}

/// One account as the API lists it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Row {
    /// The account id.
    pub id: u64,
    /// The sign-in name.
    pub username: Text<64>,
    /// The account's role.
    pub role: Role,
    /// The account revision.
    pub revision: u64,
    /// Sign-in disabled.
    pub disabled: bool,
    /// The password must be changed at the next sign-in.
    pub must_change: bool,
    /// A second factor is enrolled.
    pub totp_enabled: bool,
    /// When the password expires, in Unix seconds; zero for never.
    pub password_expires: u64,
    /// The last successful sign-in, in Unix seconds.
    pub last_login: Option<u64>,
}

impl Encode for Row {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        counter_field(json, "id", self.id)?;
        field(json, "username", &self.username)?;
        field(json, "role", &self.role)?;
        counter_field(json, "revision", self.revision)?;
        field(json, "disabled", &self.disabled)?;
        field(json, "must_change", &self.must_change)?;
        field(json, "totp_enabled", &self.totp_enabled)?;
        counter_field(json, "password_expires", self.password_expires)?;
        optional_counter_field(json, "last_login", self.last_login)?;
        json.end_object()
    }
}

impl Decode for Row {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Row, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let row = Row {
            id: fields.or_default("id")?,
            username: fields.or_default("username")?,
            role: fields.or_default("role")?,
            revision: fields.or_default("revision")?,
            disabled: fields.or_default("disabled")?,
            must_change: fields.or_default("must_change")?,
            totp_enabled: fields.or_default("totp_enabled")?,
            password_expires: fields.or_default("password_expires")?,
            last_login: fields.or_default("last_login")?,
        };
        fields.finish()?;
        Ok(row)
    }
}

/// A page of accounts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Page {
    /// At most [`PAGE_ROWS`] rows.
    pub rows: Vec<Row>,
    /// The id to continue after, if more rows exist.
    pub next: Option<u64>,
}

impl Encode for Page {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        encode_page(json, &self.rows, self.next)
    }
}

impl Decode for Page {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Page, DecodeError> {
        let (rows, next) = decode_page(value, path, PAGE_ROWS)?;
        Ok(Page { rows, next })
    }
}

/// Writes the version-1 page envelope shared by accounts, tokens and audit rows:
/// `{"version":1,"rows":[...],"next":id|null}`.
pub(crate) fn encode_page<W: Write, T: Encode>(
    json: &mut Writer<W>,
    rows: &[T],
    next: Option<u64>,
) -> fmt::Result {
    json.begin_object()?;
    field(json, "version", &1u8)?;
    field(json, "rows", rows)?;
    json.key("next")?;
    optional_counter(json, next)?;
    json.end_object()
}

/// Reads the envelope [`encode_page`] writes.
pub(crate) fn decode_page<T: Decode>(
    value: &Value<'_>,
    path: Path<'_>,
    max_rows: usize,
) -> Result<(Vec<T>, Option<u64>), DecodeError> {
    let mut fields = Fields::new(value, path)?;
    if fields.required::<u8>("version")? != 1 {
        let path = path.key("version");
        return Err(DecodeError::new(path, DecodeErrorKind::Invalid("the version must be 1")));
    }
    let rows = fields.required_with("rows", |value, path| decode_list(value, path, max_rows))?;
    let next = fields.required("next")?;
    fields.finish()?;
    Ok((rows, next))
}

/// Checks a page query.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for an oversized cursor or a limit outside 1 to
/// [`PAGE_ROWS`].
pub fn validate_query(input: &Query) -> Result<(), ValidationError> {
    limit(input.after > MAX_I64 || input.limit == 0 || usize::from(input.limit) > PAGE_ROWS)
}

/// Checks an account creation. Lengths are guaranteed by the field types.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for an invalid name or an empty password hash.
pub fn validate_create(input: &Create) -> Result<(), ValidationError> {
    limit(!valid_username(input.username.as_str()) || input.password_hash.is_empty())
}

/// Checks an account change.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for a zero or oversized target or revision, or an
/// empty password hash.
pub fn validate_change(input: &Change) -> Result<(), ValidationError> {
    limit(
        input.target == 0
            || input.target > MAX_I64
            || input.expected_revision == 0
            || input.expected_revision >= MAX_I64,
    )?;
    match &input.operation {
        Operation::Password(hash) => limit(hash.is_empty()),
        Operation::Access { .. } | Operation::Revoke => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_json, to_json};

    #[test]
    fn pages_round_trip() {
        let page = Page {
            rows: vec![Row {
                id: 1,
                username: Text::new("admin").unwrap(),
                role: Role::Admin,
                revision: 2,
                last_login: Some(u64::MAX),
                ..Default::default()
            }],
            next: Some(1),
        };
        let text = to_json(&page);
        assert_eq!(
            text,
            "{\"version\":1,\"rows\":[{\"id\":1,\"username\":\"admin\",\"role\":\"admin\",\
             \"revision\":2,\"disabled\":false,\"must_change\":false,\"totp_enabled\":false,\
             \"password_expires\":0,\"last_login\":\"18446744073709551615\"}],\"next\":1}"
        );
        assert_eq!(from_json::<Page>(text.as_bytes()), Ok(page));
        let too_many =
            format!("{{\"version\":1,\"rows\":[{}],\"next\":null}}", ["{}"; 9].join(","));
        assert!(from_json::<Page>(too_many.as_bytes()).is_err());
    }

    #[test]
    fn requests_are_bounded() {
        assert_eq!(validate_query(&Query::default()), Ok(()));
        let query = Query { limit: 9, ..Default::default() };
        assert_eq!(validate_query(&query), Err(ValidationError::InvalidLimit));
        let create = Create {
            username: Text::new("ops").unwrap(),
            password_hash: Text::default(),
            ..Default::default()
        };
        assert_eq!(validate_create(&create), Err(ValidationError::InvalidLimit));
        let change = Change {
            auth: Auth::default(),
            target: 1,
            expected_revision: 1,
            operation: Operation::Password(Text::default()),
        };
        assert_eq!(validate_change(&change), Err(ValidationError::InvalidLimit));
    }
}
