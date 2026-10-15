//! API tokens. Automation permissions are explicit endpoint capabilities, independent of
//! browser roles. Credentials contain 256 random bits; records and mailboxes carry only
//! their digest.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::access::{Action, Role};
use crate::codec::{
    Decode, DecodeError, DecodeErrorKind, Encode, Fields, Path, WireEnum, counter_field,
    decode_list, field, optional_counter_field,
};
use crate::error::{MAX_I64, ValidationError, limit};
use crate::text::Text;
use crate::users;

/// The most tokens storage keeps.
pub const CAPACITY: usize = 1024;
/// Rows per token page.
pub const PAGE_ROWS: usize = 8;

/// One capability a token may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    /// Read statistics.
    StatsRead,
    /// Read events.
    EventsRead,
    /// Read policy.
    PolicyRead,
    /// Change policy.
    PolicyWrite,
    /// Read GeoIP metadata.
    GeoipRead,
    /// Load GeoIP data.
    GeoipWrite,
    /// Read accounts.
    UsersRead,
    /// Change accounts.
    UsersWrite,
}

impl Scope {
    /// Returns the role action this scope needs.
    pub fn action(self) -> Action {
        match self {
            Scope::PolicyWrite => Action::ManagePolicy,
            Scope::GeoipWrite => Action::ManageSettings,
            Scope::UsersWrite => Action::ManageUsers,
            _ => Action::Read,
        }
    }

    /// Returns this scope's bit in a scope set.
    pub fn bit(self) -> u32 {
        1 << self.ordinal()
    }
}

impl WireEnum for Scope {
    const ALL: &'static [Scope] = &[
        Scope::StatsRead,
        Scope::EventsRead,
        Scope::PolicyRead,
        Scope::PolicyWrite,
        Scope::GeoipRead,
        Scope::GeoipWrite,
        Scope::UsersRead,
        Scope::UsersWrite,
    ];

    fn name(self) -> &'static str {
        match self {
            Scope::StatsRead => "stats_read",
            Scope::EventsRead => "events_read",
            Scope::PolicyRead => "policy_read",
            Scope::PolicyWrite => "policy_write",
            Scope::GeoipRead => "geoip_read",
            Scope::GeoipWrite => "geoip_write",
            Scope::UsersRead => "users_read",
            Scope::UsersWrite => "users_write",
        }
    }
}

/// Every scope bit.
pub const KNOWN_SCOPES: u32 = (1 << Scope::ALL.len()) - 1;

/// A page of tokens after `after`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    /// The administrator's credential.
    pub auth: users::Auth,
    /// The last id of the previous page; zero for the first page.
    pub after: u64,
    /// Rows wanted, 1 to [`PAGE_ROWS`].
    pub limit: u8,
}

impl Default for Query {
    fn default() -> Query {
        Query { auth: users::Auth::default(), after: 0, limit: PAGE_ROWS as u8 }
    }
}

/// A new token; storage keeps only its digest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Create {
    /// The administrator's credential.
    pub auth: users::Auth,
    /// A display label.
    pub label: Text<64>,
    /// The token's role.
    pub role: Role,
    /// Scope bits, each allowed by `role`.
    pub scopes: u32,
    /// When the token expires, in Unix seconds; `None` for never.
    pub expires: Option<u64>,
    /// SHA-256 of the token.
    pub digest: [u8; 32],
}

/// Disables (and optionally removes) a token.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Revoke {
    /// The administrator's credential.
    pub auth: users::Auth,
    /// The token id.
    pub target: u64,
    /// The revision the administrator saw.
    pub expected_revision: u64,
    /// Remove inactive metadata; the redacted audit remains retained.
    pub remove: bool,
}

/// One token as the API lists it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Row {
    /// The token id.
    pub id: u64,
    /// The token revision.
    pub revision: u64,
    /// The display label.
    pub label: Text<64>,
    /// The token's role.
    pub role: Role,
    /// Scope bits.
    pub scopes: u32,
    /// The creating account.
    pub created_by: u64,
    /// When it was created, in Unix seconds.
    pub created_at: u64,
    /// When it expires, in Unix seconds; `None` for never.
    pub expires: Option<u64>,
    /// Disabled by an administrator.
    pub disabled: bool,
    /// Usable now: enabled, unexpired and its creator's role still allows it.
    pub active: bool,
}

impl Encode for Row {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        counter_field(json, "id", self.id)?;
        counter_field(json, "revision", self.revision)?;
        field(json, "label", &self.label)?;
        field(json, "role", &self.role)?;
        json.key("scopes")?;
        write_scopes(json, self.scopes)?;
        counter_field(json, "created_by", self.created_by)?;
        counter_field(json, "created_at", self.created_at)?;
        optional_counter_field(json, "expires", self.expires)?;
        field(json, "disabled", &self.disabled)?;
        field(json, "active", &self.active)?;
        json.end_object()
    }
}

impl Decode for Row {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Row, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let row = Row {
            id: fields.or_default("id")?,
            revision: fields.or_default("revision")?,
            label: fields.or_default("label")?,
            role: fields.or_default("role")?,
            scopes: fields.or_with("scopes", 0, decode_scopes)?,
            created_by: fields.or_default("created_by")?,
            created_at: fields.or_default("created_at")?,
            expires: fields.or_default("expires")?,
            disabled: fields.or_default("disabled")?,
            active: fields.or_default("active")?,
        };
        fields.finish()?;
        Ok(row)
    }
}

/// A page of tokens.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Page {
    /// At most [`PAGE_ROWS`] rows.
    pub rows: Vec<Row>,
    /// The id to continue after, if more rows exist.
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

/// Writes the scope set as an array of scope names in declaration order. Bits of unknown
/// scopes are not written.
///
/// # Errors
///
/// Returns the sink's error.
pub fn write_scopes<W: Write>(json: &mut Writer<W>, scopes: u32) -> fmt::Result {
    json.begin_array()?;
    for scope in Scope::ALL.iter().filter(|scope| scopes & scope.bit() != 0) {
        scope.encode(json)?;
    }
    json.end_array()
}

/// Reads an array of distinct scope names into scope bits.
///
/// # Errors
///
/// A [`DecodeError`] for an unknown or repeated name.
pub fn decode_scopes(value: &Value<'_>, path: Path<'_>) -> Result<u32, DecodeError> {
    let names: Vec<Scope> = decode_list(value, path, Scope::ALL.len())?;
    let mut scopes = 0;
    for scope in names {
        if scopes & scope.bit() != 0 {
            return Err(DecodeError::new(path, DecodeErrorKind::Invalid("a scope is repeated")));
        }
        scopes |= scope.bit();
    }
    Ok(scopes)
}

/// Returns true for a non-empty set of known scopes that `role` allows.
pub fn valid_scopes(scopes: u32, role: Role) -> bool {
    scopes != 0
        && scopes & !KNOWN_SCOPES == 0
        && Scope::ALL
            .iter()
            .filter(|scope| scopes & scope.bit() != 0)
            .all(|scope| role.allows(scope.action()))
}

/// Returns true for a label of 1 to 64 bytes without control characters that is not only
/// spaces.
pub fn valid_label(label: &str) -> bool {
    (1..=64).contains(&label.len())
        && !label.bytes().any(|byte| byte < 32 || byte == 127)
        && !label.trim_matches(' ').is_empty()
}

/// Checks a token creation.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for an invalid label, scope set or expiry.
pub fn validate_create(input: &Create) -> Result<(), ValidationError> {
    limit(!valid_label(input.label.as_str()) || !valid_scopes(input.scopes, input.role))?;
    limit(input.expires.is_some_and(|expires| expires == 0 || expires > MAX_I64))
}

/// Checks a revocation.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for a zero or oversized target or revision.
pub fn validate_revoke(input: &Revoke) -> Result<(), ValidationError> {
    limit(
        input.target == 0
            || input.target > MAX_I64
            || input.expected_revision == 0
            || input.expected_revision >= MAX_I64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_json, to_json};

    // Port of tokens.zig "token scopes reject unknown capabilities and permissions above
    // their role". The invalid UTF-8 label case cannot be expressed: labels are `str`.
    #[test]
    fn token_scopes_reject_unknown_capabilities_and_permissions_above_their_role() {
        assert!(valid_scopes(Scope::StatsRead.bit() | Scope::EventsRead.bit(), Role::Viewer));
        assert!(!valid_scopes(Scope::PolicyWrite.bit(), Role::Viewer));
        assert!(valid_scopes(Scope::PolicyRead.bit() | Scope::PolicyWrite.bit(), Role::Operator));
        assert!(!valid_scopes(Scope::UsersWrite.bit(), Role::Operator));
        assert!(valid_scopes(KNOWN_SCOPES, Role::Admin));
        assert!(!valid_scopes(0, Role::Admin));
        assert!(!valid_scopes(KNOWN_SCOPES + 1, Role::Admin));
        assert!(valid_label("production deploy \u{65e5}\u{672c}"));
        assert!(!valid_label("line\nbreak"));
        assert!(!valid_label("   "));
    }

    #[test]
    fn rows_round_trip_with_scope_names() {
        let row = Row {
            id: 3,
            revision: 9_007_199_254_740_993,
            label: Text::new("ci").unwrap(),
            role: Role::Operator,
            scopes: Scope::StatsRead.bit() | Scope::PolicyWrite.bit(),
            created_by: 1,
            created_at: 100,
            expires: None,
            disabled: false,
            active: true,
        };
        let text = to_json(&row);
        assert_eq!(
            text,
            "{\"id\":3,\"revision\":\"9007199254740993\",\"label\":\"ci\",\"role\":\"operator\",\
             \"scopes\":[\"stats_read\",\"policy_write\"],\"created_by\":1,\"created_at\":100,\
             \"expires\":null,\"disabled\":false,\"active\":true}"
        );
        assert_eq!(from_json::<Row>(text.as_bytes()), Ok(row));
        assert!(from_json::<Row>(br#"{"scopes":["stats_read","stats_read"]}"#).is_err());
    }

    #[test]
    fn creations_and_revocations_are_bounded() {
        let mut create = Create {
            label: Text::new("deploy").unwrap(),
            role: Role::Viewer,
            scopes: Scope::StatsRead.bit(),
            ..Default::default()
        };
        assert_eq!(validate_create(&create), Ok(()));
        create.expires = Some(0);
        assert_eq!(validate_create(&create), Err(ValidationError::InvalidLimit));
        let revoke = Revoke { target: 1, expected_revision: MAX_I64, ..Default::default() };
        assert_eq!(validate_revoke(&revoke), Err(ValidationError::InvalidLimit));
    }
}
