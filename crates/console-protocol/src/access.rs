//! Roles, actions and the authenticated principal.

use crate::codec::WireEnum;
use crate::text::Text;
use crate::tokens;

/// A console account's role. Each role allows a fixed set of [`Action`]s.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    /// Reads every page; changes nothing.
    #[default]
    Viewer,
    /// Also edits policy, controls nodes and opens kiosk sessions.
    Operator,
    /// Also manages users and settings.
    Admin,
}

impl Role {
    /// Returns true if this role may perform `action`.
    pub fn allows(self, action: Action) -> bool {
        match action {
            Action::Read => true,
            Action::ManagePolicy | Action::ControlNode | Action::OpenKiosk => self != Role::Viewer,
            Action::ManageUsers | Action::ManageSettings => self == Role::Admin,
        }
    }
}

impl WireEnum for Role {
    const ALL: &'static [Role] = &[Role::Viewer, Role::Operator, Role::Admin];

    fn name(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }
}

/// Something a principal may be allowed to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Read any page or API.
    Read,
    /// Edit, order, replay and import policy.
    ManagePolicy,
    /// Drain, resume or clear bans on a node.
    ControlNode,
    /// Create and change accounts and tokens.
    ManageUsers,
    /// Change settings, notifications and GeoIP data.
    ManageSettings,
    /// Mint a kiosk code.
    OpenKiosk,
}

impl WireEnum for Action {
    const ALL: &'static [Action] = &[
        Action::Read,
        Action::ManagePolicy,
        Action::ControlNode,
        Action::ManageUsers,
        Action::ManageSettings,
        Action::OpenKiosk,
    ];

    fn name(self) -> &'static str {
        match self {
            Action::Read => "read",
            Action::ManagePolicy => "manage_policy",
            Action::ControlNode => "control_node",
            Action::ManageUsers => "manage_users",
            Action::ManageSettings => "manage_settings",
            Action::OpenKiosk => "open_kiosk",
        }
    }
}

/// An account as storage returns it for sign-in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthUser {
    /// The account id.
    pub id: u64,
    /// The sign-in name.
    pub username: Text<64>,
    /// The Argon2id PHC string.
    pub password_hash: Text<255>,
    /// The account's role.
    pub role: Role,
    /// The account revision; any change invalidates its sessions.
    pub revision: u64,
    /// The password must be changed before anything else.
    pub must_change: bool,
    /// A second factor is enrolled.
    pub totp_enabled: bool,
    /// When the password expires, in Unix seconds; zero for never.
    pub password_expires: u64,
}

/// How a request presented its credential.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum CredentialKind {
    /// A browser session cookie.
    #[default]
    Session,
    /// An API bearer token.
    Bearer,
}

/// The identity storage resolved for a credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    /// The account's own role, for a token whose role may be lower.
    pub account_role: Option<Role>,
    /// The token id, for a bearer credential.
    pub token_id: Option<u64>,
    /// The token's scope bits ([`tokens::Scope::bit`]); every scope for a session.
    pub scopes: u32,
    /// The acting account id.
    pub actor: u64,
    /// The acting account's name.
    pub username: Text<64>,
    /// The effective role.
    pub role: Role,
    /// The account revision the credential was issued under.
    pub revision: u64,
    /// When the credential expires, in Unix seconds.
    pub expires: u64,
    /// SHA-256 of the session's CSRF token.
    pub csrf_digest: [u8; 32],
    /// The password must be changed before anything else.
    pub must_change: bool,
    /// A second factor is enrolled.
    pub totp_enabled: bool,
    /// A read-only wall-display session: viewer role, statistics scope, no mutations.
    pub kiosk: bool,
}

impl Default for Principal {
    fn default() -> Principal {
        Principal {
            account_role: None,
            token_id: None,
            scopes: tokens::KNOWN_SCOPES,
            actor: 0,
            username: Text::default(),
            role: Role::Viewer,
            revision: 0,
            expires: 0,
            csrf_digest: [0; 32],
            must_change: false,
            totp_enabled: false,
            kiosk: false,
        }
    }
}

/// A request to resolve a credential digest into a [`Principal`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuthorizationCheck {
    /// SHA-256 of the presented session cookie or bearer token.
    pub session_digest: [u8; 32],
    /// Extend the session's idle deadline.
    pub touch: bool,
    /// How the credential was presented.
    pub kind: CredentialKind,
}

/// Returns true for a sign-in name of 1 to 64 ASCII letters, digits, `_`, `-` and `.`.
pub fn valid_username(username: &str) -> bool {
    (1..=64).contains(&username.len())
        && username.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    // From root.zig "owned payload boundaries and pagination reject unbounded input".
    #[test]
    fn roles_allow_their_actions() {
        assert!(!Role::Viewer.allows(Action::ControlNode));
        assert!(!Role::Operator.allows(Action::ManageUsers));
        assert!(Role::Operator.allows(Action::OpenKiosk));
        assert!(Role::Admin.allows(Action::ManageSettings));
        assert!(Role::Viewer.allows(Action::Read));
    }

    #[test]
    fn usernames_are_short_and_plain() {
        assert!(valid_username("ops.admin-1_x"));
        assert!(valid_username(&"a".repeat(64)));
        assert!(!valid_username(&"a".repeat(65)));
        assert!(!valid_username(""));
        assert!(!valid_username("a b"));
        assert!(!valid_username("caf\u{e9}"));
        assert_eq!(Principal::default().scopes, tokens::KNOWN_SCOPES);
    }
}
