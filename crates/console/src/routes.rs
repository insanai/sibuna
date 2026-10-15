//! The route table (Zig's `routes.zig`): every API route with its authentication boundary,
//! least action, token scope, kiosk and mutation flags, and the handler that serves it.
//!
//! Two changes from Zig follow the decisions on the port: the legacy `/console/stream` route
//! is gone (SID 0007 revision note; the interface never used it), and a policy import is
//! the single route `policies/import` instead of `policies/import/chunk` and
//! `policies/import/commit` (SID 0013).
//!
//! Lookup is a linear scan of a `const` table comparing the exact request-target, as Zig
//! compared it; no route has parameters, so no pattern matching or allocation is needed.

use sibuna_console_protocol::Action;
use sibuna_console_protocol::tokens::Scope;
use sibuna_http::Method;

/// Who may reach a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Access {
    /// Anyone: sign-in, setup status, kiosk exchange, the peer upgrade.
    Public,
    /// A signed-in account, also one that must change its password or enroll a second
    /// factor first.
    Account,
    /// A signed-in account without such a restriction, or a token.
    Full,
}

/// The handler a route names. Each is served by exactly one module (see
/// [`crate::dispatch`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(missing_docs)] // The names are the routes' own; the table documents each.
pub enum Handler {
    ChallengeSummary,
    ChallengeRecords,
    ChallengeDifficulty,
    NodeStatus,
    NodesMembers,
    NodeCommand,
    NodeCommandRead,
    AuditQuery,
    AuditRead,
    AuditExport,
    TokensQuery,
    TokensCreate,
    TokensRevoke,
    UsersQuery,
    UsersCreate,
    UsersChange,
    Policies,
    PoliciesTest,
    PolicyEdit,
    InspectionEdit,
    PolicyRead,
    SetupStatus,
    Login,
    Session,
    Logout,
    Password,
    Stats,
    Timeline,
    Minutes,
    MinuteSummary,
    Rankings,
    RankingHistory,
    RuleHitHistory,
    Challenges,
    Events,
    EventsSimilar,
    EventsExport,
    EventsHeads,
    SecurityQuery,
    SecurityTrends,
    Stream,
    Peer,
    Geoip,
    Totp,
    KioskToken,
    KioskExchange,
    SettingsQuery,
    SettingsChange,
    NotificationsQuery,
    NotificationsSave,
    NotificationsRemove,
    NotificationsTest,
    PagesRead,
    PagesEdit,
    PagesPreview,
    PagesPreviewGet,
    PolicyOrder,
    PolicyReplay,
    ReputationQuery,
    ReputationEdit,
    ReputationRemove,
    CountryPreview,
    CountryApply,
    PolicyImport,
    About,
}

/// One route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Route {
    /// The exact request-target.
    pub path: &'static str,
    /// The method.
    pub method: Method,
    /// Who may reach it.
    pub access: Access,
    /// The least action the principal's role must allow.
    pub action: Action,
    /// The scope a bearer token needs; `None` refuses bearer tokens.
    pub token_scope: Option<Scope>,
    /// Spends the session's mutation allowance (60 per minute).
    pub mutation: bool,
    /// Kiosk sessions may use it.
    pub kiosk: bool,
    /// What serves it.
    pub handler: Handler,
}

impl Route {
    /// A public `GET` or `POST` route; the other fields are filled with struct update.
    const fn new(path: &'static str, method: Method, access: Access, handler: Handler) -> Route {
        Route {
            path,
            method,
            access,
            action: Action::Read,
            token_scope: None,
            mutation: false,
            kiosk: false,
            handler,
        }
    }
}

/// Every route; the order is Zig's, which `find` does not depend on.
pub const ROUTES: &[Route] = &ROUTE_TABLE;

const GET: Method = Method::Get;
const POST: Method = Method::Post;

const fn full(path: &'static str, method: Method, handler: Handler) -> Route {
    Route::new(path, method, Access::Full, handler)
}

const fn read(path: &'static str, handler: Handler, scope: Scope) -> Route {
    Route { token_scope: Some(scope), ..full(path, POST, handler) }
}

const fn manage(path: &'static str, action: Action, handler: Handler) -> Route {
    Route { action, ..full(path, POST, handler) }
}

const fn mutate(path: &'static str, action: Action, handler: Handler) -> Route {
    Route { action, mutation: true, ..full(path, POST, handler) }
}

const fn scoped(route: Route, scope: Scope) -> Route {
    Route { token_scope: Some(scope), ..route }
}

const fn kiosk(route: Route) -> Route {
    Route { kiosk: true, ..route }
}

use Action::{ControlNode, ManagePolicy, ManageSettings, ManageUsers, OpenKiosk};
use Handler as H;
use Scope::{
    EventsRead, GeoipRead, GeoipWrite, PolicyRead, PolicyWrite, StatsRead, UsersRead, UsersWrite,
};

const ROUTE_TABLE: [Route; 73] = [
    Route::new("/console/peer", GET, Access::Public, H::Peer),
    full("/console/api/nodes/local", GET, H::NodeStatus),
    scoped(full("/console/api/nodes", GET, H::NodesMembers), StatsRead),
    mutate("/console/api/nodes/command", ControlNode, H::NodeCommand),
    full("/console/api/nodes/command/read", POST, H::NodeCommandRead),
    full("/console/api/audit/query", POST, H::AuditQuery),
    full("/console/api/audit/read", POST, H::AuditRead),
    full("/console/api/audit/export", POST, H::AuditExport),
    manage("/console/api/tokens/query", ManageUsers, H::TokensQuery),
    mutate("/console/api/tokens/create", ManageUsers, H::TokensCreate),
    mutate("/console/api/tokens/revoke", ManageUsers, H::TokensRevoke),
    read("/console/api/users/query", H::UsersQuery, UsersRead),
    scoped(mutate("/console/api/users/create", ManageUsers, H::UsersCreate), UsersWrite),
    scoped(mutate("/console/api/users/change", ManageUsers, H::UsersChange), UsersWrite),
    read("/console/api/minutes", H::Minutes, StatsRead),
    read("/console/api/minutes/summary", H::MinuteSummary, StatsRead),
    kiosk(read("/console/api/timeline", H::Timeline, StatsRead)),
    scoped(mutate("/console/api/inspection/edit", ManagePolicy, H::InspectionEdit), PolicyWrite),
    read("/console/api/policies/hits", H::RuleHitHistory, PolicyRead),
    read("/console/api/rankings/history", H::RankingHistory, StatsRead),
    read("/console/api/rankings/query", H::Rankings, StatsRead),
    scoped(full("/console/api/rankings", GET, H::Rankings), StatsRead),
    read("/console/api/policies/read", H::PolicyRead, PolicyRead),
    scoped(mutate("/console/api/policies/edit", ManagePolicy, H::PolicyEdit), PolicyWrite),
    read("/console/api/policies/query", H::Policies, PolicyRead),
    read("/console/api/policies/test", H::PoliciesTest, PolicyRead),
    kiosk(read("/console/api/security/trends", H::SecurityTrends, StatsRead)),
    read("/console/api/security/query", H::SecurityQuery, EventsRead),
    read("/console/api/events/similar", H::EventsSimilar, EventsRead),
    read("/console/api/events/heads", H::EventsHeads, EventsRead),
    read("/console/api/challenges", H::Challenges, StatsRead),
    read("/console/api/challenges/summary", H::ChallengeSummary, StatsRead),
    read("/console/api/challenges/records", H::ChallengeRecords, StatsRead),
    read("/console/api/challenges/difficulty", H::ChallengeDifficulty, StatsRead),
    read("/console/api/events/export", H::EventsExport, EventsRead),
    read("/console/api/events/query", H::Events, EventsRead),
    manage("/console/api/settings/query", ManageSettings, H::SettingsQuery),
    mutate("/console/api/settings/change", ManageSettings, H::SettingsChange),
    manage("/console/api/notifications/query", ManageSettings, H::NotificationsQuery),
    mutate("/console/api/notifications/save", ManageSettings, H::NotificationsSave),
    mutate("/console/api/notifications/remove", ManageSettings, H::NotificationsRemove),
    mutate("/console/api/notifications/test", ManageSettings, H::NotificationsTest),
    scoped(mutate("/console/api/policies/order", ManagePolicy, H::PolicyOrder), PolicyWrite),
    read("/console/api/policies/replay", H::PolicyReplay, PolicyRead),
    read("/console/api/reputation/query", H::ReputationQuery, PolicyRead),
    scoped(mutate("/console/api/reputation/edit", ManagePolicy, H::ReputationEdit), PolicyWrite),
    scoped(
        mutate("/console/api/reputation/remove", ManagePolicy, H::ReputationRemove),
        PolicyWrite,
    ),
    scoped(
        manage("/console/api/geoip/country/preview", ManagePolicy, H::CountryPreview),
        PolicyWrite,
    ),
    scoped(mutate("/console/api/geoip/country/apply", ManagePolicy, H::CountryApply), PolicyWrite),
    scoped(mutate("/console/api/policies/import", ManagePolicy, H::PolicyImport), PolicyWrite),
    manage("/console/api/pages/read", ManageSettings, H::PagesRead),
    mutate("/console/api/pages/edit", ManageSettings, H::PagesEdit),
    mutate("/console/api/pages/preview", ManageSettings, H::PagesPreview),
    preview("/console/api/pages/preview/challenge"),
    preview("/console/api/pages/preview/denied"),
    preview("/console/api/pages/preview/rate_limited"),
    preview("/console/api/pages/preview/banned"),
    preview("/console/api/pages/preview/overloaded"),
    mutate("/console/api/kiosk/token", OpenKiosk, H::KioskToken),
    Route::new("/console/api/kiosk/exchange", POST, Access::Public, H::KioskExchange),
    Route::new("/console/api/setup", GET, Access::Public, H::SetupStatus),
    Route::new("/console/api/login", POST, Access::Public, H::Login),
    kiosk(Route::new("/console/api/session", GET, Access::Account, H::Session)),
    Route { action: ManageSettings, ..full("/console/api/about", GET, H::About) },
    kiosk(Route::new("/console/api/logout", POST, Access::Account, H::Logout)),
    Route::new("/console/api/password", POST, Access::Account, H::Password),
    kiosk(scoped(full("/console/api/stats", GET, H::Stats), StatsRead)),
    kiosk(full("/console/ws", GET, H::Stream)),
    scoped(full("/console/api/geoip", GET, H::Geoip), GeoipRead),
    Route {
        action: ManageSettings,
        token_scope: Some(GeoipWrite),
        mutation: true,
        ..full("/console/api/geoip", POST, H::Geoip)
    },
    Route::new("/console/api/totp", GET, Access::Account, H::Totp),
    Route::new("/console/api/totp/enroll", POST, Access::Account, H::Totp),
    Route::new("/console/api/totp/confirm", POST, Access::Account, H::Totp),
];

/// A page preview read: an administrator's `GET`.
const fn preview(path: &'static str) -> Route {
    Route { action: ManageSettings, ..full(path, GET, H::PagesPreviewGet) }
}

/// Returns the route for the exact request-target `target` and `method`, or `None`.
/// Bounded: one comparison per route, no allocation.
pub fn find(target: &[u8], method: Method) -> Option<&'static Route> {
    ROUTES.iter().find(|route| route.method == method && route.path.as_bytes() == target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_route_is_unique_and_found() {
        let routes: Vec<&Route> = ROUTES.iter().collect();
        assert_eq!(routes.len(), 73);
        for (index, route) in routes.iter().enumerate() {
            assert_eq!(find(route.path.as_bytes(), route.method), Some(*route));
            let twin = routes.iter().skip(index + 1);
            assert!(!twin.into_iter().any(|o| o.path == route.path && o.method == route.method));
            assert!(route.path.starts_with("/console/"));
            // Mutations are POSTs of signed-in principals, never kiosk routes.
            if route.mutation {
                assert_eq!((route.method, route.access), (Method::Post, Access::Full));
                assert!(!route.kiosk);
            }
            if let Some(scope) = route.token_scope {
                assert!(route.access == Access::Full);
                assert!(scope.action() == Action::Read || scope.action() == route.action);
            }
        }
    }

    #[test]
    fn the_decided_route_changes_hold() {
        assert!(find(b"/console/stream", Method::Get).is_none());
        assert!(find(b"/console/api/policies/import/chunk", Method::Post).is_none());
        assert!(find(b"/console/api/policies/import/commit", Method::Post).is_none());
        let import = find(b"/console/api/policies/import", Method::Post).unwrap();
        assert_eq!(import.token_scope, Some(PolicyWrite));
        assert!(import.mutation);
        assert!(find(b"/console/api/stats?x=1", Method::Get).is_none());
        assert!(find(b"/console/api/stats", Method::Post).is_none());
        let geoip = find(b"/console/api/geoip", Method::Post).unwrap();
        assert_eq!(geoip.token_scope, Some(GeoipWrite));
        assert_eq!(find(b"/console/api/session", Method::Get).map(|r| r.kiosk), Some(true));
    }
}
