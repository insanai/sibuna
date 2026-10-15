//! The request pipeline (Zig's `App.dispatch`, `routePrincipal`, `executeRoute` and the
//! route-group modules `access_routes.zig`, `observation_routes.zig` and
//! `security_routes.zig`).
//!
//! Every request passes these steps in this order:
//!
//! 1. Ingress: behind a proxy, only a trusted network with `X-Forwarded-Proto: https`
//!    (403 `CONSOLE403`).
//! 2. The deadline moves to the storage wait plus two seconds: the head has arrived, and the
//!    request may now wait for storage and reply.
//! 3. The world geometry, for signed-in accounts without restrictions and not for tokens.
//! 4. Digest-named assets, then the shell for `/console` and `/console/`.
//! 5. Route lookup: an unknown `/console/api/*` (or any non-`GET`) is a JSON 404
//!    `CONSOLE404`; another unknown `GET` under `/console/` is the shell, so the interface
//!    can route client-side (SID 0007, "Router"; Zig answered 404 for both).
//! 6. A bearer token on a route without a token scope: 403 `CONSOLE403`.
//! 7. A `POST` must carry an `Origin` equal to the canonical origin; a bearer request may
//!    omit it (400 `CONSOLE002`).
//! 8. Non-public routes: the credential is resolved by storage, touching a browser session
//!    (401 `CONSOLE401`, or 503 `CONSOLEQUORUM` when storage cannot answer); a restricted
//!    account (password change or required second factor) reaches only account routes; the
//!    token scope, the role's action and the kiosk flag are checked (403 `CONSOLE403`).
//! 9. A cookie `POST` presents the session's CSRF token (400 `CONSOLE002`), and a mutation
//!    spends the session's allowance of 60 per minute (429 `CONSOLEMUTATION`).
//!
//! Then the route's handler runs with a [`Call`]. The setup status, session and about
//! replies are served here; every other handler belongs to a module of [`crate::api`].

use sibuna_console_protocol::codec::{Encode, counter_field, field};
use sibuna_console_protocol::storage::Failure;
use sibuna_console_protocol::{AuthorizationCheck, CredentialKind, Principal, Text, users};
use sibuna_console_storage::access::{self, Credential};
use sibuna_console_storage::accounts::is_setup_required;
use sibuna_crypto::ct;
use sibuna_http::Method;
use sibuna_json::Writer;
use sibuna_serve::{Context, ServeError};

use crate::api;
use crate::assets::{ROOT, WORLD_PATH};
use crate::http::credential::{self, Presented};
use crate::http::origin::Origin;
use crate::http::{RouteError, reply};
use crate::limits::Spend;
use crate::routes::{self, Access, Handler, Route};
use crate::shared::Shared;
use crate::storage::{HTTP_WAIT, StorageFailure};

/// What a route handler receives besides the shared state and the connection: the route,
/// who called, with which credential, from where, and the time read once for the request.
#[derive(Clone, Debug)]
pub struct Call {
    /// The matched route.
    pub route: &'static Route,
    /// The principal storage resolved; `None` on public routes.
    pub principal: Option<Principal>,
    /// The credential the request presented; `None` on public routes.
    pub presented: Option<Presented>,
    /// The client address and User-Agent digest, captured before any body was read.
    pub origin: Origin,
    /// The request's time in Unix seconds.
    pub now: u64,
}

impl Call {
    /// Returns the principal.
    ///
    /// Fails with [`RouteError::Unavailable`] on a public route, which has none; handlers
    /// of authenticated routes always have one.
    pub fn principal(&self) -> Result<&Principal, RouteError> {
        self.principal.as_ref().ok_or(RouteError::Unavailable)
    }

    /// Returns the authorization block a management request carries to storage (Zig's
    /// `origin.authority`): the credential digest, the principal's CSRF digest, whether
    /// administrators must have a second factor (behind a proxy), and the client address.
    ///
    /// Fails with [`RouteError::Unavailable`] on a public route.
    pub fn auth(&self, shared: &Shared) -> Result<users::Auth, RouteError> {
        let (Some(principal), Some(presented)) = (&self.principal, &self.presented) else {
            return Err(RouteError::Unavailable);
        };
        Ok(users::Auth {
            session_digest: presented.digest,
            csrf_digest: principal.csrf_digest,
            require_totp: shared.config.behind_proxy,
            client: Text::new(&self.origin.client).unwrap_or_default(),
        })
    }

    /// Returns the credential storage functions recheck inside their transaction (S37).
    ///
    /// Fails with [`RouteError::Unavailable`] on a public route.
    pub fn credential(&self, shared: &Shared) -> Result<Credential, RouteError> {
        let kind = self.presented.as_ref().map_or(CredentialKind::Session, |p| p.kind);
        Ok(Credential::new(kind, &self.auth(shared)?))
    }
}

/// Serves one request. Route errors are answered with their failure body; a failed
/// connection is returned to the listener.
pub(crate) fn handle(shared: &Shared, context: &mut Context<'_>) -> Result<(), ServeError> {
    match dispatch(shared, context) {
        Ok(()) => Ok(()),
        Err(RouteError::Serve(error)) => Err(error),
        Err(error) => match error.reply() {
            Some((status, code)) => reply::fail(context, status, code),
            None => Ok(()),
        },
    }
}

fn dispatch(shared: &Shared, context: &mut Context<'_>) -> Result<(), RouteError> {
    let forwarded =
        if shared.config.behind_proxy { context.header(b"X-Forwarded-Proto")? } else { None };
    if !shared.ingress.accepts(context.peer().ip(), forwarded) {
        return Err(RouteError::fail(403, "CONSOLE403"));
    }
    context.extend(HTTP_WAIT.as_secs() + 2);
    if serve_files(shared, context)? {
        return Ok(());
    }
    let Some(route) = routes::find(context.target(), context.method()) else {
        return fallback(shared, context);
    };
    let call = authenticate(shared, context, route)?;
    execute(shared, context, &call)
}

/// Serves the world geometry, a digest-named asset or the shell, and returns true; returns
/// false for any other request.
fn serve_files(shared: &Shared, context: &mut Context<'_>) -> Result<bool, RouteError> {
    let get = context.method() == Method::Get;
    if get && context.target() == WORLD_PATH.as_bytes() {
        world(shared, context)?;
        return Ok(true);
    }
    if shared.assets.serve(context)? {
        return Ok(true);
    }
    if get && matches!(context.target(), b"/console" | b"/console/") {
        shell(shared, context)?;
        return Ok(true);
    }
    Ok(false)
}

/// The world geometry: signed-in, unrestricted accounts only, never tokens.
fn world(shared: &Shared, context: &mut Context<'_>) -> Result<(), RouteError> {
    let presented = credential::presented(context).map_err(|_| unauthorized())?;
    let principal = authorize(shared, &presented)?;
    if shared.is_restricted(&principal) || principal.token_id.is_some() {
        return Err(forbidden());
    }
    let world = shared.assets.world();
    Ok(context.respond(200, b"application/octet-stream", world, &[])?)
}

fn shell(shared: &Shared, context: &mut Context<'_>) -> Result<(), RouteError> {
    let shell = shared.assets.shell();
    Ok(context.respond_cached(200, b"text/html; charset=utf-8", shell, b"no-cache", &[])?)
}

/// An unknown route: the shell for an interface path, otherwise a JSON 404.
fn fallback(shared: &Shared, context: &mut Context<'_>) -> Result<(), RouteError> {
    let target = context.target();
    let interface = context.method() == Method::Get
        && target.starts_with(b"/console/")
        && !target.starts_with(b"/console/api/")
        && !target.starts_with(ROOT.as_bytes());
    if interface {
        return shell(shared, context);
    }
    Err(RouteError::fail(404, "CONSOLE404"))
}

/// Steps 6 to 9: bearer admission, the origin check, the principal and the route checks.
fn authenticate(
    shared: &Shared,
    context: &mut Context<'_>,
    route: &'static Route,
) -> Result<Call, RouteError> {
    let bearer = context.header(b"Authorization")?.is_some();
    if bearer && route.token_scope.is_none() {
        return Err(forbidden());
    }
    if route.method == Method::Post {
        match context.header(b"Origin")? {
            Some(origin) if origin == shared.identity.origin.as_bytes() => {}
            None if bearer => {}
            _ => return Err(RouteError::BadRequest),
        }
    }
    let origin = Origin::capture(context, shared.config.behind_proxy);
    let now = shared.now();
    if route.access == Access::Public {
        return Ok(Call { route, principal: None, presented: None, origin, now });
    }
    let presented = credential::presented(context).map_err(|_| unauthorized())?;
    let principal = authorize(shared, &presented)?;
    check_route(shared, context, route, &presented, &principal, now)?;
    Ok(Call { route, principal: Some(principal), presented: Some(presented), origin, now })
}

/// Resolves `presented` through storage, moving a browser session's idle deadline.
fn authorize(shared: &Shared, presented: &Presented) -> Result<Principal, RouteError> {
    let check =
        AuthorizationCheck { session_digest: presented.digest, touch: true, kind: presented.kind };
    let now = shared.now();
    let resolved = shared
        .storage
        .transact(move |tx| Box::pin(async move { access::authorize(tx, &check, now).await }));
    match resolved {
        Ok(principal) => Ok(principal),
        // Storage could not answer: the credential is unknown, not rejected, so never 401.
        Err(StorageFailure::Console(error)) if error.failure() == Failure::Unavailable => {
            Err(RouteError::fail(503, "CONSOLEQUORUM"))
        }
        Err(StorageFailure::Console(_)) => Err(unauthorized()),
        Err(failure) => Err(failure.route_error("CONSOLEQUORUM")),
    }
}

/// The checks of Zig's `routePrincipal` once the principal is known.
fn check_route(
    shared: &Shared,
    context: &Context<'_>,
    route: &Route,
    presented: &Presented,
    principal: &Principal,
    now: u64,
) -> Result<(), RouteError> {
    let restricted = route.access == Access::Full && shared.is_restricted(principal);
    let scope_missing = principal.token_id.is_some()
        && route.token_scope.is_none_or(|scope| principal.scopes & scope.bit() == 0);
    let kiosk_refused = principal.kiosk && !route.kiosk;
    if restricted || scope_missing || kiosk_refused || !principal.role.allows(route.action) {
        return Err(forbidden());
    }
    if route.method == Method::Post {
        if principal.token_id.is_none() {
            credential::check_csrf(context, &principal.csrf_digest)?;
        }
        if route.mutation && !shared.query_budget.allow(&presented.digest, now, Spend::Mutation) {
            return Err(RouteError::fail(429, "CONSOLEMUTATION"));
        }
    }
    Ok(())
}

fn unauthorized() -> RouteError {
    RouteError::fail(401, "CONSOLE401")
}

fn forbidden() -> RouteError {
    RouteError::fail(403, "CONSOLE403")
}

/// Hands the request to the module that serves its handler.
fn execute(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    use Handler as H;
    let serve = match call.route.handler {
        H::SetupStatus => return setup_reply(shared, context),
        H::Session => return session_reply(shared, context, call),
        H::About => return about_reply(shared, context),
        H::Login | H::Logout | H::Password => api::session::handle,
        H::Totp => api::totp::handle,
        H::UsersQuery | H::UsersCreate | H::UsersChange => api::users::handle,
        H::TokensQuery | H::TokensCreate | H::TokensRevoke => api::tokens::handle,
        H::KioskToken | H::KioskExchange => api::kiosk::handle,
        H::AuditQuery | H::AuditRead | H::AuditExport => api::audit::handle,
        H::Policies | H::PoliciesTest | H::PolicyEdit | H::InspectionEdit | H::PolicyRead => {
            api::policies::handle
        }
        H::PolicyOrder
        | H::PolicyReplay
        | H::ReputationQuery
        | H::ReputationEdit
        | H::ReputationRemove
        | H::PolicyImport => api::workflows::handle,
        H::CountryPreview | H::CountryApply => api::country::handle,
        H::PagesRead | H::PagesEdit | H::PagesPreview | H::PagesPreviewGet => api::pages::handle,
        H::SettingsQuery | H::SettingsChange => api::settings::handle,
        H::NotificationsQuery
        | H::NotificationsSave
        | H::NotificationsRemove
        | H::NotificationsTest => api::notifications::handle,
        H::NodeStatus | H::NodesMembers | H::NodeCommand | H::NodeCommandRead => {
            api::nodes::handle
        }
        H::Events | H::EventsHeads | H::EventsSimilar => api::events::handle,
        H::EventsExport => api::export::handle,
        H::SecurityQuery | H::SecurityTrends => api::security::handle,
        H::ChallengeSummary | H::ChallengeRecords | H::ChallengeDifficulty => {
            api::challenges::handle
        }
        H::Minutes | H::MinuteSummary => api::minutes::handle,
        H::RuleHitHistory => api::rule_hits::handle,
        H::RankingHistory => api::ranking_history::handle,
        H::Stats | H::Timeline | H::Rankings | H::Challenges => api::live::handle,
        H::Stream => api::stream::handle,
        H::Peer => api::peer::handle,
        H::Geoip => api::geoip::handle,
    };
    serve(shared, context, call)
}

/// `{"setup_required":<bool>}`: true while no account exists.
fn setup_reply(shared: &Shared, context: &mut Context<'_>) -> Result<(), RouteError> {
    let required = shared.storage.transact(|tx| Box::pin(is_setup_required(tx)));
    let required = required.map_err(|failure| match failure {
        StorageFailure::Busy | StorageFailure::Deferred => RouteError::StorageBusy,
        StorageFailure::Timeout => RouteError::StorageTimeout,
        _ => RouteError::Unavailable,
    })?;
    Ok(reply::json(context, &SetupReply { setup_required: required })?)
}

struct SetupReply {
    setup_required: bool,
}

impl Encode for SetupReply {
    fn encode<W: std::fmt::Write>(&self, json: &mut Writer<W>) -> std::fmt::Result {
        json.begin_object()?;
        field(json, "setup_required", &self.setup_required)?;
        json.end_object()
    }
}

/// The signed-in session: account, node, role, restrictions, expiry and its CSRF token.
fn session_reply(
    shared: &Shared,
    context: &mut Context<'_>,
    call: &Call,
) -> Result<(), RouteError> {
    let principal = call.principal()?;
    let mut raw = credential::session_token(context)?;
    let csrf = sibuna_encoding::hex::encode(&credential::csrf_token(&raw));
    ct::zeroize(&mut raw);
    let reply = SessionReply {
        user: principal.actor,
        node: shared.identity.node_id,
        role: principal.role,
        must_change: principal.must_change,
        expires: principal.expires,
        totp_required: shared.needs_totp(principal.role, principal.totp_enabled),
        kiosk: principal.kiosk,
        csrf,
    };
    // Zig wiped every reply buffer; this one holds the session's CSRF token.
    let mut body = sibuna_console_protocol::codec::to_json(&reply).into_bytes();
    let sent = reply::json_bytes(context, &body, &[]);
    ct::zeroize(&mut body);
    let mut token = reply.csrf.into_bytes();
    ct::zeroize(&mut token);
    Ok(sent?)
}

struct SessionReply {
    user: u64,
    node: u32,
    role: sibuna_console_protocol::Role,
    must_change: bool,
    expires: u64,
    totp_required: bool,
    kiosk: bool,
    csrf: String,
}

impl Encode for SessionReply {
    fn encode<W: std::fmt::Write>(&self, json: &mut Writer<W>) -> std::fmt::Result {
        json.begin_object()?;
        counter_field(json, "user", self.user)?;
        field(json, "node", &self.node)?;
        field(json, "role", &self.role)?;
        field(json, "must_change", &self.must_change)?;
        field(json, "expires", &self.expires)?;
        field(json, "totp_required", &self.totp_required)?;
        field(json, "kiosk", &self.kiosk)?;
        field(json, "csrf", &self.csrf)?;
        json.end_object()
    }
}

/// Version, node identity, binding and proxy facts; never secrets or key material.
fn about_reply(shared: &Shared, context: &mut Context<'_>) -> Result<(), RouteError> {
    let config = &shared.config;
    let reply = AboutReply {
        version: &shared.identity.version,
        node: shared.identity.node_id,
        schema: sibuna_console_storage::CONSOLE.latest(),
        origin: &shared.identity.origin,
        advertise: &config.advertise,
        behind_proxy: config.behind_proxy,
        // Both lists are bounded far below 256 by `Config::validate`.
        trusted_proxies: u8::try_from(config.trusted_proxies.len()).unwrap_or(u8::MAX),
        probes: u8::try_from(config.probes.len()).unwrap_or(u8::MAX),
        cookie_secure: config.cookie_secure || config.behind_proxy,
        key_file: config.key_file.is_some(),
    };
    Ok(reply::json(context, &reply)?)
}

struct AboutReply<'a> {
    version: &'a str,
    node: u32,
    schema: u64,
    origin: &'a str,
    advertise: &'a str,
    behind_proxy: bool,
    trusted_proxies: u8,
    probes: u8,
    cookie_secure: bool,
    key_file: bool,
}

impl Encode for AboutReply<'_> {
    fn encode<W: std::fmt::Write>(&self, json: &mut Writer<W>) -> std::fmt::Result {
        json.begin_object()?;
        field(json, "version", self.version)?;
        field(json, "node", &self.node)?;
        field(json, "schema", &self.schema)?;
        field(json, "origin", self.origin)?;
        field(json, "advertise", self.advertise)?;
        field(json, "behind_proxy", &self.behind_proxy)?;
        field(json, "trusted_proxies", &self.trusted_proxies)?;
        field(json, "probes", &self.probes)?;
        field(json, "cookie_secure", &self.cookie_secure)?;
        field(json, "key_file", &self.key_file)?;
        json.end_object()
    }
}
