//! The routes `notifications/query`, `notifications/save`, `notifications/remove` and
//! `notifications/test` (Zig's `settings_routes.zig`).
//!
//! Administrators manage at most eight destinations in browser sessions only. A target is
//! checked before it is stored (a webhook is HTTPS to a public host, plain HTTP only to a
//! loopback literal; syslog is `host:port`), and checked again before every delivery by
//! the notifier. A secret is sealed on this thread under the console key, bound to the
//! target, and never echoed back. A test records its intent before the external request
//! and its result after it (S28).

use std::fmt::{self, Write};
use std::net::IpAddr;

use sibuna_console_protocol::Text;
use sibuna_console_protocol::codec::{
    Decode, DecodeError, Encode, Fields, Path, counter_field, field,
};
use sibuna_console_protocol::notifications::{
    Destination, Kind, MAX_DETAIL, MAX_SECRET, Outcome, Page, Read, Remove, Save, TestAudit,
    Transport,
};
use sibuna_console_storage::notifications::{
    Reader, query_destinations, record_test, remove_destination, save_destination,
};
use sibuna_crypto::ct;
use sibuna_crypto::sha256::Sha256;
use sibuna_json::{Value, Writer};
use sibuna_net::outbound::{self, Policy};
use sibuna_serve::Context;

use super::settings::settings_error;
use crate::auth::secrets::seal_bytes;
use crate::dispatch::Call;
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::routes::Handler;
use crate::shared::Shared;

/// The longest webhook URL Zig accepted, in bytes.
const MAX_URL: usize = 512;
/// The longest syslog address, in bytes.
const MAX_SYSLOG: usize = 255;

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with the [`RouteError`] the route answers with: `CONSOLESETTINGS` for refused
/// requests, 400 `CONSOLENOTIFYTARGET` for a target that may not be reached, 400
/// `CONSOLEKEYREQUIRED` for a secret without a console key, 503 `CONSOLENOTIFYFULL` at
/// capacity.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    match call.route.handler {
        Handler::NotificationsQuery => query(shared, context, call),
        Handler::NotificationsSave => save(shared, context, call),
        Handler::NotificationsRemove => remove(shared, context, call),
        Handler::NotificationsTest => test(shared, context, call),
        _ => Err(RouteError::Unavailable),
    }
}

/// Returns the subject a sealed secret is bound to: the first eight bytes, little-endian,
/// of SHA-256 over a domain and the destination's target. An envelope copied onto a row
/// with another target cannot be opened, and the subject is known before the row has an id
/// (Zig's `notify_target.envelopeSubject`).
pub(crate) fn envelope_subject(target: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"sibuna-console-notify-target-v1");
    hasher.update(target.as_bytes());
    let digest = hasher.finalize();
    let mut first = [0u8; 8];
    first.copy_from_slice(digest.get(..8).unwrap_or(&[0; 8]));
    u64::from_le_bytes(first)
}

/// Returns the host of `target` when it may be stored for `kind` (Zig's `validateWebhook`
/// and `validateSyslog`), or `None`.
pub(crate) fn target_host(kind: Kind, target: &str) -> Option<String> {
    match kind {
        Kind::Webhook => webhook_host(target),
        Kind::Syslog => syslog_host(target),
    }
}

/// A webhook is `https://` to a public host on port 443 or 8443, or `http://` to a loopback
/// literal on a port of 1024 or more, without user information or a fragment.
fn webhook_host(url: &str) -> Option<String> {
    if url.len() > MAX_URL || url.contains([' ', '\t', '\r', '\n', '"', '\'', '<', '>', '\\']) {
        return None;
    }
    let (https, rest) = match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
        (Some(rest), _) => (true, rest),
        (None, Some(rest)) => (false, rest),
        _ => return None,
    };
    if url.contains('#') {
        return None;
    }
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = rest.get(..end)?;
    if authority.contains('@') {
        return None;
    }
    let (host, port) = split_host_port(authority)?;
    let port = match port {
        Some(text) => text.parse::<u16>().ok().filter(|&port| port != 0)?,
        None if https => 443,
        None => 80,
    };
    let literal = host.parse::<IpAddr>().ok();
    let allowed = match literal {
        Some(address) => {
            outbound::is_allowed(
                address,
                if https { Policy::PublicOnly } else { Policy::LoopbackAllowed },
            ) && (https || address.is_loopback())
        }
        None => https,
    };
    let port_allowed = if https { port == 443 || port == 8443 } else { port >= 1024 };
    let named = outbound::Host::new(host).is_ok();
    (allowed && port_allowed && named).then(|| host.to_owned())
}

/// Splits `authority` into a host (brackets removed) and an optional port text.
fn split_host_port(authority: &str) -> Option<(&str, Option<&str>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = rest.get(..close)?;
        let after = rest.get(close + 1..)?;
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':')?),
        };
        return (!host.is_empty()).then_some((host, port));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    (!host.is_empty() && !host.contains(':')).then_some((host, port))
}

/// A syslog receiver is `host:port`; a literal address must be public or loopback.
fn syslog_host(text: &str) -> Option<String> {
    if text.is_empty() || text.len() > MAX_SYSLOG {
        return None;
    }
    let (host, port) = text.rsplit_once(':')?;
    let host = host.strip_prefix('[').and_then(|bare| bare.strip_suffix(']')).unwrap_or(host);
    if host.is_empty() || host.contains([' ', '\t', '\r', '\n', '/', '\\', '"', '\'']) {
        return None;
    }
    port.parse::<u16>().ok().filter(|&port| port != 0)?;
    if let Ok(address) = host.parse::<IpAddr>()
        && !outbound::is_allowed(address, Policy::LoopbackAllowed)
    {
        return None;
    }
    Some(host.to_owned())
}

/// The body of `notifications/query`.
struct QueryForm {
    after: u64,
}

impl Decode for QueryForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<QueryForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = QueryForm { after: fields.or_default("after")? };
        fields.finish()?;
        Ok(form)
    }
}

/// Reads one page of destinations after id `after` for the caller.
fn destinations(shared: &Shared, call: &Call, after: u64) -> Result<Page, RouteError> {
    let credential = call.credential(shared)?;
    let now = call.now;
    shared
        .storage
        .transact(move |tx| {
            Box::pin(async move {
                query_destinations(tx, Reader::Administrator(&credential), after, now).await
            })
        })
        .map_err(settings_error)
}

/// `notifications/query`: one page of destinations; secrets read only as set or not.
fn query(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let mut body = [0u8; 256];
    let form: QueryForm = read_json(context, &mut body)?;
    let page = destinations(shared, call, form.after)?;
    Ok(reply::json(context, &page)?)
}

/// The body of `notifications/save`.
struct SaveForm {
    id: Option<u64>,
    expected_revision: u64,
    kind: Kind,
    transport: Transport,
    label: String,
    target: String,
    secret: String,
    clear_secret: bool,
    events: u8,
    cooldown_seconds: u32,
    enabled: bool,
}

impl Decode for SaveForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<SaveForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = SaveForm {
            id: fields.or_default("id")?,
            expected_revision: fields.or_default("expected_revision")?,
            kind: fields.required("kind")?,
            transport: fields.or("transport", Transport::Udp)?,
            label: fields.required("label")?,
            target: fields.required("target")?,
            secret: fields.or_default("secret")?,
            clear_secret: fields.or_default("clear_secret")?,
            events: fields.required("events")?,
            cooldown_seconds: fields.required("cooldown_seconds")?,
            enabled: fields.or("enabled", true)?,
        };
        fields.finish()?;
        Ok(form)
    }
}

impl Drop for SaveForm {
    /// The plaintext secret is wiped once the form is done with.
    fn drop(&mut self) {
        let mut secret = std::mem::take(&mut self.secret).into_bytes();
        ct::zeroize(&mut secret);
    }
}

/// Seals the form's secret under the console key, bound to its target; `None` when the
/// form carries no new secret.
fn seal(shared: &Shared, form: &SaveForm) -> Result<Option<Vec<u8>>, RouteError> {
    if form.secret.is_empty() {
        return Ok(None);
    }
    if form.secret.len() > MAX_SECRET {
        return Err(RouteError::fail(400, "CONSOLESETTINGS"));
    }
    let key = shared.keys.totp.as_ref().ok_or(RouteError::fail(400, "CONSOLEKEYREQUIRED"))?;
    let subject = envelope_subject(&form.target);
    let sealed = seal_bytes(form.secret.as_bytes(), key.bytes(), subject)
        .map_err(|_| RouteError::Unavailable)?;
    Ok(Some(sealed.to_vec()))
}

/// `notifications/save`: creates (no id) or changes (with its revision) one destination.
fn save(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let mut body = [0u8; 4096];
    let form: SaveForm = read_json(context, &mut body)?;
    let host = target_host(form.kind, &form.target)
        .ok_or(RouteError::fail(400, "CONSOLENOTIFYTARGET"))?;
    let envelope = seal(shared, &form)?;
    let refused = || RouteError::fail(400, "CONSOLESETTINGS");
    let input = Save {
        auth: call.auth(shared)?,
        id: form.id,
        expected_revision: form.expected_revision,
        kind: form.kind,
        transport: form.transport,
        label: Text::new(&form.label).map_err(|_| refused())?,
        target: Text::new(&form.target).map_err(|_| refused())?,
        target_host: Text::from_string(host).map_err(|_| refused())?,
        secret_envelope: None,
        clear_secret: form.clear_secret,
        events: form.events,
        cooldown_seconds: form.cooldown_seconds,
        enabled: form.enabled,
    };
    drop(form);
    let credential = call.credential(shared)?;
    let now = call.now;
    let id = shared
        .storage
        .transact(move |tx| {
            Box::pin(async move {
                save_destination(tx, &credential, &input, envelope.as_deref(), now).await
            })
        })
        .map_err(settings_error)?;
    Ok(reply::json(context, &Saved { id })?)
}

/// `{"id":<counter>}`.
struct Saved {
    id: u64,
}

impl Encode for Saved {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        counter_field(json, "id", self.id)?;
        json.end_object()
    }
}

/// The body of `notifications/remove`.
struct RemoveForm {
    id: u64,
    expected_revision: u64,
}

impl Decode for RemoveForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<RemoveForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = RemoveForm {
            id: fields.required("id")?,
            expected_revision: fields.required("expected_revision")?,
        };
        fields.finish()?;
        Ok(form)
    }
}

/// `notifications/remove`: deletes one destination at its revision.
fn remove(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let mut body = [0u8; 256];
    let form: RemoveForm = read_json(context, &mut body)?;
    let input = Remove {
        auth: call.auth(shared)?,
        id: form.id,
        expected_revision: form.expected_revision,
    };
    let credential = call.credential(shared)?;
    let now = call.now;
    shared
        .storage
        .transact(move |tx| {
            Box::pin(async move { remove_destination(tx, &credential, &input, now).await })
        })
        .map_err(settings_error)?;
    Ok(reply::json_bytes(context, b"{\"ok\":true}", &[])?)
}

/// The body of `notifications/test`.
struct TestForm {
    id: u64,
}

impl Decode for TestForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<TestForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = TestForm { id: fields.required("id")? };
        fields.finish()?;
        Ok(form)
    }
}

/// Records a test's intent (`outcome` `None`) or result, and returns whether storage
/// recorded it.
fn record(shared: &Shared, call: &Call, audit: &TestAudit) -> Result<(), RouteError> {
    let credential = call.credential(shared)?;
    let (audit, now) = (audit.clone(), shared.now());
    shared
        .storage
        .transact(move |tx| {
            Box::pin(async move { record_test(tx, &credential, &audit, now).await })
        })
        .map_err(settings_error)
}

/// `notifications/test`: one test delivery to a stored destination, audited before and
/// after.
fn test(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let mut body = [0u8; 256];
    let form: TestForm = read_json(context, &mut body)?;
    let page = destinations(shared, call, form.id.saturating_sub(1))?;
    let destination: Destination = page
        .rows
        .into_iter()
        .find(|row| row.id == form.id)
        .ok_or(RouteError::fail(404, "CONSOLESETTINGS"))?;
    let mut operation = [0u8; 16];
    while operation == [0; 16] {
        operation = crate::random::array().map_err(|_| RouteError::Unavailable)?;
    }
    let auth = call.auth(shared)?;
    let mut audit = TestAudit {
        auth: auth.clone(),
        destination: destination.id,
        revision: destination.revision,
        operation,
        outcome: None,
        detail: Text::default(),
    };
    record(shared, call, &audit)?;
    let read = Read { auth, id: destination.id, revision: destination.revision, lease: None };
    let delivery = shared.notifier.test_destination(shared, &destination, &read);
    audit.outcome = Some(if delivery.delivered { Outcome::Delivered } else { Outcome::Failed });
    audit.detail = Text::new(clip(&delivery.detail)).unwrap_or_default();
    let recorded = record(shared, call, &audit).is_ok();
    let outcome = Tested { delivered: delivery.delivered, detail: &audit.detail, recorded };
    Ok(reply::json(context, &outcome)?)
}

/// Returns `text` cut to [`MAX_DETAIL`] bytes at a character boundary.
fn clip(text: &str) -> &str {
    let end = (0..=text.len().min(MAX_DETAIL)).rev().find(|&end| text.is_char_boundary(end));
    text.get(..end.unwrap_or(0)).unwrap_or_default()
}

/// A test's outcome.
struct Tested<'a> {
    delivered: bool,
    detail: &'a Text<MAX_DETAIL>,
    recorded: bool,
}

impl Encode for Tested<'_> {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "delivered", &self.delivered)?;
        field(json, "detail", self.detail)?;
        field(json, "audit_recorded", &self.recorded)?;
        json.end_object()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::codec::from_json;

    // notify_target.zig: "webhook targets are https to public hosts or http to loopback
    // literals" (the storage half; the notifier checks again before delivery).
    #[test]
    fn webhooks_are_https_to_public_hosts_or_http_to_loopback_literals() {
        assert_eq!(
            target_host(Kind::Webhook, "https://hooks.example/notify?team=ops").as_deref(),
            Some("hooks.example")
        );
        assert_eq!(
            target_host(Kind::Webhook, "https://[2606:4700::1]:8443/x").as_deref(),
            Some("2606:4700::1")
        );
        for refused in [
            "http://hooks.example/x",
            "https://user@hooks.example/x",
            "https://10.0.0.1/x",
            "https://169.254.169.254/",
            "ftp://hooks.example/x",
            "https://hooks.example:22/x",
            "https://[fe80::1]/x",
            "https://hooks.example/x#frag",
            "",
            "https://hooks.example:9443/x",
            "http://127.0.0.1:80/hook",
            "https://hooks.example:0/x",
            "https://hooks example/x",
        ] {
            assert_eq!(target_host(Kind::Webhook, refused), None, "{refused}");
        }
    }

    #[test]
    fn syslog_targets_are_host_and_port() {
        assert_eq!(target_host(Kind::Syslog, "logs.example:514").as_deref(), Some("logs.example"));
        assert_eq!(target_host(Kind::Syslog, "127.0.0.1:514").as_deref(), Some("127.0.0.1"));
        assert_eq!(target_host(Kind::Syslog, "[::1]:514").as_deref(), Some("::1"));
        for refused in ["logs.example", "10.0.0.1:514", "logs.example:0", ":514", "a/b:514"] {
            assert_eq!(target_host(Kind::Syslog, refused), None, "{refused}");
        }
    }

    #[test]
    fn subjects_bind_the_target_and_forms_decode() {
        assert_ne!(
            envelope_subject("https://a.example/x"),
            envelope_subject("https://b.example/x")
        );
        let form: SaveForm = from_json(
            br#"{"id":3,"expected_revision":"5","kind":"webhook","transport":"udp","label":"hook",
            "target":"https://x","secret":"","clear_secret":false,"events":2,"cooldown_seconds":5,
            "enabled":true}"#,
        )
        .unwrap();
        assert_eq!((form.id, form.expected_revision, form.events), (Some(3), 5, 2));
        assert_eq!(clip(&"\u{e9}".repeat(60)).len(), 96);
    }
}
