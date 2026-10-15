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
use sibuna_json::{Value, Writer};
use sibuna_serve::Context;

use super::settings::settings_error;
use crate::auth::secrets::seal_bytes;
use crate::dispatch::Call;
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::notify::target::{envelope_subject, target_host};
use crate::routes::Handler;
use crate::shared::Shared;

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
