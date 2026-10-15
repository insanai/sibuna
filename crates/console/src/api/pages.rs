//! The routes `pages/read`, `pages/edit`, `pages/preview` and the `pages/preview/<kind>`
//! reads (Zig's `page_routes.zig`).
//!
//! Administrators edit the five response pages. A draft is compiled and kept for its
//! session ([`Drafts`]); the `GET` preview renders it (or the stored page) with sample
//! values under `respond_isolated`, a sandbox policy in an opaque origin, so operator markup
//! never runs inside the console's own origin. Edits and resets are revision checked and
//! audited by digest in storage (S19).

use std::fmt::{self, Write};
use std::sync::{Mutex, PoisonError};

use sibuna_console_protocol::codec::{
    Decode, DecodeError, Encode, Fields, Path, WireEnum, counter_field, field,
};
use sibuna_console_protocol::pages::{self, Document, Html, Kind};
use sibuna_console_storage::pages::{change_page, read_page, template_kind};
use sibuna_json::{Value, Writer};
use sibuna_policy::pages::{Template, Values};
use sibuna_serve::Context;

use crate::dispatch::Call;
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::routes::Handler;
use crate::shared::{Setup, Shared};
use crate::storage::StorageFailure;

/// The most drafts kept, for all sessions together.
pub const MAX_DRAFTS: usize = 16;
/// The body bound of the edit and preview routes: a full template, escaped.
const BODY: usize = 40 * 1024;
/// The prefix of the preview reads.
const PREVIEW_PREFIX: &str = "/console/api/pages/preview/";

/// One session's unsaved template.
#[derive(Debug)]
struct Draft {
    session: [u8; 32],
    kind: Kind,
    html: String,
    stored_at: u64,
}

/// Unsaved template drafts, one per session and at most [`MAX_DRAFTS`] in all; a new
/// session's draft replaces the oldest one.
#[derive(Debug, Default)]
pub struct Drafts {
    slots: Mutex<Vec<Draft>>,
}

impl Drafts {
    /// Returns an empty draft store.
    pub fn new(setup: &Setup<'_>) -> Drafts {
        let _ = setup;
        Drafts::default()
    }

    /// Keeps `html` as the draft of `session` for `kind`, replacing the session's earlier
    /// draft, or the oldest draft when the store is full.
    fn store(&self, session: [u8; 32], kind: Kind, html: &str, now: u64) {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let draft = Draft { session, kind, html: html.to_owned(), stored_at: now };
        if let Some(slot) = slots.iter_mut().find(|slot| slot.session == session) {
            *slot = draft;
        } else if slots.len() < MAX_DRAFTS {
            slots.push(draft);
        } else if let Some(oldest) = slots.iter_mut().min_by_key(|slot| slot.stored_at) {
            *oldest = draft;
        }
    }

    /// Returns a copy of the draft of `session` for `kind`, if any.
    fn take(&self, session: &[u8; 32], kind: Kind) -> Option<String> {
        let slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let draft = slots.iter().find(|slot| slot.kind == kind && &slot.session == session)?;
        Some(draft.html.clone())
    }

    /// Returns how many drafts are kept.
    pub fn count(&self) -> usize {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner).len()
    }
}

/// A page kind by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KindName(Kind);

impl WireEnum for KindName {
    const ALL: &'static [KindName] = &[
        KindName(Kind::Challenge),
        KindName(Kind::Denied),
        KindName(Kind::RateLimited),
        KindName(Kind::Banned),
        KindName(Kind::Overloaded),
    ];

    fn name(self) -> &'static str {
        template_kind(self.0).name()
    }
}

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with the [`RouteError`] the route answers with.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    match call.route.handler {
        Handler::PagesRead => read(shared, context, call),
        Handler::PagesEdit => edit(shared, context, call),
        Handler::PagesPreview => preview(shared, context, call),
        Handler::PagesPreviewGet => {
            let name = call.route.path.strip_prefix(PREVIEW_PREFIX).unwrap_or_default();
            let kind = KindName::from_name(name).ok_or(RouteError::BadRequest)?;
            render(shared, context, call, kind.0)
        }
        _ => Err(RouteError::Unavailable),
    }
}

/// Maps a page route's storage failure: invalid input is `CONSOLEPAGE`, every other
/// refusal `CONSOLESETTINGS`.
fn page_error(failure: StorageFailure) -> RouteError {
    match failure.failure() {
        sibuna_console_protocol::storage::Failure::InvalidInput => {
            failure.route_error("CONSOLEPAGE")
        }
        _ => failure.route_error("CONSOLESETTINGS"),
    }
}

fn page_refused() -> RouteError {
    RouteError::fail(400, "CONSOLEPAGE")
}

/// The body of `pages/read`.
struct ReadForm {
    kind: KindName,
}

impl Decode for ReadForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<ReadForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = ReadForm { kind: fields.required("kind")? };
        fields.finish()?;
        Ok(form)
    }
}

/// Reads the stored template of `kind`, or the built-in one.
fn stored(shared: &Shared, call: &Call, kind: Kind) -> Result<Document, RouteError> {
    let input = pages::Read { auth: call.auth(shared)?, kind };
    let credential = call.credential(shared)?;
    let challenge = shared.policy.challenge_page().to_owned();
    let now = call.now;
    shared
        .storage
        .transact(move |tx| {
            Box::pin(async move { read_page(tx, &credential, &input, &challenge, now).await })
        })
        .map_err(page_error)
}

/// `pages/read`: one template with its revision and digest.
fn read(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let mut body = [0u8; 256];
    let form: ReadForm = read_json(context, &mut body)?;
    let document = stored(shared, call, form.kind.0)?;
    Ok(reply::json(context, &DocumentReply(&document))?)
}

/// A template in Zig's shape.
struct DocumentReply<'a>(&'a Document);

impl Encode for DocumentReply<'_> {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        let document = self.0;
        json.begin_object()?;
        field(json, "kind", &KindName(document.kind))?;
        counter_field(json, "revision", document.revision)?;
        field(json, "customized", &document.customized)?;
        field(json, "sha256", &document.sha256)?;
        field(json, "html", &document.html)?;
        json.end_object()
    }
}

/// The body of `pages/edit`.
struct EditForm {
    kind: KindName,
    expected_revision: u64,
    reset: bool,
    html: String,
}

impl Decode for EditForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<EditForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = EditForm {
            kind: fields.required("kind")?,
            expected_revision: fields.required("expected_revision")?,
            reset: fields.or_default("reset")?,
            html: fields.or_default("html")?,
        };
        fields.finish()?;
        Ok(form)
    }
}

/// `pages/edit`: replaces or resets one template at its revision.
fn edit(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let mut body = vec![0u8; BODY];
    let form: EditForm = read_json(context, &mut body)?;
    if form.reset != form.html.is_empty() {
        return Err(page_refused());
    }
    let html = match form.reset {
        true => None,
        false => Some(Html::from_string(form.html).map_err(|_| page_refused())?),
    };
    let input = pages::Edit {
        auth: call.auth(shared)?,
        kind: form.kind.0,
        expected_revision: form.expected_revision,
        reset: form.reset,
        html,
    };
    let credential = call.credential(shared)?;
    let now = call.now;
    shared
        .storage
        .transact(move |tx| {
            Box::pin(async move { change_page(tx, &credential, &input, now).await })
        })
        .map_err(page_error)?;
    Ok(reply::json_bytes(context, b"{\"ok\":true}", &[])?)
}

/// The body of `pages/preview`.
struct PreviewForm {
    kind: KindName,
    html: String,
}

impl Decode for PreviewForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<PreviewForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = PreviewForm { kind: fields.required("kind")?, html: fields.required("html")? };
        fields.finish()?;
        Ok(form)
    }
}

/// `pages/preview`: compiles a draft and keeps it for this session's preview read.
fn preview(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let session = call.presented.as_ref().ok_or(RouteError::Unavailable)?.digest;
    let mut body = vec![0u8; BODY];
    let form: PreviewForm = read_json(context, &mut body)?;
    if form.html.is_empty() || form.html.len() > pages::MAX_BYTES {
        return Err(page_refused());
    }
    let kind = form.kind.0;
    if let Err(error) = Template::compile(template_kind(kind), form.html.as_bytes()) {
        let refused = Accepted { path: None, diagnostic: Some(error.name()) };
        return Ok(reply::json(context, &refused)?);
    }
    shared.drafts.store(session, kind, &form.html, call.now);
    let path = Some(preview_path(kind));
    Ok(reply::json(context, &Accepted { path, diagnostic: None })?)
}

/// Returns the preview read of `kind`.
fn preview_path(kind: Kind) -> &'static str {
    match kind {
        Kind::Challenge => "/console/api/pages/preview/challenge",
        Kind::Denied => "/console/api/pages/preview/denied",
        Kind::RateLimited => "/console/api/pages/preview/rate_limited",
        Kind::Banned => "/console/api/pages/preview/banned",
        Kind::Overloaded => "/console/api/pages/preview/overloaded",
    }
}

/// `{"accepted":true,"path":...}` or `{"accepted":false,"diagnostic":...}`.
struct Accepted {
    path: Option<&'static str>,
    diagnostic: Option<&'static str>,
}

impl Encode for Accepted {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "accepted", &self.path.is_some())?;
        if let Some(path) = self.path {
            field(json, "path", path)?;
        }
        if let Some(diagnostic) = self.diagnostic {
            field(json, "diagnostic", diagnostic)?;
        }
        json.end_object()
    }
}

/// The `GET` preview: the session's draft, or else the stored page, rendered with sample
/// values under the sandbox policy.
fn render(
    shared: &Shared,
    context: &mut Context<'_>,
    call: &Call,
    kind: Kind,
) -> Result<(), RouteError> {
    let session = call.presented.as_ref().ok_or(RouteError::Unavailable)?.digest;
    let html = match shared.drafts.take(&session, kind) {
        Some(html) => html,
        None => stored(shared, call, kind)?.html.into_string(),
    };
    let template =
        Template::compile(template_kind(kind), html.as_bytes()).map_err(|_| page_refused())?;
    let values = Values {
        status: 403,
        reason: "sample: blocked by rule example",
        retry_after: 30,
        request_id: "0123456789abcdef",
        node: shared.identity.node_id,
        challenge: "<p><em>Solver block appears here.</em></p>",
    };
    let mut page = Vec::with_capacity(template.measure(&values));
    template.write(&mut page, &values).map_err(|_| RouteError::Unavailable)?;
    Ok(context.respond_isolated(200, b"text/html; charset=utf-8", &page)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::codec::from_json;

    #[test]
    fn drafts_are_per_session_and_bounded() {
        let drafts = Drafts::default();
        drafts.store([1; 32], Kind::Denied, "<p>a</p>", 10);
        drafts.store([1; 32], Kind::Banned, "<p>b</p>", 11);
        assert_eq!(drafts.take(&[1; 32], Kind::Denied), None);
        assert_eq!(drafts.take(&[1; 32], Kind::Banned).as_deref(), Some("<p>b</p>"));
        assert_eq!(drafts.take(&[2; 32], Kind::Banned), None);
        for index in 0..MAX_DRAFTS as u8 {
            drafts.store([index + 2; 32], Kind::Denied, "<p>c</p>", 20 + u64::from(index));
        }
        assert_eq!(drafts.count(), MAX_DRAFTS);
        // The oldest draft, the first session's, made room for the last.
        assert_eq!(drafts.take(&[1; 32], Kind::Banned), None);
        assert!(drafts.take(&[MAX_DRAFTS as u8 + 1; 32], Kind::Denied).is_some());
    }

    #[test]
    fn forms_accept_the_interface_bodies() {
        let read: ReadForm = from_json(br#"{"kind":"rate_limited"}"#).unwrap();
        assert_eq!(read.kind.0, Kind::RateLimited);
        let edit: EditForm = from_json(
            br#"{"kind":"denied","expected_revision":"2","reset":false,"html":"<p>Draft</p>"}"#,
        )
        .unwrap();
        assert_eq!((edit.expected_revision, edit.reset), (2, false));
        assert!(from_json::<ReadForm>(br#"{"kind":"other"}"#).is_err());
        for kind in KindName::ALL {
            assert_eq!(preview_path(kind.0), format!("{PREVIEW_PREFIX}{}", kind.name()));
        }
    }
}
