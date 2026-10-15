//! Managed-rule workflows that use the editor's requests (`workflow_controller.zig` and
//! `policy_transfer.zig`): moving a rule, replaying retained events against the draft,
//! importing and exporting one rule document, and replacing every rule with a policy set.
//!
//! A policy set is reviewed first (count and batch digest), then sent one document per
//! request (`import/chunk`) and committed (`import/commit`). SID 0013 replaces the chunks
//! and the commit with one bounded request; this module keeps the request shapes the
//! server accepts today.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::{Action, Text};
use sibuna_html::write_value;
use sibuna_json::Value;

use super::form::{Form, FormError};
use super::limits;
use super::manager::ManagedView;
use super::replay::Replay;
use super::{Policies, success};
use crate::commands::Field;
use crate::error::UiError;
use crate::json;
use crate::page::Context;
use crate::render::Html;
use crate::snippets;
use crate::state::{Phase, State};

/// The most documents a policy set holds.
const MAX_SET_DOCUMENTS: usize = 128;
/// The most bytes of compact documents a policy set holds.
const MAX_SET_BYTES: usize = 64 * 1024;
/// The most bytes of one compact document.
const MAX_DOCUMENT: usize = 4096;

/// Where a policy set import stands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Stage {
    /// No set is staged.
    #[default]
    Idle,
    /// The set waits for the operator's confirmation; nothing was sent.
    Review,
    /// Documents are being sent.
    Sending,
    /// The commit is in flight.
    Committing,
}

/// A policy set being imported.
#[derive(Debug, Default)]
pub struct ImportAll {
    /// Where the import stands.
    pub stage: Stage,
    /// Documents sent so far.
    pub sent: usize,
    /// The batch digest that groups the chunks: 64 lowercase hex digits.
    pub digest: String,
    /// The committed revision the set replaces.
    pub expected: Text<20>,
    /// The compact documents, at most 128.
    pub documents: Vec<String>,
}

/// Why a single-rule import or export was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransferError {
    /// The editor is not open for this, or the role may not import.
    Unavailable,
    /// The document or the fields are invalid.
    Invalid(FormError),
    /// The document belongs to another rule.
    InvalidId,
}

impl From<FormError> for TransferError {
    fn from(error: FormError) -> TransferError {
        TransferError::Invalid(error)
    }
}

/// The members a rule document may have.
const DOCUMENT_FIELDS: [&str; 13] = [
    "id",
    "name",
    "action",
    "priority",
    "enabled",
    "path",
    "user_agent",
    "algorithm",
    "difficulty",
    "weight",
    "headers",
    "cidrs",
    "limits",
];

/// Checks the members of an imported document before it is loaded: only known members;
/// `id`, `name` and `action` present as strings; `path`, `user_agent` and `algorithm`
/// strings or null; and a known action.
fn validate_fields(source: &str) -> Result<(), FormError> {
    let root = sibuna_json::parse_with_limits(source.as_bytes(), &json::limits(source.len()))
        .map_err(|_| FormError::InvalidDocument)?;
    let object = root.as_object().ok_or(FormError::InvalidDocument)?;
    if object.iter().any(|(key, _)| !DOCUMENT_FIELDS.contains(&key)) {
        return Err(FormError::InvalidDocument);
    }
    for key in ["id", "name", "action", "path", "user_agent", "algorithm"] {
        let required = matches!(key, "id" | "name" | "action");
        match object.get(key) {
            None if required => return Err(FormError::InvalidDocument),
            None | Some(Value::String(_)) => {}
            Some(Value::Null) if !required => {}
            Some(_) => return Err(FormError::InvalidDocument),
        }
    }
    match json::string(&root, "action") {
        "deny" | "allow" | "challenge" | "weigh" => Ok(()),
        _ => Err(FormError::InvalidDocument),
    }
}

/// Returns the lowercase hexadecimal text of `bytes`.
fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing into a `String` cannot fail.
        let _ = write!(text, "{byte:02x}");
    }
    text
}

impl Policies {
    /// Handles the ordering, replay and policy set actions; returns false for others.
    pub(super) fn workflow_action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        let up = name.strip_prefix("managed-up:");
        if let Some(id) = up.or_else(|| name.strip_prefix("managed-down:")) {
            let committed = self.manager.committed.clone();
            if !cx.state.allows(Action::ManagePolicy) || committed.is_empty() {
                return Ok(true);
            }
            let fields = [
                ("id", Field::Text(id)),
                ("expected_revision", Field::Text(committed.as_str())),
                ("direction", Field::Text(if up.is_some() { "up" } else { "down" })),
            ];
            self.post_managed(cx, "order", &fields)?;
            return Ok(true);
        }
        match name {
            "managed-replay" => self.replay(cx, fields)?,
            "managed-import-all" => {
                if json::string(fields, "confirmed") != "on" {
                    cx.state.set_message(
                        "Confirm that the set replaces every managed rule before reviewing it.",
                    );
                } else {
                    self.review_set(cx.state, json::string(fields, "documents"));
                }
            }
            "managed-import-cancel" => self.manager.import_all = ImportAll::default(),
            "managed-import-confirm" if self.manager.import_all.stage == Stage::Review => {
                self.manager.import_all.stage = Stage::Sending;
                self.manager.import_all.sent = 0;
                self.send_chunk(cx)?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Replays a day of retained events against the draft.
    fn replay(&mut self, cx: &mut Context<'_>, fields: &Value<'_>) -> Result<(), UiError> {
        let Some(document) = self.capture_document(cx, fields)? else { return Ok(()) };
        let manager = &self.manager;
        let (rule, committed) = (manager.form.name.clone(), manager.committed.clone());
        let fields = [
            ("rule", Field::Text(rule.as_str())),
            ("hours", Field::Unsigned(24)),
            ("draft", Field::Text(&document)),
            ("committed", Field::Text(committed.as_str())),
        ];
        self.post_managed(cx, "replay", &fields)
    }

    /// Parses a pasted policy set, keeps its compact documents and shows the count and
    /// digest to confirm. Nothing is sent until the operator confirms.
    fn review_set(&mut self, state: &mut State, text: &str) {
        let manager = &mut self.manager;
        if !state.allows(Action::ManagePolicy) || manager.committed.is_empty() {
            return;
        }
        let parsed = sibuna_json::parse_with_limits(text.as_bytes(), &json::limits(text.len()));
        let Some(items) = parsed.as_ref().ok().and_then(Value::as_array) else {
            return state.set_message("The policy set must be a JSON array of rule documents.");
        };
        if items.is_empty() || items.len() > MAX_SET_DOCUMENTS {
            return state
                .set_message("The policy set must hold between 1 and 128 rule documents.");
        }
        let mut documents = Vec::with_capacity(items.len());
        let mut used = 0;
        for item in items {
            if item.as_object().is_none() {
                return state
                    .set_message("Every entry of the policy set must be a rule document.");
            }
            let document = item.to_string();
            used += document.len();
            if used > MAX_SET_BYTES {
                return state.set_message("The policy set exceeds 64 KiB of compact documents.");
            }
            if document.len() > MAX_DOCUMENT {
                return state.set_message("One rule document exceeds 4 KiB.");
            }
            documents.push(document);
        }
        // The key only groups chunks; the storage owner hashes the staged set at commit.
        // It is unique to the session: its CSRF text, the time, the size and the count.
        let mut key = [0u8; 32];
        for (byte, csrf) in key.iter_mut().zip(state.csrf.as_str().bytes()) {
            *byte = csrf;
        }
        key[..8].copy_from_slice(&state.browser_time.to_le_bytes());
        // `used` is at most 64 KiB and the count at most 128, so both fit.
        key[8..12].copy_from_slice(&u32::try_from(used).unwrap_or(u32::MAX).to_le_bytes());
        key[12] = u8::try_from(documents.len()).unwrap_or(u8::MAX);
        manager.import_all = ImportAll {
            stage: Stage::Review,
            sent: 0,
            digest: hex(&key),
            expected: manager.committed.clone(),
            documents,
        };
    }

    /// Sends the next document of the policy set.
    fn send_chunk(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        let import = &self.manager.import_all;
        let index = import.sent;
        let document = import.documents.get(index).cloned().unwrap_or_default();
        let (digest, ordinal) = (import.digest.clone(), u64::try_from(index).unwrap_or(0));
        let fields = [
            ("digest", Field::Text(&digest)),
            ("ordinal", Field::Unsigned(ordinal)),
            ("document", Field::Text(&document)),
        ];
        self.post_managed(cx, "import-chunk", &fields)
    }

    /// Takes a reply that belongs to a workflow; returns false for other replies.
    pub(super) fn workflow_response(
        &mut self,
        cx: &mut Context<'_>,
        id: &str,
        body: &Value<'_>,
    ) -> Result<bool, UiError> {
        let manager = &mut self.manager;
        if id.starts_with("managed-order-") {
            manager.committed = Text::new(json::string(body, "committed"))?;
            manager.listing = None;
            manager.next = Text::default();
            success(
                cx.state,
                "Rule moved. The data plane applies the order after its next rebuild.",
            );
            self.post_managed(cx, "catalog", &[("kind", Field::Text("catalog"))])?;
        } else if id.starts_with("managed-replay-") {
            manager.replay = Some(Replay::read(body));
            cx.commands.focus("#policy-replay")?;
        } else if id.starts_with("managed-import-chunk-") {
            let import = &mut manager.import_all;
            import.sent += 1;
            if import.sent < import.documents.len() {
                self.send_chunk(cx)?;
                return Ok(true);
            }
            import.stage = Stage::Committing;
            let (digest, expected) = (import.digest.clone(), import.expected.clone());
            let count = u64::try_from(import.documents.len()).unwrap_or(0);
            let fields = [
                ("digest", Field::Text(&digest)),
                ("count", Field::Unsigned(count)),
                ("expected_revision", Field::Text(expected.as_str())),
            ];
            self.post_managed(cx, "import-commit", &fields)?;
        } else if id.starts_with("managed-import-commit-") {
            manager.committed = Text::new(json::string(body, "committed"))?;
            manager.import_all = ImportAll::default();
            manager.view = ManagedView::Catalog;
            manager.listing = None;
            manager.next = Text::default();
            success(
                cx.state,
                "Policy set replaced. The data plane applies it after its next rebuild.",
            );
            self.post_managed(cx, "catalog", &[("kind", Field::Text("catalog"))])?;
        } else {
            return Ok(false);
        }
        Ok(true)
    }

    /// Imports one rule document into the draft, or exports the draft as a download.
    pub(super) fn transfer(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        let importing = name == "managed-import";
        if !importing && name != "managed-export" {
            return Ok(false);
        }
        match self.apply_transfer(cx.state, importing, fields) {
            Ok(None) => {
                success(cx.state, "Draft imported. Review and preview it before saving.");
                cx.commands.focus_top("#managed-editor")?;
            }
            Ok(Some(document)) => cx.commands.emit_fields(&[
                ("op", Field::Text("save-text")),
                ("filename", Field::Text("sibuna-rule.json")),
                ("text", Field::Text(&document)),
            ])?,
            Err(error) => {
                cx.state.set_message(
                    if error == TransferError::Invalid(FormError::InvalidRuleLimit) {
                        limits::INVALID_MESSAGE
                    } else {
                        "Check the rule JSON, field types and ID. No rule was imported or saved."
                    },
                );
                cx.commands.focus("#console-message")?;
            }
        }
        Ok(true)
    }

    /// Returns the exported document, or `None` after an import replaced the draft.
    fn apply_transfer(
        &mut self,
        state: &State,
        importing: bool,
        fields: &Value<'_>,
    ) -> Result<Option<String>, TransferError> {
        let manager = &mut self.manager;
        let model = &self.applied;
        if !state.is_full_access()
            || state.phase != Phase::Policies
            || !manager.active
            || manager.view != ManagedView::Editor
            || !manager.review.is_empty()
            || model.busy
            || model.testing
            || (importing && !state.allows(Action::ManagePolicy))
        {
            return Err(TransferError::Unavailable);
        }
        if fields.as_object().is_none() {
            return Err(FormError::InvalidDocument.into());
        }
        if !importing {
            manager.form.capture(fields)?;
            if !manager.id.is_empty() && manager.id != manager.form.id {
                return Err(TransferError::InvalidId);
            }
            return Ok(Some(manager.form.document()?));
        }
        let document = json::field(fields, "document").and_then(Value::as_str);
        let document = document.ok_or(FormError::InvalidDocument)?;
        manager.import_text = Text::new(document).map_err(FormError::from)?;
        validate_fields(document)?;
        let form = Form::load(document)?;
        form.document()?;
        if !manager.id.is_empty() && manager.id != form.id {
            return Err(TransferError::InvalidId);
        }
        // Replace only after parsing succeeds. Import never submits a storage mutation.
        manager.form = form;
        manager.historical = Text::default();
        self.applied.decision = None;
        Ok(None)
    }

    /// Draws the single-rule import and the policy set import.
    pub(super) fn render_transfer(&self, state: &State, out: &mut Html<'_>) -> fmt::Result {
        if !state.allows(Action::ManagePolicy) {
            return Ok(());
        }
        let manager = &self.manager;
        snippets::render_policy_import(
            out,
            &snippets::PolicyImportValues { document: &manager.import_text.as_str() },
        )?;
        let import = &manager.import_all;
        let staged = import.stage != Stage::Idle;
        snippets::render_policy_import_all(
            out,
            &snippets::PolicyImportAllValues {
                open: &if staged { " open" } else { "" },
                busy: &if self.applied.busy || staged { " disabled" } else { "" },
            },
        )?;
        if staged {
            render_staged(out, import)?;
        }
        out.write_str("</details>")
    }

    /// A failed chunk or commit leaves the staged set for review again.
    pub(super) fn import_failed(&mut self, id: &str) {
        let import = &mut self.manager.import_all;
        if id.starts_with("managed-import-")
            && matches!(import.stage, Stage::Sending | Stage::Committing)
        {
            import.stage = Stage::Review;
        }
    }
}

/// Draws the staged set and its confirmation.
fn render_staged(out: &mut Html<'_>, import: &ImportAll) -> fmt::Result {
    let busy = if import.stage == Stage::Review { "" } else { " disabled" };
    out.write_str("<div class=\"sb-panel mt-3\"><p role=\"status\">")?;
    write_value(out, &import.documents.len())?;
    out.write_str(" rule documents (batch ")?;
    out.escaped(&import.digest)?;
    out.write_str("), replacing every managed rule at revision ")?;
    out.escaped(import.expected.as_str())?;
    out.write_str(". ")?;
    out.write_str(match import.stage {
        Stage::Review => "Nothing has been sent yet.",
        Stage::Sending => "Sending documents\u{2026}",
        Stage::Committing => "Committing\u{2026}",
        Stage::Idle => "",
    })?;
    out.write_str(
        "</p><div class=\"flex gap-2\"><button class=\"btn btn-primary\" \
         data-action=\"managed-import-confirm\"",
    )?;
    out.write_str(busy)?;
    out.write_str(
        ">Replace all rules</button><button class=\"btn\" data-action=\"managed-import-cancel\"",
    )?;
    out.write_str(busy)?;
    out.write_str(">Cancel</button></div></div>")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ported from `policy_transfer.zig`.
    #[test]
    fn import_rejects_ignored_fields_and_preserves_the_old_draft_on_id_mismatch() {
        let mut state = State { phase: Phase::Policies, ..State::new() };
        state.csrf.set("test").unwrap();
        state.role.set("admin").unwrap();
        let mut page = Policies::default();
        page.manager.active = true;
        page.manager.view = ManagedView::Editor;
        page.manager.id.set("original").unwrap();
        let typo = "{\"id\":\"a\",\"name\":\"a\",\"action\":\"deny\",\"typo\":true}";
        assert_eq!(validate_fields(typo), Err(FormError::InvalidDocument));
        let fields = sibuna_json::parse(
            br#"{"document":"{\"id\":\"new\",\"name\":\"Imported\",\"action\":\"deny\"}"}"#,
        )
        .unwrap();
        assert_eq!(page.apply_transfer(&state, true, &fields), Err(TransferError::InvalidId));
        assert!(page.manager.form.name.is_empty());
        page.manager.id = Text::default();
        assert_eq!(page.apply_transfer(&state, true, &fields), Ok(None));
        assert_eq!(page.manager.form.name.as_str(), "Imported");
        assert!(!page.applied.busy);
    }

    #[test]
    fn a_policy_set_digest_groups_by_session_time_size_and_count() {
        let mut state = State { browser_time: 0x0102, ..State::new() };
        state.csrf.set("0123456789abcdefghijklmnopqrstuvwxyz").unwrap();
        state.role.set("admin").unwrap();
        let mut page = Policies::default();
        page.manager.committed.set("4").unwrap();
        page.review_set(&mut state, "[{\"id\":\"a\"},{\"b\":1.50}]");
        let import = &page.manager.import_all;
        assert_eq!(import.stage, Stage::Review);
        assert_eq!(import.documents, ["{\"id\":\"a\"}", "{\"b\":1.50}"]);
        let expected = "0201000000000000140000000264656667\
                        68696a6b6c6d6e6f70717273747576";
        assert_eq!(import.digest, expected);
        page.review_set(&mut state, "[1]");
        assert_eq!(
            state.message.as_str(),
            "Every entry of the policy set must be a rule document."
        );
        page.review_set(&mut state, "{}");
        assert_eq!(
            state.message.as_str(),
            "The policy set must be a JSON array of rule documents."
        );
        let big =
            format!("[{}]", vec![format!("{{\"a\":\"{}\"}}", "x".repeat(4000)); 17].join(","));
        page.review_set(&mut state, &big);
        assert_eq!(state.message.as_str(), "The policy set exceeds 64 KiB of compact documents.");
    }
}
