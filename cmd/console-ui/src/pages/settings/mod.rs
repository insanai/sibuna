//! Console settings (phase `settings`): notification destinations, spike thresholds,
//! bounded retention, the response-page editor ([`templates`]) and the About facts.
//!
//! Ported from `settings_state.zig`, `settings_controller.zig`, `settings_page.zig` and
//! the response-page files. Every mutation carries an expected revision; delivery tests
//! report their outcome inline. Replies decode as the protocol's `notifications::Page`
//! and `notifications::SettingsPage`.
//!
//! Deliberate changes: the About reply is read into [`About`] when it arrives; Zig kept
//! its JSON text in a 512-byte buffer (refusing a longer reply) and parsed it again on
//! every render. "Saved." is set after the refresh that follows a change, so the operator
//! sees it (Zig cleared it again at once; see SID 0007).

mod render;
pub mod templates;

use sibuna_console_protocol::codec::{Decode, Path, WireEnum};
use sibuna_console_protocol::notifications::{self, Destination, Event, Setting, SettingsPage};
use sibuna_console_protocol::settings::{self, Group};
use sibuna_console_protocol::{Action, Text};
use sibuna_json::Value;

use crate::commands::{Field, write_fields};
use crate::error::UiError;
use crate::json;
use crate::page::{Context, Page, Reply, SESSION_ENDED, Screen, View};
use crate::pages::management::{Ticket, index_after, is_on};
use crate::render::Html;
use crate::state::{Phase, State};
use templates::Templates;

/// What the newest settings request does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Kind {
    /// Reads a page of destinations.
    #[default]
    Query,
    /// Saves a destination.
    Save,
    /// Removes a destination.
    Remove,
    /// Tests a destination's delivery.
    Testing,
    /// Reads the stored settings.
    Settings,
    /// Changes a setting.
    SettingChange,
    /// Reads the About facts.
    About,
}

/// The About facts of the serving node, read from `/console/api/about`. Absent or
/// mistyped members read as empty, zero or no.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct About {
    /// The software version.
    pub version: String,
    /// The node id.
    pub node: i64,
    /// The console schema version.
    pub schema: i64,
    /// The console origin.
    pub origin: String,
    /// The advertised console link; empty for the origin.
    pub advertise: String,
    /// The console runs behind a trusted proxy.
    pub behind_proxy: bool,
    /// The number of trusted proxy ranges.
    pub trusted_proxies: i64,
    /// Cookies are marked secure.
    pub cookie_secure: bool,
    /// A console key file is configured.
    pub key_file: bool,
    /// The configured peer probes.
    pub probes: i64,
}

impl About {
    /// Reads the facts from a reply body.
    pub fn read(body: &Value<'_>) -> About {
        let number = |key| json::field(body, key).and_then(json::integer).unwrap_or(0);
        About {
            version: json::string(body, "version").to_owned(),
            node: number("node"),
            schema: number("schema"),
            origin: json::string(body, "origin").to_owned(),
            advertise: json::string(body, "advertise").to_owned(),
            behind_proxy: json::is_true(body, "behind_proxy"),
            trusted_proxies: number("trusted_proxies"),
            cookie_secure: json::is_true(body, "cookie_secure"),
            key_file: json::is_true(body, "key_file"),
            probes: number("probes"),
        }
    }
}

/// The settings page.
#[derive(Debug, Default)]
pub struct Settings {
    /// The destinations of the current page, at most `notifications::PAGE_ROWS`.
    pub rows: Vec<Destination>,
    /// The id the current page continues after.
    pub after: u64,
    /// The id the next page continues after.
    pub next: Option<u64>,
    /// The stored settings, at most one per known setting.
    pub settings: Vec<Setting>,
    /// The destination being edited.
    pub selected: Option<usize>,
    /// A request is in flight.
    pub busy: bool,
    /// The destinations have arrived.
    pub loaded: bool,
    /// What the newest request does.
    pub kind: Kind,
    /// The newest request.
    pub ticket: Ticket,
    /// The last delivery test's outcome.
    pub result: Text<{ notifications::MAX_DETAIL }>,
    /// The last delivery test succeeded and was audited.
    pub result_ok: bool,
    /// The About facts, once read.
    pub about: Option<About>,
    /// The response-page editor.
    pub templates: Templates,
}

/// Returns the event bits of the ticked event checkboxes.
fn events(fields: &Value<'_>) -> u8 {
    Event::ALL
        .iter()
        .filter(|event| is_on(fields, event.name()))
        .fold(0, |mask, event| mask | event.bit())
}

impl Settings {
    /// Returns to the defaults, keeping both ticket generations.
    fn clear(&mut self) {
        let mut templates = std::mem::take(&mut self.templates);
        templates.clear();
        *self = Settings { ticket: self.ticket.forget(), templates, ..Settings::default() };
    }

    /// Returns the stored setting `key`, if any.
    pub fn setting(&self, key: &str) -> Option<&Setting> {
        self.settings.iter().find(|item| item.key.as_str() == key)
    }

    /// Accepts a page of destinations; an open destination beyond the page is closed.
    ///
    /// # Errors
    ///
    /// [`UiError::InvalidResponse`] for a malformed page or an invalid event set.
    pub fn accept_page(&mut self, body: &Value<'_>) -> Result<(), UiError> {
        let page = notifications::Page::decode(body, Path::Root)?;
        if page.rows.iter().any(|row| row.events == 0 || row.events > notifications::ALL_EVENTS) {
            return Err(UiError::InvalidResponse);
        }
        self.rows = page.rows;
        self.next = page.next;
        self.loaded = true;
        self.selected = self.selected.filter(|index| *index < self.rows.len());
        Ok(())
    }

    /// Issues the next request id for `kind`.
    fn ticket(&mut self, state: &mut State, kind: Kind) -> Result<String, UiError> {
        let id = self.ticket.issue("settings")?.to_owned();
        self.busy = true;
        self.kind = kind;
        state.clear_message();
        Ok(id)
    }

    /// Sends a read: destinations, stored settings or About.
    fn query(&mut self, cx: &mut Context<'_>, kind: Kind) -> Result<(), UiError> {
        let id = self.ticket(cx.state, kind)?;
        let result = match kind {
            Kind::About => cx.get(&id, "/console/api/about"),
            Kind::Settings => {
                cx.post(&id, "/console/api/settings/query", &mut |json| write_fields(json, &[]))
            }
            _ => {
                let after = self.after;
                cx.post(&id, "/console/api/notifications/query", &mut |json| {
                    write_fields(json, &[("after", Field::Unsigned(after))])
                })
            }
        };
        self.busy &= result.is_ok();
        result
    }

    /// Saves the destination form, new or the selected one.
    fn save(&mut self, cx: &mut Context<'_>, fields: &Value<'_>) -> Result<(), UiError> {
        let Ok(cooldown) = json::string(fields, "cooldown_seconds").parse::<u32>() else {
            cx.state.set_message("Cooldown must be a whole number of seconds (0 to 86400).");
            return Ok(());
        };
        let mask = events(fields);
        if mask == 0 {
            cx.state.set_message("Select at least one event for this destination.");
            return Ok(());
        }
        let id = self.ticket(cx.state, Kind::Save)?;
        let selected = self.selected.and_then(|index| self.rows.get(index));
        let destination = selected.map_or(Field::Null, |row| Field::Unsigned(row.id));
        let revision = selected.map_or_else(|| "0".to_owned(), |row| row.revision.to_string());
        let kind = json::string(fields, "kind");
        let transport = if kind == "syslog" { json::string(fields, "transport") } else { "udp" };
        let result = cx.post(&id, "/console/api/notifications/save", &mut |json| {
            write_fields(
                json,
                &[
                    ("id", destination),
                    ("expected_revision", Field::Text(&revision)),
                    ("kind", Field::Text(kind)),
                    ("transport", Field::Text(transport)),
                    ("label", Field::Text(json::string(fields, "label"))),
                    ("target", Field::Text(json::string(fields, "target"))),
                    ("secret", Field::Text(json::string(fields, "secret"))),
                    ("clear_secret", Field::Bool(is_on(fields, "clear_secret"))),
                    ("events", Field::Unsigned(u64::from(mask))),
                    ("cooldown_seconds", Field::Unsigned(u64::from(cooldown))),
                    ("enabled", Field::Bool(is_on(fields, "enabled"))),
                ],
            )
        });
        self.busy &= result.is_ok();
        result
    }

    /// Removes (`settings-remove`) or tests (`settings-test`) the selected destination.
    fn selected_action(&mut self, cx: &mut Context<'_>, remove: bool) -> Result<(), UiError> {
        let Some(row) = self.selected.and_then(|index| self.rows.get(index)) else {
            return Ok(());
        };
        let (destination, revision) = (row.id, row.revision.to_string());
        let id = self.ticket(cx.state, if remove { Kind::Remove } else { Kind::Testing })?;
        let result = if remove {
            cx.post(&id, "/console/api/notifications/remove", &mut |json| {
                write_fields(
                    json,
                    &[
                        ("id", Field::Unsigned(destination)),
                        ("expected_revision", Field::Text(&revision)),
                    ],
                )
            })
        } else {
            cx.post(&id, "/console/api/notifications/test", &mut |json| {
                write_fields(json, &[("id", Field::Unsigned(destination))])
            })
        };
        self.busy &= result.is_ok();
        result
    }

    /// Changes a threshold or retention setting. Retention needs the acknowledgement that
    /// older records will be deleted.
    fn change_setting(&mut self, cx: &mut Context<'_>, fields: &Value<'_>) -> Result<(), UiError> {
        let key = json::string(fields, "key");
        let Some(entry) = settings::definition(key) else { return Ok(()) };
        let confirmed = is_on(fields, "confirmed");
        let value = json::string(fields, "value");
        if !settings::is_valid(key, value) || (entry.group == Group::Retention && !confirmed) {
            return Ok(());
        }
        let revision = self.setting(key).map_or(0, |item| item.revision).to_string();
        let id = self.ticket(cx.state, Kind::SettingChange)?;
        let result = cx.post(&id, "/console/api/settings/change", &mut |json| {
            write_fields(
                json,
                &[
                    ("key", Field::Text(key)),
                    ("confirmed", Field::Bool(confirmed)),
                    ("value", Field::Text(value)),
                    ("expected_revision", Field::Text(&revision)),
                ],
            )
        });
        self.busy &= result.is_ok();
        result
    }

    /// Handles the page's own actions once the page is open and idle.
    fn page_action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<(), UiError> {
        match name {
            "settings-refresh" => {
                self.after = 0;
                self.query(cx, Kind::Query)
            }
            "settings-next" => match self.next {
                Some(next) => {
                    self.after = next;
                    self.query(cx, Kind::Query)
                }
                None => Ok(()),
            },
            "settings-new" => {
                self.selected = None;
                self.result = Text::default();
                cx.commands.focus("#destination-label")
            }
            "settings-save" => self.save(cx, fields),
            "settings-remove" => self.selected_action(cx, true),
            "settings-test" => self.selected_action(cx, false),
            "settings-thresholds" => self.change_setting(cx, fields),
            _ => match index_after(name, "settings-open-") {
                Some(index) if index < self.rows.len() => {
                    self.selected = Some(index);
                    self.result = Text::default();
                    cx.commands.focus("#destination-label")
                }
                _ => Ok(()),
            },
        }
    }

    /// Takes a successful reply of `kind`.
    fn accept(
        &mut self,
        cx: &mut Context<'_>,
        kind: Kind,
        body: &Value<'_>,
    ) -> Result<(), UiError> {
        match kind {
            Kind::Query => {
                self.accept_page(body)?;
                self.query(cx, Kind::Settings)
            }
            Kind::Settings => {
                self.settings = SettingsPage::decode(body, Path::Root)?.rows;
                if self.about.is_none() {
                    self.query(cx, Kind::About)?;
                }
                Ok(())
            }
            Kind::About => {
                self.about = Some(About::read(body));
                Ok(())
            }
            Kind::Testing => {
                self.result_ok = json::is_true(body, "delivered");
                if json::is_true(body, "audit_recorded") {
                    self.result.set(json::string(body, "detail"))?;
                } else {
                    self.result.set(if self.result_ok {
                        "Delivered; the audit completion is unconfirmed. Check Audit before \
                         retrying."
                    } else {
                        "Delivery failed; the audit completion is unconfirmed."
                    })?;
                    self.result_ok = false;
                }
                self.query(cx, Kind::Query)
            }
            Kind::Save | Kind::Remove | Kind::SettingChange => {
                // A threshold save keeps the open destination; saves and removals close it.
                if kind != Kind::SettingChange {
                    self.selected = None;
                }
                self.query(cx, Kind::Query)?;
                cx.state.set_message("Saved.");
                cx.state.message_success = true;
                Ok(())
            }
        }
    }
}

impl Page for Settings {
    fn screen(&self) -> Option<Screen> {
        Some(Screen::Phase(Phase::Settings))
    }

    fn render(&self, view: &View<'_>, out: &mut Html<'_>) -> std::fmt::Result {
        render::page(self, view.state, out)
    }

    fn action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        let allowed = cx.state.allows(Action::ManageSettings);
        if name == "settings" && allowed {
            self.clear();
            cx.state.phase = Phase::Settings;
            cx.state.clear_message();
            cx.state.stats_busy = false;
            cx.state.stale = true;
            self.query(cx, Kind::Query)?;
            self.templates.read(cx)?;
            return Ok(true);
        }
        if self.templates.action(cx, name, fields)? {
            return Ok(true);
        }
        if !name.starts_with("settings-") {
            return Ok(false);
        }
        if allowed && cx.state.phase == Phase::Settings && !self.busy {
            self.page_action(cx, name, fields)?;
        }
        Ok(true)
    }

    fn response(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) -> Result<bool, UiError> {
        let templates = reply.id.starts_with("pages-");
        if !templates && !reply.id.starts_with("settings-") {
            return Ok(false);
        }
        let Some((status, body)) = reply.complete() else { return Ok(true) };
        if templates {
            self.templates.response(cx, reply.id, status, body)?;
            return Ok(true);
        }
        if cx.state.phase != Phase::Settings || !self.ticket.is(reply.id) {
            return Ok(true);
        }
        self.busy = false;
        if status == 401 {
            cx.end_session(SESSION_ENDED)?;
            return Ok(true);
        }
        if status != 200 {
            cx.state.set_message(failure(status));
            cx.commands.focus("#console-message")?;
            return Ok(true);
        }
        self.accept(cx, self.kind, body)?;
        Ok(true)
    }

    fn reset(&mut self) {
        self.clear();
    }
}

/// Returns the message for a refused settings request.
fn failure(status: i64) -> &'static str {
    match status {
        400 => {
            "Destination rejected: use an HTTPS public webhook (HTTP only for loopback) or \
             host:port for syslog, with a secret of at most 64 bytes."
        }
        409 => "Someone changed this entry first. Refresh and review before retrying.",
        403 => "Only an administrator can change settings.",
        _ => "Settings request failed. Refresh and try again.",
    }
}

#[cfg(test)]
mod tests;
