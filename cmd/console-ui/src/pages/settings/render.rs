//! The settings page markup (`settings_page.zig`).

use std::fmt::{self, Write as _};

use sibuna_console_protocol::Action;
use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::notifications::{self, Event, Kind, Transport};
use sibuna_console_protocol::settings::{CATALOG, Group};

use super::{About, Settings};
use crate::render::{Html, value};
use crate::snippets;
use crate::state::State;

/// Returns `text` when `on`, otherwise nothing.
fn when(on: bool, text: &'static str) -> &'static str {
    if on { text } else { "" }
}

/// Draws the settings page.
pub(super) fn page(model: &Settings, state: &State, out: &mut Html<'_>) -> fmt::Result {
    let busy = when(model.busy, " disabled");
    snippets::render_settings_header(out, &snippets::SettingsHeaderValues { busy: &busy })?;
    if !state.allows(Action::ManageSettings) {
        return out
            .write_str("<p>An administrator manages notifications and thresholds.</p></main>");
    }
    if !state.message.is_empty() {
        out.write_str("<p id=\"console-message\" tabindex=\"-1\" role=\"status\">")?;
        out.escaped(state.message.as_str())?;
        out.write_str("</p>")?;
    }
    out.write_str(
        "<section class=\"sb-panel\"><h2>Notification destinations</h2><p class=\"sb-note\">\
         At most eight destinations. Webhooks receive a JSON body with an HMAC-SHA256 \
         signature when a secret is set; syslog receives RFC 5424 lines over UDP or framed \
         TCP, selected explicitly below. Secrets are stored sealed and never shown again.</p>\
         <div class=\"overflow-x-auto\"><table class=\"table\"><thead><tr><th>Label</th>\
         <th>Kind</th><th>Target</th><th>Events</th><th>Last outcome</th><th></th></tr>\
         </thead><tbody>",
    )?;
    for (index, row) in model.rows.iter().enumerate() {
        snippets::render_notification_row(
            out,
            &snippets::NotificationRowValues {
                label: &row.label.as_str(),
                kind: &kind_label(row.kind, row.transport),
                target: &row.target.as_str(),
                events: &events_text(row.events),
                outcome: &row.last_outcome.map_or("never", |outcome| outcome.name()),
                detail: &row.last_detail.as_str(),
                enabled: &when(!row.enabled, " (disabled)"),
                index: &index,
            },
        )?;
    }
    out.write_str(
        "</tbody></table></div><div class=\"flex flex-wrap gap-2 mt-3\">\
         <button class=\"btn btn-sm\" data-action=\"settings-new\"",
    )?;
    out.write_str(busy)?;
    out.write_str(
        ">New destination</button><button class=\"btn btn-sm\" data-action=\"settings-next\"",
    )?;
    out.write_str(when(model.busy || model.next.is_none(), " disabled"))?;
    out.write_str(">Next page</button></div>")?;
    form(model, out)?;
    thresholds(model, out)?;
    model.templates.render(out)?;
    if let Some(about) = &model.about {
        render_about(about, out)?;
    }
    out.write_str("</main>")
}

fn kind_label(kind: Kind, transport: Transport) -> &'static str {
    match (kind, transport) {
        (Kind::Webhook, _) => "webhook",
        (Kind::Syslog, Transport::Tcp) => "syslog / TCP",
        (Kind::Syslog, Transport::Udp) => "syslog / UDP",
    }
}

fn events_text(mask: u8) -> &'static str {
    match mask {
        notifications::ALL_EVENTS => "all",
        1 => "denial spike",
        2 => "ban",
        4 => "node unhealthy",
        8 => "leader change",
        _ => "several",
    }
}

/// Draws the destination form: the selected destination, or a new one (a webhook over
/// UDP, every event, enabled).
fn form(model: &Settings, out: &mut Html<'_>) -> fmt::Result {
    let row = model.selected.and_then(|index| model.rows.get(index));
    let kind = row.map_or(Kind::Webhook, |row| row.kind);
    let transport = row.map_or(Transport::Udp, |row| row.transport);
    let events = row.map_or(0, |row| row.events);
    let checked = |event: Event| when(events == 0 || events & event.bit() != 0, " checked");
    let secret_note = if row.is_some_and(|row| row.secret_set) {
        "A secret is stored. Leave blank to keep it or tick clear to remove it."
    } else {
        "Optional shared secret for the webhook signature (at most 64 bytes)."
    };
    snippets::render_notification_form(
        out,
        &snippets::NotificationFormValues {
            heading: &if row.is_none() { "New destination" } else { "Edit destination" },
            webhook: &when(kind == Kind::Webhook, " selected"),
            syslog: &when(kind == Kind::Syslog, " selected"),
            udp: &when(transport == Transport::Udp, " selected"),
            tcp: &when(transport == Transport::Tcp, " selected"),
            label: &row.map_or("", |row| row.label.as_str()),
            target: &row.map_or("", |row| row.target.as_str()),
            secret_note: &secret_note,
            spike: &checked(Event::DenialSpike),
            ban: &checked(Event::Ban),
            unhealthy: &checked(Event::NodeUnhealthy),
            leader: &checked(Event::LeaderChange),
            cooldown: &row.map_or(0, |row| row.cooldown_seconds),
            enabled: &when(row.is_none_or(|row| row.enabled), " checked"),
            busy: &when(model.busy, " disabled"),
            existing: &when(model.selected.is_none(), " disabled"),
        },
    )?;
    if !model.result.is_empty() {
        out.write_str("<p role=\"status\" class=\"")?;
        out.write_str(if model.result_ok { "sb-success" } else { "sb-error" })?;
        out.write_str("\">Test delivery: ")?;
        out.escaped(model.result.as_str())?;
        out.write_str("</p>")?;
    }
    out.write_str("</section>")
}

fn thresholds(model: &Settings, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<section class=\"sb-panel\"><h2>Denial spike thresholds</h2><p class=\"sb-note\">A \
         spike is raised when denials in the last 60 seconds exceed both the minimum and the \
         factor times the previous 60 seconds; it re-arms below that threshold.</p>",
    )?;
    setting_rows(model, Group::Notification, out)?;
    out.write_str(
        "</section><section class=\"sb-panel\"><h2>Retention</h2><p class=\"sb-note\">Choose \
         retention within the displayed limits. Cleanup deletes older records in bounded \
         batches. A higher value cannot restore deleted history. Rankings also have a fixed \
         512 MiB quota and may expire sooner.</p>",
    )?;
    setting_rows(model, Group::Retention, out)?;
    out.write_str("</section>")
}

fn setting_rows(model: &Settings, group: Group, out: &mut Html<'_>) -> fmt::Result {
    let retention = group == Group::Retention;
    for entry in CATALOG.iter().filter(|entry| entry.group == group) {
        let current = model.setting(entry.key);
        snippets::render_setting_row(
            out,
            &snippets::SettingRowValues {
                key: &entry.key,
                label: &entry.label,
                maximum: &entry.maximum,
                default: &entry.default,
                confirmation: &when(!retention, " hidden"),
                required: &when(retention, " required"),
                value: &current.map_or(entry.default, |item| item.value.as_str()),
                revision: &current.map_or(0, |item| item.revision),
                busy: &when(model.busy, " disabled"),
            },
        )?;
    }
    Ok(())
}

fn render_about(about: &About, out: &mut Html<'_>) -> fmt::Result {
    let yes = |flag: bool| if flag { "yes" } else { "no" };
    out.write_str(
        "<section class=\"sb-panel\"><h2>About</h2><dl class=\"sb-facts\"><dt>Version</dt><dd>",
    )?;
    out.escaped(&about.version)?;
    out.write_str("</dd><dt>Node</dt><dd>")?;
    value(out, &about.node)?;
    out.write_str("</dd><dt>Console schema</dt><dd>")?;
    value(out, &about.schema)?;
    out.write_str("</dd><dt>Origin</dt><dd>")?;
    out.escaped(&about.origin)?;
    out.write_str("</dd><dt>Advertised console</dt><dd>")?;
    out.escaped(if about.advertise.is_empty() { "same as origin" } else { &about.advertise })?;
    out.write_str("</dd><dt>Behind a trusted proxy</dt><dd>")?;
    out.write_str(yes(about.behind_proxy))?;
    out.write_str(" (")?;
    value(out, &about.trusted_proxies)?;
    out.write_str(" trusted ranges)</dd><dt>Secure cookies</dt><dd>")?;
    out.write_str(yes(about.cookie_secure))?;
    out.write_str("</dd><dt>Console key file</dt><dd>")?;
    out.write_str(yes(about.key_file))?;
    out.write_str("</dd><dt>Configured peer probes</dt><dd>")?;
    value(out, &about.probes)?;
    out.write_str("</dd></dl></section>")
}
