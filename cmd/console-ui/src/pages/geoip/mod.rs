//! The GeoIP database (phase `geoip`): the active dataset's metadata, the import's
//! progress and the import form.
//!
//! Ported from `geoip_page.zig` and the GeoIP branches of `main.zig`
//! (`geographicAction`, `geoResponse`, and the timer and visibility branches). The
//! metadata moved out of the Zig `State` into [`Geoip`].

use std::fmt::{self, Write as _};

use sibuna_console_protocol::Text;
use sibuna_console_protocol::geo::Metadata;
use sibuna_json::Value;

use crate::commands::{Field, write_fields};
use crate::error::UiError;
use crate::format;
use crate::json;
use crate::page::{Context, Page, Reply, SESSION_ENDED, Screen, View};
use crate::render::{Html, value};
use crate::state::{Phase, State};

/// The import states during which the page polls every second.
const ACTIVE: [&str; 3] = ["downloading", "validating", "storing"];

/// The GeoIP page.
#[derive(Debug, Default)]
pub struct Geoip {
    /// The active dataset.
    pub metadata: Metadata,
    /// The import state the server reports, such as `storing` or `failed`.
    pub status: Text<16>,
    /// Ranges the import has processed.
    pub progress: u32,
    /// An import request is in flight or an import is running.
    pub importing: bool,
}

impl Geoip {
    /// Returns true when the active dataset comes from DB-IP.
    fn is_dbip(&self) -> bool {
        self.metadata.provider.as_str() == "dbip"
    }

    /// Takes a status reply; an active import polls again in a second.
    fn accept(&mut self, cx: &mut Context<'_>, body: &Value<'_>) -> Result<(), UiError> {
        cx.state.clear_message();
        let number = |key| json::unsigned_or_zero(body, key);
        let ranges = u32::try_from(number("ranges")).map_err(|_| UiError::InvalidResponse)?;
        self.metadata = Metadata {
            revision: number("revision"),
            digest: Text::new(json::string(body, "digest"))?,
            provider: Text::new(json::string(body, "provider"))?,
            source_version: Text::new(json::string(body, "source_version"))?,
            source_digests: Text::new(json::string(body, "source_digests"))?,
            ranges,
            loaded_at: number("loaded_at"),
        };
        self.status = Text::new(json::string(body, "status"))?;
        self.progress =
            u32::try_from(number("processed_ranges")).map_err(|_| UiError::InvalidResponse)?;
        self.importing = ACTIVE.contains(&self.status.as_str());
        if self.importing {
            cx.commands.timer("geoip", 1000)?;
        }
        Ok(())
    }

    /// Takes a reply to `geoip` or `geo-import`.
    fn reply(
        &mut self,
        cx: &mut Context<'_>,
        id: &str,
        status: i64,
        body: &Value<'_>,
    ) -> Result<(), UiError> {
        self.importing = false;
        if cx.state.phase != Phase::Geoip {
            return Ok(());
        }
        match status {
            401 | 403 => cx.end_session(SESSION_ENDED),
            0 => {
                cx.state.set_message("Connection lost. Import status is unknown; reconnecting.");
                self.importing = true;
                cx.commands.timer("geoip", 5000)
            }
            200 if id == "geo-import" => cx.get("geoip", "/console/api/geoip"),
            200 => self.accept(cx, body),
            _ => {
                cx.state.set_message(
                    "Import could not start. Check the source month, checksum, and revision.",
                );
                Ok(())
            }
        }
    }
}

impl Page for Geoip {
    fn screen(&self) -> Option<Screen> {
        Some(Screen::Phase(Phase::Geoip))
    }

    fn render(&self, view: &View<'_>, out: &mut Html<'_>) -> fmt::Result {
        render(self, view.state, out)
    }

    fn action(
        &mut self,
        cx: &mut Context<'_>,
        name: &str,
        fields: &Value<'_>,
    ) -> Result<bool, UiError> {
        if name == "geoip" && cx.state.is_full_access() {
            cx.state.phase = Phase::Geoip;
            cx.state.stats_busy = false;
            cx.get("geoip", "/console/api/geoip")?;
            return Ok(true);
        }
        if name != "geo-import" || cx.state.phase != Phase::Geoip || self.importing {
            return Ok(false);
        }
        self.importing = true;
        let revision = self.metadata.revision;
        cx.post("geo-import", "/console/api/geoip", &mut |json| {
            write_fields(
                json,
                &[
                    ("provider", Field::Text(json::string(fields, "provider"))),
                    ("source_version", Field::Text(json::string(fields, "source_version"))),
                    ("expected_revision", Field::Unsigned(revision)),
                    ("checksum", Field::Text(json::string(fields, "checksum"))),
                    ("csv", Field::Text(json::string(fields, "csv"))),
                ],
            )
        })?;
        Ok(true)
    }

    fn response(&mut self, cx: &mut Context<'_>, reply: &Reply<'_, '_>) -> Result<bool, UiError> {
        if reply.id != "geoip" && reply.id != "geo-import" {
            return Ok(false);
        }
        if let Some((status, body)) = reply.complete() {
            self.reply(cx, reply.id, status, body)?;
        }
        Ok(true)
    }

    fn timer(&mut self, cx: &mut Context<'_>, id: &str) -> Result<bool, UiError> {
        // Zig refreshed the open page on every timer but the age tick and the reputation
        // undo deadline, which returned before reaching this branch.
        if cx.state.phase == Phase::Geoip && id != "age" && id != "reputation-undo" {
            cx.get("geoip", "/console/api/geoip")?;
        }
        Ok(false)
    }

    fn resume(&mut self, cx: &mut Context<'_>) -> Result<(), UiError> {
        if cx.state.phase == Phase::Geoip {
            cx.get("geoip", "/console/api/geoip")?;
        }
        Ok(())
    }

    fn reset(&mut self) {
        *self = Geoip::default();
    }
}

/// Draws the GeoIP page.
fn render(model: &Geoip, state: &State, out: &mut Html<'_>) -> fmt::Result {
    out.write_str(
        "<main class=\"sb-main min-h-screen\"><header class=\"sb-header\"><div>\
         <p class=\"sb-subtitle\">COUNTRY ENRICHMENT</p>\
         <h1 id=\"page-heading\" tabindex=\"-1\">GeoIP</h1></div>\
         <button class=\"btn\" data-action=\"dashboard\">Back to dashboard</button></header>\
         <section class=\"sb-panel mt-6\">",
    )?;
    out.write_str(if model.is_dbip() {
        "<h2>DB-IP IP to Country Lite</h2><p>Monthly country data, licensed under CC BY 4.0. \
         <a href=\"https://db-ip.com/db/lite.php\">IP Geolocation by DB-IP</a>.</p>"
    } else {
        "<h2>ip-location-db user-country</h2><p>Daily country data in the public domain \
         (PDDL 1.0); no attribution is required.</p>"
    })?;
    let metadata = &model.metadata;
    out.write_str("<p>Active revision: ")?;
    value(out, &metadata.revision)?;
    out.write_str(" \u{b7} Known ranges loaded: ")?;
    value(out, &metadata.ranges)?;
    out.write_str(" \u{b7} Source version: ")?;
    out.escaped(metadata.source_version.as_str())?;
    out.write_str("</p><p>Generation digest: <code class=\"break-all\">")?;
    out.escaped(if metadata.digest.is_empty() { "none" } else { metadata.digest.as_str() })?;
    out.write_str("</code></p><p>Loaded: ")?;
    if metadata.loaded_at == 0 {
        out.write_str("never")?;
    } else {
        format::timestamp(out, metadata.loaded_at)?;
    }
    out.write_str("</p><p>Status: ")?;
    out.escaped(model.status.as_str())?;
    out.write_str(" \u{b7} ")?;
    value(out, &model.progress)?;
    out.write_str(" ranges processed</p>")?;
    if model.status.as_str() == "failed" {
        out.write_str(
            "<p role=\"status\" class=\"sb-error\">Import failed. The previous generation \
             remains active. Check the provider, published version, network connection, CSV, \
             and checksum before retrying.</p>",
        )?;
    }
    if !state.message.is_empty() {
        out.write_str("<p role=\"status\" class=\"sb-error\">")?;
        out.escaped(state.message.as_str())?;
        out.write_str("</p>")?;
    }
    if state.role.as_str() != "admin" {
        return out
            .write_str("<p>An administrator can import a country database.</p></section></main>");
    }
    form(model, out)
}

fn form(model: &Geoip, out: &mut Html<'_>) -> fmt::Result {
    let dbip = model.is_dbip();
    out.write_str(
        "<form id=\"geo-import\" class=\"sb-settings-form\"><label for=\"provider\">Provider\
         </label><select id=\"provider\" name=\"provider\" class=\"select select-bordered\">\
         <option value=\"user-country\"",
    )?;
    out.write_str(if dbip { "" } else { " selected" })?;
    out.write_str(
        ">ip-location-db user-country (public domain, daily)</option><option value=\"dbip\"",
    )?;
    out.write_str(if dbip { " selected" } else { "" })?;
    out.write_str(
        ">DB-IP IP to Country Lite (CC BY 4.0, monthly)</option></select>\
         <label for=\"source_version\">Published version (YYYY-MM-DD, or YYYY-MM for DB-IP)\
         </label><input id=\"source_version\" name=\"source_version\" \
         class=\"input input-bordered\" required pattern=\"[0-9]{4}-[0-9]{2}(-[0-9]{2})?\" \
         maxlength=\"10\" value=\"",
    )?;
    out.escaped(model.metadata.source_version.as_str())?;
    out.write_str(
        "\"><label for=\"checksum\">Operator SHA-256 of the source bytes (optional)</label>\
         <input id=\"checksum\" name=\"checksum\" class=\"input input-bordered\" \
         maxlength=\"64\"><p class=\"sb-note\">Publisher checksums are always verified when \
         the provider publishes them; an independently supplied digest also pins the \
         expected files.</p><details><summary>Import a small CSV instead</summary>\
         <label for=\"csv\">Address start, address end, country code (up to 8 KiB)</label>\
         <textarea id=\"csv\" name=\"csv\" class=\"textarea textarea-bordered\" rows=\"5\" \
         maxlength=\"8192\"></textarea></details><p class=\"sb-note\">Otherwise the console \
         downloads the selected version from the provider over HTTPS. Invalid data never \
         replaces the active database.</p><button class=\"btn btn-primary\" type=\"submit\"",
    )?;
    if model.importing {
        out.write_str(" disabled aria-busy=\"true\"")?;
    }
    out.write_str(">Import country data</button></form></section></main>")
}

#[cfg(test)]
mod tests;
