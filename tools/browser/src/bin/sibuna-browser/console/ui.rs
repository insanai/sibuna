//! The console's interface as the checks drive it: selectors, forms and readings shared by
//! `console` and `dashboards`.
//!
//! The selectors come from `cmd/console-ui`: the sign-in form `form#login` (fields
//! `#username`, `#password`, `#code`), the forced change `form#change-password` (fields
//! `#old_password`, `#password`), the wall-display exchange `form#kiosk-exchange`
//! (`#kiosk-code`), the navigation `nav#console-navigation` whose first menu holds one
//! `button[data-action]` per page, every page's `h1#page-heading`, the operator message
//! `#console-message`, the traffic tiles `.sb-tiles .sb-tile` (label in `.sb-subtitle`,
//! value in `strong`), the traffic period form `form#traffic-period`, and the account
//! page's wall-display grant `form#kiosk-grant` with its code in `#wall-display-code`.
//! Every failure is a sentence for the report.

use std::time::Duration;

use sibuna_browser::{ConsoleMessage, Error, Page};

/// The global function the violation listener reports through.
pub const CSP_BINDING: &str = "__sibunaBrowserCsp";

/// Runs in every document before its scripts: reports each Content-Security-Policy
/// violation as "<directive> <blocked URI>".
const CSP_OBSERVER: &str = r"document.addEventListener('securitypolicyviolation', (event) => {
  const binding = window.__sibunaBrowserCsp;
  if (typeof binding === 'function') {
    binding(event.violatedDirective + ' ' + (event.blockedURI || '(inline)'));
  }
});";

/// True once the Traffic dashboard is on screen.
pub const ON_TRAFFIC: &str =
    "document.querySelector('h1#page-heading')?.textContent === 'Traffic overview'";

/// True once a wall display shows its Traffic view, headed "<scope> \u{b7} Traffic".
pub const ON_KIOSK_TRAFFIC: &str = "!!document.querySelector('main[data-kiosk=true]') && \
    (document.querySelector('h1#page-heading')?.textContent ?? '').endsWith(' Traffic')";

/// The operator message the console shows for a rate-limited sign-in or exchange.
const TOO_MANY: &str = "Too many attempts";

/// How long a sign-in or exchange rate limit window lasts, plus a margin.
const LIMIT_WINDOW: Duration = Duration::from_secs(61);

/// The viewport of every console page.
pub const VIEWPORT: (u32, u32) = (1440, 960);

/// A browser error as a report sentence.
pub fn failed(doing: &str, error: &Error) -> String {
    format!("{doing}: {error}")
}

/// Sets the viewport and installs the violation listener; call before the first
/// navigation.
///
/// # Errors
///
/// The browser's errors.
pub fn prepare(page: &mut Page<'_>) -> Result<(), Error> {
    page.set_viewport(VIEWPORT.0, VIEWPORT.1, false)?;
    page.add_binding(CSP_BINDING)?;
    page.add_init_script(CSP_OBSERVER)
}

/// The shell's URL for the console `origin`.
pub fn shell_url(origin: &str) -> String {
    format!("{}/console/", origin.trim_end_matches('/'))
}

/// Loads the shell and waits for the sign-in form.
///
/// # Errors
///
/// A sentence naming what did not happen.
pub fn open_sign_in(page: &mut Page<'_>, origin: &str, timeout: Duration) -> Result<(), String> {
    let url = shell_url(origin);
    page.navigate(&url).map_err(|error| failed(&format!("loading {url}"), &error))?;
    page.wait_for("!!document.querySelector('form#login')", timeout)
        .map_err(|error| failed("waiting for the sign-in form", &error))?;
    Ok(())
}

/// Replaces the value of the input `selector` with `text`, typed.
///
/// # Errors
///
/// A sentence naming the field.
pub fn fill(page: &mut Page<'_>, selector: &str, text: &str) -> Result<(), String> {
    let clear = format!(
        "(() => {{ const e = document.querySelector({}); if (e) e.value = ''; return !!e; }})()",
        js_string(selector)
    );
    let found = page.evaluate(&clear).map_err(|error| failed("clearing a field", &error))?;
    if found.as_bool() != Some(true) {
        return Err(format!("the field `{selector}` is missing"));
    }
    page.type_text(selector, text)
        .map_err(|error| failed(&format!("typing into {selector}"), &error))
}

/// Clicks `selector`.
///
/// # Errors
///
/// A sentence naming the element.
pub fn click(page: &mut Page<'_>, selector: &str) -> Result<(), String> {
    page.click(selector).map_err(|error| failed(&format!("clicking {selector}"), &error))
}

/// Where a sign-in led.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedIn {
    /// The Traffic dashboard is shown.
    Traffic,
    /// The console demands a new password first.
    MustChange,
}

/// The state after a submitted form: "change", "traffic", "message:<text>" or "" (not
/// settled yet).
const AFTER_SUBMIT: &str = r"(() => {
  if (document.querySelector('form button[type=submit][disabled]')) return '';
  const heading = document.querySelector('h1#page-heading')?.textContent ?? '';
  const kiosk = !!document.querySelector('main[data-kiosk=true]');
  if (heading === 'Traffic overview' || (kiosk && heading.endsWith(' Traffic')))
    return 'traffic';
  const message = document.querySelector('#console-message');
  if (message && message.textContent) return 'message:' + message.textContent;
  if (document.querySelector('form#change-password')) return 'change';
  return '';
})()";

/// Submits the form `form` after `fill_fields` and waits for where it leads, retrying once
/// after the rate-limit window when the console answers "Too many attempts".
fn submit_settled(
    page: &mut Page<'_>,
    form: &str,
    timeout: Duration,
    fill_fields: &dyn Fn(&mut Page<'_>) -> Result<(), String>,
) -> Result<String, String> {
    for attempt in 0..2 {
        fill_fields(page)?;
        click(page, &format!("{form} button[type=submit]"))?;
        let state = page
            .wait_for(AFTER_SUBMIT, timeout)
            .map_err(|error| failed(&format!("waiting for the reply to {form}"), &error))?
            .as_string()
            .unwrap_or_default();
        if attempt == 0 && state.contains(TOO_MANY) {
            page.idle_for(LIMIT_WINDOW)
                .map_err(|error| failed("waiting out the limit", &error))?;
            continue;
        }
        return Ok(state);
    }
    Err(format!("{form} stayed rate limited after waiting a minute"))
}

/// Signs in on the sign-in form.
///
/// # Errors
///
/// A sentence with the console's message when the sign-in is refused.
pub fn sign_in(
    page: &mut Page<'_>,
    username: &str,
    password: &str,
    timeout: Duration,
) -> Result<SignedIn, String> {
    let state = submit_settled(page, "form#login", timeout, &|page| {
        fill(page, "#username", username)?;
        fill(page, "#password", password)
    })?;
    match state.as_str() {
        "change" => Ok(SignedIn::MustChange),
        "traffic" => Ok(SignedIn::Traffic),
        other => Err(format!("the sign-in was refused: {}", other.trim_start_matches("message:"))),
    }
}

/// Replaces the password on the forced-change form and waits for the Traffic dashboard.
///
/// # Errors
///
/// A sentence with the console's message when the change is refused.
pub fn change_password(
    page: &mut Page<'_>,
    old: &str,
    new: &str,
    timeout: Duration,
) -> Result<(), String> {
    let state = submit_settled(page, "form#change-password", timeout, &|page| {
        fill(page, "#old_password", old)?;
        fill(page, "#password", new)
    })?;
    if state == "traffic" {
        Ok(())
    } else {
        Err(format!(
            "the password change did not lead to the Traffic dashboard: {}",
            if state == "change" { "the form is still shown".into() } else { state }
        ))
    }
}

/// Exchanges a wall-display `code` on the sign-in page and waits for the Traffic dashboard.
///
/// # Errors
///
/// A sentence with the console's message when the exchange is refused.
pub fn exchange_kiosk_code(
    page: &mut Page<'_>,
    code: &str,
    timeout: Duration,
) -> Result<(), String> {
    let state = submit_settled(page, "form#kiosk-exchange", timeout, &|page| {
        fill(page, "#kiosk-code", code)
    })?;
    if state == "traffic" {
        Ok(())
    } else {
        Err(format!("the code exchange was refused: {}", state.trim_start_matches("message:")))
    }
}

/// Opens the page of the navigation action `action` (or the Security tab for
/// `security-overview`) and waits until its heading is shown and the history names it.
/// Returns the heading.
///
/// # Errors
///
/// A sentence naming the page.
pub fn open_page(page: &mut Page<'_>, action: &str, timeout: Duration) -> Result<String, String> {
    let quoted = js_string(action);
    let selector = if action == "security-overview" {
        format!("[role=group] button[data-action={quoted}]")
    } else {
        format!("#console-navigation > ul button[data-action={quoted}]")
    };
    click(page, &selector)?;
    let shown = format!(
        "location.hash === '#' + {quoted} && \
         document.getElementById('app')?.getAttribute('aria-busy') === 'false' && \
         (document.querySelector('h1#page-heading')?.textContent ?? '')"
    );
    let heading = page
        .wait_for(&shown, timeout)
        .map_err(|error| failed(&format!("waiting for the `{action}` page"), &error))?;
    Ok(heading.as_string().unwrap_or_default())
}

/// Lets a page load its data: waits until nothing is marked busy (at most `timeout`) and
/// then for `quiet` more, collecting events.
///
/// # Errors
///
/// Connection errors.
pub fn settle(page: &mut Page<'_>, timeout: Duration, quiet: Duration) -> Result<(), Error> {
    let idle = "!document.querySelector('[aria-busy=\"true\"], button[disabled][aria-busy]')";
    match page.wait_for(idle, timeout) {
        Ok(_) | Err(Error::Timeout { .. }) => {}
        Err(error) => return Err(error),
    }
    page.idle_for(quiet)
}

/// Chooses "Live boot totals" as the traffic period, so the tiles follow the stream.
///
/// # Errors
///
/// A sentence naming what did not happen.
pub fn choose_live_totals(page: &mut Page<'_>, timeout: Duration) -> Result<(), String> {
    let select = "(() => { \
                  const s = document.querySelector('#traffic-period select[name=hours]'); \
                  if (!s) return false; s.value = '0'; return true; })()";
    let chosen = page.evaluate(select).map_err(|error| failed("choosing the period", &error))?;
    if chosen.as_bool() != Some(true) {
        return Err("the traffic period form is missing".into());
    }
    click(page, "#traffic-period button.btn-primary")?;
    let live = "[...document.querySelectorAll('.sb-note')]\
                .some((note) => note.textContent.startsWith('Live totals'))";
    page.wait_for(live, timeout)
        .map_err(|error| failed("waiting for live boot totals", &error))?;
    Ok(())
}

/// The traffic tiles as (label, value) pairs.
///
/// # Errors
///
/// A sentence when the tiles cannot be read.
pub fn tiles(page: &mut Page<'_>) -> Result<Vec<(String, String)>, String> {
    let read = "[...document.querySelectorAll('.sb-tiles .sb-tile')].map((tile) => \
                [tile.querySelector('.sb-subtitle')?.textContent ?? '', \
                 tile.querySelector('strong')?.textContent ?? ''])";
    let value = page.evaluate(read).map_err(|error| failed("reading the tiles", &error))?;
    let parsed = value.value().map_err(|error| failed("reading the tiles", &error))?;
    let pairs = parsed
        .as_array()
        .unwrap_or_default()
        .iter()
        .map(|pair| {
            let items = pair.as_array().unwrap_or_default();
            let text = |index: usize| {
                items.get(index).and_then(|item| item.as_str()).unwrap_or_default().to_owned()
            };
            (text(0), text(1))
        })
        .collect();
    Ok(pairs)
}

/// The value of the tile `label`, or empty.
pub fn tile_value(tiles: &[(String, String)], label: &str) -> String {
    tiles
        .iter()
        .find(|(name, _)| name == label)
        .map(|(_, value)| value.clone())
        .unwrap_or_default()
}

/// The tiles as one line: "Requests 12, Admitted 3, ...".
pub fn tiles_line(tiles: &[(String, String)]) -> String {
    let parts: Vec<String> =
        tiles.iter().map(|(label, value)| format!("{label} {value}")).collect();
    parts.join(", ")
}

/// The number of `stats` deltas the page received over its WebSockets.
pub fn stats_delta_count(page: &Page<'_>) -> usize {
    page.websocket_frames()
        .iter()
        .filter(|frame| {
            !frame.sent
                && frame.payload.contains("\"op\":\"delta\"")
                && frame.payload.contains("\"topic\":\"stats\"")
        })
        .count()
}

/// Mints a wall-display code on the account page and returns it.
///
/// # Errors
///
/// A sentence naming what did not happen.
pub fn mint_kiosk_code(
    page: &mut Page<'_>,
    label: &str,
    timeout: Duration,
) -> Result<String, String> {
    if page.evaluate("!!document.querySelector('form#kiosk-grant')").ok().and_then(|v| v.as_bool())
        != Some(true)
    {
        open_page(page, "account", timeout)?;
    }
    page.wait_for("!!document.querySelector('form#kiosk-grant')", timeout)
        .map_err(|error| failed("waiting for the wall-display form", &error))?;
    fill(page, "#wall-display-label", label)?;
    click(page, "#kiosk-grant button[type=submit]")?;
    let code = "(() => { const v = document.querySelector('#wall-display-code')?.value ?? ''; \
                return /^[0-9a-f]{64}$/.test(v) ? v : ''; })()";
    let code = page
        .wait_for(code, timeout)
        .map_err(|error| failed("waiting for the wall-display code", &error))?;
    code.as_string().ok_or_else(|| "the wall-display code is not text".into())
}

/// Hides a minted code, so the grant form is offered again.
///
/// # Errors
///
/// A sentence naming what did not happen.
pub fn hide_kiosk_code(page: &mut Page<'_>, timeout: Duration) -> Result<(), String> {
    click(page, "button[data-action=kiosk-grant-hide]")?;
    page.wait_for("!!document.querySelector('form#kiosk-grant')", timeout)
        .map_err(|error| failed("waiting for the grant form again", &error))?;
    Ok(())
}

/// What went wrong on a page: exceptions, console errors and CSP violations, as lines.
///
/// Console errors for which `expected` holds are left out, and so is Chromium's own
/// request for `/favicon.ico`, which the console answers 404: the browser makes it for
/// every new origin, not the page.
pub fn problems(page: &Page<'_>, expected: &dyn Fn(&ConsoleMessage) -> bool) -> Vec<String> {
    let mut lines: Vec<String> = page
        .exceptions()
        .iter()
        .map(|exception| {
            format!("exception: {} ({}:{})", exception.text, exception.url, exception.line)
        })
        .collect();
    lines.extend(
        page.console_messages()
            .iter()
            .filter(|message| message.is_error() && !is_favicon(message) && !expected(message))
            .map(|message| {
                format!(
                    "console {} {}: {} {}",
                    message.source, message.level, message.text, message.url
                )
            }),
    );
    lines.extend(
        page.binding_calls()
            .iter()
            .filter(|call| call.name == CSP_BINDING)
            .map(|call| format!("CSP violation: {}", call.payload)),
    );
    lines
}

/// No console error is expected.
pub fn none_expected(_: &ConsoleMessage) -> bool {
    false
}

/// The browser's report of the signed-out session check: the shell asks
/// `/console/api/session` first, and the console answers 401 until someone signs in.
pub fn signed_out_probe(message: &ConsoleMessage) -> bool {
    message.source == "network"
        && message.url.ends_with("/console/api/session")
        && message.text.contains("status of 401")
}

/// True for the browser's report of its own favicon request.
fn is_favicon(message: &ConsoleMessage) -> bool {
    message.source == "network" && message.url.ends_with("/favicon.ico")
}

/// `text` as a JavaScript string literal.
pub fn js_string(text: &str) -> String {
    let mut literal = String::new();
    // Writing into a String cannot fail.
    let _ = sibuna_json::write_string(&mut literal, text);
    literal
}
