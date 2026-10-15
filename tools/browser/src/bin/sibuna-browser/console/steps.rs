//! The steps of the console walk, each judged into a [`Step`] with its screenshots.

use std::time::Duration;

use sibuna_browser::{Browser, Page};

use super::ui::{self, SignedIn, failed};
use super::{Step, Walk, step};
use crate::traffic::{self, Target};

/// How long a page may keep loading after its heading is shown, collecting errors.
const QUIET: Duration = Duration::from_millis(1500);

/// The requests per traffic burst, and the threads sending them.
const BURST: u32 = 150;
const BURST_THREADS: u32 = 4;

/// The file of the globe's geometry, which only a signed-in dashboard may fetch.
const GEOMETRY: &str = "world-110m.bin";

/// Turns the problems a page reported into the step's failure.
fn judge_problems(problems: Vec<String>, step: &mut Step) -> Result<(), String> {
    if problems.is_empty() {
        return Ok(());
    }
    let count = problems.len();
    step.notes.extend(problems);
    Err(format!("{count} exception(s), console error(s) or CSP violation(s); see below"))
}

/// Step 1: the shell before sign-in opens no WebSocket and fetches no geometry.
pub fn shell(walk: &mut Walk<'_>, page: &mut Page<'_>) -> bool {
    let mut step = step("shell");
    step.outcome = shell_check(walk, page, &mut step);
    walk.screenshot(page, "sign-in-form", &mut step);
    walk.record(step)
}

fn shell_check(walk: &Walk<'_>, page: &mut Page<'_>, step: &mut Step) -> Result<String, String> {
    ui::open_sign_in(page, &walk.settings.url, walk.settings.timeout)?;
    // Give a shell that would connect early the time to do so.
    page.idle_for(Duration::from_secs(2)).map_err(|error| failed("idling", &error))?;
    for request in page.requests() {
        step.notes.push(format!("request {} {}", request.method, request.url));
    }
    if let Some(socket) = page.websockets().first() {
        return Err(format!("the signed-out shell opened a WebSocket to {}", socket.url));
    }
    if let Some(request) = page.requests().iter().find(|request| request.url.contains(GEOMETRY)) {
        return Err(format!("the signed-out shell requested {}", request.url));
    }
    judge_problems(ui::problems(page, &ui::signed_out_probe), step)?;
    Ok(format!(
        "the sign-in form is shown after {} request(s), none for {GEOMETRY}; no WebSocket",
        page.requests().len()
    ))
}

/// Step 2: sign-in, the forced password change, and the Traffic dashboard.
pub fn sign_in(walk: &mut Walk<'_>, page: &mut Page<'_>) -> bool {
    let mut step = step("sign-in");
    page.clear_observations();
    step.outcome = sign_in_check(walk, page, &mut step);
    walk.screenshot(page, "traffic-dashboard", &mut step);
    walk.record(step)
}

fn sign_in_check(
    walk: &mut Walk<'_>,
    page: &mut Page<'_>,
    step: &mut Step,
) -> Result<String, String> {
    let settings = walk.settings;
    let timeout = settings.timeout;
    let signed = ui::sign_in(page, &settings.username, &settings.password, timeout)?;
    let detail = match (signed, &settings.new_password) {
        (SignedIn::MustChange, None) => {
            return Err("the console demands a new password; give --new-password-file".into());
        }
        (SignedIn::Traffic, Some(_)) => {
            return Err("the console did not demand a password change".into());
        }
        (SignedIn::MustChange, Some(new)) => {
            walk.screenshot(page, "password-change", step);
            ui::change_password(page, &settings.password, new, timeout)?;
            "the initial password led to the forced change, then to the Traffic dashboard"
        }
        (SignedIn::Traffic, None) => "the password led to the Traffic dashboard",
    };
    page.wait_for_observation("the stream's WebSocket to open", timeout, |page| {
        page.websockets().iter().any(|socket| socket.status == 101 && !socket.closed)
    })
    .map_err(|error| failed("waiting for the stream", &error))?;
    ui::settle(page, timeout, QUIET).map_err(|error| failed("settling", &error))?;
    let geometry = page.requests().iter().any(|request| request.url.contains(GEOMETRY));
    step.notes.push(format!("{GEOMETRY} requested after sign-in: {geometry}"));
    judge_problems(ui::problems(page, &ui::none_expected), step)?;
    Ok(format!("{detail}; the stream's WebSocket is open"))
}

/// Step 3: the Traffic tiles follow generated traffic across two stream deltas.
pub fn traffic(walk: &mut Walk<'_>, page: &mut Page<'_>, target: &Target) -> bool {
    let mut step = step("traffic");
    page.clear_observations();
    step.outcome = traffic_check(walk, page, target, &mut step);
    walk.screenshot(page, "traffic-after-bursts", &mut step);
    walk.record(step)
}

fn traffic_check(
    walk: &Walk<'_>,
    page: &mut Page<'_>,
    target: &Target,
    step: &mut Step,
) -> Result<String, String> {
    let timeout = walk.settings.timeout;
    ui::choose_live_totals(page, timeout)?;
    page.idle_for(Duration::from_secs(1)).map_err(|error| failed("idling", &error))?;
    let tiles = ui::tiles(page)?;
    step.notes.push(format!("before: {}", ui::tiles_line(&tiles)));
    let mut values = vec![ui::tile_value(&tiles, "Requests")];
    let first_delta = ui::stats_delta_count(page);
    for round in 1..=2 {
        let deltas = ui::stats_delta_count(page);
        let tally = traffic::burst(target, BURST, BURST_THREADS);
        step.notes.push(format!("burst {round}: {}", tally.summary()));
        let previous = values.last().cloned().unwrap_or_default();
        let changed = format!("{} !== {}", REQUESTS_TILE, ui::js_string(&previous));
        page.wait_for(&changed, timeout).map_err(|error| {
            failed(&format!("waiting for the tiles after burst {round}"), &error)
        })?;
        page.wait_for_observation("a stats delta", timeout, |page| {
            ui::stats_delta_count(page) > deltas
        })
        .map_err(|error| failed(&format!("waiting for a delta after burst {round}"), &error))?;
        let tiles = ui::tiles(page)?;
        let seen = ui::stats_delta_count(page) - first_delta;
        step.notes
            .push(format!("after burst {round} ({seen} deltas): {}", ui::tiles_line(&tiles)));
        values.push(ui::tile_value(&tiles, "Requests"));
    }
    let deltas = ui::stats_delta_count(page) - first_delta;
    if deltas < 2 {
        return Err(format!("only {deltas} stats delta(s) arrived"));
    }
    judge_problems(ui::problems(page, &ui::none_expected), step)?;
    Ok(format!("the Requests tile went {} across {deltas} stats deltas", values.join(" -> ")))
}

/// The text of the Requests tile's value.
const REQUESTS_TILE: &str = "([...document.querySelectorAll('.sb-tiles .sb-tile')]\
    .find((tile) => tile.querySelector('.sb-subtitle')?.textContent === 'Requests')\
    ?.querySelector('strong')?.textContent ?? '')";

/// The pages of the navigation as (action, label) pairs, with the Security tab after the
/// dashboard.
const NAVIGATION: &str = "[...document.querySelectorAll('#console-navigation > ul \
    button[data-action]')].map((button) => [button.dataset.action, button.textContent.trim()])";

/// Step 4: every page of the navigation, and the Security tab.
pub fn pages(walk: &mut Walk<'_>, page: &mut Page<'_>) {
    let mut pages = match navigation(page) {
        Ok(pages) if !pages.is_empty() => pages,
        outcome => {
            let mut step = step("pages");
            let reason = outcome.err().unwrap_or_else(|| "the navigation offers no pages".into());
            step.outcome = Err(reason);
            walk.record(step);
            return;
        }
    };
    let after_dashboard =
        pages.iter().position(|(action, _)| action == "dashboard").map_or(0, |i| i + 1);
    pages
        .insert(after_dashboard, ("security-overview".into(), "Security (statistics tab)".into()));
    for (action, label) in pages {
        let mut step = step(format!("page: {label}"));
        page.clear_observations();
        step.outcome = page_check(walk, page, &action, &mut step);
        walk.screenshot(page, &format!("page-{action}"), &mut step);
        walk.record(step);
    }
}

/// The navigation's pages as (action, label) pairs.
fn navigation(page: &mut Page<'_>) -> Result<Vec<(String, String)>, String> {
    let listed =
        page.evaluate(NAVIGATION).map_err(|error| failed("reading the navigation", &error))?;
    let value = listed.value().map_err(|error| failed("reading the navigation", &error))?;
    let pairs = value
        .as_array()
        .unwrap_or_default()
        .iter()
        .filter_map(|pair| {
            let items = pair.as_array()?;
            Some((items.first()?.as_str()?.to_owned(), items.get(1)?.as_str()?.to_owned()))
        })
        .collect();
    Ok(pairs)
}

/// The texts of error states on screen.
const ERROR_STATES: &str = "[...document.querySelectorAll(\
    '.sb-error, .alert-error, [role=alert]')].map((node) => node.textContent.trim())\
    .filter((text) => text.length > 0)";

/// The focused element and the scroll position, for reading a screenshot.
const FOCUS: &str = "(() => { const e = document.activeElement; \
    return (e ? e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + \
    (e.className ? '.' + String(e.className).split(' ').join('.') : '') : 'none') + \
    ' at scrollY ' + Math.round(scrollY); })()";

fn page_check(
    walk: &Walk<'_>,
    page: &mut Page<'_>,
    action: &str,
    step: &mut Step,
) -> Result<String, String> {
    let timeout = walk.settings.timeout;
    let heading = ui::open_page(page, action, timeout)?;
    ui::settle(page, timeout, QUIET).map_err(|error| failed("settling", &error))?;
    if let Ok(states) = page.evaluate(ERROR_STATES)
        && let Ok(value) = states.value()
    {
        for text in value.as_array().unwrap_or_default().iter().filter_map(|item| item.as_str()) {
            step.notes.push(format!("error state shown: {text}"));
        }
    }
    if let Ok(focus) = page.evaluate(FOCUS) {
        step.notes.push(format!("focus and scroll: {}", focus.as_string().unwrap_or_default()));
    }
    judge_problems(ui::problems(page, &ui::none_expected), step)?;
    Ok(format!("heading \"{heading}\""))
}

/// Step 5: a wall display opened with a one-time code shows statistics only.
pub fn kiosk(walk: &mut Walk<'_>, page: &mut Page<'_>) -> bool {
    let mut step = step("kiosk");
    page.clear_observations();
    step.outcome = kiosk_check(walk, page, &mut step);
    walk.record(step)
}

fn kiosk_check(
    walk: &mut Walk<'_>,
    page: &mut Page<'_>,
    step: &mut Step,
) -> Result<String, String> {
    let timeout = walk.settings.timeout;
    let code = ui::mint_kiosk_code(page, "walk-through display", timeout)?;
    walk.screenshot(page, "kiosk-grant", step);
    ui::hide_kiosk_code(page, timeout)?;
    let mut browser = Browser::launch(crate::browser_options())
        .map_err(|error| failed("launching a second browser", &error))?;
    let mut display =
        browser.new_page().map_err(|error| failed("opening the display's page", &error))?;
    ui::prepare(&mut display).map_err(|error| failed("preparing the display", &error))?;
    let outcome = display_check(walk, &mut display, &code, step);
    if outcome.is_err() {
        walk.screenshot(&mut display, "kiosk-display-failed", step);
    }
    outcome
}

/// Exchanges `code` on the display and judges what the display shows and may do.
fn display_check(
    walk: &mut Walk<'_>,
    display: &mut Page<'_>,
    code: &str,
    step: &mut Step,
) -> Result<String, String> {
    let timeout = walk.settings.timeout;
    ui::open_sign_in(display, &walk.settings.url, timeout)?;
    ui::exchange_kiosk_code(display, code, timeout)?;
    display
        .wait_for_observation("the display's WebSocket to open", timeout, |page| {
            page.websockets().iter().any(|socket| socket.status == 101 && !socket.closed)
        })
        .map_err(|error| failed("waiting for the display's stream", &error))?;
    ui::settle(display, timeout, QUIET).map_err(|error| failed("settling", &error))?;
    let tiles = ui::tiles(display)?;
    step.notes.push(format!("display tiles: {}", ui::tiles_line(&tiles)));
    walk.screenshot(display, "kiosk-display", step);
    judge_problems(ui::problems(display, &ui::signed_out_probe), step)?;
    let refused = kiosk_limits(display, timeout, step)?;
    walk.screenshot(display, "kiosk-after-users-route", step);
    Ok(format!(
        "the display shows its Traffic view ({} tiles) without navigation; {refused}",
        tiles.len()
    ))
}

/// Checks that the display offers no management page and is refused one; returns what
/// was refused.
fn kiosk_limits(
    display: &mut Page<'_>,
    timeout: Duration,
    step: &mut Step,
) -> Result<String, String> {
    let offered = "!!document.querySelector('#console-navigation, [data-action=users], \
                   [data-action=settings], [data-action=account]')";
    let offered =
        display.evaluate(offered).map_err(|error| failed("looking for management", &error))?;
    if offered.as_bool() != Some(false) {
        return Err("the display offers management navigation".into());
    }
    let probe =
        "fetch('/console/api/nodes/local', {credentials: 'same-origin'}).then((r) => r.status)";
    let status = display
        .evaluate(probe)
        .map_err(|error| failed("requesting a management route", &error))?
        .as_f64()
        .unwrap_or(0.0);
    step.notes.push(format!("GET /console/api/nodes/local from the display: {status}"));
    if status != 401.0 && status != 403.0 {
        return Err(format!("the display's request for a management route answered {status}"));
    }
    display
        .evaluate("location.hash = '#users'")
        .map_err(|error| failed("asking for the users route", &error))?;
    display.idle_for(Duration::from_secs(1)).map_err(|error| failed("idling", &error))?;
    display
        .wait_for(ui::ON_KIOSK_TRAFFIC, timeout)
        .map_err(|error| failed("the display left its Traffic view for #users", &error))?;
    Ok(format!(
        "GET /console/api/nodes/local answered {status}; the #users route keeps the Traffic view"
    ))
}

/// Step 6: signing out shows the sign-in form and closes every WebSocket.
pub fn sign_out(walk: &mut Walk<'_>, page: &mut Page<'_>) -> bool {
    let mut step = step("sign-out");
    page.clear_observations();
    step.outcome = sign_out_check(walk, page, &mut step);
    walk.screenshot(page, "signed-out", &mut step);
    walk.record(step)
}

fn sign_out_check(
    walk: &Walk<'_>,
    page: &mut Page<'_>,
    step: &mut Step,
) -> Result<String, String> {
    let timeout = walk.settings.timeout;
    let open = page.websockets().iter().filter(|socket| !socket.closed).count();
    if open == 0 {
        return Err("no WebSocket was open before signing out".into());
    }
    ui::click(page, "#console-navigation button[data-action=logout]")?;
    page.wait_for("!!document.querySelector('form#login')", timeout)
        .map_err(|error| failed("waiting for the sign-in form", &error))?;
    page.wait_for_observation("every WebSocket to close", timeout, |page| {
        page.websockets().iter().all(|socket| socket.closed)
    })
    .map_err(|error| failed("waiting for the WebSocket to close", &error))?;
    for socket in page.websockets() {
        step.notes.push(format!(
            "socket {}: {} frames in, {} out, closed",
            socket.url, socket.frames_received, socket.frames_sent
        ));
    }
    judge_problems(ui::problems(page, &ui::none_expected), step)?;
    Ok(format!("{open} open WebSocket(s) closed; the sign-in form is shown"))
}
