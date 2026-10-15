//! `sibuna-browser challenge`: solve the interstitial in Chromium and reach the origin.
//!
//! The check loads a protected URL, records the screencast, and waits until the page is
//! no longer the interstitial and shows origin content. A DevTools binding reports every
//! change of the interstitial's status line (`#status`), across the reload, so we learn
//! which solver ran ("(WASM)" or "(JS fallback)") and the time the page itself reported.
//! The check fails when the origin is not reached in time, when the URL was not
//! challenged, when no session cookie was set, when the solver is not the expected one,
//! or when the page threw an exception.

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use sibuna_browser::{Browser, Cookie, Error, Page, Recording, RecordingOptions};

use crate::arguments::{Flag, Flags, UsageError};

/// The flags `challenge` accepts.
pub const FLAGS: &[Flag] = &[
    Flag { name: "--url", takes_value: true },
    Flag { name: "--out", takes_value: true },
    Flag { name: "--no-wasm", takes_value: false },
    Flag { name: "--expect", takes_value: true },
    Flag { name: "--cookie", takes_value: true },
    Flag { name: "--timeout", takes_value: true },
];

/// The global function the status observer reports through.
const STATUS_BINDING: &str = "__sibunaBrowserStatus";

/// Runs in every document before its scripts: reports `#status` now and on every change.
/// The binding is looked up at each report, so the order in which DevTools installs the
/// binding and this script does not matter.
const STATUS_OBSERVER: &str = r"(() => {
  const report = (text) => {
    const binding = window.__sibunaBrowserStatus;
    if (typeof binding === 'function') binding(text);
  };
  const watch = () => {
    const status = document.getElementById('status');
    if (!status) return;
    let last = null;
    const send = () => {
      const text = status.textContent;
      if (text !== last) { last = text; report(text); }
    };
    send();
    const changes = {childList: true, characterData: true, subtree: true};
    new MutationObserver(send).observe(status, changes);
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', watch);
  else watch();
})()";

/// True on the default interstitial: its status line and progress bar.
const INTERSTITIAL: &str =
    "!!(document.getElementById('status') && document.querySelector('.progress-bar'))";

/// The checked flags of `challenge`.
#[derive(Debug)]
pub struct Settings {
    url: String,
    out: PathBuf,
    no_wasm: bool,
    expect: String,
    cookie: String,
    timeout: Duration,
}

impl Settings {
    /// Reads and checks the flags.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] for a missing `--url` or `--out` or an invalid timeout.
    pub fn read(flags: &Flags) -> Result<Settings, UsageError> {
        Ok(Settings {
            url: flags.required("--url")?.to_owned(),
            out: flags.required_path("--out")?,
            no_wasm: flags.is_set("--no-wasm"),
            expect: flags.value("--expect").unwrap_or_default().to_owned(),
            cookie: flags.value("--cookie").unwrap_or("__sibuna_token").to_owned(),
            timeout: flags.seconds("--timeout", 60)?,
        })
    }

    /// The solver this run must use.
    fn expected_solver(&self) -> Solver {
        if self.no_wasm { Solver::JavaScript } else { Solver::WebAssembly }
    }
}

/// Which proof-of-work engine the interstitial reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Solver {
    WebAssembly,
    JavaScript,
    Unknown,
}

impl Solver {
    /// The solver named by the status lines: the fallback once announced wins.
    fn from_statuses(statuses: &[Status]) -> Solver {
        if statuses.iter().any(|status| status.text.contains("(JS fallback)")) {
            Solver::JavaScript
        } else if statuses.iter().any(|status| status.text.contains("(WASM)")) {
            Solver::WebAssembly
        } else {
            Solver::Unknown
        }
    }

    fn name(self) -> &'static str {
        match self {
            Solver::WebAssembly => "WebAssembly (WASM)",
            Solver::JavaScript => "JavaScript fallback (JS fallback)",
            Solver::Unknown => "unknown (no solver status was seen)",
        }
    }
}

/// One text the interstitial's status line showed, and when, from navigation start.
#[derive(Clone, Debug)]
struct Status {
    after: Duration,
    text: String,
}

/// Everything one run observed.
#[derive(Debug)]
struct Report {
    browser: String,
    /// The origin was reached (`Ok`) or why not.
    origin: Result<(), String>,
    time_to_origin: Duration,
    statuses: Vec<Status>,
    cookie: Option<Cookie>,
    documents: Vec<String>,
    final_status: u16,
    console: Vec<String>,
    console_error_count: usize,
    exceptions: Vec<String>,
    network_failures: Vec<String>,
    recording: Option<Recording>,
    before: Before,
    after: PathBuf,
}

/// Runs the check and prints its report. Returns whether it passed.
///
/// # Errors
///
/// The browser's errors before the check could be judged: launch, navigation, writing.
pub fn run(settings: &Settings) -> Result<bool, Error> {
    fs::create_dir_all(&settings.out).map_err(|error| Error::Io {
        context: format!("creating {}", settings.out.display()),
        source: error,
    })?;
    let mut browser = Browser::launch(crate::browser_options())?;
    let version = browser.version()?;
    let mut page = browser.new_page()?;
    if settings.no_wasm {
        page.disable_webassembly()?;
    }
    page.set_viewport(1280, 800, false)?;
    page.add_binding(STATUS_BINDING)?;
    page.add_init_script(STATUS_OBSERVER)?;
    page.start_recording(&settings.out.join("frames"), RecordingOptions::default())?;
    page.hold_requests(VERIFY_PATTERN)?;
    let started = Instant::now();
    let deadline = started + settings.timeout;
    page.navigate(&settings.url)?;
    let before = capture_before(&mut page, settings, deadline)?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    let origin = page
        .wait_for(&origin_expression(&settings.expect), remaining)
        .map(|_| ())
        .map_err(|error| error.to_string());
    let time_to_origin = started.elapsed().saturating_sub(before.held);
    // Let the origin paint so the last frames and any late errors are captured.
    page.idle_for(Duration::from_millis(500))?;
    let after = settings.out.join("after.png");
    page.screenshot(&after)?;
    let recording = page.stop_recording()?;
    let cookie = page.cookies()?.into_iter().find(|cookie| cookie.name == settings.cookie);
    let mut report = observe(&page, started, before);
    report.browser = version;
    report.origin = origin;
    report.time_to_origin = time_to_origin;
    report.cookie = cookie;
    report.recording = recording;
    report.after = after;
    let failures = judge(&report, settings);
    print_report(&report, settings, &failures);
    Ok(failures.is_empty())
}

/// The verification request, held so that the "before" screenshot shows the interstitial.
const VERIFY_PATTERN: &str = "*/__sibuna/verify*";

/// The "before" screenshot and how it was taken.
#[derive(Debug)]
struct Before {
    path: PathBuf,
    /// The interstitial was on screen.
    interstitial: bool,
    /// How long the verification request was held for the screenshot.
    held: Duration,
}

/// Takes the "before" screenshot. On the interstitial, it waits for the solver's
/// verification request, which is held, and shoots while the page shows "Verifying
/// solution"; the solve itself takes only tens of milliseconds, too fast to catch
/// otherwise. The hold time is reported and left out of the timings.
fn capture_before(
    page: &mut Page<'_>,
    settings: &Settings,
    deadline: Instant,
) -> Result<Before, Error> {
    let path = settings.out.join("before.png");
    let interstitial = page.evaluate(INTERSTITIAL).is_ok_and(|value| value.is_truthy());
    let remaining = deadline.saturating_duration_since(Instant::now());
    let held_request =
        if interstitial { page.wait_for_held_request(remaining).ok() } else { None };
    let holding = Instant::now();
    page.screenshot(&path)?;
    if let Some(request) = &held_request {
        page.release_request(request)?;
    }
    page.stop_holding_requests()?;
    let held = if held_request.is_some() { holding.elapsed() } else { Duration::ZERO };
    Ok(Before { path, interstitial, held })
}

/// The expression that holds once the origin page is shown.
fn origin_expression(expect: &str) -> String {
    let mut literal = String::new();
    let _ = sibuna_json::write_string(&mut literal, expect);
    format!(
        "document.readyState === 'complete' && !({INTERSTITIAL}) && !!document.body \
         && document.body.innerText.trim().length > 0 \
         && document.body.innerText.includes({literal})"
    )
}

/// Collects what the page reported, with the fields `run` fills left empty.
fn observe(page: &Page<'_>, started: Instant, before: Before) -> Report {
    let statuses = page
        .binding_calls()
        .iter()
        .filter(|call| call.name == STATUS_BINDING)
        .map(|call| Status {
            after: call.at.saturating_duration_since(started),
            text: call.payload.clone(),
        })
        .collect();
    let documents: Vec<String> = page
        .document_responses()
        .iter()
        .map(|document| format!("{} {}", document.status, document.url))
        .collect();
    Report {
        browser: String::new(),
        origin: Ok(()),
        time_to_origin: Duration::ZERO,
        statuses,
        cookie: None,
        final_status: page.document_responses().last().map_or(0, |document| document.status),
        documents,
        console: page
            .console_messages()
            .iter()
            .map(|message| format!("[{} {}] {}", message.source, message.level, message.text))
            .collect(),
        console_error_count: page.console_messages().iter().filter(|m| m.is_error()).count(),
        exceptions: page.exceptions().iter().map(|exception| exception.text.clone()).collect(),
        network_failures: page
            .network_failures()
            .iter()
            .map(|failure| format!("{} {}", failure.error_text, failure.url))
            .collect(),
        recording: None,
        before,
        after: PathBuf::new(),
    }
}

/// The reasons the run failed; empty when it passed.
fn judge(report: &Report, settings: &Settings) -> Vec<String> {
    let mut failures = Vec::new();
    if let Err(error) = &report.origin {
        failures.push(format!("the origin was not reached: {error}"));
    }
    if !report.before.interstitial && report.statuses.is_empty() {
        failures.push("the URL was not challenged: no interstitial was seen".into());
    }
    let solver = Solver::from_statuses(&report.statuses);
    if solver != settings.expected_solver() {
        failures.push(format!(
            "expected the {} solver, saw {}",
            settings.expected_solver().name(),
            solver.name()
        ));
    }
    if report.cookie.is_none() {
        failures.push(format!("no `{}` session cookie was set", settings.cookie));
    }
    if !(200..400).contains(&report.final_status) {
        failures.push(format!("the last document answered {}", report.final_status));
    }
    if !report.exceptions.is_empty() {
        failures.push(format!("{} uncaught exception(s)", report.exceptions.len()));
    }
    failures
}

/// The time the interstitial reported in "Verified in N ms", if it did.
fn reported_time(statuses: &[Status]) -> Option<&str> {
    statuses.iter().find_map(|status| {
        status.text.strip_prefix("Verified in ").and_then(|rest| rest.split(". ").next())
    })
}

/// The time from the status that names the solver in use (the last "(WASM)" or "(JS
/// fallback)" line) to "Verifying solution". For WebAssembly it includes starting the
/// worker and compiling the module; the fallback is announced by the running worker.
fn solve_time(statuses: &[Status]) -> Option<Duration> {
    let named =
        |status: &&Status| status.text.contains("(WASM)") || status.text.contains("(JS fallback)");
    let computing = statuses.iter().rev().find(named)?;
    let verifying =
        statuses.iter().find(|status| status.text.starts_with("Verifying solution"))?;
    verifying.after.checked_sub(computing.after)
}

fn print_report(report: &Report, settings: &Settings, failures: &[String]) {
    let mut text = String::new();
    write_report(&mut text, report, settings);
    if failures.is_empty() {
        text.push_str("result:            PASS\n");
    } else {
        text.push_str("result:            FAIL\n");
        for failure in failures {
            text.push_str(&format!("  - {failure}\n"));
        }
    }
    let _ = io::stdout().lock().write_all(text.as_bytes());
}

fn write_report(text: &mut String, report: &Report, settings: &Settings) {
    let line = |text: &mut String, label: &str, value: &str| {
        let label = if label.is_empty() { String::new() } else { format!("{label}:") };
        text.push_str(&format!("{label:<19}{value}\n"));
    };
    let mode = if settings.no_wasm { "WebAssembly disabled" } else { "WebAssembly enabled" };
    line(text, "challenge", &format!("{} ({mode})", settings.url));
    line(text, "browser", &report.browser);
    line(text, "solver", Solver::from_statuses(&report.statuses).name());
    let solve = solve_time(&report.statuses)
        .map_or("not seen".into(), |time| format!("{} ms", time.as_millis()));
    line(text, "solve", &format!("{solve} (status naming the solver to \"Verifying\")"));
    let held = report.before.held.as_millis();
    let reported = match reported_time(&report.statuses) {
        Some(time) => format!("Verified in {time} (includes {held} ms held for the screenshot)"),
        None => "nothing".into(),
    };
    line(text, "page reported", &reported);
    line(
        text,
        "time to origin",
        &format!("{} ms from navigation start, hold excluded", report.time_to_origin.as_millis()),
    );
    for status in &report.statuses {
        line(text, "  status", &format!("+{} ms {}", status.after.as_millis(), status.text));
    }
    for document in &report.documents {
        line(text, "  document", document);
    }
    let cookie = match &report.cookie {
        Some(cookie) => format!(
            "{} set (HttpOnly: {}, {} characters)",
            cookie.name,
            cookie.http_only,
            cookie.value.len()
        ),
        None => format!("{} missing", settings.cookie),
    };
    line(text, "cookie", &cookie);
    let shown = if report.before.interstitial { "interstitial" } else { "not the interstitial" };
    line(text, "before", &format!("{} ({shown})", report.before.path.display()));
    line(text, "after", &report.after.display().to_string());
    if let Some(recording) = &report.recording {
        line(
            text,
            "frames",
            &format!("{} in {}", recording.frame_count, recording.directory.display()),
        );
    }
    line(
        text,
        "console",
        &format!("{} message(s), {} error(s)", report.console.len(), report.console_error_count),
    );
    for message in &report.console {
        line(text, "", message);
    }
    line(text, "exceptions", &report.exceptions.len().to_string());
    for exception in &report.exceptions {
        line(text, "", exception);
    }
    line(text, "network failures", &report.network_failures.len().to_string());
    for failure in &report.network_failures {
        line(text, "", failure);
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn statuses(texts: &[(u64, &str)]) -> Vec<Status> {
        texts
            .iter()
            .map(|&(ms, text)| Status { after: Duration::from_millis(ms), text: text.into() })
            .collect()
    }

    #[test]
    fn names_the_solver_and_times_from_the_status_lines() {
        let wasm = statuses(&[
            (10, "Computing sequential-work proof (WASM)..."),
            (90, "Verifying solution with firewall..."),
            (95, "Verified in 120 ms. Loading page..."),
        ]);
        assert_eq!(Solver::from_statuses(&wasm), Solver::WebAssembly);
        assert_eq!(solve_time(&wasm), Some(Duration::from_millis(80)));
        assert_eq!(reported_time(&wasm), Some("120 ms"));
        let fallback = statuses(&[
            (10, "Computing sequential-work proof (WASM)..."),
            (12, "Computing sequential-work proof (JS fallback)..."),
            (20, "Computing... (4096 steps)"),
        ]);
        assert_eq!(Solver::from_statuses(&fallback), Solver::JavaScript);
        assert_eq!(solve_time(&fallback), None, "not verified yet");
        let mut verified = fallback.clone();
        verified.extend(statuses(&[(70, "Verifying solution with firewall...")]));
        assert_eq!(solve_time(&verified), Some(Duration::from_millis(58)));
        assert_eq!(Solver::from_statuses(&[]), Solver::Unknown);
    }

    #[test]
    fn the_origin_expression_quotes_the_expected_text() {
        let expression = origin_expression("it's \"here\"");
        assert!(expression.ends_with(r#"includes("it's \"here\"")"#));
        assert!(expression.contains(INTERSTITIAL));
    }

    #[test]
    fn writes_frames_under_the_output_directory() {
        let settings = Settings {
            url: "http://127.0.0.1:1/".into(),
            out: Path::new("/tmp/x").to_owned(),
            no_wasm: true,
            expect: String::new(),
            cookie: "__sibuna_token".into(),
            timeout: Duration::from_secs(1),
        };
        assert_eq!(settings.expected_solver(), Solver::JavaScript);
        assert_eq!(settings.out.join("frames"), Path::new("/tmp/x/frames"));
    }
}
