//! `sibuna-browser console`: a walk through the management console in Chromium.
//!
//! The walk loads the shell signed out, signs in (replacing the temporary password when
//! asked), watches the Traffic tiles follow generated data-plane traffic, opens every page
//! of the navigation, opens a wall display with a one-time code in a second browser, and
//! signs out. Every step is judged, photographed and written to `report.txt`:
//!
//! 1. `shell`: before sign-in the shell opens no WebSocket and does not fetch the globe's
//!    geometry (`world-110m.bin`).
//! 2. `sign-in`: the initial password leads to the forced password change (with
//!    `--new-password-file`), and then to the Traffic dashboard with its WebSocket open.
//! 3. `traffic` (with `--traffic`): with live boot totals, two bursts of requests change
//!    the Requests tile, across at least two `stats` deltas of the stream.
//! 4. `page: <name>`: every navigation page (and the Security tab) shows its heading, with
//!    no exception, console error or Content-Security-Policy violation.
//! 5. `kiosk`: a code minted on the account page opens, in a browser with no session, a
//!    display that shows statistics only and is refused a management route.
//! 6. `sign-out`: signing out shows the sign-in form and closes every WebSocket.
//!
//! A step that cannot be judged because an earlier one failed is left out; the run fails
//! when any step failed.

mod steps;
pub mod ui;

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sibuna_browser::{Browser, Error, Page};

use crate::arguments::{Flag, Flags, UsageError};
use crate::traffic::Target;

/// The flags `console` accepts.
pub const FLAGS: &[Flag] = &[
    Flag { name: "--url", takes_value: true },
    Flag { name: "--username", takes_value: true },
    Flag { name: "--password-file", takes_value: true },
    Flag { name: "--new-password-file", takes_value: true },
    Flag { name: "--traffic", takes_value: true },
    Flag { name: "--out", takes_value: true },
    Flag { name: "--timeout", takes_value: true },
];

/// The tallest screenshot taken, in CSS pixels.
const MAX_SHOT_HEIGHT: u32 = 8000;

/// The checked flags of `console`.
#[derive(Debug)]
pub struct Settings {
    /// The console's origin, such as `http://127.0.0.1:9443`.
    pub url: String,
    /// The administrator's name.
    pub username: String,
    /// The password to sign in with.
    pub password: String,
    /// The password to set when the console demands a change.
    pub new_password: Option<String>,
    /// Where data-plane traffic goes, when tiles are to be checked.
    pub traffic: Option<Target>,
    /// Where screenshots and the report go.
    pub out: PathBuf,
    /// How long each wait may take.
    pub timeout: Duration,
}

impl Settings {
    /// Reads and checks the flags, and reads the password files.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] for a missing flag, an unreadable or empty password file, or an
    /// invalid `--traffic` URL.
    pub fn read(flags: &Flags) -> Result<Settings, UsageError> {
        let traffic = match flags.value("--traffic") {
            Some(url) => Some(Target::parse(url).map_err(|problem| {
                UsageError::new(
                    format!("`--traffic {url}`: {problem}."),
                    "Give the daemon's data-plane URL, such as `http://127.0.0.1:8080/`.",
                )
            })?),
            None => None,
        };
        let new_password = match flags.value("--new-password-file") {
            Some(path) => Some(read_secret("--new-password-file", Path::new(path))?),
            None => None,
        };
        Ok(Settings {
            url: flags.required("--url")?.trim_end_matches('/').to_owned(),
            username: flags.required("--username")?.to_owned(),
            password: read_secret("--password-file", &flags.required_path("--password-file")?)?,
            new_password,
            traffic,
            out: flags.required_path("--out")?,
            timeout: flags.seconds("--timeout", 30)?,
        })
    }
}

/// Reads a password from the first line of `path`.
///
/// # Errors
///
/// A [`UsageError`] naming `flag` when the file cannot be read or its first line is empty.
pub fn read_secret(flag: &str, path: &Path) -> Result<String, UsageError> {
    let text = fs::read_to_string(path).map_err(|error| {
        UsageError::new(
            format!("`{flag} {}` cannot be read: {error}.", path.display()),
            "Give a file whose first line is the password.",
        )
    })?;
    let line = text.lines().next().unwrap_or_default().trim_end_matches('\r');
    if line.is_empty() {
        return Err(UsageError::new(
            format!("`{flag} {}` holds no password on its first line.", path.display()),
            "Write the password on the file's first line.",
        ));
    }
    Ok(line.to_owned())
}

/// One judged step of the walk.
#[derive(Debug)]
pub struct Step {
    /// The step's name, such as `sign-in` or `page: Events`.
    pub name: String,
    /// What was seen (`Ok`) or why the step failed.
    pub outcome: Result<String, String>,
    /// Further observations, such as tile values.
    pub notes: Vec<String>,
    /// The screenshots taken during the step.
    pub screenshots: Vec<PathBuf>,
}

/// The walk in progress: its settings, judged steps and screenshot counter.
pub struct Walk<'s> {
    settings: &'s Settings,
    browser: String,
    steps: Vec<Step>,
    shots: u32,
}

impl<'s> Walk<'s> {
    /// Takes a numbered screenshot `NN-<name>.png` of the whole page (at most
    /// [`MAX_SHOT_HEIGHT`] pixels high); a failure becomes a note of `step`.
    pub fn screenshot(&mut self, page: &mut Page<'_>, name: &str, step: &mut Step) {
        self.shots += 1;
        let path = self.settings.out.join(format!("{:02}-{name}.png", self.shots));
        // A whole-page capture of a scrolled page paints fixed elements (the hidden skip
        // link) at the scroll offset; the page steps note the scroll position instead.
        let _ = page.evaluate("window.scrollTo(0, 0)");
        match page.screenshot_full_page(&path, MAX_SHOT_HEIGHT) {
            Ok(()) => step.screenshots.push(path),
            Err(error) => step.notes.push(format!("no screenshot {}: {error}", path.display())),
        }
    }

    /// Records a finished step and returns whether it passed.
    pub fn record(&mut self, step: Step) -> bool {
        let passed = step.outcome.is_ok();
        self.steps.push(step);
        passed
    }
}

/// A new step named `name`, passing until judged otherwise.
pub fn step(name: impl Into<String>) -> Step {
    Step {
        name: name.into(),
        outcome: Ok(String::new()),
        notes: Vec::new(),
        screenshots: Vec::new(),
    }
}

/// Runs the walk and prints its report. Returns whether every step passed.
///
/// # Errors
///
/// The browser's errors before any step could be judged (launch), and writing the report.
pub fn run(settings: &Settings) -> Result<bool, Error> {
    fs::create_dir_all(&settings.out).map_err(|error| Error::Io {
        context: format!("creating {}", settings.out.display()),
        source: error,
    })?;
    let mut browser = Browser::launch(crate::browser_options())?;
    let version = browser.version()?;
    let mut page = browser.new_page()?;
    ui::prepare(&mut page)?;
    let mut walk = Walk { settings, browser: version, steps: Vec::new(), shots: 0 };
    steps::shell(&mut walk, &mut page);
    if steps::sign_in(&mut walk, &mut page) {
        if let Some(target) = &settings.traffic {
            steps::traffic(&mut walk, &mut page, target);
        }
        steps::pages(&mut walk, &mut page);
        steps::kiosk(&mut walk, &mut page);
        steps::sign_out(&mut walk, &mut page);
    }
    drop(page);
    drop(browser);
    finish(&walk)
}

/// Writes the report to standard output and `report.txt`; returns whether all passed.
fn finish(walk: &Walk<'_>) -> Result<bool, Error> {
    let passed = walk.steps.iter().all(|step| step.outcome.is_ok());
    let text = report(walk, passed);
    let _ = io::stdout().lock().write_all(text.as_bytes());
    let path = walk.settings.out.join("report.txt");
    fs::write(&path, text).map_err(|error| Error::Io {
        context: format!("writing {}", path.display()),
        source: error,
    })?;
    Ok(passed)
}

/// The report: the run's settings, then one block per step, then the verdict.
fn report(walk: &Walk<'_>, passed: bool) -> String {
    let settings = walk.settings;
    let mut text = String::new();
    let _ = writeln!(text, "console walk-through of {}", ui::shell_url(&settings.url));
    let _ = writeln!(text, "browser:   {}", walk.browser);
    let _ = writeln!(text, "user:      {}", settings.username);
    let traffic = if settings.traffic.is_some() { "generated" } else { "not generated" };
    let _ = writeln!(text, "traffic:   {traffic}");
    let _ = writeln!(text, "out:       {}\n", settings.out.display());
    for step in &walk.steps {
        let (verdict, detail) = match &step.outcome {
            Ok(detail) => ("PASS", detail),
            Err(reason) => ("FAIL", reason),
        };
        let _ = writeln!(text, "[{verdict}] {}: {detail}", step.name);
        for note in &step.notes {
            let _ = writeln!(text, "       {note}");
        }
        for shot in &step.screenshots {
            let _ = writeln!(text, "       screenshot {}", shot.display());
        }
    }
    let failed = walk.steps.iter().filter(|step| step.outcome.is_err()).count();
    let verdict = if passed { "PASS" } else { "FAIL" };
    let _ = writeln!(text, "\nresult: {verdict} ({} steps, {failed} failed)", walk.steps.len());
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_first_line_of_a_password_file() {
        let directory = std::env::temp_dir();
        let path = directory.join(format!("sibuna-browser-secret-{}", std::process::id()));
        fs::write(&path, "correct horse\r\nignored\n").unwrap();
        assert_eq!(read_secret("--password-file", &path).unwrap(), "correct horse");
        fs::write(&path, "\nlater").unwrap();
        let error = read_secret("--password-file", &path).unwrap_err().to_string();
        assert!(error.contains("holds no password"), "{error}");
        fs::remove_file(&path).unwrap();
        assert!(read_secret("--password-file", &path).is_err());
    }

    #[test]
    fn the_report_lists_steps_notes_and_the_verdict() {
        let settings = Settings {
            url: "http://127.0.0.1:9".into(),
            username: "admin".into(),
            password: "x".into(),
            new_password: None,
            traffic: None,
            out: PathBuf::from("/tmp/out"),
            timeout: Duration::from_secs(1),
        };
        let mut walk = Walk {
            settings: &settings,
            browser: "Chrome/155".into(),
            steps: Vec::new(),
            shots: 0,
        };
        let mut shell = step("shell");
        shell.outcome = Ok("no WebSocket".into());
        shell.screenshots.push(PathBuf::from("/tmp/out/01-shell.png"));
        assert!(walk.record(shell));
        let mut sign_in = step("sign-in");
        sign_in.outcome = Err("refused".into());
        sign_in.notes.push("message: Sign-in failed".into());
        assert!(!walk.record(sign_in));
        let text = report(&walk, false);
        assert!(
            text.contains("[PASS] shell: no WebSocket\n       screenshot /tmp/out/01-shell.png")
        );
        assert!(text.contains("[FAIL] sign-in: refused\n       message: Sign-in failed"));
        assert!(text.ends_with("result: FAIL (2 steps, 1 failed)\n"));
    }
}
