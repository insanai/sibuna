//! `sibuna-browser dashboards`: a smoke run of several Traffic dashboards under sustained
//! data-plane traffic.
//!
//! Each dashboard runs in its own Chromium, so each holds its own session. The console
//! allows five sign-ins per minute per address and per account, and five wall-display
//! exchanges per minute per address, so the first three dashboards are administrator
//! sessions and the rest wall displays opened with codes the first one mints; a sign-in
//! or exchange that is still refused for its rate waits out the minute once. The
//! administrator dashboards show live boot totals, as wall displays always do.
//!
//! While the generator sends requests at a steady rate, the run polls every page, reads
//! its Requests tile every two seconds and counts the `stats` deltas its WebSocket
//! receives. It passes when every dashboard saw at least two deltas and two changes of the
//! Requests tile, kept its WebSocket open and reported no exception, console error or CSP
//! violation, and when every request was answered. With `--pid` it reports the daemon's
//! resident memory before the dashboards open, before the traffic and after it.

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use sibuna_browser::{Browser, Error, Page};

use crate::arguments::{Flag, Flags, UsageError};
use crate::console::read_secret;
use crate::console::ui::{self, SignedIn, failed};
use crate::traffic::{self, Tally, Target};

/// The flags `dashboards` accepts.
pub const FLAGS: &[Flag] = &[
    Flag { name: "--url", takes_value: true },
    Flag { name: "--username", takes_value: true },
    Flag { name: "--password-file", takes_value: true },
    Flag { name: "--new-password-file", takes_value: true },
    Flag { name: "--traffic", takes_value: true },
    Flag { name: "--out", takes_value: true },
    Flag { name: "--count", takes_value: true },
    Flag { name: "--duration", takes_value: true },
    Flag { name: "--rate", takes_value: true },
    Flag { name: "--threads", takes_value: true },
    Flag { name: "--pid", takes_value: true },
    Flag { name: "--timeout", takes_value: true },
];

/// The most administrator sessions opened; the other dashboards are wall displays.
const ADMIN_SESSIONS: usize = 3;

/// How often each dashboard's tiles are read.
const SAMPLE_EVERY: Duration = Duration::from_secs(2);

/// How long each page's events are processed per round of the polling loop.
const POLL_SLICE: Duration = Duration::from_millis(40);

/// How long the dashboards are watched after the traffic stops, for the last deltas.
const TAIL: Duration = Duration::from_secs(3);

/// The checked flags of `dashboards`.
#[derive(Debug)]
pub struct Settings {
    url: String,
    username: String,
    password: String,
    new_password: Option<String>,
    traffic: Target,
    out: PathBuf,
    count: usize,
    duration: Duration,
    rate: u32,
    threads: u32,
    pid: Option<u32>,
    timeout: Duration,
}

impl Settings {
    /// Reads and checks the flags, and reads the password files.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] for a missing flag, an unreadable password file, an invalid number
    /// or an invalid `--traffic` URL.
    pub fn read(flags: &Flags) -> Result<Settings, UsageError> {
        let url = flags.required("--traffic")?;
        let traffic = Target::parse(url).map_err(|problem| {
            UsageError::new(
                format!("`--traffic {url}`: {problem}."),
                "Give the daemon's data-plane URL, such as `http://127.0.0.1:8080/`.",
            )
        })?;
        let new_password = match flags.value("--new-password-file") {
            Some(path) => Some(read_secret("--new-password-file", path.as_ref())?),
            None => None,
        };
        let pid = match flags.value("--pid") {
            Some(_) => Some(flags.number("--pid", 1, u32::MAX)?),
            None => None,
        };
        Ok(Settings {
            url: flags.required("--url")?.trim_end_matches('/').to_owned(),
            username: flags.required("--username")?.to_owned(),
            password: read_secret("--password-file", &flags.required_path("--password-file")?)?,
            new_password,
            traffic,
            out: flags.required_path("--out")?,
            count: flags.number("--count", 8, 16)? as usize,
            duration: flags.seconds("--duration", 30)?,
            rate: flags.number("--rate", 200, 100_000)?,
            threads: flags.number("--threads", 4, 64)?,
            pid,
            timeout: flags.seconds("--timeout", 30)?,
        })
    }
}

/// One dashboard's session and what it showed.
#[derive(Debug, Default)]
struct Board {
    /// "administrator" or "wall display".
    kind: &'static str,
    /// The `stats` deltas received before the traffic started.
    deltas_before: usize,
    /// The deltas received during the traffic and the tail.
    deltas: usize,
    /// The distinct Requests values read, in order.
    values: Vec<String>,
    /// The last tile reading.
    last_tiles: String,
    /// Why the dashboard failed, or what went wrong on it.
    problems: Vec<String>,
    /// The screenshot after the run.
    screenshot: Option<PathBuf>,
}

/// Resident memory of the daemon, in KiB: (VmRSS, VmHWM).
type Memory = Option<(u64, u64)>;

/// Everything the run observed.
#[derive(Debug, Default)]
struct Report {
    /// Why the dashboards could not be opened, if they could not.
    setup_failure: Option<String>,
    boards: Vec<Board>,
    tally: Tally,
    memory_start: Memory,
    memory_before: Memory,
    memory_after: Memory,
}

/// Opens the dashboards, runs the traffic, prints the report and writes `report.txt`.
/// Returns whether the run passed.
///
/// # Errors
///
/// The browser's errors before the dashboards could be judged (launching them), and
/// writing the report.
pub fn run(settings: &Settings) -> Result<bool, Error> {
    fs::create_dir_all(&settings.out).map_err(|error| Error::Io {
        context: format!("creating {}", settings.out.display()),
        source: error,
    })?;
    let mut report = Report { memory_start: memory(settings.pid), ..Report::default() };
    let mut browsers = Vec::with_capacity(settings.count);
    for _ in 0..settings.count {
        browsers.push(Browser::launch(crate::browser_options())?);
    }
    let mut pages = Vec::with_capacity(settings.count);
    for browser in &mut browsers {
        let mut page = browser.new_page()?;
        ui::prepare(&mut page)?;
        pages.push(page);
    }
    report.boards = (0..settings.count).map(|_| Board::default()).collect();
    report.setup_failure = open_dashboards(settings, &mut pages, &mut report.boards).err();
    if report.setup_failure.is_none() {
        report.memory_before = memory(settings.pid);
        report.tally = watch(settings, &mut pages, &mut report.boards);
        report.memory_after = memory(settings.pid);
        judge(settings, &mut pages, &mut report);
    }
    drop(pages);
    drop(browsers);
    let passed = passed(&report);
    let text = report_text(settings, &report, passed);
    let _ = io::stdout().lock().write_all(text.as_bytes());
    let path = settings.out.join("report.txt");
    fs::write(&path, text).map_err(|error| Error::Io {
        context: format!("writing {}", path.display()),
        source: error,
    })?;
    Ok(passed)
}

/// Signs in the administrator dashboards, mints codes on the first one for the wall
/// displays and opens them, and leaves every page on its Traffic view with its stream open.
fn open_dashboards(
    settings: &Settings,
    pages: &mut [Page<'_>],
    boards: &mut [Board],
) -> Result<(), String> {
    let admins = pages.len().min(ADMIN_SESSIONS);
    let mut password = settings.password.clone();
    for (index, page) in pages.iter_mut().enumerate().take(admins) {
        ui::open_sign_in(page, &settings.url, settings.timeout)?;
        match ui::sign_in(page, &settings.username, &password, settings.timeout)? {
            SignedIn::Traffic => {}
            SignedIn::MustChange => {
                let new = settings.new_password.clone().ok_or_else(|| {
                    "the console demands a new password; give --new-password-file".to_owned()
                })?;
                ui::change_password(page, &password, &new, settings.timeout)?;
                password = new;
            }
        }
        boards[index].kind = "administrator";
    }
    let (first, rest) = pages.split_first_mut().ok_or("no dashboard to open")?;
    for (offset, display) in rest.iter_mut().enumerate().skip(admins - 1) {
        let label = format!("smoke display {}", offset + 2);
        let code = ui::mint_kiosk_code(first, &label, settings.timeout)?;
        ui::hide_kiosk_code(first, settings.timeout)?;
        ui::open_sign_in(display, &settings.url, settings.timeout)?;
        ui::exchange_kiosk_code(display, &code, settings.timeout)?;
        boards[offset + 1].kind = "wall display";
    }
    if !first.evaluate(ui::ON_TRAFFIC).is_ok_and(|value| value.is_truthy()) {
        ui::open_page(first, "dashboard", settings.timeout)?;
    }
    for (page, board) in pages.iter_mut().zip(boards.iter_mut()) {
        if board.kind == "administrator" {
            ui::choose_live_totals(page, settings.timeout)?;
        }
        page.wait_for_observation("the stream's WebSocket to open", settings.timeout, |page| {
            page.websockets().iter().any(|socket| socket.status == 101 && !socket.closed)
        })
        .map_err(|error| failed("waiting for a dashboard's stream", &error))?;
        page.clear_observations();
    }
    Ok(())
}

/// Runs the traffic on its own threads while polling every page; returns the tally.
fn watch(settings: &Settings, pages: &mut [Page<'_>], boards: &mut [Board]) -> Tally {
    for (page, board) in pages.iter_mut().zip(boards.iter_mut()) {
        board.deltas_before = ui::stats_delta_count(page);
        sample(page, board);
    }
    std::thread::scope(|scope| {
        let target = &settings.traffic;
        let generator = scope.spawn(move || {
            traffic::sustain(target, settings.duration, settings.rate, settings.threads)
        });
        let end = Instant::now() + settings.duration + TAIL;
        let mut next_sample = Instant::now() + SAMPLE_EVERY;
        while Instant::now() < end {
            let sampling = Instant::now() >= next_sample;
            for (page, board) in pages.iter_mut().zip(boards.iter_mut()) {
                if let Err(error) = page.idle_for(POLL_SLICE) {
                    board.problems.push(failed("polling", &error));
                }
                if sampling {
                    sample(page, board);
                }
            }
            if sampling {
                next_sample += SAMPLE_EVERY;
            }
        }
        generator.join().unwrap_or_default()
    })
}

/// Reads the page's tiles and remembers a new Requests value.
fn sample(page: &mut Page<'_>, board: &mut Board) {
    match ui::tiles(page) {
        Ok(tiles) => {
            let value = ui::tile_value(&tiles, "Requests");
            if board.values.last() != Some(&value) {
                board.values.push(value);
            }
            board.last_tiles = ui::tiles_line(&tiles);
        }
        Err(reason) => board.problems.push(reason),
    }
}

/// Counts each page's deltas, checks its stream and problems, and photographs it.
fn judge(settings: &Settings, pages: &mut [Page<'_>], report: &mut Report) {
    for (index, (page, board)) in pages.iter_mut().zip(report.boards.iter_mut()).enumerate() {
        board.deltas = ui::stats_delta_count(page).saturating_sub(board.deltas_before);
        if !page.websockets().iter().any(|socket| socket.status == 101 && !socket.closed) {
            board.problems.push("its WebSocket is not open after the run".into());
        }
        if board.deltas < 2 {
            board.problems.push(format!("only {} stats delta(s) arrived", board.deltas));
        }
        if board.values.len() < 3 {
            board.problems.push(format!(
                "the Requests tile changed {} time(s), not at least twice",
                board.values.len().saturating_sub(1)
            ));
        }
        board.problems.extend(ui::problems(page, &ui::none_expected));
        let path = settings.out.join(format!("dashboard-{:02}.png", index + 1));
        match page.screenshot(&path) {
            Ok(()) => board.screenshot = Some(path),
            Err(error) => board.problems.push(failed("taking the screenshot", &error)),
        }
    }
}

/// True when the setup worked, every dashboard passed and every request was answered.
fn passed(report: &Report) -> bool {
    report.setup_failure.is_none()
        && report.boards.iter().all(|board| board.problems.is_empty())
        && report.tally.errors == 0
        && report.tally.answered_count() > 0
}

/// Reads `VmRSS` and `VmHWM` of process `pid` from `/proc/<pid>/status`, in KiB.
fn memory(pid: Option<u32>) -> Memory {
    let status = fs::read_to_string(format!("/proc/{}/status", pid?)).ok()?;
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
    };
    Some((field("VmRSS:")?, field("VmHWM:")?))
}

fn memory_text(memory: Memory) -> String {
    match memory {
        Some((rss, peak)) => format!("VmRSS {rss} KiB (VmHWM {peak} KiB)"),
        None => "not measured".into(),
    }
}

/// The report: settings, memory, traffic, one block per dashboard, the verdict.
fn report_text(settings: &Settings, report: &Report, passed: bool) -> String {
    let mut text = String::new();
    let _ = writeln!(text, "dashboards smoke run against {}", ui::shell_url(&settings.url));
    let _ = writeln!(
        text,
        "dashboards: {} ({} administrator sessions, the rest wall displays), each in its own \
         Chromium",
        settings.count,
        settings.count.min(ADMIN_SESSIONS)
    );
    let _ = writeln!(
        text,
        "traffic:    {} s at {} requests/s from {} threads",
        settings.duration.as_secs(),
        settings.rate,
        settings.threads
    );
    if let Some(reason) = &report.setup_failure {
        let _ = writeln!(text, "setup:      FAIL: {reason}");
    }
    let _ =
        writeln!(text, "daemon memory at start:          {}", memory_text(report.memory_start));
    let _ =
        writeln!(text, "daemon memory, dashboards open:  {}", memory_text(report.memory_before));
    let _ =
        writeln!(text, "daemon memory after the traffic: {}", memory_text(report.memory_after));
    let _ = writeln!(text, "data plane: {}\n", report.tally.summary());
    for (index, board) in report.boards.iter().enumerate() {
        let verdict = if board.problems.is_empty() { "PASS" } else { "FAIL" };
        let _ = writeln!(
            text,
            "[{verdict}] dashboard {} ({}): {} stats deltas; Requests {}",
            index + 1,
            board.kind,
            board.deltas,
            board.values.join(" -> ")
        );
        let _ = writeln!(text, "       last tiles: {}", board.last_tiles);
        for problem in &board.problems {
            let _ = writeln!(text, "       {problem}");
        }
        if let Some(path) = &board.screenshot {
            let _ = writeln!(text, "       screenshot {}", path.display());
        }
    }
    let _ = writeln!(text, "\nresult: {}", if passed { "PASS" } else { "FAIL" });
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_memory_of_this_process() {
        let (rss, peak) = memory(Some(std::process::id())).unwrap();
        assert!(rss > 0 && peak >= rss, "{rss} {peak}");
        assert_eq!(memory(None), None);
    }

    #[test]
    fn a_run_passes_only_with_answers_and_healthy_dashboards() {
        let mut report = Report::default();
        report.boards.push(Board { kind: "wall display", ..Board::default() });
        assert!(!passed(&report), "no request was answered");
        report.tally.statuses.insert(200, 10);
        assert!(passed(&report));
        report.tally.errors = 1;
        assert!(!passed(&report));
        report.tally.errors = 0;
        report.boards[0].problems.push("only 1 stats delta(s) arrived".into());
        assert!(!passed(&report));
    }
}
