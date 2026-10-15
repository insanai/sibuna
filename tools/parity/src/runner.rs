//! Runs the scenarios of one configuration: starts both daemons with identical flags and
//! seed, plays every scenario against each, compares, and classifies each difference as
//! allowed (with the allow-list entry) or unexplained.

use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::allow::{self, Entry, Subject};
use crate::client::{Pacer, Transcript, run_case};
use crate::compare::{Difference, answer_of, compare, escape};
use crate::configs::Config;
use crate::corpus::{Case, Category, Request};
use crate::daemon::Daemon;
use crate::response::Event;

/// The master seed both daemons load: fixed, so tokens and tickets are comparable.
pub const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// Challenge issues per second per daemon; the adaptive baseline is 50 (see [`Pacer`]).
const ISSUES_PER_SECOND: u32 = 40;

/// The two daemon binaries.
#[derive(Clone, Debug)]
pub struct Binaries {
    /// The Zig build.
    pub zig: PathBuf,
    /// The Rust build.
    pub rust: PathBuf,
}

/// A difference and the allow-list entry that explains it, if one does.
#[derive(Clone, Debug)]
pub struct Finding {
    /// The difference.
    pub difference: Difference,
    /// The id of the explaining entry.
    pub allowed_by: Option<String>,
}

/// The outcome of one scenario.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// The scenario's id.
    pub case: usize,
    /// Its category.
    pub category: Category,
    /// Its label.
    pub label: String,
    /// Requests it sent.
    pub requests: usize,
    /// What the Zig daemon answered, one entry per event: a status code, `closed`,
    /// `timeout` or `garbage`. It shows what the corpus exercised.
    pub answers: Vec<String>,
    /// The differences found; empty when the answers were identical.
    pub findings: Vec<Finding>,
    /// The Zig transcript, kept when there are findings (or when asked to keep all).
    pub zig: Option<Transcript>,
    /// The Rust transcript, kept when there are findings (or when asked to keep all).
    pub rust: Option<Transcript>,
}

impl Outcome {
    /// True when some difference has no allow-list entry.
    pub fn is_unexplained(&self) -> bool {
        self.findings.iter().any(|finding| finding.allowed_by.is_none())
    }
}

/// The outcome of one configuration.
#[derive(Debug)]
pub struct ConfigOutcome {
    /// The configuration's name.
    pub config: String,
    /// The daemons' arguments (with placeholder ports).
    pub arguments: Vec<String>,
    /// One outcome per scenario, in corpus order.
    pub outcomes: Vec<Outcome>,
    /// Problems with the daemons themselves, such as a crash during the run.
    pub failures: Vec<String>,
}

/// What every configuration of a run shares.
#[derive(Clone, Copy, Debug)]
pub struct Settings<'a> {
    /// The daemon binaries.
    pub binaries: &'a Binaries,
    /// The stub origin's address.
    pub origin: SocketAddr,
    /// Client threads per configuration.
    pub workers: usize,
    /// The allow-list.
    pub allow: &'a [Entry],
    /// Keep the transcripts of identical scenarios too, for the report's `cases/`.
    pub keep_all: bool,
}

/// Starts the two daemons of `config` with their logs in `dir`.
fn start_pair(
    config: &Config,
    settings: &Settings<'_>,
    dir: &Path,
) -> io::Result<(Daemon, Daemon)> {
    fs::create_dir_all(dir)?;
    let secret = dir.join("secret.hex");
    write_private(&secret, SEED_HEX.as_bytes())?;
    let policy = match config.policy_text() {
        Some(text) => {
            let path = dir.join("policy.json");
            fs::write(&path, text)?;
            Some(path)
        }
        None => None,
    };
    let origin = settings.origin.port();
    let args = |port| config.arguments(port, origin, &secret, policy.as_deref());
    let start = |binary: &Path, log: &str| Daemon::start(binary, args, &dir.join(log));
    let binaries = settings.binaries;
    Ok((start(&binaries.zig, "zig.log")?, start(&binaries.rust, "rust.log")?))
}

/// Writes a file only its owner can read, as the daemons require of secrets.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)?.write_all(bytes)
}

/// Runs `cases` (all of `config`) with the settings' client threads; the daemons' files
/// and logs go to `dir`.
///
/// # Errors
///
/// Fails when a daemon cannot be started.
pub fn run_config(
    config: &Config,
    cases: &[&Case],
    dir: &Path,
    settings: &Settings<'_>,
) -> io::Result<ConfigOutcome> {
    let (mut zig, mut rust) = start_pair(config, settings, dir)?;
    let pacers = (Pacer::new(ISSUES_PER_SECOND), Pacer::new(ISSUES_PER_SECOND));
    let next = AtomicUsize::new(0);
    let results = Mutex::new(Vec::with_capacity(cases.len()));
    std::thread::scope(|scope| {
        for _ in 0..settings.workers.max(1) {
            scope.spawn(|| {
                // Relaxed: the counter only hands out distinct indices.
                while let Some(case) = cases.get(next.fetch_add(1, Ordering::Relaxed)) {
                    let zig_transcript = run_case(case, zig.address, &pacers.0);
                    let rust_transcript = run_case(case, rust.address, &pacers.1);
                    let outcome = judge(config, case, zig_transcript, rust_transcript, settings);
                    results.lock().unwrap_or_else(|poison| poison.into_inner()).push(outcome);
                }
            });
        }
    });
    let mut outcomes = results.into_inner().unwrap_or_else(|poison| poison.into_inner());
    outcomes.sort_by_key(|outcome| outcome.case);
    let mut counters = metrics(config, zig.address, rust.address, settings);
    explain_metrics(&mut counters, &outcomes);
    outcomes.push(counters);
    let mut failures = Vec::new();
    for (name, daemon) in [("zig", &mut zig), ("rust", &mut rust)] {
        if let Some(status) = daemon.exited() {
            failures.push(format!(
                "the {name} daemon (pid {}) exited during the run: {status}",
                daemon.pid()
            ));
        }
    }
    let secret = dir.join("secret.hex");
    let arguments = config.arguments(0, settings.origin.port(), &secret, None);
    Ok(ConfigOutcome { config: config.name.clone(), arguments, outcomes, failures })
}

/// Compares two transcripts and looks up each difference in the allow-list.
fn judge(
    config: &Config,
    case: &Case,
    zig: Transcript,
    rust: Transcript,
    settings: &Settings<'_>,
) -> Outcome {
    let findings: Vec<Finding> = compare(&zig, &rust)
        .into_iter()
        .map(|difference| {
            let (connection, step) = (difference.connection, difference.step);
            let (requests, paths) = history(case, connection, step);
            let zig_status = answer_of(&zig, connection, step);
            let rust_status = answer_of(&rust, connection, step);
            let subject = Subject {
                config: &config.name,
                category: case.category.name(),
                label: &case.label,
                requests: &requests,
                paths: &paths,
                field: &difference.field,
                zig: &difference.zig,
                rust: &difference.rust,
                zig_status: &zig_status,
                rust_status: &rust_status,
            };
            let allowed_by =
                allow::explain(settings.allow, &subject).map(|entry| entry.id.clone());
            Finding { difference, allowed_by }
        })
        .collect();
    let keep = settings.keep_all || !findings.is_empty();
    let answers = zig
        .connections
        .iter()
        .flatten()
        .flat_map(|exchange| &exchange.events)
        .map(|event| match event {
            Event::Response(response) => response.status.to_string(),
            Event::Closed => "closed".to_owned(),
            Event::Timeout(_) => "timeout".to_owned(),
            Event::Garbage(_) => "garbage".to_owned(),
        })
        .collect();
    Outcome {
        case: case.id,
        category: case.category,
        label: case.label.clone(),
        requests: case.request_count(),
        answers,
        findings,
        zig: keep.then_some(zig),
        rust: keep.then_some(rust),
    }
}

/// The scenario's requests up to request `step` of connection `connection`, escaped and
/// each preceded by two line breaks, and the paths among them (request targets without their
/// query, and the original URIs of forward-authorization metadata): what the allow-list's
/// `request` and `path` conditions search.
fn history(case: &Case, connection: usize, step: usize) -> (String, String) {
    let mut text = String::new();
    let mut paths = String::new();
    for (index, requests) in case.connections.iter().enumerate().take(connection + 1) {
        let count = if index == connection { step + 1 } else { requests.len() };
        for request in requests.iter().take(count) {
            // Escaped text never holds two line breaks in a row, so this separates requests.
            text.push_str("\n\n");
            text.push_str(&escape(request, 16 * 1024));
            for path in request_paths(request) {
                paths.push('\n');
                paths.push_str(&escape(path, 16 * 1024));
            }
        }
    }
    (text, paths)
}

/// The path of the request target and of any `X-Forwarded-Uri` or `X-Original-URI` field.
fn request_paths(request: &[u8]) -> Vec<&[u8]> {
    let without_query = |target: &'_ [u8]| -> usize {
        target.iter().position(|&byte| byte == b'?').unwrap_or(target.len())
    };
    let mut lines = request.split(|&byte| byte == b'\n');
    let mut paths = Vec::new();
    if let Some(target) = lines.next().and_then(|line| line.split(|&byte| byte == b' ').nth(1)) {
        paths.push(&target[..without_query(target)]);
    }
    for line in lines.take_while(|line| *line != b"\r" && !line.is_empty()) {
        let Some(colon) = line.iter().position(|&byte| byte == b':') else { continue };
        let name = &line[..colon];
        if name.eq_ignore_ascii_case(b"x-forwarded-uri")
            || name.eq_ignore_ascii_case(b"x-original-uri")
        {
            let value = line[colon + 1..].trim_ascii();
            paths.push(&value[..without_query(value)]);
        }
    }
    paths
}

/// The allow-list id given to counter differences that follow from allowed differences.
pub const METRICS_FOLLOW: &str = "metrics-follow-allowed-differences";

/// The counters differ whenever the answers did. When every answer difference of the
/// configuration is allowed (and there is at least one), the counter differences follow
/// from them and are allowed too; otherwise they stay unexplained beside their causes.
fn explain_metrics(counters: &mut Outcome, outcomes: &[Outcome]) {
    let any_allowed = outcomes.iter().any(|outcome| !outcome.findings.is_empty());
    let all_allowed = outcomes.iter().all(|outcome| !outcome.is_unexplained());
    if !(any_allowed && all_allowed) {
        return;
    }
    for finding in &mut counters.findings {
        if finding.allowed_by.is_none() && finding.difference.field == "body" {
            finding.allowed_by = Some(METRICS_FOLLOW.to_owned());
        }
    }
}

/// After the corpus, both daemons must report the same counters: they saw the same
/// requests and made the same decisions.
fn metrics(
    config: &Config,
    zig: SocketAddrV4,
    rust: SocketAddrV4,
    settings: &Settings<'_>,
) -> Outcome {
    let request = Request::get("/__sibuna/metrics").header("User-Agent", "parity/1.0").encode();
    let case = Case {
        id: usize::MAX,
        config: 0,
        category: Category::Metrics,
        label: "metrics after the corpus".into(),
        source: Ipv4Addr::new(127, 255, 254, 1),
        connections: vec![vec![request]],
    };
    let pacer = Pacer::new(ISSUES_PER_SECOND);
    let zig = run_case(&case, zig, &pacer);
    let rust = run_case(&case, rust, &pacer);
    judge(config, &case, zig, rust, settings)
}
