//! `bench product`: whole daemons under `wrk`, the successor of `benchmarks/tools.py`.
//!
//! For each mode (forward auth, reverse proxy), each surface (Gate, Shield) and each daemon
//! (Rust, and Zig when given), we start the daemon in memory pinned to `--cpus`, obtain a
//! session by solving its challenge, and drive four workloads with wrk pinned to
//! `--load-cpus`: admitted with a session, challenged, an allowed static path, and an SQL
//! injection with a session. Each workload runs `--repetitions` times; we report the median
//! with the min-max spread, the daemon's CPU time per request (`/proc/<pid>/stat`) and its
//! peak resident set (`VmHWM`, reset before each run).
//!
//! With `--anubis <path>`, Anubis is a third product after the Sibuna surfaces of each mode,
//! as in `tools.py`: started with its flags and `GOMAXPROCS` equal to the worker count,
//! pinned to the same CPUs, with a session obtained by solving its challenge (see
//! [`crate::anubis`]). The origin is then `caddy respond` unless `--origin` says otherwise,
//! every run waits until fewer than 3,000 sockets are in `TIME_WAIT`, as `tools.py` did, and
//! the results go to `comparison-latest` instead of `product-latest`.

mod summary;
mod wrk;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::anubis::{self, TokenScheme};
use crate::args::Args;
use crate::daemon::{self, Config, Daemon, Implementation, Mode, Surface};
use crate::error::{Error, Result};
use crate::json::Json;
use crate::process::{self, CpuSet, Process, TempDir};
use crate::report::write_results;
use crate::server::Server;
use crate::stats::Spread;
use crate::{meta, origin, paths};

use summary::{product_document, product_markdown};

pub use wrk::Load;

/// The daemons to measure, each with the binary to run.
pub type Daemons = Vec<(Implementation, PathBuf)>;

/// Reads one figure of a sample.
type Metric<'f> = &'f dyn Fn(&Sample) -> f64;

/// The SQL injection query of the attack workload.
const ATTACK: &str = "/search?q=%27%20OR%201%3D1--";

/// Sockets in `TIME_WAIT` below which a comparison run may start, as in `tools.py`.
const TIME_WAIT_LIMIT: usize = 3000;

/// The longest wait for sockets in `TIME_WAIT` to drain before a comparison run.
const TIME_WAIT_TIMEOUT: Duration = Duration::from_secs(90);

/// One product under test: a Sibuna daemon on one surface, or Anubis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Subject {
    /// A Sibuna daemon, Rust or Zig, as Gate or Shield.
    Sibuna(Implementation, Surface),
    /// Anubis, given with `--anubis`.
    Anubis,
}

impl Subject {
    /// Returns the product name of the result files (`sibuna-gate`, `sibuna-shield`,
    /// `anubis`).
    fn product(self) -> &'static str {
        match self {
            Subject::Sibuna(_, surface) => surface.product(),
            Subject::Anubis => "anubis",
        }
    }

    /// Returns a short column name: `rust gate`, `zig shield`, `anubis`.
    fn label(self) -> String {
        match self {
            Subject::Sibuna(implementation, surface) => {
                let surface = surface.product().trim_start_matches("sibuna-");
                format!("{} {surface}", implementation.name())
            }
            Subject::Anubis => "anubis".to_owned(),
        }
    }

    /// Returns the implementation name of the result files (`rust`, `zig`, `anubis`).
    fn implementation(self) -> &'static str {
        match self {
            Subject::Sibuna(implementation, _) => implementation.name(),
            Subject::Anubis => "anubis",
        }
    }
}

/// A product under test while it runs.
enum Running {
    /// A Sibuna daemon.
    Sibuna(Daemon),
    /// An Anubis server.
    Anubis(Server),
}

impl Running {
    fn pid(&self) -> u32 {
        match self {
            Running::Sibuna(daemon) => daemon.pid(),
            Running::Anubis(server) => server.pid(),
        }
    }

    fn port(&self) -> u16 {
        match self {
            Running::Sibuna(daemon) => daemon.port,
            Running::Anubis(server) => server.port,
        }
    }

    /// Obtains a session by solving the product's challenge, as a browser would.
    fn session_cookie(&self) -> Result<String> {
        match self {
            Running::Sibuna(daemon) => daemon.session_cookie(),
            Running::Anubis(server) => anubis::session_cookie(server.port),
        }
    }
}

/// What the origin is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginKind {
    /// This program's stub origin (`sibuna-bench origin`).
    Stub,
    /// `caddy respond`, as `tools.py` used.
    Caddy,
}

/// A running origin, stopped when dropped.
pub struct Origin {
    _process: Process,
    /// Its port.
    pub port: u16,
    /// A description for the result file.
    pub description: &'static str,
}

impl Origin {
    /// Starts the origin pinned to `cpus` and waits until it accepts connections.
    ///
    /// # Errors
    ///
    /// Fails when it cannot start or does not listen within ten seconds.
    pub fn start(kind: OriginKind, cpus: &CpuSet) -> Result<Origin> {
        let port = process::free_port()?;
        let (program, args, description) = match kind {
            OriginKind::Stub => {
                let exe =
                    std::env::current_exe().map_err(|e| Error::io("locating this program", e))?;
                let args = vec!["origin".to_owned(), "--port".to_owned(), port.to_string()];
                (exe, args, "sibuna-bench origin (std-only, keep-alive, static 200)")
            }
            OriginKind::Caddy => {
                let args =
                    ["respond", "--listen", &format!("127.0.0.1:{port}"), "--body", origin::BODY];
                let args = args.iter().map(|s| (*s).to_owned()).collect();
                (PathBuf::from("caddy"), args, "caddy respond (static 200)")
            }
        };
        let process = Process::spawn("origin", &program, &args, Some(cpus), None)?;
        for _ in 0..200 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Ok(Origin { _process: process, port, description });
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(Error::new("ORIGIN FAILED", format!("The origin did not listen on port {port}.")))
    }
}

/// The options of `bench product`.
struct Options {
    daemons: Daemons,
    anubis: Option<PathBuf>,
    cpus: CpuSet,
    load_cpus: CpuSet,
    load: Load,
    repetitions: u32,
    origin: OriginKind,
    surfaces: Vec<Surface>,
    modes: Vec<Mode>,
    out: PathBuf,
}

/// Parses the options shared by `product`, `latency` and `admission`: the daemons and the
/// CPU sets, with `default_cpus` for the daemons when `--cpus` is absent.
pub fn parse_daemons(args: &mut Args, default_cpus: &str) -> Result<(Daemons, CpuSet, CpuSet)> {
    let rust = args.value("--rust")?.map_or_else(paths::rust_daemon, PathBuf::from);
    let mut daemons = vec![(Implementation::Rust, rust)];
    if let Some(zig) = args.value("--zig")? {
        daemons.push((Implementation::Zig, PathBuf::from(zig)));
    }
    if args.flag("--zig-only") {
        daemons.remove(0);
    }
    for (_, path) in &daemons {
        if !path.is_file() {
            return Err(Error::new(
                "NO DAEMON",
                format!("There is no daemon at {}.", path.display()),
            )
            .hint("Build it with `cargo build --release -p sibuna`, or pass `--rust <path>`."));
        }
    }
    let cpus = CpuSet::parse(&args.parsed("--cpus", default_cpus.to_owned())?)?;
    let load_cpus = CpuSet::parse(&args.parsed("--load-cpus", "8-15".to_owned())?)?;
    Ok((daemons, cpus, load_cpus))
}

/// Parses a comma-separated list with `parse`, naming `option` in the error.
pub fn parse_list<T>(
    text: &str,
    option: &str,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<Vec<T>> {
    text.split(',')
        .map(|item| {
            parse(item.trim()).ok_or_else(|| {
                Error::new("INVALID VALUE", format!("`{option}` cannot hold `{item}`."))
                    .hint("Run `cargo xtask bench help` for the expected values.")
            })
        })
        .collect()
}

/// Takes `--anubis <path>` and checks that the file exists.
///
/// # Errors
///
/// Fails when the option names no file.
pub fn parse_anubis(args: &mut Args) -> Result<Option<PathBuf>> {
    let Some(path) = args.value("--anubis")?.map(PathBuf::from) else {
        return Ok(None);
    };
    if !path.is_file() {
        return Err(Error::new("NO ANUBIS", format!("There is no file at {}.", path.display()))
            .hint("Download a release from github.com/TecharoHQ/anubis and pass its `anubis`."));
    }
    Ok(Some(path))
}

fn parse_options(mut args: Args) -> Result<Options> {
    let (daemons, cpus, load_cpus) = parse_daemons(&mut args, "0-3")?;
    let anubis = parse_anubis(&mut args)?;
    let defaults = Load::default();
    let load = Load {
        threads: args.parsed("--threads", defaults.threads)?,
        connections: args.parsed("--connections", defaults.connections)?,
        seconds: args.parsed("--seconds", defaults.seconds)?,
    };
    // tools.py measured Anubis behind `caddy respond`; keep that origin for the comparison.
    let default_origin = if anubis.is_some() { "caddy" } else { "stub" };
    let origin = match args.parsed("--origin", default_origin.to_owned())?.as_str() {
        "stub" => OriginKind::Stub,
        "caddy" => OriginKind::Caddy,
        other => {
            return Err(Error::new("INVALID VALUE", format!("`--origin` cannot be `{other}`."))
                .hint("Use `stub` or `caddy`."));
        }
    };
    let options = Options {
        daemons,
        anubis,
        cpus,
        load_cpus,
        load,
        repetitions: args.parsed("--repetitions", 3)?.max(1),
        origin,
        surfaces: parse_list(
            &args.parsed("--surfaces", "gate,shield".to_owned())?,
            "--surfaces",
            Surface::parse,
        )?,
        modes: parse_list(
            &args.parsed("--modes", "forward_auth,reverse_proxy".to_owned())?,
            "--modes",
            Mode::parse,
        )?,
        out: args.value("--out")?.map_or_else(paths::results_dir, PathBuf::from),
    };
    args.finish(&[
        "--rust",
        "--zig",
        "--zig-only",
        "--anubis",
        "--cpus",
        "--load-cpus",
        "--threads",
        "--connections",
        "--seconds",
        "--repetitions",
        "--origin",
        "--surfaces",
        "--modes",
        "--out",
    ])?;
    Ok(options)
}

/// One request shape driven by wrk.
struct Workload {
    name: &'static str,
    path: &'static str,
    headers: Vec<(String, String)>,
    expected: u16,
    description: &'static str,
}

/// The four workloads of `tools.py`, with the statuses it expected. Anubis in forward-auth
/// mode is asked at its check endpoint instead of `/private`.
fn workloads(subject: Subject, mode: Mode, cookie: &str) -> [Workload; 4] {
    let check = match (subject, mode) {
        (Subject::Anubis, Mode::ForwardAuth) => anubis::CHECK,
        _ => "/private",
    };
    let shield = matches!(subject, Subject::Sibuna(_, Surface::Shield));
    let browser = daemon::browser_headers();
    let mut with_cookie = browser.clone();
    with_cookie.push(("Cookie".to_owned(), cookie.to_owned()));
    let mut curl = browser.clone();
    curl[0].1 = "curl/8.0".to_owned();
    [
        Workload {
            name: "admitted",
            path: check,
            headers: with_cookie.clone(),
            expected: 200,
            description: "Valid session cookie; the request is admitted (and proxied).",
        },
        Workload {
            name: "challenged",
            path: check,
            headers: browser,
            expected: if mode == Mode::ForwardAuth { 401 } else { 200 },
            description: "No cookie, browser User-Agent; the daemon answers with its challenge.",
        },
        Workload {
            name: "allowed_static",
            path: "/robots.txt",
            headers: curl,
            expected: 200,
            description: "Non-browser client on a path allowed without a challenge.",
        },
        Workload {
            name: "attack",
            path: ATTACK,
            headers: with_cookie,
            expected: if shield { 403 } else { 200 },
            description: "Valid session plus an SQL injection query; only Shield refuses it.",
        },
    ]
}

/// One wrk run's measurements of the daemon.
struct Sample {
    summary: wrk::Summary,
    cpu_seconds: f64,
    peak_rss_kib: u64,
}

impl Sample {
    fn seconds(&self) -> f64 {
        self.summary.duration_us as f64 / 1e6
    }

    fn requests_per_second(&self) -> f64 {
        self.summary.requests as f64 / self.seconds().max(1e-9)
    }

    fn cpu_us_per_request(&self) -> f64 {
        self.cpu_seconds * 1e6 / self.summary.requests.max(1) as f64
    }

    fn to_json(&self) -> Json {
        let mut errors = Json::object();
        for (kind, count) in wrk::ERROR_KINDS.iter().zip(self.summary.errors) {
            errors.set(kind, count);
        }
        Json::object()
            .with("requests", self.summary.requests)
            .with("requests_per_second", self.requests_per_second())
            .with("latency_us", self.summary.latency.to_json())
            .with("errors", errors)
            .with("cpu_seconds", self.cpu_seconds)
            .with("cores_busy", self.cpu_seconds / self.seconds().max(1e-9))
            .with("cpu_us_per_request", self.cpu_us_per_request())
            .with("peak_rss_kib", self.peak_rss_kib)
    }
}

/// The repeated runs of one workload against one daemon.
struct WorkloadResult {
    workload: Workload,
    status: std::result::Result<u16, String>,
    samples: Vec<Sample>,
    failures: Vec<String>,
}

impl WorkloadResult {
    fn spread(&self, value: impl Fn(&Sample) -> f64) -> Option<Spread> {
        Spread::of(&self.samples.iter().map(value).collect::<Vec<_>>())
    }

    fn to_json(&self) -> Json {
        let w = &self.workload;
        let status = match &self.status {
            Ok(code) => Json::from(*code),
            Err(text) => Json::from(format!("probe failed: {text}")),
        };
        let median = |f: &dyn Fn(&Sample) -> f64| self.spread(f).map(|s| s.median);
        let spreads: [(&str, Metric<'_>); 7] = [
            ("requests_per_second", &Sample::requests_per_second),
            ("latency_us_p50", &|s| s.summary.latency.p50),
            ("latency_us_p90", &|s| s.summary.latency.p90),
            ("latency_us_p99", &|s| s.summary.latency.p99),
            ("latency_us_p999", &|s| s.summary.latency.p999),
            ("cpu_us_per_request", &Sample::cpu_us_per_request),
            ("cores_busy", &|s| s.cpu_seconds / s.seconds().max(1e-9)),
        ];
        let mut json = Json::object().with("failed", self.samples.is_empty()).with(
            "failures",
            self.failures.iter().map(|f| Json::from(f.as_str())).collect::<Vec<_>>(),
        );
        for (name, value) in spreads {
            json.set(&format!("{name}_median"), median(value));
        }
        let rates = self.spread(Sample::requests_per_second);
        json.set("requests_per_second_min", rates.map(|s| s.min));
        json.set("requests_per_second_max", rates.map(|s| s.max));
        let mut spread_json = Json::object();
        for (name, value) in spreads {
            spread_json.set(name, self.spread(value).map(Spread::to_json));
        }
        let mut totals = Json::object();
        for (index, kind) in wrk::ERROR_KINDS.iter().enumerate() {
            totals.set(kind, self.samples.iter().map(|s| s.summary.errors[index]).sum::<u64>());
        }
        json.with("spread", spread_json)
            .with("peak_rss_kib_max", self.samples.iter().map(|s| s.peak_rss_kib).max())
            .with("errors_total", totals)
            .with("samples", self.samples.iter().map(Sample::to_json).collect::<Vec<_>>())
            .with("path", w.path)
            .with("status", status)
            .with("expected_status", w.expected)
            .with("description", w.description)
    }
}

/// One product (a daemon on one surface, or Anubis), one mode: four workloads.
struct CaseResult {
    subject: Subject,
    mode: Mode,
    workers: usize,
    cpus: CpuSet,
    binary_bytes: Option<u64>,
    idle_rss_kib: u64,
    rss_kib_after_workload: u64,
    workloads: Vec<WorkloadResult>,
}

impl CaseResult {
    fn to_json(&self) -> Json {
        let mut workloads = Json::object();
        for result in &self.workloads {
            workloads.set(result.workload.name, result.to_json());
        }
        Json::object()
            .with("product", self.subject.product())
            .with("implementation", self.subject.implementation())
            .with("mode", self.mode.name())
            .with("workers", self.workers)
            .with(
                "cpu_affinity",
                self.cpus.cpus.iter().map(|&c| Json::from(c)).collect::<Vec<_>>(),
            )
            .with("binary_bytes", self.binary_bytes)
            .with("idle_rss_kib", self.idle_rss_kib)
            .with("workloads", workloads)
            .with("rss_kib_after_workload", self.rss_kib_after_workload)
    }
}

/// Everything a case needs besides its daemon.
struct Bench<'a> {
    options: &'a Options,
    origin_port: u16,
    script: PathBuf,
    temp: &'a Path,
}

/// `sibuna-bench product`.
///
/// # Errors
///
/// Fails on bad options or when the origin or a daemon cannot start; a workload whose wrk
/// run fails is recorded as failed instead.
pub fn command(args: Args, stdout: &mut dyn Write) -> Result<()> {
    let options = parse_options(args)?;
    let temp = TempDir::new("product")?;
    let script = temp.path().join("done.lua");
    fs::write(&script, wrk::DONE_LUA).map_err(|e| Error::io(script.display(), e))?;
    let origin = Origin::start(options.origin, &options.load_cpus)?;
    let load_before = meta::load_average();
    let bench = Bench { options: &options, origin_port: origin.port, script, temp: temp.path() };
    let mut cases = Vec::new();
    for &mode in &options.modes {
        for (subject, binary) in subjects(&options) {
            let line = format!(
                "Measuring {} {} {}\n",
                subject.implementation(),
                subject.product(),
                mode.name()
            );
            stdout.write_all(line.as_bytes()).map_err(|e| Error::io("stdout", e))?;
            cases.push(run_case(&bench, subject, binary, mode, stdout)?);
        }
    }
    let description = origin.description;
    drop(origin);
    let mut document = product_document(&options, description, &cases);
    document.set("load_average_before", load_before);
    let markdown = product_markdown(&options, &cases);
    let name = if options.anubis.is_some() { "comparison-latest" } else { "product-latest" };
    write_results(&options.out, name, &document, &markdown)?;
    let path = options.out.join(format!("{name}.json"));
    let text = format!("\n{markdown}\nResults: {}\n", path.display());
    stdout.write_all(text.as_bytes()).map_err(|e| Error::io("stdout", e))
}

/// Returns the products of one mode in the order of measurement: each surface with each
/// daemon, then Anubis, as `tools.py` ordered them.
fn subjects(options: &Options) -> Vec<(Subject, &Path)> {
    let mut subjects = Vec::new();
    for &surface in &options.surfaces {
        for (implementation, binary) in &options.daemons {
            subjects.push((Subject::Sibuna(*implementation, surface), binary.as_path()));
        }
    }
    if let Some(binary) = &options.anubis {
        subjects.push((Subject::Anubis, binary.as_path()));
    }
    subjects
}

/// Starts `subject` from `binary` in `mode`, pinned to the daemon CPUs.
fn start_subject(
    bench: &Bench<'_>,
    subject: Subject,
    binary: &Path,
    mode: Mode,
) -> Result<Running> {
    let options = bench.options;
    let workers = options.cpus.count();
    let label = format!("{}-{}-{}", subject.implementation(), subject.product(), mode.name());
    match subject {
        Subject::Sibuna(_, surface) => {
            let config = Config { surface, mode, workers, origin_port: bench.origin_port };
            let daemon = Daemon::start(&label, binary, Some(&options.cpus), &config, bench.temp)?;
            Ok(Running::Sibuna(daemon))
        }
        Subject::Anubis => {
            let origin_port = (mode == Mode::ReverseProxy).then_some(bench.origin_port);
            let setup = anubis::Setup { origin_port, workers, scheme: TokenScheme::Ed25519 };
            let server = anubis::start(&label, binary, &setup, &options.cpus, bench.temp)?;
            Ok(Running::Anubis(server))
        }
    }
}

fn run_case(
    bench: &Bench<'_>,
    subject: Subject,
    binary: &Path,
    mode: Mode,
    stdout: &mut dyn Write,
) -> Result<CaseResult> {
    let options = bench.options;
    if options.anubis.is_some() {
        process::drain_time_wait(TIME_WAIT_LIMIT, TIME_WAIT_TIMEOUT);
    }
    let running = start_subject(bench, subject, binary, mode)?;
    std::thread::sleep(Duration::from_millis(500));
    let idle_rss_kib = process::status_kib(running.pid(), "VmRSS")?;
    let cookie = running.session_cookie()?;
    let mut results = Vec::new();
    for workload in workloads(subject, mode, &cookie) {
        let result = measure_workload(bench, &running, workload);
        let line = progress_line(subject, mode, &result);
        stdout.write_all(line.as_bytes()).map_err(|e| Error::io("stdout", e))?;
        results.push(result);
    }
    Ok(CaseResult {
        subject,
        mode,
        workers: options.cpus.count(),
        cpus: options.cpus.clone(),
        binary_bytes: fs::metadata(binary).ok().map(|m| m.len()),
        idle_rss_kib,
        rss_kib_after_workload: process::status_kib(running.pid(), "VmRSS")?,
        workloads: results,
    })
}

fn measure_workload(bench: &Bench<'_>, running: &Running, workload: Workload) -> WorkloadResult {
    let options = bench.options;
    // Only a comparison with Anubis waits for TIME_WAIT, as tools.py did; Rust against Zig
    // runs as before.
    let drain = || {
        if options.anubis.is_some() {
            process::drain_time_wait(TIME_WAIT_LIMIT, TIME_WAIT_TIMEOUT);
        }
    };
    drain();
    let port = running.port();
    let status = crate::http::request(port, "GET", workload.path, &workload.headers, b"")
        .map(|r| r.status)
        .map_err(|e| e.message);
    let pid = running.pid();
    let mut result =
        WorkloadResult { workload, status, samples: Vec::new(), failures: Vec::new() };
    for _ in 0..options.repetitions {
        drain();
        process::reset_peak_rss(pid);
        let before = process::cpu_seconds(pid);
        let summary = wrk::run(
            options.load,
            &options.load_cpus,
            &bench.script,
            port,
            result.workload.path,
            &result.workload.headers,
        );
        let after = process::cpu_seconds(pid);
        let peak = process::status_kib(pid, "VmHWM");
        match (summary, before, after, peak) {
            (Ok(summary), Ok(before), Ok(after), Ok(peak_rss_kib)) => {
                result.samples.push(Sample { summary, cpu_seconds: after - before, peak_rss_kib });
            }
            (Err(e), ..) | (_, Err(e), ..) | (_, _, Err(e), _) | (.., Err(e)) => {
                result.failures.push(e.message);
            }
        }
    }
    result
}

fn progress_line(subject: Subject, mode: Mode, result: &WorkloadResult) -> String {
    let status =
        result.status.as_ref().map_or_else(|e| format!("probe failed ({e})"), u16::to_string);
    let prefix = format!(
        "  {:<4} {:<13} {:<13} {:<15} {status:>3}",
        subject.implementation(),
        subject.product(),
        mode.name(),
        result.workload.name
    );
    match (result.spread(Sample::requests_per_second), result.spread(|s| s.summary.latency.p99)) {
        (Some(rate), Some(p99)) => {
            let cpu = result.spread(Sample::cpu_us_per_request).map_or(0.0, |s| s.median);
            format!(
                "{prefix} {:>9.0} req/s  p99 {:>6.2} ms  cpu {cpu:>5.1} us/req\n",
                rate.median,
                p99.median / 1000.0
            )
        }
        _ => format!("{prefix} FAILED: {}\n", result.failures.last().map_or("", String::as_str)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workloads_expect_the_tools_py_statuses() {
        let shield = Subject::Sibuna(Implementation::Rust, Surface::Shield);
        let shield = workloads(shield, Mode::ForwardAuth, "t=1");
        let statuses: Vec<u16> = shield.iter().map(|w| w.expected).collect();
        assert_eq!(statuses, [200, 401, 200, 403]);
        assert_eq!(shield[0].path, "/private");
        let gate = Subject::Sibuna(Implementation::Zig, Surface::Gate);
        let gate = workloads(gate, Mode::ReverseProxy, "t=1");
        let statuses: Vec<u16> = gate.iter().map(|w| w.expected).collect();
        assert_eq!(statuses, [200, 200, 200, 200]);
        assert!(gate[0].headers.iter().any(|(n, v)| n == "Cookie" && v == "t=1"));
        assert!(!gate[1].headers.iter().any(|(n, _)| n == "Cookie"));
        assert_eq!(gate[2].headers[0], ("User-Agent".to_owned(), "curl/8.0".to_owned()));
    }

    #[test]
    fn anubis_is_asked_at_its_check_endpoint_in_forward_auth_mode() {
        let forward = workloads(Subject::Anubis, Mode::ForwardAuth, "a=1");
        let paths: Vec<&str> = forward.iter().map(|w| w.path).collect();
        assert_eq!(paths, [anubis::CHECK, anubis::CHECK, "/robots.txt", ATTACK]);
        let statuses: Vec<u16> = forward.iter().map(|w| w.expected).collect();
        assert_eq!(statuses, [200, 401, 200, 200]);
        let proxy = workloads(Subject::Anubis, Mode::ReverseProxy, "a=1");
        assert_eq!(proxy[0].path, "/private");
        assert_eq!(Subject::Anubis.product(), "anubis");
        let zig_gate = Subject::Sibuna(Implementation::Zig, Surface::Gate);
        assert_eq!((zig_gate.implementation(), zig_gate.label().as_str()), ("zig", "zig gate"));
        assert_eq!(Subject::Anubis.label(), "anubis");
    }

    #[test]
    fn parses_lists() {
        let modes = parse_list("forward_auth, reverse_proxy", "--modes", Mode::parse).unwrap();
        assert_eq!(modes, [Mode::ForwardAuth, Mode::ReverseProxy]);
        assert!(parse_list("edge", "--modes", Mode::parse).is_err());
    }
}
