//! `bench latency`: latency at equal offered load, measured by an open-loop generator.
//!
//! wrk keeps a fixed number of requests in flight, so a slow daemon also receives fewer
//! requests, and wrk's percentiles leave out the requests it never sent while it waited
//! (coordinated omission). Here each connection follows a fixed schedule: request `k` of a
//! connection is due at `start + offset + k * interval`, independent of earlier answers, as
//! in wrk2. When an answer arrives after the next request was due, that request is sent at
//! once and its latency counts from the time it was due, so time spent waiting behind a slow
//! answer is charged to the daemon. When the connection was idle at the due time, latency
//! counts from the actual send, so the generator's own sleep overshoot is not charged.
//!
//! The generator runs in a child process (`sibuna-bench generate`) pinned to the load CPUs,
//! one thread per connection with blocking I/O.

mod generator;

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use crate::args::Args;
use crate::daemon::{Config, Daemon, Implementation, Mode, Surface, browser_headers};
use crate::error::{Error, Result};
use crate::json::Json;
use crate::process::{self, CpuSet, TempDir};
use crate::product::{Daemons, Origin, OriginKind, parse_daemons, parse_list};
use crate::report::{Table, fmt_count, write_results};
use crate::stats::Spread;
use crate::{meta, paths};

pub use generator::generate_command;
use generator::{LATENCY_KEYS, RateResult};

/// The options of `bench latency`.
struct Options {
    daemons: Daemons,
    cpus: CpuSet,
    load_cpus: CpuSet,
    rates: Vec<f64>,
    seconds: f64,
    warmup: f64,
    connections: usize,
    repetitions: u32,
    surface: Surface,
    modes: Vec<Mode>,
    out: PathBuf,
}

fn parse_options(mut args: Args) -> Result<Options> {
    let (daemons, cpus, load_cpus) = parse_daemons(&mut args, "0-3")?;
    let rates = args.parsed("--rates", "10000,25000,50000,100000,150000".to_owned())?;
    let surface = args.parsed("--surface", "shield".to_owned())?;
    let modes = args.parsed("--modes", "forward_auth,reverse_proxy".to_owned())?;
    let options = Options {
        daemons,
        cpus,
        load_cpus,
        rates: parse_list(&rates, "--rates", |r| r.parse().ok().filter(|&r: &f64| r > 0.0))?,
        seconds: args.parsed("--seconds", 10.0)?,
        warmup: args.parsed("--warmup", 2.0)?,
        connections: args.parsed("--connections", 64)?,
        repetitions: args.parsed("--repetitions", 3)?.max(1),
        surface: Surface::parse(&surface).ok_or_else(|| {
            Error::new("INVALID VALUE", format!("`--surface` cannot be `{surface}`."))
                .hint("Use `gate` or `shield`.")
        })?,
        modes: parse_list(&modes, "--modes", Mode::parse)?,
        out: args.value("--out")?.map_or_else(paths::results_dir, PathBuf::from),
    };
    args.finish(&[
        "--rust",
        "--zig",
        "--zig-only",
        "--cpus",
        "--load-cpus",
        "--rates",
        "--seconds",
        "--warmup",
        "--connections",
        "--repetitions",
        "--surface",
        "--modes",
        "--out",
    ])?;
    Ok(options)
}

/// One generator run and the daemon CPU time per answer it cost.
struct Measured {
    result: RateResult,
    cpu_us_per_request: Option<f64>,
}

/// The repeated runs of one daemon at one rate.
struct Point {
    rate: f64,
    runs: Vec<Measured>,
}

impl Point {
    fn spread(&self, value: impl Fn(&Measured) -> f64) -> Option<Spread> {
        Spread::of(&self.runs.iter().map(value).collect::<Vec<_>>())
    }

    fn latency(&self, index: usize) -> Option<Spread> {
        self.spread(|m| m.result.latency_us[index])
    }

    fn cpu(&self) -> Option<Spread> {
        let values: Vec<f64> = self.runs.iter().filter_map(|m| m.cpu_us_per_request).collect();
        Spread::of(&values)
    }

    fn failures(&self) -> u64 {
        self.runs.iter().map(|m| m.result.errors + m.result.bad_status).sum()
    }

    fn to_json(&self) -> Json {
        let mut latency = Json::object();
        for (index, key) in LATENCY_KEYS.iter().enumerate() {
            latency.set(key, self.latency(index).map(Spread::to_json));
        }
        let runs = self
            .runs
            .iter()
            .map(|m| m.result.to_json().with("daemon_cpu_us_per_request", m.cpu_us_per_request));
        Json::object()
            .with("target_rps", self.rate)
            .with("achieved_rps", self.spread(|m| m.result.achieved_rps).map(Spread::to_json))
            .with("latency_us", latency)
            .with("daemon_cpu_us_per_request", self.cpu().map(Spread::to_json))
            .with("errors_total", self.failures())
            .with("repetitions", runs.collect::<Vec<_>>())
    }
}

/// One daemon's results at every rate, in one mode.
struct Series {
    implementation: Implementation,
    mode: Mode,
    points: Vec<Point>,
}

/// `sibuna-bench latency`.
///
/// # Errors
///
/// Fails on bad options, or when the origin, a daemon or a generator run fails.
pub fn command(args: Args, stdout: &mut dyn Write) -> Result<()> {
    let options = parse_options(args)?;
    let temp = TempDir::new("latency")?;
    let origin = Origin::start(OriginKind::Stub, &options.load_cpus)?;
    let load_before = meta::load_average();
    let mut series = Vec::new();
    for &mode in &options.modes {
        series.extend(run_mode(&options, mode, origin.port, &temp, stdout)?);
    }
    drop(origin);
    let mut document = latency_document(&options, &series);
    document.set("load_average_before", load_before);
    document.set("load_average_after", meta::load_average());
    let markdown = latency_markdown(&options, &series);
    write_results(&options.out, "latency-latest", &document, &markdown)?;
    let text =
        format!("\n{markdown}\nResults: {}\n", options.out.join("latency-latest.json").display());
    stdout.write_all(text.as_bytes()).map_err(|e| Error::io("stdout", e))
}

/// Starts every daemon in `mode` and steps through the rates and repetitions, alternating
/// daemons at each step so that slow drift of the machine affects both alike.
fn run_mode(
    options: &Options,
    mode: Mode,
    origin_port: u16,
    temp: &TempDir,
    stdout: &mut dyn Write,
) -> Result<Vec<Series>> {
    let config =
        Config { surface: options.surface, mode, workers: options.cpus.count(), origin_port };
    let mut running = Vec::new();
    for (implementation, binary) in &options.daemons {
        let label = format!("{}-latency-{}", implementation.name(), mode.name());
        let daemon = Daemon::start(&label, binary, Some(&options.cpus), &config, temp.path())?;
        let cookie = daemon.session_cookie()?;
        let points = options.rates.iter().map(|&rate| Point { rate, runs: Vec::new() }).collect();
        running.push((daemon, cookie, Series { implementation: *implementation, mode, points }));
    }
    for index in 0..options.rates.len() {
        for _ in 0..options.repetitions {
            for (daemon, cookie, series) in &mut running {
                let point = &mut series.points[index];
                let measured = measure(options, daemon, cookie, point.rate)?;
                let line =
                    progress_line(series.implementation, mode, point.rate, &measured.result);
                stdout.write_all(line.as_bytes()).map_err(|e| Error::io("stdout", e))?;
                point.runs.push(measured);
            }
        }
    }
    Ok(running.into_iter().map(|(_, _, series)| series).collect())
}

fn measure(options: &Options, daemon: &Daemon, cookie: &str, rate: f64) -> Result<Measured> {
    let before = process::cpu_seconds(daemon.pid()).ok();
    let result = run_generator(options, daemon.port, cookie, rate)?;
    let after = process::cpu_seconds(daemon.pid()).ok();
    let cpu_us_per_request =
        before.zip(after).map(|(b, a)| (a - b) * 1e6 / result.responses.max(1) as f64);
    Ok(Measured { result, cpu_us_per_request })
}

fn progress_line(implementation: Implementation, mode: Mode, rate: f64, r: &RateResult) -> String {
    format!(
        "  {:<4} {:<13} {:>8} req/s offered {:>9.0} achieved  p50 {:>8.1} us  p99 {:>9.1} us  \
         p99.9 {:>9.1} us  errors {}\n",
        implementation.name(),
        mode.name(),
        rate,
        r.achieved_rps,
        r.latency_us[0],
        r.latency_us[2],
        r.latency_us[3],
        r.errors + r.bad_status
    )
}

/// Runs `sibuna-bench generate` pinned to the load CPUs against the admitted workload.
fn run_generator(options: &Options, port: u16, cookie: &str, rate: f64) -> Result<RateResult> {
    let exe = std::env::current_exe().map_err(|e| Error::io("locating this program", e))?;
    let mut command = Command::new("taskset");
    command.arg("-c").arg(options.load_cpus.to_list()).arg(exe).arg("generate");
    command.args(["--port", &port.to_string(), "--path", "/private", "--rate", &rate.to_string()]);
    command.args(["--seconds", &options.seconds.to_string()]);
    command.args(["--warmup", &options.warmup.to_string()]);
    command.args(["--connections", &options.connections.to_string()]);
    for (name, value) in browser_headers() {
        command.arg("--header").arg(format!("{name}: {value}"));
    }
    command.arg("--header").arg(format!("Cookie: {cookie}"));
    let output = command.output().map_err(|e| Error::io("running the generator", e))?;
    let failed =
        || Error::new("GENERATOR FAILED", String::from_utf8_lossy(&output.stderr).into_owned());
    if !output.status.success() {
        return Err(failed());
    }
    sibuna_json::parse(&output.stdout)
        .ok()
        .and_then(|v| RateResult::from_json(&v))
        .ok_or_else(failed)
}

fn latency_document(options: &Options, series: &[Series]) -> Json {
    let mut daemons = Json::object();
    for (implementation, path) in &options.daemons {
        daemons.set(implementation.name(), meta::binary(path));
    }
    let load = Json::object()
        .with("generator", "sibuna-bench generate (open loop, one blocking thread per connection)")
        .with("connections", options.connections)
        .with("seconds", options.seconds)
        .with("warmup_seconds", options.warmup)
        .with("repetitions", options.repetitions)
        .with("rates", options.rates.iter().map(|&r| Json::from(r)).collect::<Vec<_>>())
        .with("workload", "admitted: GET /private with a valid session cookie")
        .with("product", options.surface.product());
    let runs = series.iter().map(|s| {
        Json::object()
            .with("implementation", s.implementation.name())
            .with("product", options.surface.product())
            .with("mode", s.mode.name())
            .with("rates", s.points.iter().map(Point::to_json).collect::<Vec<_>>())
    });
    Json::object()
        .with("meta", meta::machine(&paths::workspace_root(), &options.cpus))
        .with("load", load)
        .with("daemon_cpus", options.cpus.to_list())
        .with("load_cpus", options.load_cpus.to_list())
        .with("daemons", daemons)
        .with("runs", runs.collect::<Vec<_>>())
        .with("method", METHOD)
}

/// How the figures are made, recorded with every result.
const METHOD: &str = "Each connection sends on a fixed schedule; latency counts from the due \
    time when the previous answer made the request late, otherwise from the actual send \
    (coordinated-omission correction as in wrk2). Percentiles are nearest-rank over every \
    measured request of one run; each figure is the median over the repetitions, with the \
    min-max spread beside it in latency_us.";

fn latency_markdown(options: &Options, series: &[Series]) -> String {
    let mut out = format!(
        "# Latency at equal offered load\n\nGenerated by `cargo xtask bench latency` on {}. \
         Open-loop generator, {} connections, {} s warm-up and {} s measured per run, {} runs \
         per rate (median, with the min-max of p99 beside it); {} admitted requests \
         (`GET /private` with a session). Latency in microseconds.\n",
        meta::utc_now(),
        options.connections,
        options.warmup,
        options.seconds,
        options.repetitions,
        options.surface.product()
    );
    for &mode in &options.modes {
        let mut table = Table::new(&[
            "Offered req/s",
            "Impl",
            "Achieved req/s",
            "p50",
            "p90",
            "p99",
            "p99 min-max",
            "p99.9",
            "max",
            "Errors",
            "CPU us/req",
        ]);
        for index in 0..options.rates.len() {
            for s in series.iter().filter(|s| s.mode == mode) {
                if let Some(point) = s.points.get(index) {
                    table.row(markdown_row(s.implementation, point));
                }
            }
        }
        out.push_str(&format!("\n## {}\n\n{}", mode.name(), table.markdown()));
    }
    out
}

fn markdown_row(implementation: Implementation, point: &Point) -> Vec<String> {
    let median =
        |s: Option<Spread>| s.map_or_else(|| "-".to_owned(), |s| format!("{:.0}", s.median));
    let p99 = point.latency(2);
    vec![
        fmt_count(point.rate),
        implementation.name().to_owned(),
        point
            .spread(|m| m.result.achieved_rps)
            .map_or_else(|| "-".to_owned(), |s| fmt_count(s.median)),
        median(point.latency(0)),
        median(point.latency(1)),
        median(p99),
        p99.map_or_else(|| "-".to_owned(), |s| format!("{:.0}-{:.0}", s.min, s.max)),
        median(point.latency(3)),
        median(point.latency(4)),
        point.failures().to_string(),
        point.cpu().map_or_else(|| "-".to_owned(), |s| format!("{:.2}", s.median)),
    ]
}
