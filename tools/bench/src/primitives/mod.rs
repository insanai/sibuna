//! `bench primitives`: the primitive timings of `benchmarks/benchmark.zig`, for the Rust
//! crates.
//!
//! The suite runs in a child of this program (`sibuna-bench primitives-run`) pinned to one
//! CPU. The child prints a JSON document (`{"meta": .., "runs": [..]}`) in the row shape of
//! the Zig benchmark, which this program reads back.

mod workloads;

use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use sibuna_json::Value;

use crate::args::Args;
use crate::daemon::{Config, Daemon, Mode, Surface};
use crate::error::{Error, Result};
use crate::json::{Json, member, member_f64, member_str, member_u64, round2};
use crate::process::{self, CpuSet, TempDir};
use crate::report::{Table, fmt_ns, write_results};
use crate::{meta, paths};

/// Timed batches per workload, as in the Zig benchmark.
const BATCHES: usize = 7;

/// The batch timings of one workload, reduced to nanoseconds per operation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Timing {
    /// Operations per batch.
    pub iterations: u64,
    /// The median batch, per operation.
    pub median: f64,
    /// The fastest batch, per operation.
    pub min: f64,
    /// The slowest batch, per operation.
    pub max: f64,
}

/// Runs `body(context, iterations)` in seven timed batches after an untimed warm-up of at
/// most 1,000 operations, with a fresh `reset()` context before the warm-up and each batch,
/// and reduces the batch times to nanoseconds per operation (Zig's `measure`).
///
/// Timers surround whole batches: a clock read per operation would cost as much as the
/// sub-100 ns work it measures, so the spread is across batches. Creating and dropping the
/// context is not timed.
pub fn measure<C>(
    iterations: u64,
    mut reset: impl FnMut() -> C,
    body: impl Fn(&C, u64) -> u64,
) -> Timing {
    let warm = reset();
    black_box(body(&warm, iterations.min(1000)));
    drop(warm);
    let mut samples = [0u128; BATCHES];
    let mut sink = 0u64;
    for sample in &mut samples {
        let context = reset();
        let start = Instant::now();
        sink = sink.wrapping_add(body(&context, iterations));
        *sample = start.elapsed().as_nanos();
        drop(context);
    }
    black_box(sink);
    samples.sort_unstable();
    let per_op = |ns: u128| ns as f64 / iterations as f64;
    Timing {
        iterations,
        median: per_op(samples[BATCHES / 2]),
        min: per_op(samples[0]),
        max: per_op(samples[BATCHES - 1]),
    }
}

/// One measured workload, in the row shape of the Zig benchmark's JSON.
#[derive(Clone, Debug, PartialEq)]
pub struct Run {
    /// `sibuna`, or `sibuna-naive` for the sequential-search reference row.
    pub implementation: String,
    /// The subsystem (`pow_verify`, `token_auth`, ...).
    pub subsystem: String,
    /// The workload within the subsystem.
    pub workload: String,
    /// The timing.
    pub timing: Timing,
    /// Input bytes per operation, for throughput rows; 0 otherwise.
    pub bytes_per_op: u64,
}

impl Run {
    fn new(subsystem: &str, workload: &str, timing: Timing) -> Run {
        Run {
            implementation: "sibuna".to_owned(),
            subsystem: subsystem.to_owned(),
            workload: workload.to_owned(),
            timing,
            bytes_per_op: 0,
        }
    }

    /// Returns the operations per second of the median batch.
    pub fn ops_per_sec(&self) -> u64 {
        if self.timing.median > 0.0 { (1e9 / self.timing.median) as u64 } else { 0 }
    }

    /// Returns the row as the Zig benchmark prints it.
    pub fn to_json(&self) -> Json {
        Json::object()
            .with("impl", self.implementation.as_str())
            .with("subsystem", self.subsystem.as_str())
            .with("workload", self.workload.as_str())
            .with("measured", true)
            .with("iterations", self.timing.iterations)
            .with("ns_per_op_median", round2(self.timing.median))
            .with("ns_per_op_min", round2(self.timing.min))
            .with("ns_per_op_max", round2(self.timing.max))
            .with("ops_per_sec", self.ops_per_sec())
            .with("alloc_bytes", Json::Null)
            .with("bytes_per_op", self.bytes_per_op)
    }

    /// Reads a row printed by the suite.
    fn from_json(value: &Value<'_>) -> Option<Run> {
        Some(Run {
            implementation: member_str(value, "impl")?.to_owned(),
            subsystem: member_str(value, "subsystem")?.to_owned(),
            workload: member_str(value, "workload")?.to_owned(),
            timing: Timing {
                iterations: member_u64(value, "iterations")?,
                median: member_f64(value, "ns_per_op_median")?,
                min: member_f64(value, "ns_per_op_min")?,
                max: member_f64(value, "ns_per_op_max")?,
            },
            bytes_per_op: member_u64(value, "bytes_per_op").unwrap_or(0),
        })
    }
}

/// The sizes of the policy engine and its tables, in bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sizes {
    /// The engine value plus the heap it owns.
    pub engine_bytes: usize,
    /// The heap of the 40-signature bot automaton.
    pub bot_table_bytes: usize,
    /// The heap of the WAF signature automaton.
    pub waf_table_bytes: usize,
}

/// `sibuna-bench primitives-run`: runs the Rust suite and prints its JSON on stdout.
///
/// # Errors
///
/// Fails when stdout cannot be written.
pub fn run_suite(out: &mut dyn std::io::Write) -> Result<()> {
    let (runs, sizes) = workloads::run_all();
    let document = Json::object()
        .with(
            "meta",
            Json::object()
                .with("engine_bytes", sizes.engine_bytes)
                .with("bot_table_bytes", sizes.bot_table_bytes)
                .with("waf_table_bytes", sizes.waf_table_bytes)
                .with("allocation_measurement", "not instrumented; API/source audit only"),
        )
        .with("runs", runs.iter().map(Run::to_json).collect::<Vec<_>>());
    out.write_all(document.to_pretty().as_bytes()).map_err(|e| Error::io("stdout", e))
}

/// The options of `bench primitives`.
struct Options {
    rust_daemon: PathBuf,
    cpu: CpuSet,
    rounds: u32,
    out: PathBuf,
}

/// `sibuna-bench primitives`: runs the suite and writes `primitives-latest.json` and
/// `primitives-latest.md`.
///
/// # Errors
///
/// Fails on bad options, or when the suite fails or prints something unreadable.
pub fn command(mut args: Args, stdout: &mut dyn std::io::Write) -> Result<()> {
    let options = Options {
        rust_daemon: args.value("--rust")?.map_or_else(paths::rust_daemon, PathBuf::from),
        cpu: CpuSet::parse(&args.parsed("--cpu", "4".to_owned())?)?,
        rounds: args.parsed("--rounds", 3)?.max(1),
        out: args.value("--out")?.map_or_else(paths::results_dir, PathBuf::from),
    };
    args.finish(&["--rust", "--cpu", "--rounds", "--out"])?;
    let suite = run_rounds(&options, stdout)?;
    let document = Json::object()
        .with("meta", primitives_meta(&options, &suite)?)
        .with("runs", suite.runs.iter().map(Run::to_json).collect::<Vec<_>>());
    let table = results_table(&suite.runs);
    let markdown = format!(
        "# Primitive timings\n\nGenerated by `cargo xtask bench primitives` on {}. Seven \
         batches after an untimed warm-up; median per operation with the min-max spread \
         across batches, from the least disturbed of {} rounds.\n\n{}\n",
        meta::utc_now(),
        options.rounds,
        table.markdown()
    );
    write_results(&options.out, "primitives-latest", &document, &markdown)?;
    let text = format!(
        "{}\nResults: {}\n",
        table.text(),
        options.out.join("primitives-latest.json").display()
    );
    stdout.write_all(text.as_bytes()).map_err(|e| Error::io("stdout", e))
}

/// Runs the suite `rounds` times and keeps for every row the round with the lowest median.
///
/// The host may be shared: another process on the CPU or its SMT sibling, or a lower clock,
/// slows a whole suite run, and the fastest round of a row is the one least disturbed.
/// Within a round the statistics are those of the Zig benchmark.
fn run_rounds(options: &Options, stdout: &mut dyn std::io::Write) -> Result<Suite> {
    let self_exe = std::env::current_exe().map_err(|e| Error::io("locating this program", e))?;
    let mut best: Option<Suite> = None;
    for round in 1..=options.rounds {
        let line = format!("Round {round} of {}\n", options.rounds);
        stdout.write_all(line.as_bytes()).map_err(|e| Error::io("stdout", e))?;
        let suite = run_pinned(&self_exe, &["primitives-run"], &options.cpu)?;
        best = Some(keep_fastest(best, suite));
    }
    best.ok_or_else(|| Error::new("SUITE FAILED", "No round ran."))
}

/// Returns `best` with every row replaced by the row of `next` when that one is faster.
fn keep_fastest(best: Option<Suite>, next: Suite) -> Suite {
    let Some(mut best) = best else {
        return next;
    };
    for row in &mut best.runs {
        if let Some(other) = find(&next.runs, row)
            && other.timing.median < row.timing.median
        {
            *row = other.clone();
        }
    }
    best
}

/// A suite's parsed output.
struct Suite {
    meta: Json,
    runs: Vec<Run>,
}

/// Runs `program args` pinned to `cpu` and parses the JSON document it prints.
fn run_pinned(program: &Path, args: &[&str], cpu: &CpuSet) -> Result<Suite> {
    let output = Command::new("taskset")
        .arg("-c")
        .arg(cpu.to_list())
        .arg(program)
        .args(args)
        .output()
        .map_err(|e| Error::io(format!("running {}", program.display()), e))?;
    let failed = |what: &str| {
        Error::new("SUITE FAILED", format!("{} {what}.", program.display()))
            .hint("Run it by hand to see its output.")
    };
    if !output.status.success() {
        return Err(failed(&format!("exited with {}", output.status)));
    }
    let start =
        output.stdout.iter().position(|&b| b == b'{').ok_or_else(|| failed("printed no JSON"))?;
    let value =
        sibuna_json::parse(&output.stdout[start..]).map_err(|_| failed("printed invalid JSON"))?;
    let runs = member(&value, "runs")
        .and_then(Value::as_array)
        .ok_or_else(|| failed("printed no runs"))?
        .iter()
        .map(Run::from_json)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| failed("printed a malformed run"))?;
    let meta = member(&value, "meta").map_or_else(Json::object, Json::from_value);
    Ok(Suite { meta, runs })
}

/// Returns the metadata: the machine, the suite's sizes, the toolchain, and the daemon
/// binary with its idle resident memory.
fn primitives_meta(options: &Options, suite: &Suite) -> Result<Json> {
    let mut meta = meta::machine(&paths::workspace_root(), &options.cpu);
    if let Json::Object(members) = &suite.meta {
        for (key, value) in members {
            meta.set(key, value.clone());
        }
    }
    meta.set("pinned_cpu", options.cpu.to_list());
    meta.set("rounds", options.rounds);
    meta.set(
        "timing",
        "7 batches, untimed reset and warmup; no per-operation clock reads; per row the \
         fastest of `rounds` suite runs",
    );
    let (rust_daemon, idle_rss_kb) = daemon_footprint(&options.rust_daemon)?;
    // The book's Part VIII reads these two names, as `run.py` wrote them.
    meta.set("binary_bytes", std::fs::metadata(&options.rust_daemon).ok().map(|m| m.len()));
    meta.set("idle_rss_kb", idle_rss_kb);
    meta.set("rust_daemon", rust_daemon);
    meta.set(
        "wasm_bytes",
        paths::wasm_solver().and_then(|p| std::fs::metadata(p).ok()).map(|m| m.len()),
    );
    Ok(meta)
}

/// Returns the binary's size and hash, and its resident memory one second after start with
/// two workers in reverse-proxy Shield mode (as `run.py` measured `idle_rss_kb`).
fn daemon_footprint(binary: &Path) -> Result<(Json, Option<u64>)> {
    let mut json = meta::binary(binary);
    if !binary.exists() {
        return Ok((json, None));
    }
    let temp = TempDir::new("idle")?;
    let config =
        Config { surface: Surface::Shield, mode: Mode::ReverseProxy, workers: 2, origin_port: 9 };
    let daemon = Daemon::start("idle-daemon", binary, None, &config, temp.path())?;
    std::thread::sleep(Duration::from_secs(1));
    let idle = process::status_kib(daemon.pid(), "VmRSS")?;
    json.set("idle_rss_kb", idle);
    Ok((json, Some(idle)))
}

fn find<'r>(runs: &'r [Run], row: &Run) -> Option<&'r Run> {
    runs.iter().find(|r| {
        r.implementation == row.implementation
            && r.subsystem == row.subsystem
            && r.workload == row.workload
    })
}

/// Returns one row per workload: the median per operation and the min-max across batches.
fn results_table(runs: &[Run]) -> Table {
    let mut table = Table::new(&["Impl", "Subsystem", "Workload", "ns/op", "min-max"]);
    for row in runs {
        table.row(vec![
            row.implementation.clone(),
            row.subsystem.clone(),
            row.workload.clone(),
            fmt_ns(row.timing.median),
            format!("{}-{}", fmt_ns(row.timing.min), fmt_ns(row.timing.max)),
        ]);
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measure_resets_the_context_before_every_batch() {
        let mut resets = 0;
        let timing = measure(
            100,
            || {
                resets += 1;
                std::cell::Cell::new(0u64)
            },
            |count, n| {
                count.set(count.get() + n);
                count.get()
            },
        );
        assert_eq!(resets, 1 + BATCHES);
        assert_eq!(timing.iterations, 100);
        assert!(timing.min <= timing.median && timing.median <= timing.max);
    }

    #[test]
    fn rows_round_trip_through_json() {
        let timing = Timing { iterations: 10, median: 2.5, min: 2.0, max: 3.0 };
        let mut row = Run::new("http_parser", "x", timing);
        row.bytes_per_op = 8;
        let text = row.to_json().to_pretty();
        let value = sibuna_json::parse(text.as_bytes()).unwrap();
        assert_eq!(Run::from_json(&value), Some(row.clone()));
        assert_eq!(row.ops_per_sec(), 400_000_000);
        let table = results_table(&[row]).markdown();
        assert!(table.contains("http_parser"), "{table}");
    }

    #[test]
    fn keeps_the_fastest_round_of_each_row() {
        let timing = |median| Timing { iterations: 1, median, min: median, max: median };
        let suite = |a, b| Suite {
            meta: Json::object(),
            runs: vec![Run::new("s", "a", timing(a)), Run::new("s", "b", timing(b))],
        };
        let best = keep_fastest(Some(suite(5.0, 1.0)), suite(2.0, 3.0));
        let medians: Vec<f64> = best.runs.iter().map(|r| r.timing.median).collect();
        assert_eq!(medians, [2.0, 1.0]);
    }
}
