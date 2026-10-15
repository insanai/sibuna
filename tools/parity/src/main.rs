//! `sibuna-parity`: proves at scale that the Rust daemon makes the same decisions and
//! writes the same responses as the Zig daemon (SID 0010, acceptance criterion 2).
//!
//! The tool starts a stub origin ([`origin`]), then for each configuration ([`configs`]:
//! reverse proxy and forward authorization, gate and shield, with and without the sample
//! policy, with and without trusted forwarded headers) starts both daemons with identical
//! flags and the same master seed. It generates a deterministic corpus ([`corpus`]) of
//! scenarios from a seed, plays each against both daemons over raw TCP ([`client`]), and
//! compares the status lines, header sets, bodies and the origin's echo of what it
//! received, after masking the values that are random by design ([`compare`]).
//! Differences that the allow-list ([`allow`]) explains are counted; any other fails the
//! run. The report directory ([`report`]) holds the summary and every mismatch with its
//! requests and both answers.
//!
//! Run it as `cargo xtask parity [options]`; `--help` lists the options.

mod allow;
mod client;
mod compare;
mod configs;
mod corpus;
mod daemon;
mod fragments;
mod options;
mod origin;
mod report;
mod response;
mod rng;
mod runner;
mod socket;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use options::Options;
use runner::{Binaries, ConfigOutcome};

/// Exit status for usage and setup errors; 1 means unexplained differences.
const EXIT_USAGE: u8 = 2;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let options = match options::parse(&arguments) {
        Ok(Some(options)) => options,
        Ok(None) => return say(options::HELP, ExitCode::SUCCESS),
        Err(message) => {
            let text = format!("parity: {message}\nHint: Run with --help to list the options.\n");
            return complain(&text);
        }
    };
    match run(&options) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => complain(&format!("parity: {error}\n")),
    }
}

fn say(text: &str, code: ExitCode) -> ExitCode {
    let _ = io::stdout().lock().write_all(text.as_bytes());
    code
}

fn complain(text: &str) -> ExitCode {
    let _ = io::stderr().lock().write_all(text.as_bytes());
    ExitCode::from(EXIT_USAGE)
}

/// The workspace root: this crate lives in `tools/parity`.
fn workspace_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.ancestors().nth(2).unwrap_or(manifest).to_path_buf()
}

/// Builds the Rust daemon with `cargo build --release -p sibuna` and returns its path.
fn build_rust() -> io::Result<PathBuf> {
    let root = workspace_root();
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .args(["build", "--release", "-p", "sibuna"])
        .current_dir(&root)
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!("cargo build --release -p sibuna failed: {status}")));
    }
    let target =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    Ok(target.join("release").join("sibuna"))
}

/// Runs the whole comparison. Returns whether every difference was explained.
fn run(options: &Options) -> Result<bool, Box<dyn std::error::Error>> {
    let allow_text = std::fs::read(&options.allow).map_err(|error| {
        format!("cannot read the allow-list {}: {error}", options.allow.display())
    })?;
    let allow = allow::parse(&allow_text)?;
    let rust = match &options.rust {
        Some(path) => path.clone(),
        None => build_rust()?,
    };
    let binaries = Binaries { zig: options.zig.clone(), rust };
    // The corpus is always generated over every configuration, so a scenario id names the
    // same scenario whatever the filters.
    let configs = configs::all();
    let cases = corpus::generate(options.seed, options.requests, &configs);
    let selected: Vec<&corpus::Case> = cases
        .iter()
        .filter(|case| options.cases.is_empty() || options.cases.contains(&case.id))
        .filter(|case| {
            let name = &configs[case.config].name;
            options.configs.iter().all(|pattern| allow::glob(pattern, name))
        })
        .collect();
    let origin = origin::start()?;
    let mut status = io::stderr().lock();
    let _ = writeln!(
        status,
        "parity: {} scenarios ({} requests) over {} configurations; origin on {origin}",
        selected.len(),
        selected.iter().map(|case| case.request_count()).sum::<usize>(),
        configs.len()
    );
    drop(status);
    let settings = runner::Settings {
        binaries: &binaries,
        origin,
        workers: options.workers,
        allow: &allow,
        keep_all: options.keep_all,
    };
    let results = run_configs(options, &configs, &selected, &settings)?;
    let info = report::RunInfo {
        seed: options.seed,
        requests: options.requests,
        zig: binaries.zig.display().to_string(),
        rust: binaries.rust.display().to_string(),
        rerun: format!(
            "cargo xtask parity --seed {} --requests {} --case {{case}} --rust {}",
            options.seed,
            options.requests,
            binaries.rust.display()
        ),
    };
    let summary = report::write(&options.report, &info, &results)?;
    let _ = io::stdout().lock().write_all(summary.as_bytes());
    let _ = writeln!(io::stderr().lock(), "parity: report in {}", options.report.display());
    let failed = results.iter().any(|result| {
        !result.failures.is_empty() || result.outcomes.iter().any(runner::Outcome::is_unexplained)
    });
    Ok(!failed)
}

/// Runs the configurations, `options.jobs` at a time.
fn run_configs(
    options: &Options,
    configs: &[configs::Config],
    cases: &[&corpus::Case],
    settings: &runner::Settings<'_>,
) -> io::Result<Vec<ConfigOutcome>> {
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<(usize, io::Result<ConfigOutcome>)>> = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..options.jobs.max(1) {
            scope.spawn(|| {
                loop {
                    // Relaxed: the counter only hands out distinct indices.
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(config) = configs.get(index) else { break };
                    let mine: Vec<&corpus::Case> =
                        cases.iter().copied().filter(|case| case.config == index).collect();
                    if mine.is_empty() {
                        continue;
                    }
                    let dir = options.report.join("daemons").join(&config.name);
                    let outcome = runner::run_config(config, &mine, &dir, settings);
                    if let Ok(done) = &outcome {
                        let count = done.outcomes.len();
                        let _ = writeln!(
                            io::stderr().lock(),
                            "parity: {} done ({count} scenarios)",
                            done.config
                        );
                    }
                    results
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .push((index, outcome));
                }
            });
        }
    });
    let mut results = results.into_inner().unwrap_or_else(|poison| poison.into_inner());
    results.sort_by_key(|(index, _)| *index);
    results.into_iter().map(|(_, outcome)| outcome).collect()
}
