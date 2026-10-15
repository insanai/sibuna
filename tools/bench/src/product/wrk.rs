//! Driving `wrk` and reading its summary.
//!
//! A small Lua `done` hook makes wrk print its totals and latency percentiles as one JSON
//! line (`WRKJSON {...}`), which is easier to read exactly than its human summary.

use std::path::Path;
use std::process::Command;

use sibuna_json::Value;

use crate::error::{Error, Result};
use crate::json::{Json, member, member_f64, member_u64};
use crate::process::CpuSet;

/// The `done` hook, extended from `tools.py` with the 99.9th percentile.
pub const DONE_LUA: &str = r#"
done = function(summary, latency, requests)
  io.write(string.format('WRKJSON {"requests":%d,"duration_us":%d,"bytes":%d,'
    .. '"errors":{"connect":%d,"read":%d,"write":%d,"status":%d,"timeout":%d},'
    .. '"latency_us":{"p50":%d,"p90":%d,"p99":%d,"p999":%d,"max":%d,"mean":%.1f}}\n',
    summary.requests, summary.duration, summary.bytes, summary.errors.connect,
    summary.errors.read, summary.errors.write, summary.errors.status, summary.errors.timeout,
    latency:percentile(50), latency:percentile(90), latency:percentile(99),
    latency:percentile(99.9), latency.max, latency.mean))
end
"#;

/// The closed-loop load of one wrk run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Load {
    /// wrk threads (`-t`).
    pub threads: u32,
    /// Open connections (`-c`).
    pub connections: u32,
    /// Duration in seconds (`-d`).
    pub seconds: u32,
}

impl Default for Load {
    /// The defaults of `tools.py`: two threads, 64 connections, five seconds.
    fn default() -> Load {
        Load { threads: 2, connections: 64, seconds: 5 }
    }
}

/// Latency percentiles in microseconds, as wrk's histogram reports them.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Latency {
    /// Median.
    pub p50: f64,
    /// 90th percentile.
    pub p90: f64,
    /// 99th percentile.
    pub p99: f64,
    /// 99.9th percentile.
    pub p999: f64,
    /// Maximum.
    pub max: f64,
    /// Mean.
    pub mean: f64,
}

impl Latency {
    /// Returns the percentiles as a JSON object.
    pub fn to_json(self) -> Json {
        Json::object()
            .with("p50", self.p50)
            .with("p90", self.p90)
            .with("p99", self.p99)
            .with("p999", self.p999)
            .with("max", self.max)
            .with("mean", self.mean)
    }
}

/// The socket and status errors wrk counted.
pub const ERROR_KINDS: [&str; 5] = ["connect", "read", "write", "status", "timeout"];

/// One wrk run's totals.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Summary {
    /// Completed requests.
    pub requests: u64,
    /// The run's wall time in microseconds.
    pub duration_us: u64,
    /// Bytes read.
    pub bytes: u64,
    /// Error counts in the order of [`ERROR_KINDS`]; `status` counts non-2xx/3xx answers.
    pub errors: [u64; 5],
    /// Latency percentiles.
    pub latency: Latency,
}

/// Returns wrk's version line.
pub fn version() -> String {
    // `wrk -v` prints its banner and exits with status 1.
    Command::new("wrk")
        .arg("-v")
        .output()
        .ok()
        .and_then(|out| {
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.lines().next().map(|l| l.trim().to_owned())
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Runs wrk pinned to `cpus` against `http://127.0.0.1:<port><path>` with `headers`.
///
/// # Errors
///
/// Fails when wrk cannot start, exits with an error (for example when it cannot connect at
/// all) or prints no summary.
pub fn run(
    load: Load,
    cpus: &CpuSet,
    script: &Path,
    port: u16,
    path: &str,
    headers: &[(String, String)],
) -> Result<Summary> {
    let mut command = Command::new("taskset");
    command
        .arg("-c")
        .arg(cpus.to_list())
        .arg("wrk")
        .arg(format!("-t{}", load.threads))
        .arg(format!("-c{}", load.connections))
        .arg(format!("-d{}s", load.seconds))
        .arg("--latency")
        .arg("-s")
        .arg(script);
    for (name, value) in headers {
        command.arg("-H").arg(format!("{name}: {value}"));
    }
    command.arg(format!("http://127.0.0.1:{port}{path}"));
    let output = command.output().map_err(|e| {
        Error::io("running wrk", e).hint("Install wrk (`apt install wrk`) and taskset.")
    })?;
    let text = String::from_utf8_lossy(&output.stdout);
    let failed = || {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail: String = format!("{text}{stderr}").chars().rev().take(300).collect();
        Error::new("WRK FAILED", tail.chars().rev().collect::<String>())
    };
    if !output.status.success() {
        return Err(failed());
    }
    text.lines()
        .find_map(|line| line.strip_prefix("WRKJSON "))
        .and_then(|json| sibuna_json::parse(json.as_bytes()).ok().and_then(|v| parse_summary(&v)))
        .ok_or_else(failed)
}

fn parse_summary(value: &Value<'_>) -> Option<Summary> {
    let errors = member(value, "errors")?;
    let latency = member(value, "latency_us")?;
    let mut counts = [0u64; 5];
    for (count, kind) in counts.iter_mut().zip(ERROR_KINDS) {
        *count = member_u64(errors, kind)?;
    }
    Some(Summary {
        requests: member_u64(value, "requests")?,
        duration_us: member_u64(value, "duration_us")?,
        bytes: member_u64(value, "bytes")?,
        errors: counts,
        latency: Latency {
            p50: member_f64(latency, "p50")?,
            p90: member_f64(latency, "p90")?,
            p99: member_f64(latency, "p99")?,
            p999: member_f64(latency, "p999")?,
            max: member_f64(latency, "max")?,
            mean: member_f64(latency, "mean")?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_done_hook_line() {
        let line = concat!(
            r#"{"requests":1100841,"duration_us":5014000,"bytes":99,"#,
            r#""errors":{"connect":0,"read":1,"write":0,"status":7,"timeout":0},"#,
            r#""latency_us":{"p50":146,"p90":202,"p99":321,"p999":800,"max":5901,"mean":155.8}}"#
        )
        .as_bytes();
        let value = sibuna_json::parse(line).unwrap();
        let summary = parse_summary(&value).unwrap();
        assert_eq!(summary.requests, 1_100_841);
        assert_eq!(summary.errors, [0, 1, 0, 7, 0]);
        assert_eq!(summary.latency.p99, 321.0);
        assert_eq!(summary.latency.mean, 155.8);
        let incomplete = sibuna_json::parse(br#"{"requests":1}"#).unwrap();
        assert_eq!(parse_summary(&incomplete), None);
    }
}
