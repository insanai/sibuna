//! The open-loop generator (`sibuna-bench generate`): one blocking thread per connection,
//! each sending on a fixed schedule and timing every answer.

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use sibuna_json::Value;

use crate::args::Args;
use crate::error::{Error, Result};
use crate::http;
use crate::json::{Json, member, member_f64, member_u64};
use crate::stats::percentile;
/// The most latency samples one generator run may hold (8 bytes each).
const MAX_SAMPLES: f64 = 50e6;

/// The options of one generator run.
#[derive(Clone, Debug)]
pub struct Schedule {
    /// The daemon's port on 127.0.0.1.
    pub port: u16,
    /// The request target.
    pub path: String,
    /// Extra request headers.
    pub headers: Vec<(String, String)>,
    /// Requests per second over all connections.
    pub rate: f64,
    /// Seconds measured, after the warm-up.
    pub seconds: f64,
    /// Seconds of load before measuring starts.
    pub warmup: f64,
    /// Connections, one thread each.
    pub connections: usize,
}

/// What one connection observed.
#[derive(Debug, Default)]
struct Observed {
    /// Latencies of measured requests, in nanoseconds.
    latencies: Vec<u64>,
    /// Answers received, warm-up included.
    responses: u64,
    /// Connection, I/O and framing errors.
    errors: u64,
    /// Answers whose status was not the expected one.
    bad_status: u64,
    /// When the last measured answer arrived.
    last_done: Option<Instant>,
}

/// One rate's result.
#[derive(Clone, Debug, PartialEq)]
pub struct RateResult {
    /// The offered load, requests per second.
    pub target_rps: f64,
    /// Measured answers per second: their count over the time from the start of measurement
    /// to the last of them. Below the offered rate when the daemon could not keep up.
    pub achieved_rps: f64,
    /// Answers received during measurement.
    pub requests: u64,
    /// Answers received, warm-up included.
    pub responses: u64,
    /// Connection and I/O errors.
    pub errors: u64,
    /// Answers with an unexpected status.
    pub bad_status: u64,
    /// Percentiles in microseconds: p50, p90, p99, p99.9, max, mean.
    pub latency_us: [f64; 6],
}

/// The names of [`RateResult::latency_us`] in result files, in order.
pub const LATENCY_KEYS: [&str; 6] = ["p50", "p90", "p99", "p999", "max", "mean"];

impl RateResult {
    /// Returns the result as JSON, as `generate` prints it.
    pub fn to_json(&self) -> Json {
        let mut latency = Json::object();
        for (key, value) in LATENCY_KEYS.iter().zip(self.latency_us) {
            latency.set(key, (value * 10.0).round() / 10.0);
        }
        Json::object()
            .with("target_rps", self.target_rps)
            .with("achieved_rps", (self.achieved_rps * 10.0).round() / 10.0)
            .with("requests", self.requests)
            .with("responses", self.responses)
            .with("errors", self.errors)
            .with("bad_status", self.bad_status)
            .with("latency_us", latency)
    }

    /// Reads a result printed by `generate`.
    pub fn from_json(value: &Value<'_>) -> Option<RateResult> {
        let latency = member(value, "latency_us")?;
        let mut latency_us = [0.0; 6];
        for (slot, key) in latency_us.iter_mut().zip(LATENCY_KEYS) {
            *slot = member_f64(latency, key)?;
        }
        Some(RateResult {
            target_rps: member_f64(value, "target_rps")?,
            achieved_rps: member_f64(value, "achieved_rps")?,
            requests: member_u64(value, "requests")?,
            responses: member_u64(value, "responses")?,
            errors: member_u64(value, "errors")?,
            bad_status: member_u64(value, "bad_status")?,
            latency_us,
        })
    }
}

/// Runs the open-loop schedule and returns the merged result.
///
/// # Errors
///
/// Fails when the schedule is empty or would hold more than 50 million samples.
pub fn generate(schedule: &Schedule) -> Result<RateResult> {
    let expected = schedule.rate * schedule.seconds;
    if schedule.connections == 0 || schedule.rate <= 0.0 || expected > MAX_SAMPLES {
        return Err(Error::new(
            "INVALID SCHEDULE",
            "The rate, duration or connection count is out of range.",
        )
        .hint("Use a positive rate and at most 50 million requests per run."));
    }
    let mut request = http::request_head("GET", &schedule.path, schedule.port, &schedule.headers);
    request.push_str("\r\n");
    let start = Instant::now() + Duration::from_millis(200);
    let observed: Vec<Observed> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..schedule.connections)
            .map(|k| {
                let request = request.as_bytes();
                scope.spawn(move || run_connection(schedule, request, start, k))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap_or_default()).collect()
    });
    let mut latencies: Vec<u64> = Vec::with_capacity(expected as usize + 1024);
    let (mut responses, mut errors, mut bad_status) = (0, 0, 0);
    let mut last_done = None;
    for o in observed {
        last_done = last_done.max(o.last_done);
        latencies.extend_from_slice(&o.latencies);
        responses += o.responses;
        errors += o.errors;
        bad_status += o.bad_status;
    }
    latencies.sort_unstable();
    let measure_from = start + Duration::from_secs_f64(schedule.warmup);
    let span =
        last_done.map_or(0.0, |done| done.saturating_duration_since(measure_from).as_secs_f64());
    let us = |ns: u64| ns as f64 / 1000.0;
    let mean = latencies.iter().map(|&n| n as f64).sum::<f64>() / latencies.len().max(1) as f64;
    Ok(RateResult {
        target_rps: schedule.rate,
        achieved_rps: latencies.len() as f64 / span.max(schedule.seconds),
        requests: latencies.len() as u64,
        responses,
        errors,
        bad_status,
        latency_us: [
            us(percentile(&latencies, 50.0)),
            us(percentile(&latencies, 90.0)),
            us(percentile(&latencies, 99.0)),
            us(percentile(&latencies, 99.9)),
            us(latencies.last().copied().unwrap_or(0)),
            mean / 1000.0,
        ],
    })
}

/// Follows connection `k`'s schedule until the end of the run.
fn run_connection(schedule: &Schedule, request: &[u8], start: Instant, k: usize) -> Observed {
    let interval = Duration::from_secs_f64(schedule.connections as f64 / schedule.rate);
    let measure_from = start + Duration::from_secs_f64(schedule.warmup);
    let end = measure_from + Duration::from_secs_f64(schedule.seconds);
    let per_connection = schedule.rate * schedule.seconds / schedule.connections as f64;
    let mut observed = Observed {
        latencies: Vec::with_capacity(per_connection as usize + 64),
        ..Observed::default()
    };
    // Spread the connections' first requests evenly over one interval.
    let mut due = start + interval.mul_f64(k as f64 / schedule.connections as f64);
    let mut previous_done = start;
    let mut stream: Option<TcpStream> = None;
    let mut buffer = Vec::with_capacity(16 * 1024);
    while due < end {
        let now = Instant::now();
        if now < due {
            std::thread::sleep(due - now);
        }
        let sent = Instant::now();
        match exchange(&mut stream, schedule.port, request, &mut buffer) {
            Ok(status) => {
                let done = Instant::now();
                // Late because the previous answer was late: charge the wait to the daemon.
                let origin = if previous_done > due { due } else { sent };
                observed.responses += 1;
                if status != 200 {
                    observed.bad_status += 1;
                }
                if due >= measure_from {
                    observed
                        .latencies
                        .push(done.saturating_duration_since(origin).as_nanos() as u64);
                    observed.last_done = Some(done);
                }
                previous_done = done;
            }
            Err(_) => {
                observed.errors += 1;
                stream = None;
                previous_done = Instant::now();
            }
        }
        due += interval;
    }
    observed
}

/// Sends `request` on the connection (opening it when needed) and reads the answer.
fn exchange(
    stream: &mut Option<TcpStream>,
    port: u16,
    request: &[u8],
    buffer: &mut Vec<u8>,
) -> std::io::Result<u16> {
    if stream.is_none() {
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        let fresh = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
        fresh.set_nodelay(true)?;
        fresh.set_read_timeout(Some(Duration::from_secs(10)))?;
        *stream = Some(fresh);
    }
    let Some(connection) = stream.as_mut() else {
        return Err(std::io::Error::other("no connection"));
    };
    connection.write_all(request)?;
    let (status, close) = http::read_response(connection, buffer)?;
    if close {
        *stream = None;
    }
    Ok(status)
}

/// `sibuna-bench generate`: runs one schedule and prints its result as JSON.
///
/// # Errors
///
/// Fails on bad options or an invalid schedule.
pub fn generate_command(mut args: Args, stdout: &mut dyn Write) -> Result<()> {
    let mut headers = Vec::new();
    for header in args.values("--header")? {
        let (name, value) = header.split_once(':').ok_or_else(|| {
            Error::new("INVALID VALUE", format!("`--header` needs `Name: value`, not `{header}`."))
        })?;
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    let schedule = Schedule {
        port: args.parsed("--port", 0)?,
        path: args.parsed("--path", "/".to_owned())?,
        headers,
        rate: args.parsed("--rate", 1000.0)?,
        seconds: args.parsed("--seconds", 10.0)?,
        warmup: args.parsed("--warmup", 2.0)?,
        connections: args.parsed("--connections", 64)?,
    };
    args.finish(&[
        "--port",
        "--path",
        "--rate",
        "--seconds",
        "--warmup",
        "--connections",
        "--header",
    ])?;
    let result = generate(&schedule)?;
    stdout.write_all(result.to_json().to_pretty().as_bytes()).map_err(|e| Error::io("stdout", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn generator_keeps_the_offered_rate_against_a_fast_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let response: &'static [u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                std::thread::spawn(move || crate::origin::serve_connection(stream, response));
            }
        });
        let schedule = Schedule {
            port,
            path: "/".to_owned(),
            headers: Vec::new(),
            rate: 2000.0,
            seconds: 0.5,
            warmup: 0.1,
            connections: 4,
        };
        let result = generate(&schedule).unwrap();
        assert_eq!(result.errors, 0);
        assert!((900..=1100).contains(&result.requests), "{result:?}");
        assert!(result.latency_us[0] > 0.0 && result.latency_us[0] <= result.latency_us[2]);
        let text = result.to_json().to_pretty();
        let parsed = RateResult::from_json(&sibuna_json::parse(text.as_bytes()).unwrap()).unwrap();
        assert_eq!(parsed.requests, result.requests);
    }

    #[test]
    fn rejects_empty_and_huge_schedules() {
        let schedule = Schedule {
            port: 1,
            path: "/".to_owned(),
            headers: Vec::new(),
            rate: 0.0,
            seconds: 1.0,
            warmup: 0.0,
            connections: 1,
        };
        assert!(generate(&schedule).is_err());
        assert!(generate(&Schedule { rate: 1e9, ..schedule.clone() }).is_err());
        assert!(generate(&Schedule { rate: 10.0, connections: 0, ..schedule }).is_err());
    }
}
