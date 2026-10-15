//! Data-plane traffic for the console checks: plain HTTP/1.1 GETs over `std::net`.
//!
//! Each request opens a connection, sends `Connection: close` and reads the reply to its
//! end, so no response framing has to be parsed and every latency includes the connect.
//! The paths, user agents and `X-Forwarded-For` addresses rotate, so a daemon that trusts
//! forwarded addresses sees many clients, and some requests look like attacks: we want
//! admitted, challenged and denied outcomes alike on the dashboard.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// How long one request may take, connect included.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The most response bytes read per request; the rest is ignored.
const MAX_RESPONSE: usize = 1 << 20;

/// The paths requests rotate through, appended to the target's base path. The `origin`
/// fixture answers `missing/` with 404 and `broken/` with 500.
const PATHS: [&str; 10] = [
    "",
    "index.html",
    "about",
    "search?q=sibuna",
    "static/app.js",
    "?id=1%27%20OR%20%271%27=%271",
    ".env",
    "wp-login.php",
    "missing/old-page",
    "broken/report",
];

/// The user agents requests rotate through.
const AGENTS: [&str; 3] = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0 \
     Safari/537.36",
    "curl/8.5.0",
    "python-requests/2.32.3",
];

/// Where traffic goes: the address to connect to, the `Host` field and the base path.
#[derive(Clone, Debug)]
pub struct Target {
    address: SocketAddr,
    host: String,
    base: String,
}

impl Target {
    /// Parses an `http://host:port/path` URL and resolves its host.
    ///
    /// # Errors
    ///
    /// A message for a URL that is not plain `http://`, or a host that does not resolve.
    pub fn parse(url: &str) -> Result<Target, String> {
        let rest =
            url.strip_prefix("http://").ok_or_else(|| format!("`{url}` is not an http:// URL"))?;
        let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
        if host.is_empty() {
            return Err(format!("`{url}` names no host"));
        }
        let with_port = if host.contains(':') { host.to_owned() } else { format!("{host}:80") };
        let address = with_port
            .to_socket_addrs()
            .ok()
            .and_then(|mut addresses| addresses.next())
            .ok_or_else(|| format!("`{host}` does not resolve"))?;
        let mut base = format!("/{path}");
        if !base.ends_with('/') {
            base.push('/');
        }
        Ok(Target { address, host: host.to_owned(), base })
    }
}

/// What a run of requests saw.
#[derive(Clone, Debug, Default)]
pub struct Tally {
    /// Replies by HTTP status.
    pub statuses: BTreeMap<u16, u64>,
    /// Requests that got no complete status line (refused, reset, timed out).
    pub errors: u64,
    /// The latency of every answered request, in microseconds.
    pub latencies: Vec<u64>,
    /// How long the run took.
    pub elapsed: Duration,
}

impl Tally {
    /// The number of requests sent.
    pub fn sent_count(&self) -> u64 {
        self.statuses.values().sum::<u64>() + self.errors
    }

    /// The number of requests that got an HTTP reply of any status.
    pub fn answered_count(&self) -> u64 {
        self.statuses.values().sum()
    }

    /// Adds `other`'s requests to this tally, keeping the longer elapsed time.
    pub fn merge(&mut self, other: Tally) {
        for (status, count) in other.statuses {
            *self.statuses.entry(status).or_default() += count;
        }
        self.errors += other.errors;
        self.latencies.extend(other.latencies);
        self.elapsed = self.elapsed.max(other.elapsed);
    }

    /// The latency at quantile `q` (0 to 1) in microseconds, or 0 without replies.
    pub fn percentile(&self, q: f64) -> u64 {
        let mut sorted = self.latencies.clone();
        sorted.sort_unstable();
        let Some(last) = sorted.len().checked_sub(1) else { return 0 };
        let rank = ((last as f64) * q.clamp(0.0, 1.0)).round() as usize;
        sorted.get(rank.min(last)).copied().unwrap_or(0)
    }

    /// One line: counts by status, errors, rate and latency percentiles.
    pub fn summary(&self) -> String {
        let statuses: Vec<String> =
            self.statuses.iter().map(|(status, count)| format!("{status}: {count}")).collect();
        let seconds = self.elapsed.as_secs_f64().max(0.001);
        format!(
            "{} sent in {:.1} s ({:.0}/s); answered {} ({}); errors {}; latency p50 {} us, \
             p90 {} us, p99 {} us, max {} us",
            self.sent_count(),
            seconds,
            self.sent_count() as f64 / seconds,
            self.answered_count(),
            statuses.join(", "),
            self.errors,
            self.percentile(0.5),
            self.percentile(0.9),
            self.percentile(0.99),
            self.percentile(1.0)
        )
    }
}

/// Sends `count` requests from `threads` threads as fast as they are answered.
pub fn burst(target: &Target, count: u32, threads: u32) -> Tally {
    let threads = threads.clamp(1, 64);
    let started = Instant::now();
    let mut total = Tally::default();
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|worker| {
                scope.spawn(move || {
                    let mut tally = Tally::default();
                    for index in (worker..count).step_by(threads as usize) {
                        record(&mut tally, target, u64::from(index));
                    }
                    tally
                })
            })
            .collect();
        for worker in workers {
            if let Ok(tally) = worker.join() {
                total.merge(tally);
            }
        }
    });
    total.elapsed = started.elapsed();
    total
}

/// Sends about `rate` requests per second for `duration` from `threads` threads, each on
/// its own fixed schedule; a thread that falls behind sends at once and does not catch up
/// by bursting.
pub fn sustain(target: &Target, duration: Duration, rate: u32, threads: u32) -> Tally {
    let threads = threads.clamp(1, 64);
    let interval = Duration::from_secs_f64(f64::from(threads) / f64::from(rate.max(1)));
    let started = Instant::now();
    let end = started + duration;
    let mut total = Tally::default();
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|worker| {
                scope.spawn(move || {
                    let mut tally = Tally::default();
                    let mut next =
                        started + interval.mul_f64(f64::from(worker) / f64::from(threads));
                    let mut index = u64::from(worker);
                    while next < end {
                        if let Some(wait) = next.checked_duration_since(Instant::now()) {
                            std::thread::sleep(wait);
                        }
                        record(&mut tally, target, index);
                        index += u64::from(threads);
                        next = (next + interval).max(Instant::now());
                    }
                    tally
                })
            })
            .collect();
        for worker in workers {
            if let Ok(tally) = worker.join() {
                total.merge(tally);
            }
        }
    });
    total.elapsed = started.elapsed();
    total
}

/// Sends request number `index` and counts its outcome.
fn record(tally: &mut Tally, target: &Target, index: u64) {
    let started = Instant::now();
    match request(target, index) {
        Ok(status) => {
            *tally.statuses.entry(status).or_default() += 1;
            let micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
            tally.latencies.push(micros);
        }
        Err(_) => tally.errors += 1,
    }
}

/// The text of request number `index`: its path, agent and forwarded address rotate.
fn request_text(target: &Target, index: u64) -> String {
    // The remainders are below the arrays' lengths, so the indexing is in bounds.
    let path = PATHS[(index % PATHS.len() as u64) as usize];
    let agent = AGENTS[(index / 3 % AGENTS.len() as u64) as usize];
    // 203.0.113.0/24 and 198.51.100.0/24 are documentation networks: no real client.
    let network = if index.is_multiple_of(2) { "203.0.113" } else { "198.51.100" };
    let host = 1 + index / 2 % 250;
    format!(
        "GET {}{path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {agent}\r\nAccept: */*\r\n\
         X-Forwarded-For: {network}.{host}\r\nConnection: close\r\n\r\n",
        target.base, target.host
    )
}

/// Sends one request and returns the reply's status.
fn request(target: &Target, index: u64) -> io::Result<u16> {
    let mut stream = TcpStream::connect_timeout(&target.address, REQUEST_TIMEOUT)?;
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
    stream.write_all(request_text(target, index).as_bytes())?;
    let mut reply = Vec::with_capacity(4096);
    stream.take(MAX_RESPONSE as u64).read_to_end(&mut reply)?;
    status(&reply).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no status line"))
}

/// The status code of an `HTTP/1.x NNN ...` reply.
fn status(reply: &[u8]) -> Option<u16> {
    let line = reply.split(|&byte| byte == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split(' ');
    parts.next().filter(|version| version.starts_with("HTTP/1."))?;
    parts.next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_targets() {
        let target = Target::parse("http://127.0.0.1:8080").unwrap();
        assert_eq!((target.host.as_str(), target.base.as_str()), ("127.0.0.1:8080", "/"));
        assert_eq!(target.address.port(), 8080);
        let target = Target::parse("http://127.0.0.1:9/app").unwrap();
        assert_eq!(target.base, "/app/");
        assert!(Target::parse("https://127.0.0.1/").is_err());
        assert!(Target::parse("http:///x").is_err());
    }

    #[test]
    fn rotates_paths_agents_and_addresses() {
        let target = Target::parse("http://127.0.0.1:1/").unwrap();
        let first = request_text(&target, 0);
        assert!(first.starts_with("GET / HTTP/1.1\r\nHost: 127.0.0.1:1\r\n"), "{first}");
        assert!(first.contains("X-Forwarded-For: 203.0.113.1\r\n"));
        let second = request_text(&target, 7);
        assert!(second.starts_with("GET /wp-login.php HTTP/1.1"));
        assert!(request_text(&target, 19).starts_with("GET /broken/report HTTP/1.1"));
        assert!(second.contains("User-Agent: python-requests"));
        assert!(second.contains("X-Forwarded-For: 198.51.100.4\r\n"));
    }

    #[test]
    fn reads_status_lines_and_percentiles() {
        assert_eq!(status(b"HTTP/1.1 403 Forbidden\r\n\r\n"), Some(403));
        assert_eq!(status(b"HTTP/1.0 200 OK\n"), Some(200));
        assert_eq!(status(b"SSH-2.0\r\n"), None);
        assert_eq!(status(b""), None);
        let tally = Tally {
            latencies: (1..=100).collect(),
            statuses: BTreeMap::from([(200, 90), (403, 10)]),
            errors: 2,
            elapsed: Duration::from_secs(1),
        };
        assert_eq!((tally.percentile(0.5), tally.percentile(0.99)), (51, 99));
        assert_eq!((tally.percentile(1.0), Tally::default().percentile(0.5)), (100, 0));
        assert_eq!((tally.sent_count(), tally.answered_count()), (102, 100));
        assert!(tally.summary().contains("200: 90, 403: 10"));
    }

    #[test]
    fn counts_refused_connections_as_errors() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let target = Target::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let tally = burst(&target, 3, 2);
        assert_eq!((tally.errors, tally.answered_count()), (3, 0));
    }
}
