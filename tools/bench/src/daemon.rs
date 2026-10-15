//! Starting a Sibuna daemon (Rust or Zig, the same flags for both) and obtaining a session
//! the way a browser does: fetch a challenge, solve it with `sibuna-pow`, submit the proof.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sibuna_json::Value;
use sibuna_pow::hashcash;

use crate::error::{Error, Result};
use crate::http;
use crate::json::{member_str, member_u64};
use crate::process::{self, CpuSet, Process};

/// The browser headers of every benchmark request, as `compare.py` sent them.
pub const BROWSER_HEADERS: [(&str, &str); 5] = [
    ("User-Agent", "Mozilla/5.0 SibunaBenchmark"),
    ("Accept", "text/html"),
    ("Accept-Encoding", "gzip"),
    ("X-Real-IP", "203.0.113.30"),
    ("X-Forwarded-For", "203.0.113.30"),
];

/// Returns [`BROWSER_HEADERS`] as owned pairs.
pub fn browser_headers() -> Vec<(String, String)> {
    BROWSER_HEADERS.iter().map(|&(n, v)| (n.to_owned(), v.to_owned())).collect()
}

/// Which daemon build runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Implementation {
    /// The Rust port, `cmd/sibuna`.
    Rust,
    /// The Zig original.
    Zig,
}

impl Implementation {
    /// Returns `rust` or `zig`.
    pub fn name(self) -> &'static str {
        match self {
            Implementation::Rust => "rust",
            Implementation::Zig => "zig",
        }
    }
}

/// The product surface: challenge only, or challenge and semantic WAF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Surface {
    /// `--gate`: bot challenge only.
    Gate,
    /// `--shield`: bot challenge and semantic WAF.
    Shield,
}

impl Surface {
    /// Returns the product name used in result files (`sibuna-gate`, `sibuna-shield`).
    pub fn product(self) -> &'static str {
        match self {
            Surface::Gate => "sibuna-gate",
            Surface::Shield => "sibuna-shield",
        }
    }

    /// Parses `gate` or `shield`.
    pub fn parse(text: &str) -> Option<Surface> {
        match text {
            "gate" => Some(Surface::Gate),
            "shield" => Some(Surface::Shield),
            _ => None,
        }
    }
}

/// How the daemon is deployed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The ingress asks the daemon whether to admit; there is no origin.
    ForwardAuth,
    /// The daemon proxies admitted requests to the origin.
    ReverseProxy,
}

impl Mode {
    /// Returns `forward_auth` or `reverse_proxy`, the daemon's own spelling.
    pub fn name(self) -> &'static str {
        match self {
            Mode::ForwardAuth => "forward_auth",
            Mode::ReverseProxy => "reverse_proxy",
        }
    }

    /// Parses `forward_auth` or `reverse_proxy`.
    pub fn parse(text: &str) -> Option<Mode> {
        match text {
            "forward_auth" => Some(Mode::ForwardAuth),
            "reverse_proxy" => Some(Mode::ReverseProxy),
            _ => None,
        }
    }
}

/// The flags a daemon starts with; both implementations receive the same ones.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Gate or Shield.
    pub surface: Surface,
    /// Forward auth or reverse proxy.
    pub mode: Mode,
    /// Accept threads (`--workers`), the size of the CPU set by default.
    pub workers: usize,
    /// The origin port for reverse-proxy mode.
    pub origin_port: u16,
}

impl Config {
    /// Returns the command line of `tools.py`: in memory, Hashcash at 8 bits, a rate limit
    /// high enough never to engage, and a five-second idle timeout.
    pub fn args(&self, port: u16) -> Vec<String> {
        let surface = match self.surface {
            Surface::Gate => "--gate",
            Surface::Shield => "--shield",
        };
        let mut args: Vec<String> = [
            surface,
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--workers",
            &self.workers.to_string(),
            "--algorithm",
            "hashcash",
            "--difficulty",
            "8",
            "--rate-limit",
            "100000000",
            "--idle-timeout",
            "5",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        match self.mode {
            Mode::ForwardAuth => args.extend(["--mode".into(), "forward_auth".into()]),
            Mode::ReverseProxy => args.extend([
                "--upstream-host".into(),
                "127.0.0.1".into(),
                "--upstream-port".into(),
                self.origin_port.to_string(),
            ]),
        }
        args
    }
}

/// A running daemon, stopped when dropped.
#[derive(Debug)]
pub struct Daemon {
    /// The process.
    pub process: Process,
    /// The port it listens on.
    pub port: u16,
    /// Its log file.
    pub log: PathBuf,
}

impl Daemon {
    /// Starts `binary` with `config`, pinned to `cpus`, logging into `log_dir`, and waits
    /// until `/__sibuna/health` answers 200.
    ///
    /// # Errors
    ///
    /// Fails when the daemon cannot start, exits, or is not healthy within 30 seconds; the
    /// message carries the end of its log.
    pub fn start(
        label: &str,
        binary: &Path,
        cpus: Option<&CpuSet>,
        config: &Config,
        log_dir: &Path,
    ) -> Result<Daemon> {
        let port = process::free_port()?;
        let log = log_dir.join(format!("{label}.log"));
        let process = Process::spawn(label, binary, &config.args(port), cpus, Some(&log))?;
        let mut daemon = Daemon { process, port, log };
        daemon.wait_healthy()?;
        Ok(daemon)
    }

    /// Returns the daemon's process id.
    pub fn pid(&self) -> u32 {
        self.process.pid()
    }

    fn wait_healthy(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if !self.process.is_running() {
                return Err(self.failure("exited during startup"));
            }
            if http::request(self.port, "GET", "/__sibuna/health", &[], b"")
                .is_ok_and(|r| r.status == 200)
            {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(self.failure("did not answer /__sibuna/health within 30 seconds"))
    }

    fn failure(&self, what: &str) -> Error {
        let name = self.process.name();
        Error::new(
            "DAEMON FAILED",
            format!("{name} {what}. Its log ends:\n{}", process::tail(&self.log, 2000)),
        )
        .hint("Run the daemon by hand with the same flags to see the problem.")
    }

    /// Obtains a session cookie (`name=value`) by solving a Hashcash challenge for
    /// `/private`, as a browser would.
    ///
    /// # Errors
    ///
    /// Fails when the challenge or the verification is refused or malformed.
    pub fn session_cookie(&self) -> Result<String> {
        let headers = browser_headers();
        let issued = http::request(
            self.port,
            "GET",
            "/__sibuna/challenge.json?path=/private",
            &headers,
            b"",
        )?;
        let bad = |what: &str| {
            Error::new("SESSION FAILED", format!("{}: {what}.", self.process.name()))
                .hint("Check that the daemon runs with `--algorithm hashcash`.")
        };
        if issued.status != 200 {
            return Err(bad(&format!("challenge.json answered {}", issued.status)));
        }
        let value: Value<'_> =
            sibuna_json::parse(&issued.body).map_err(|_| bad("challenge.json is not JSON"))?;
        let id = member_str(&value, "id").ok_or_else(|| bad("the challenge has no id"))?;
        let bits = member_u64(&value, "difficulty").ok_or_else(|| bad("no difficulty"))?;
        let bits = u32::try_from(bits).map_err(|_| bad("the difficulty is out of range"))?;
        let nonce = hashcash::solve_bits(id.as_bytes(), bits, 1 << 40)
            .ok_or_else(|| bad("no nonce solves the challenge"))?;
        let body = format!("{{\"challenge_id\":\"{id}\",\"nonce\":\"{nonce}\"}}");
        let mut post_headers = headers;
        post_headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
        let verified =
            http::request(self.port, "POST", "/__sibuna/verify", &post_headers, body.as_bytes())?;
        if verified.status != 200 {
            return Err(bad(&format!("verify answered {}", verified.status)));
        }
        let cookies: Vec<&str> = verified
            .header_values("set-cookie")
            .filter_map(|v| v.split(';').next())
            .map(str::trim)
            .filter(|pair| {
                pair.split_once('=').is_some_and(|(n, v)| !n.is_empty() && !v.is_empty())
            })
            .collect();
        if cookies.is_empty() {
            return Err(bad("verify set no cookie"));
        }
        Ok(cookies.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_modes_have_the_tools_py_flags() {
        let config =
            Config { surface: Surface::Gate, mode: Mode::ForwardAuth, workers: 4, origin_port: 9 };
        let args = config.args(8080).join(" ");
        assert_eq!(
            args,
            "--gate --host 127.0.0.1 --port 8080 --workers 4 --algorithm hashcash --difficulty 8 \
             --rate-limit 100000000 --idle-timeout 5 --mode forward_auth"
        );
        let config = Config { surface: Surface::Shield, mode: Mode::ReverseProxy, ..config };
        let args = config.args(8080).join(" ");
        assert!(args.starts_with("--shield "));
        assert!(args.ends_with("--upstream-host 127.0.0.1 --upstream-port 9"));
    }

    #[test]
    fn names_parse_back() {
        for mode in [Mode::ForwardAuth, Mode::ReverseProxy] {
            assert_eq!(Mode::parse(mode.name()), Some(mode));
        }
        assert_eq!(Surface::parse("gate"), Some(Surface::Gate));
        assert_eq!(Surface::parse("edge"), None);
    }
}
