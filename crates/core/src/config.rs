//! Daemon options, their defaults, the help text and the startup banner.
//!
//! [`Config`] is plain data with public fields; [`Config::default`] holds every default of
//! the Zig daemon, and [`Config::parse_args`] fills it from a command line (see `args.rs`).

use std::fmt;

use crate::incident_heads::Extra;

mod args;

pub use args::{ArgError, ArgErrorKind};

/// Where the daemon sits in front of the origin.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Sibuna relays admitted requests to the origin itself.
    #[default]
    ReverseProxy,
    /// An ingress asks Sibuna for a verdict and relays the request itself.
    ForwardAuth,
}

impl Mode {
    /// Parses `proxy` or `reverse_proxy`, and `forward_auth` or `auth`, case-sensitively.
    /// Returns `None` for any other text.
    pub fn parse(text: &str) -> Option<Mode> {
        match text {
            "proxy" | "reverse_proxy" => Some(Mode::ReverseProxy),
            "forward_auth" | "auth" => Some(Mode::ForwardAuth),
            _ => None,
        }
    }

    /// Returns the canonical name, `reverse_proxy` or `forward_auth`.
    pub fn name(self) -> &'static str {
        match self {
            Mode::ReverseProxy => "reverse_proxy",
            Mode::ForwardAuth => "forward_auth",
        }
    }
}

/// The proof-of-work algorithm a challenge asks for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum PowAlgorithm {
    /// SHA-256 hashcash with leading zero bits.
    Hashcash,
    /// The Cohen-Pietrzak proof of sequential work.
    #[default]
    Posw,
}

impl PowAlgorithm {
    /// Parses `hashcash` or `sha256`, and `posw`, ignoring ASCII case. Returns `None` for
    /// any other text.
    pub fn parse(text: &str) -> Option<PowAlgorithm> {
        if text.eq_ignore_ascii_case("hashcash") || text.eq_ignore_ascii_case("sha256") {
            Some(PowAlgorithm::Hashcash)
        } else if text.eq_ignore_ascii_case("posw") {
            Some(PowAlgorithm::Posw)
        } else {
            None
        }
    }

    /// Returns the canonical name, `hashcash` or `posw`.
    pub fn name(self) -> &'static str {
        match self {
            PowAlgorithm::Hashcash => "hashcash",
            PowAlgorithm::Posw => "posw",
        }
    }
}

/// How session tokens are authenticated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum TokenScheme {
    /// A keyed BLAKE3 MAC.
    #[default]
    Mac,
    /// An Ed25519 signature.
    Ed25519,
}

impl TokenScheme {
    /// Parses `mac` or `ed25519`, ignoring ASCII case. Returns `None` for any other text.
    pub fn parse(text: &str) -> Option<TokenScheme> {
        if text.eq_ignore_ascii_case("mac") {
            Some(TokenScheme::Mac)
        } else if text.eq_ignore_ascii_case("ed25519") {
            Some(TokenScheme::Ed25519)
        } else {
            None
        }
    }

    /// Returns the canonical name, `mac` or `ed25519`.
    pub fn name(self) -> &'static str {
        match self {
            TokenScheme::Mac => "mac",
            TokenScheme::Ed25519 => "ed25519",
        }
    }
}

/// Where persistent state lives (SID 0011).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StorageBackend {
    /// Nothing persists; policies come from `--policy-file`.
    InMemory,
    /// One node: the SQLite file `<data-dir>/sibuna.db`.
    Sqlite,
    /// A cluster: one PostgreSQL database shared by every node.
    Postgres,
}

/// The daemon's configuration. Every field has the Zig daemon's default.
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    /// The address the daemon listens on.
    pub listen_host: String,
    /// The port the daemon listens on.
    pub listen_port: u16,
    /// The origin's host.
    pub upstream_host: String,
    /// The origin's port.
    pub upstream_port: u16,
    /// Reverse proxy or forward auth.
    pub mode: Mode,
    /// Work bits: hashcash leading zero bits, or PoSW depth plus three.
    pub default_difficulty: u32,
    /// The proof-of-work algorithm.
    pub algorithm: PowAlgorithm,
    /// PoSW openings per proof.
    pub posw_challenges: u8,
    /// How session tokens are authenticated.
    pub token_scheme: TokenScheme,
    /// The session token lifetime in seconds.
    pub token_ttl_seconds: u64,
    /// The challenge lifetime in seconds.
    pub challenge_ttl_seconds: u64,
    /// The session cookie name.
    pub cookie_name: String,
    /// Whether the session cookie carries the `Secure` attribute.
    pub secure_cookie: bool,
    /// The master seed; `None` means "derive it from `secret_file`, the environment, or a
    /// fresh random value at startup".
    pub secret_seed: Option<[u8; 32]>,
    /// The file holding the master seed.
    pub secret_file: Option<String>,
    /// The declarative JSON policy file.
    pub policy_file: Option<String>,
    /// Whether `X-Forwarded-For` and `X-Real-IP` from the peer are trusted; `None` means
    /// "only in forward-auth mode", where the ingress is the only peer.
    pub trust_forwarded: Option<bool>,
    /// Accept threads; zero means one per CPU. Each accepted connection is then served on
    /// its own thread up to `max_connections`.
    pub workers: u16,
    /// Connections served concurrently; further ones are answered 503.
    pub max_connections: u32,
    /// The longest silence a connection may hold a worker: a request head must arrive
    /// within it, and during an exchange it bounds the gap between successive relayed
    /// chunks on either socket, so a silent origin is cut while a slow active response is
    /// not.
    pub idle_timeout_seconds: u32,
    /// An admitted WebSocket's idle deadline, refreshed by traffic either way.
    pub websocket_idle_timeout_seconds: u32,
    /// Requests per rate window per client.
    pub rate_limit: u32,
    /// The rate window in seconds.
    pub rate_window_seconds: u64,
    /// Challenge issuances and solution verifications a client may spend per rate window.
    /// These routes bypass policy, so they carry their own budget: issuing is cheap but
    /// verifying a proof is not, and neither may be free to a client the limiter has
    /// already refused elsewhere.
    pub challenge_rate_limit: u32,
    /// The honeypot ban duration in seconds.
    pub ban_seconds: u64,
    /// Whether the semantic WAF runs (shield) or only the challenge (gate).
    pub waf: bool,
    /// Database steps one console period aggregate may spend before it fails as
    /// unavailable; paged reads keep a fixed light budget. Set by the console options.
    pub console_query_steps: u64,
    /// Whether redacted request heads (and, for audited admitted requests, the origin
    /// response head) are stored beside each incident. Off by default; console builds only.
    pub console_capture_heads: bool,
    /// Header names whose values the stored heads keep beside the built-in list.
    pub console_capture_headers: Extra,
    /// The single-node data directory holding `sibuna.db`; `None` without it.
    pub data_dir: Option<String>,
    /// The PostgreSQL connection string of a cluster. It is a secret: `Debug` and the banner
    /// never show it.
    pub database_url: Option<String>,
    /// An owner-only file holding the PostgreSQL connection string.
    pub database_url_file: Option<String>,
    /// This node's id, bound into challenge keys and the top bits of incident identifiers;
    /// required with a database URL. See [`Config::node_id`].
    pub cluster_node: Option<u32>,
    /// The storage tick interval in milliseconds: incident drain and policy change polling.
    pub storage_poll_ms: u64,
    /// Verbose logging.
    pub verbose: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            listen_host: "0.0.0.0".to_owned(),
            listen_port: 8080,
            upstream_host: "127.0.0.1".to_owned(),
            upstream_port: 3000,
            mode: Mode::ReverseProxy,
            default_difficulty: 16,
            algorithm: PowAlgorithm::Posw,
            posw_challenges: 16,
            token_scheme: TokenScheme::Mac,
            token_ttl_seconds: 86_400,
            challenge_ttl_seconds: 300,
            cookie_name: "__sibuna_token".to_owned(),
            secure_cookie: false,
            secret_seed: None,
            secret_file: None,
            policy_file: None,
            trust_forwarded: None,
            workers: 0,
            max_connections: 1024,
            idle_timeout_seconds: 15,
            websocket_idle_timeout_seconds: 300,
            rate_limit: 100,
            rate_window_seconds: 10,
            challenge_rate_limit: 30,
            ban_seconds: 3600,
            waf: true,
            console_query_steps: 4_000_000,
            console_capture_heads: false,
            console_capture_headers: Extra::default(),
            data_dir: None,
            database_url: None,
            database_url_file: None,
            cluster_node: None,
            storage_poll_ms: 500,
            verbose: false,
        }
    }
}

impl Config {
    /// Connections, idle leases and task slots share one 8192-entry capacity.
    pub const MAX_CONNECTIONS_LIMIT: u32 = 8192;

    /// Returns whether forwarded client addresses are trusted: the explicit choice, or
    /// else true exactly in forward-auth mode.
    pub fn trusts_forwarded(&self) -> bool {
        self.trust_forwarded.unwrap_or(self.mode == Mode::ForwardAuth)
    }

    /// Returns this node's id, zero when `--cluster-node` was not given.
    pub fn node_id(&self) -> u32 {
        self.cluster_node.unwrap_or(0)
    }

    /// Returns where persistent state lives: PostgreSQL when a database URL or URL file is
    /// set, SQLite when a data directory is set, and memory otherwise.
    pub fn storage_backend(&self) -> StorageBackend {
        if self.database_url.is_some() || self.database_url_file.is_some() {
            StorageBackend::Postgres
        } else if self.data_dir.is_some() {
            StorageBackend::Sqlite
        } else {
            StorageBackend::InMemory
        }
    }

    /// Writes the startup banner for daemon `version` into `out`. It never shows the
    /// master seed or a database URL. Fails only when `out` fails.
    pub fn write_banner(&self, out: &mut impl fmt::Write, version: &str) -> fmt::Result {
        const RULE: &str =
            "--------------------------------------------------------------------------------";
        let surface = if self.waf {
            "shield (challenge + semantic WAF + limits)"
        } else {
            "gate (challenge only)"
        };
        let storage = match self.storage_backend() {
            StorageBackend::InMemory => "in-memory only",
            StorageBackend::Sqlite => "sqlite (policies, reputation, forensics)",
            StorageBackend::Postgres => "postgresql cluster (policies, reputation, forensics)",
        };
        let secret = match self.secret_file {
            Some(_) => "loaded from file",
            None => "random (set --secret-file)",
        };
        writeln!(out, "{RULE}")?;
        writeln!(out, "  SIBUNA Web AI Firewall & Anti-Crawler Daemon v{version}")?;
        writeln!(out, "  \"Weighing incoming connections with silicon speed\"")?;
        writeln!(out, "{RULE}")?;
        writeln!(out, "Mode:        {}", self.mode.name())?;
        writeln!(out, "Listening:   {}:{}", self.listen_host, self.listen_port)?;
        writeln!(out, "Upstream:    {}:{}", self.upstream_host, self.upstream_port)?;
        writeln!(
            out,
            "Proof:       {} at {} work bits ({} tokens)",
            self.algorithm.name(),
            self.default_difficulty,
            self.token_scheme.name()
        )?;
        writeln!(out, "Surface:     {surface}")?;
        writeln!(out, "Storage:     {storage}")?;
        writeln!(out, "Secret:      {secret}")?;
        writeln!(out, "{RULE}")
    }
}

impl fmt::Debug for Config {
    /// Lists every field, with the master seed and the database URL shown as `[redacted]`.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redact = |present: bool| present.then_some(crate::incident_heads::REDACTED);
        out.debug_struct("Config")
            .field("listen_host", &self.listen_host)
            .field("listen_port", &self.listen_port)
            .field("upstream_host", &self.upstream_host)
            .field("upstream_port", &self.upstream_port)
            .field("mode", &self.mode)
            .field("default_difficulty", &self.default_difficulty)
            .field("algorithm", &self.algorithm)
            .field("posw_challenges", &self.posw_challenges)
            .field("token_scheme", &self.token_scheme)
            .field("token_ttl_seconds", &self.token_ttl_seconds)
            .field("challenge_ttl_seconds", &self.challenge_ttl_seconds)
            .field("cookie_name", &self.cookie_name)
            .field("secure_cookie", &self.secure_cookie)
            .field("secret_seed", &redact(self.secret_seed.is_some()))
            .field("secret_file", &self.secret_file)
            .field("policy_file", &self.policy_file)
            .field("trust_forwarded", &self.trust_forwarded)
            .field("workers", &self.workers)
            .field("max_connections", &self.max_connections)
            .field("idle_timeout_seconds", &self.idle_timeout_seconds)
            .field("websocket_idle_timeout_seconds", &self.websocket_idle_timeout_seconds)
            .field("rate_limit", &self.rate_limit)
            .field("rate_window_seconds", &self.rate_window_seconds)
            .field("challenge_rate_limit", &self.challenge_rate_limit)
            .field("ban_seconds", &self.ban_seconds)
            .field("waf", &self.waf)
            .field("console_query_steps", &self.console_query_steps)
            .field("console_capture_heads", &self.console_capture_heads)
            .field("console_capture_headers", &self.console_capture_headers)
            .field("data_dir", &self.data_dir)
            .field("database_url", &redact(self.database_url.is_some()))
            .field("database_url_file", &self.database_url_file)
            .field("cluster_node", &self.cluster_node)
            .field("storage_poll_ms", &self.storage_poll_ms)
            .field("verbose", &self.verbose)
            .finish()
    }
}

/// The data-plane part of `sibuna --help`. The daemon prints the console's help before it
/// when the console is compiled in.
pub const HELP: &str = "\
Usage: sibuna [options]

Network:
  --port, -p <port>            Listening port (default: 8080)
  --host, -h <host>            Listening host (default: 0.0.0.0)
  --upstream-host <host>       Upstream origin host (default: 127.0.0.1)
  --upstream-port, -u <port>   Upstream origin port (default: 3000)
  --mode, -m <mode>            reverse_proxy | forward_auth (default: reverse_proxy)
  --workers, -w <n>            Accept threads (default: one per CPU)
  --max-connections <n>        Concurrent connections served (default: 1024)
  --trust-forwarded            Honour X-Forwarded-For / X-Real-IP from the peer
  --no-trust-forwarded         Never honour them, even in forward_auth mode
  --idle-timeout <s>           HTTP socket idle timeout in seconds (default: 15)
  --websocket-idle-timeout <s> WebSocket idle timeout in seconds (default: 300)

Proof of work and sessions:
  --algorithm, -a <alg>        posw | hashcash (default: posw)
  --difficulty, -d <bits>      Work bits (default: 16)
  --posw-challenges <t>        PoSW openings per proof (default: 16)
  --token-scheme <s>           mac | ed25519 (default: mac)
  --token-ttl <s>              Session lifetime in seconds (default: 86400)
  --challenge-ttl <s>          Challenge lifetime in seconds (default: 300)
  --secret-file, -s <path>     Master seed (64 hex chars); random if omitted
  --cookie-name <name>         Session cookie name (default: __sibuna_token)
  --secure-cookie              Emit the Secure cookie attribute

Surface:
  --gate | --no-waf            Bot challenge only (Anubis-style)
  --shield | --waf             Bot challenge + semantic WAF (default)
  --rate-limit <n>             Requests per window per client (default: 100)
  --rate-window <s>            Rate window seconds (default: 10)
  --challenge-rate-limit <n>   Challenge issues and verifies per window (default: 30)
  --ban-seconds <s>            Honeypot ban duration (default: 3600)
  --policy-file, -P <path>     Declarative JSON policy file

Storage (SID 0011):
  --data-dir, -D <path>        One node: persist to the SQLite file <path>/sibuna.db
  --database-url <url>         Cluster: shared PostgreSQL database (postgres://...)
  --database-url-file <path>   Read the database URL from an owner-only file
  --cluster-node <id>          This node's id (required with a database URL)
  --storage-poll-ms <ms>       Storage tick interval (default: 500)

  --verbose, -v                Verbose logging
  --help                       Show this help message
  --version                    Print the version and exit

Unknown options and out-of-range values stop startup with a diagnostic.
";

#[cfg(test)]
mod tests;
