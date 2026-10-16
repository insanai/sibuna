//! `bench admission`: admission operations per second against Anubis over loopback, the
//! successor of `benchmarks/compare.py`.
//!
//! Each product runs in forward-auth mode, every thread pinned to `--cpus` (two CPUs by
//! default: two Sibuna workers, `GOMAXPROCS=2`). Two clients, each with one keep-alive
//! connection, time four operations in `--batches` batches each:
//!
//! - `valid_session`: a check with a valid session cookie (`200`);
//! - `unauthenticated_check`: the same check without a cookie (`401`);
//! - `challenge_bootstrap`: what a browser fetches to start a challenge, the interstitial and
//!   the challenge record for Sibuna, the page with the embedded challenge for Anubis;
//! - `proof_verification`: the verification of a fresh proof, prepared outside the timer.
//!
//! Hashcash work is matched as in the product runs: 8 zero bits for Sibuna, 2 zero hex digits
//! for Anubis. Sibuna's adaptive difficulty adds bits once challenges are issued faster than
//! 50 per second, and the bootstrap batches issue far faster than that; proof challenges are
//! therefore issued 25 ms apart, after the smoothed rate has decayed back to 8 bits. Sibuna
//! runs with a challenge budget of 100 million per window, so its limiter is checked but never
//! exhausted. Anubis runs twice, with its default Ed25519 tokens and with HS512.
//!
//! Deliberate changes from `compare.py`: the clients are threads of this program, not Python
//! processes, so the figures are no longer limited by the clients; the program re-executes
//! itself under `taskset` so that the clients run on `--load-cpus`; a batch is timed from the
//! moment both clients hold a connection, so connection setup is outside the timer; the Zig
//! daemon can be measured beside the Rust daemon.

mod client;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use sibuna_json::Value;
use sibuna_pow::hashcash;

use crate::anubis::{self, TokenScheme};
use crate::args::Args;
use crate::daemon::{Implementation, browser_headers};
use crate::error::{Error, Result};
use crate::json::{Json, member_str, member_u64};
use crate::process::{self, CpuSet, TempDir};
use crate::product::{Daemons, parse_anubis, parse_daemons};
use crate::report::{Table, fmt_count, write_results};
use crate::server::{Launch, Server};
use crate::stats::Spread;
use crate::{meta, paths};

use client::{BatchTiming, CLIENTS, Exchange, run_batch};

/// Set in the environment of the pinned re-execution, to its CPU list.
const PINNED_ENV: &str = "SIBUNA_BENCH_CLIENT_CPUS";

/// Sibuna's difficulty in bits, and the work Anubis's 2 hex digits ask for.
const BITS: u32 = 8;

/// The time between two proof challenges: 40 per second, below the 50/s adaptive baseline.
const ISSUE_INTERVAL: Duration = Duration::from_millis(25);

/// How long we wait for the adaptive difficulty to return to [`BITS`].
const ISSUE_TIMEOUT: Duration = Duration::from_secs(180);

/// Sibuna's challenge budget per window for this fixture.
const CHALLENGE_BUDGET: u64 = 100_000_000;

/// Operations per batch of the session, unauthenticated and bootstrap operations.
const OPERATIONS: usize = 200;

/// Proofs per batch of the verification operation.
const PROOFS: usize = 64;

/// The options of `bench admission`.
struct Options {
    daemons: Daemons,
    anubis: PathBuf,
    cpus: CpuSet,
    load_cpus: CpuSet,
    batches: usize,
    out: PathBuf,
}

fn parse_options(mut args: Args) -> Result<Options> {
    let (daemons, cpus, load_cpus) = parse_daemons(&mut args, "0-1")?;
    let anubis = parse_anubis(&mut args)?.ok_or_else(|| {
        Error::new("MISSING VALUE", "`admission` compares with Anubis and needs `--anubis`.")
            .hint("Write `cargo xtask bench admission --anubis <path/to/anubis>`.")
    })?;
    let batches: usize = args.parsed("--batches", 7)?;
    if batches == 0 {
        return Err(Error::new("INVALID VALUE", "`--batches` must be positive."));
    }
    let out = args.value("--out")?.map_or_else(paths::results_dir, PathBuf::from);
    args.finish(&[
        "--rust",
        "--zig",
        "--zig-only",
        "--anubis",
        "--cpus",
        "--load-cpus",
        "--batches",
        "--out",
    ])?;
    Ok(Options { daemons, anubis, cpus, load_cpus, batches, out })
}

/// A product and token scheme under test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Contender {
    /// A Sibuna daemon, with its default keyed BLAKE3 tokens.
    Sibuna(Implementation),
    /// Anubis with one token scheme.
    Anubis(TokenScheme),
}

impl Contender {
    fn product(self) -> &'static str {
        match self {
            Contender::Sibuna(_) => "sibuna",
            Contender::Anubis(_) => "anubis",
        }
    }

    fn implementation(self) -> &'static str {
        match self {
            Contender::Sibuna(implementation) => implementation.name(),
            Contender::Anubis(_) => "anubis",
        }
    }

    fn token_scheme(self) -> &'static str {
        match self {
            Contender::Sibuna(_) => "blake3",
            Contender::Anubis(scheme) => scheme.name(),
        }
    }

    /// Returns the forward-auth check endpoint.
    fn check(self) -> &'static str {
        match self {
            Contender::Sibuna(_) => "/private",
            Contender::Anubis(_) => anubis::CHECK,
        }
    }
}

/// `sibuna-bench admission`.
///
/// # Errors
///
/// Fails on bad options, when a product cannot start, or when an operation answers an
/// unexpected status.
pub fn command(args: Args, stdout: &mut dyn Write) -> Result<()> {
    let original = args.remaining().to_vec();
    let options = parse_options(args)?;
    if std::env::var_os(PINNED_ENV).is_none() {
        return run_pinned(&options.load_cpus, &original);
    }
    let temp = TempDir::new("admission")?;
    let mut contenders: Vec<(Contender, &Path)> = options
        .daemons
        .iter()
        .map(|(implementation, path)| (Contender::Sibuna(*implementation), path.as_path()))
        .collect();
    for scheme in [TokenScheme::Ed25519, TokenScheme::Hs512] {
        contenders.push((Contender::Anubis(scheme), options.anubis.as_path()));
    }
    let mut runs = Vec::new();
    for (contender, binary) in contenders {
        let line = format!(
            "Measuring {} {} ({})\n",
            contender.implementation(),
            contender.product(),
            contender.token_scheme()
        );
        stdout.write_all(line.as_bytes()).map_err(|e| Error::io("stdout", e))?;
        runs.push(run_case(&options, contender, binary, temp.path(), stdout)?);
    }
    let document = admission_document(&options, &runs);
    let markdown = admission_markdown(&options, &runs);
    write_results(&options.out, "admission-latest", &document, &markdown)?;
    let path = options.out.join("admission-latest.json");
    let text = format!("\n{markdown}\nResults: {}\n", path.display());
    stdout.write_all(text.as_bytes()).map_err(|e| Error::io("stdout", e))
}

/// Runs this program again with the same arguments, pinned to `cpus`, so that the clients
/// and everything they start run there; the products pin themselves to `--cpus`.
fn run_pinned(cpus: &CpuSet, arguments: &[String]) -> Result<()> {
    let exe = std::env::current_exe().map_err(|e| Error::io("locating this program", e))?;
    let status = Command::new("taskset")
        .arg("-c")
        .arg(cpus.to_list())
        .arg(exe)
        .arg("admission")
        .args(arguments)
        .env(PINNED_ENV, cpus.to_list())
        .status()
        .map_err(|e| Error::io("running taskset", e).hint("Install taskset (util-linux)."))?;
    if status.success() {
        return Ok(());
    }
    Err(Error::new(
        "ADMISSION FAILED",
        format!("The admission run on CPUs {} ended with {status}.", cpus.to_list()),
    )
    .hint("Its own error message is above."))
}

/// The four operations of one contender and what it cost.
struct CaseResult {
    contender: Contender,
    binary: PathBuf,
    operations: Vec<(&'static str, Measurement)>,
    rss_kib_after_workload: u64,
}

/// The batches of one operation.
struct Measurement {
    batches: Vec<BatchTiming>,
    operations_per_batch: usize,
}

impl Measurement {
    fn rate(&self) -> Option<Spread> {
        let rates: Vec<f64> = self.batches.iter().map(|b| b.operations_per_second).collect();
        Spread::of(&rates)
    }

    fn slowest(&self) -> Option<Spread> {
        let values: Vec<f64> =
            self.batches.iter().map(|b| b.slowest_client_ns_per_operation).collect();
        Spread::of(&values)
    }

    fn to_json(&self) -> Json {
        let rate = self.rate();
        let rates: Vec<Json> =
            self.batches.iter().map(|b| Json::from(b.operations_per_second)).collect();
        Json::object()
            .with("operations_per_second_median", rate.map(|s| s.median))
            .with("operations_per_second_min", rate.map(|s| s.min))
            .with("operations_per_second_max", rate.map(|s| s.max))
            .with("operations_per_second_batches", rates)
            .with("slowest_client_ns_per_operation_median", self.slowest().map(|s| s.median))
            .with("batches", self.batches.len())
            .with("operations_per_batch", self.operations_per_batch)
            .with("clients", CLIENTS)
    }
}

/// Starts `contender` from `binary` in forward-auth mode, pinned to the daemon CPUs.
fn start(options: &Options, contender: Contender, binary: &Path, dir: &Path) -> Result<Server> {
    let workers = options.cpus.count();
    let label = format!("{}-{}", contender.implementation(), contender.token_scheme());
    match contender {
        Contender::Sibuna(_) => {
            let port = process::free_port()?;
            Server::start(Launch {
                label: &label,
                binary,
                args: sibuna_args(port, workers),
                env: vec![("GOMAXPROCS", workers.to_string())],
                cpus: &options.cpus,
                port,
                log_dir: dir,
                probe: contender.check(),
                ready_status: 401,
            })
        }
        Contender::Anubis(scheme) => {
            let setup = anubis::Setup { origin_port: None, workers, scheme };
            anubis::start(&label, binary, &setup, &options.cpus, dir)
        }
    }
}

/// Returns the command line of `compare.py` for Sibuna on `port`.
fn sibuna_args(port: u16, workers: usize) -> Vec<String> {
    let args = [
        "--gate",
        "--mode",
        "forward_auth",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--workers",
        &workers.to_string(),
        "--algorithm",
        "hashcash",
        "--difficulty",
        &BITS.to_string(),
        "--rate-limit",
        "100000000",
        "--idle-timeout",
        "2",
        "--challenge-rate-limit",
        &CHALLENGE_BUDGET.to_string(),
    ];
    args.iter().map(|s| (*s).to_owned()).collect()
}

fn run_case(
    options: &Options,
    contender: Contender,
    binary: &Path,
    dir: &Path,
    stdout: &mut dyn Write,
) -> Result<CaseResult> {
    let server = start(options, contender, binary, dir)?;
    let port = server.port;
    let cookie = perform(port, &proof(port, contender)?)?;
    let mut with_cookie = browser_headers();
    with_cookie.push(("Cookie".to_owned(), cookie));
    let valid = vec![Exchange::new(port, "GET", contender.check(), &with_cookie, b"", 200)];
    perform(port, &valid[0])?;
    let missing =
        vec![Exchange::new(port, "GET", contender.check(), &browser_headers(), b"", 401)];
    let mut operations = Vec::new();
    for (name, group) in [
        ("valid_session", valid),
        ("unauthenticated_check", missing),
        ("challenge_bootstrap", bootstrap(port, contender)),
    ] {
        // One untimed warm-up of the operation before the measured batches.
        for exchange in &group {
            perform(port, exchange)?;
        }
        let groups: Vec<&[Exchange]> = vec![group.as_slice(); OPERATIONS];
        let batches =
            (0..options.batches).map(|_| run_batch(port, &groups)).collect::<Result<Vec<_>>>()?;
        let measurement = Measurement { batches, operations_per_batch: OPERATIONS };
        progress(stdout, name, &measurement)?;
        operations.push((name, measurement));
    }
    let measurement = measure_proofs(options, port, contender)?;
    progress(stdout, "proof_verification", &measurement)?;
    operations.push(("proof_verification", measurement));
    Ok(CaseResult {
        contender,
        binary: binary.to_path_buf(),
        operations,
        rss_kib_after_workload: process::status_kib(server.pid(), "VmRSS")?,
    })
}

/// Times the verification of fresh proofs: every batch gets its own, prepared before it.
fn measure_proofs(options: &Options, port: u16, contender: Contender) -> Result<Measurement> {
    let mut batches = Vec::new();
    for _ in 0..options.batches {
        let proofs: Vec<[Exchange; 1]> =
            (0..PROOFS).map(|_| proof(port, contender).map(|p| [p])).collect::<Result<_>>()?;
        let groups: Vec<&[Exchange]> = proofs.iter().map(|p| p.as_slice()).collect();
        batches.push(run_batch(port, &groups)?);
    }
    Ok(Measurement { batches, operations_per_batch: PROOFS })
}

/// Returns the requests a browser makes to start a challenge.
fn bootstrap(port: u16, contender: Contender) -> Vec<Exchange> {
    let headers = browser_headers();
    match contender {
        Contender::Sibuna(_) => vec![
            Exchange::new(port, "GET", "/__sibuna/challenge", &headers, b"", 200),
            Exchange::new(port, "GET", CHALLENGE_JSON, &headers, b"", 200),
        ],
        Contender::Anubis(_) => vec![Exchange::new(port, "GET", "/private", &headers, b"", 200)],
    }
}

/// Sibuna's challenge record for `/private`.
const CHALLENGE_JSON: &str = "/__sibuna/challenge.json?path=/private";

/// Fetches and solves a fresh challenge and returns the request that submits the proof.
fn proof(port: u16, contender: Contender) -> Result<Exchange> {
    let mut headers = browser_headers();
    match contender {
        Contender::Sibuna(_) => {
            let id = issue(port)?;
            let nonce = hashcash::solve_bits(id.as_bytes(), BITS, 1 << 40).ok_or_else(|| {
                Error::new("NO SOLUTION", format!("No nonce solves challenge {id}."))
            })?;
            let body = format!("{{\"challenge_id\":\"{id}\",\"nonce\":\"{nonce}\"}}");
            headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
            Ok(Exchange::new(port, "POST", "/__sibuna/verify", &headers, body.as_bytes(), 200))
        }
        Contender::Anubis(_) => {
            let pass = anubis::prepare_pass(port)?;
            headers.push(("Cookie".to_owned(), pass.cookie));
            Ok(Exchange::new(port, "GET", &pass.target, &headers, b"", 302))
        }
    }
}

/// Asks Sibuna on `port` for challenges, 25 ms apart, until one has [`BITS`] bits, and
/// returns its id. Between refusals it waits a second for the smoothed issue rate to decay.
fn issue(port: u16) -> Result<String> {
    let deadline = Instant::now() + ISSUE_TIMEOUT;
    loop {
        std::thread::sleep(ISSUE_INTERVAL);
        let response = crate::http::request(port, "GET", CHALLENGE_JSON, &browser_headers(), b"")?;
        let bad = || {
            Error::new(
                "BAD CHALLENGE",
                format!("Sibuna on port {port} issued no usable challenge."),
            )
            .hint("Check that the daemon runs with `--algorithm hashcash`.")
        };
        if response.status != 200 {
            return Err(bad());
        }
        let value: Value<'_> = sibuna_json::parse(&response.body).map_err(|_| bad())?;
        let bits = member_u64(&value, "difficulty").ok_or_else(bad)?;
        if bits == u64::from(BITS) {
            return member_str(&value, "id").map(str::to_owned).ok_or_else(bad);
        }
        if Instant::now() >= deadline {
            return Err(Error::new(
                "DIFFICULTY STAYED HIGH",
                format!("The adaptive difficulty stayed at {bits} bits, above {BITS}."),
            ));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Sends `exchange` once on a fresh connection and returns the cookies it set.
///
/// # Errors
///
/// Fails when it cannot be sent or answers another status than expected.
fn perform(port: u16, exchange: &Exchange) -> Result<String> {
    let response = exchange.send_once(port)?;
    if response.status != exchange.expected() {
        let excerpt =
            String::from_utf8_lossy(&response.body[..response.body.len().min(200)]).into_owned();
        return Err(Error::new(
            "UNEXPECTED STATUS",
            format!(
                "{}: expected {}, got {}:\n{excerpt}",
                exchange.label(),
                exchange.expected(),
                response.status
            ),
        ));
    }
    Ok(response.cookie_header())
}

fn progress(stdout: &mut dyn Write, name: &str, measurement: &Measurement) -> Result<()> {
    let rate = measurement.rate().map_or(0.0, |s| s.median);
    let line = format!("  {name:<22} {:>9} ops/s\n", fmt_count(rate));
    stdout.write_all(line.as_bytes()).map_err(|e| Error::io("stdout", e))
}

fn case_json(case: &CaseResult, cpus: &CpuSet) -> Json {
    let affinity: Vec<Json> = cpus.cpus.iter().map(|&c| Json::from(c)).collect();
    let mut json = Json::object()
        .with("product", case.contender.product())
        .with("implementation", case.contender.implementation())
        .with("token_scheme", case.contender.token_scheme())
        .with("binary", meta::binary(&case.binary))
        .with("binary_bytes", fs::metadata(&case.binary).ok().map(|m| m.len()))
        .with("cpu_affinity", affinity);
    if let Contender::Sibuna(_) = case.contender {
        json.set("challenge_rate_limit", CHALLENGE_BUDGET);
    }
    for (name, measurement) in &case.operations {
        json.set(name, measurement.to_json());
    }
    json.with("rss_kib_after_workload", case.rss_kib_after_workload)
}

fn admission_document(options: &Options, runs: &[CaseResult]) -> Json {
    let mut daemons = Json::object();
    for (implementation, path) in &options.daemons {
        daemons.set(implementation.name(), meta::binary(path));
    }
    daemons.set("anubis", meta::binary(&options.anubis));
    Json::object()
        .with("meta", meta::machine(&paths::workspace_root(), &options.cpus))
        .with("anubis_version", anubis::version(&options.anubis))
        .with("daemon_cpus", options.cpus.to_list())
        .with("client_cpus", options.load_cpus.to_list())
        .with("daemons", daemons)
        .with("runs", runs.iter().map(|r| case_json(r, &options.cpus)).collect::<Vec<_>>())
        .with("limitations", LIMITATIONS.iter().map(|&l| Json::from(l)).collect::<Vec<_>>())
}

/// What these runs do not show, recorded with every result.
const LIMITATIONS: [&str; 8] = [
    "Two client threads, each with one keep-alive connection, on the client CPU set; the \
     product on two CPUs (two Sibuna workers, GOMAXPROCS=2); loopback HTTP forward auth, no \
     origin or TLS.",
    "Every product thread is pinned to the same CPU set with taskset before the product starts.",
    "Hashcash work matched at 8 zero bits / 2 zero hex digits; same User-Agent and client \
     address.",
    "Proof challenges are issued below the 50/s adaptive baseline so the matched work holds; \
     the bootstrap batches above it measure issuance only, which is difficulty independent.",
    "Sibuna reserves 100 million challenge operations per window for this fixture; the limiter \
     check remains, but exhaustion and production budgets are not measured.",
    "Default Anubis Ed25519 and optional HS512 are both tested; Sibuna uses its default keyed \
     BLAKE3 MAC. Bootstrap is the interstitial plus the JSON challenge for Sibuna and the page \
     with the embedded challenge for Anubis; static assets excluded.",
    "Fresh proofs are prepared outside the timed batches; browser solve time and network \
     latency are not measured. A batch is timed once both clients hold a connection.",
    "Batches are short (200 operations, 64 proofs); sequential runs are not a universal \
     product ranking.",
];

fn admission_markdown(options: &Options, runs: &[CaseResult]) -> String {
    let mut out = format!(
        "# Admission operations\n\nGenerated by `cargo xtask bench admission` on {}. Two \
         clients on CPUs {}, products on CPUs {}; operations per second, median of {} \
         batches ({OPERATIONS} operations, {PROOFS} proofs), with the min-max beside it.\n\n",
        meta::utc_now(),
        options.load_cpus.to_list(),
        options.cpus.to_list(),
        options.batches,
    );
    let names = ["valid_session", "unauthenticated_check", "challenge_bootstrap"];
    let mut header = vec!["Product", "Impl", "Token"];
    header.extend(names);
    header.extend(["proof_verification", "RSS after KiB"]);
    let mut rates = Table::new(&header);
    let mut spreads = Table::new(&header[..header.len() - 1]);
    for run in runs {
        let lead = [
            run.contender.product(),
            run.contender.implementation(),
            run.contender.token_scheme(),
        ];
        let mut row: Vec<String> = lead.iter().map(|s| (*s).to_owned()).collect();
        let mut spread_row = row.clone();
        for (_, measurement) in &run.operations {
            let rate = measurement.rate();
            row.push(rate.map_or_else(|| "-".to_owned(), |s| fmt_count(s.median)));
            spread_row.push(rate.map_or_else(
                || "-".to_owned(),
                |s| format!("{}-{}", fmt_count(s.min), fmt_count(s.max)),
            ));
        }
        row.push(run.rss_kib_after_workload.to_string());
        rates.row(row);
        spreads.row(spread_row);
    }
    out.push_str(&rates.markdown());
    out.push_str("\n## Spread\n\nThe slowest and fastest batch, operations per second.\n\n");
    out.push_str(&spreads.markdown());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sibuna_has_the_command_line_of_compare_py() {
        assert_eq!(
            sibuna_args(8080, 2).join(" "),
            "--gate --mode forward_auth --host 127.0.0.1 --port 8080 --workers 2 --algorithm \
             hashcash --difficulty 8 --rate-limit 100000000 --idle-timeout 2 \
             --challenge-rate-limit 100000000"
        );
    }

    #[test]
    fn contenders_name_their_product_and_endpoints() {
        let sibuna = Contender::Sibuna(Implementation::Rust);
        assert_eq!(
            (sibuna.product(), sibuna.token_scheme(), sibuna.check()),
            ("sibuna", "blake3", "/private")
        );
        let anubis = Contender::Anubis(TokenScheme::Hs512);
        assert_eq!((anubis.implementation(), anubis.token_scheme()), ("anubis", "hs512"));
        assert_eq!(anubis.check(), anubis::CHECK);
        assert_eq!(bootstrap(80, sibuna).len(), 2);
        assert_eq!(bootstrap(80, anubis).len(), 1);
    }

    #[test]
    fn requires_anubis() {
        let args = Args::new(vec!["--rust".into(), "/bin/sh".into()]);
        let error = parse_options(args).err().unwrap();
        assert!(error.message.contains("--anubis"));
    }
}
