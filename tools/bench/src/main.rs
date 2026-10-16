//! `sibuna-bench`: Sibuna's benchmarks, run as `cargo xtask bench <command>`.
//!
//! Four commands replace the Zig repository's benchmark drivers:
//!
//! - `primitives` runs the sixteen workloads of `benchmarks/benchmark.zig` against the Rust
//!   crates with the same inputs, iteration counts and statistics (seven batches after an
//!   untimed warm-up; median, minimum and maximum per operation).
//! - `product` replaces `benchmarks/tools.py`: whole daemons in front of a stub origin under
//!   `wrk`, four workloads, in forward-auth and reverse-proxy modes, for Gate and Shield; with
//!   `--anubis`, Anubis is measured beside them behind `caddy respond`, as `tools.py` did.
//! - `latency` drives the daemon with an open-loop generator at fixed rates, so that p99 can
//!   be compared at equal offered load.
//! - `admission` replaces `benchmarks/compare.py`: admission operations per second of Sibuna
//!   and Anubis in forward-auth mode, from two clients over keep-alive connections.
//!
//! Results go to `benchmarks/results/<command>-latest.json` with a Markdown summary beside
//! it. The README in that directory documents the JSON shapes.
//!
//! Deliberate changes from the Zig drivers:
//!
//! - Everything is Rust: wrk is driven through `std::process::Command`, and the origin and
//!   the latency generator are subcommands of this program (`origin`, `generate`), so the
//!   benchmark needs no Python and no Caddy (`--origin caddy` remains available).
//! - Processes are pinned with `taskset -c` before they start, so every thread inherits the
//!   CPU set; `tools.py` re-pinned threads after start. The load generator and origin get a
//!   CPU set of their own instead of native scheduling.
//! - CPU time comes from `/proc/<pid>/stat` (clock ticks) instead of `ps` (whole seconds in
//!   some containers), and peak memory is `VmHWM`, reset through `clear_refs` before each run,
//!   instead of `ps` samples every 100 ms.
//! - wrk reports p90 and p99.9 too, and every figure carries its min-max spread.
//! - `primitives` runs the suite over several rounds (`--rounds`, 3 by default) and keeps,
//!   per row, the round with the lowest median: on a shared host a busy SMT sibling or a
//!   lower clock slows whole suite runs. Within a round the statistics are Zig's.
//! - The policy rows leave `RequestView::client_address` empty, so the engine parses the
//!   client address text inside evaluation, as the Zig engine did; the daemon parses it
//!   once per request before evaluation.

mod admission;
mod anubis;
mod args;
mod daemon;
mod error;
mod http;
mod json;
mod latency;
mod meta;
mod origin;
mod paths;
mod primitives;
mod process;
mod product;
mod report;
mod server;
mod stats;

use std::io::{self, Write};
use std::process::ExitCode;

use args::Args;
use error::{Error, Result};

const USAGE: &str = "\
Sibuna benchmarks.

Usage: cargo xtask bench <COMMAND> [OPTIONS]

Commands:
  primitives   Primitive timings of benchmark.zig for the Rust crates
  product      Whole daemons under wrk: four workloads, two modes, Gate and Shield
  latency      Open-loop latency at fixed offered rates
  admission    Admission operations per second of Sibuna and Anubis (needs --anubis)
  help         Print this help

primitives options:
  --rust <PATH>         The daemon (default: sibuna beside this program)
  --cpu <LIST>          CPU the suite is pinned to (default: 4)
  --rounds <N>          Runs of the suite; per row the fastest (default: 3)
  --out <DIR>           Result directory (default: benchmarks/results)

product and latency options:
  --rust <PATH>         The daemon (default: sibuna beside this program)
  --cpus <LIST>         CPUs of the daemon; --workers is their count (default: 0-3)
  --load-cpus <LIST>    CPUs of wrk, the generator and the origin (default: 8-15)
  --modes <LIST>        forward_auth,reverse_proxy (default: both)
  --out <DIR>           Result directory (default: benchmarks/results)

product options:
  --threads <N>         wrk threads (default: 2)
  --connections <N>     wrk connections (default: 64)
  --seconds <N>         Seconds per wrk run (default: 5)
  --repetitions <N>     Runs per workload; the median is reported (default: 3)
  --surfaces <LIST>     gate,shield (default: both)
  --origin <KIND>       stub (default) or caddy (default with --anubis)
  --anubis <PATH>       Also measure Anubis; results go to comparison-latest

latency options:
  --rates <LIST>        Offered requests per second (default: 10000,25000,50000,100000,150000)
  --seconds <N>         Measured seconds per rate (default: 10)
  --warmup <N>          Unmeasured seconds before each rate (default: 2)
  --connections <N>     Connections, one thread each (default: 64)
  --surface <NAME>      gate or shield (default: shield)

admission options:
  --anubis <PATH>       The Anubis binary (required)
  --rust <PATH>         The daemon (default: sibuna beside this program)
  --cpus <LIST>         CPUs of the products (default: 0-1)
  --load-cpus <LIST>    CPUs of the two clients (default: 8-15)
  --batches <N>         Timed batches per operation; the median is reported (default: 7)
  --out <DIR>           Result directory (default: benchmarks/results)
";

fn main() -> ExitCode {
    let mut items: Vec<String> = std::env::args().skip(1).collect();
    if items.is_empty() {
        items.push("help".to_owned());
    }
    let command = items.remove(0);
    let args = Args::new(items);
    let mut stdout = io::stdout().lock();
    let result = match command.as_str() {
        "primitives" => primitives::command(args, &mut stdout),
        "product" => product::command(args, &mut stdout),
        "latency" => latency::command(args, &mut stdout),
        "admission" => admission::command(args, &mut stdout),
        "primitives-run" => args.finish(&[]).and_then(|()| primitives::run_suite(&mut stdout)),
        "generate" => latency::generate_command(args, &mut stdout),
        "origin" => run_origin(args),
        "help" | "-h" | "--help" => {
            stdout.write_all(USAGE.as_bytes()).map_err(|e| Error::io("stdout", e))
        }
        other => {
            Err(Error::new("UNKNOWN COMMAND", format!("There is no command named `{other}`."))
                .hint("Run `cargo xtask bench help` to list the commands."))
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr(), "{error}");
            ExitCode::FAILURE
        }
    }
}

/// `sibuna-bench origin --port N`: serves the stub origin until killed.
fn run_origin(mut args: Args) -> Result<()> {
    let port: u16 = args.parsed("--port", 0)?;
    args.finish(&["--port"])?;
    if port == 0 {
        return Err(Error::new("MISSING VALUE", "`origin` needs `--port <N>`."));
    }
    origin::serve(port)
}
