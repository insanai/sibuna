//! `sibuna-bench`: Sibuna's benchmarks, run as `cargo xtask bench <command>`.
//!
//! Three commands replace the Zig repository's benchmark drivers:
//!
//! - `primitives` runs the sixteen workloads of `benchmarks/benchmark.zig` against the Rust
//!   crates with the same inputs, iteration counts and statistics (seven batches after an
//!   untimed warm-up; median, minimum and maximum per operation), and with `--zig` runs the
//!   Zig benchmark binary on the same CPU for one comparison table.
//! - `product` replaces `benchmarks/tools.py`: whole daemons in front of a stub origin under
//!   `wrk`, four workloads, in forward-auth and reverse-proxy modes, for Gate and Shield.
//! - `latency` drives the daemons with an open-loop generator at fixed rates, so that p99 can
//!   be compared at equal offered load.
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
//! - `primitives` alternates the Zig and Rust suites over several rounds (`--rounds`, 3 by
//!   default) and keeps, per row, the round with the lowest median: on a shared host a busy
//!   SMT sibling or a lower clock slows whole suite runs, and alternation exposes both
//!   implementations to the same conditions. Within a round the statistics are Zig's.
//! - The policy rows leave `RequestView::client_address` empty, so the engine parses the
//!   client address text inside evaluation, as the Zig engine did; the daemon parses it
//!   once per request before evaluation.
//! - Result files hold the Rust rows in the Zig shape (`runs`) and the Zig rows beside them
//!   (`zig_baseline`, `implementation`), instead of one implementation per file.

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
mod stats;

use std::io::{self, Write};
use std::process::ExitCode;

use args::Args;
use error::{Error, Result};

const USAGE: &str = "\
Sibuna benchmarks.

Usage: cargo xtask bench <COMMAND> [OPTIONS]

Commands:
  primitives   Primitive timings of benchmark.zig for the Rust crates (and Zig with --zig)
  product      Whole daemons under wrk: four workloads, two modes, Gate and Shield
  latency      Open-loop latency at fixed offered rates
  help         Print this help

primitives options:
  --zig <PATH>          The Zig benchmark binary (sibuna-benchmark) to compare with
  --zig-daemon <PATH>   Also record the Zig daemon's size and idle memory
  --rust <PATH>         The Rust daemon (default: sibuna beside this program)
  --cpu <LIST>          CPU both suites are pinned to (default: 4)
  --rounds <N>          Alternating runs of each suite; per row the fastest (default: 3)
  --out <DIR>           Result directory (default: benchmarks/results)

product and latency options:
  --rust <PATH>         The Rust daemon (default: sibuna beside this program)
  --zig <PATH>          The Zig daemon, measured with the same flags
  --zig-only            Measure only the Zig daemon
  --cpus <LIST>         CPUs of the daemons; --workers is their count (default: 0-3)
  --load-cpus <LIST>    CPUs of wrk, the generator and the origin (default: 8-15)
  --modes <LIST>        forward_auth,reverse_proxy (default: both)
  --out <DIR>           Result directory (default: benchmarks/results)

product options:
  --threads <N>         wrk threads (default: 2)
  --connections <N>     wrk connections (default: 64)
  --seconds <N>         Seconds per wrk run (default: 5)
  --repetitions <N>     Runs per workload; the median is reported (default: 3)
  --surfaces <LIST>     gate,shield (default: both)
  --origin <KIND>       stub (default) or caddy

latency options:
  --rates <LIST>        Offered requests per second (default: 10000,25000,50000,100000,150000)
  --seconds <N>         Measured seconds per rate (default: 10)
  --warmup <N>          Unmeasured seconds before each rate (default: 2)
  --connections <N>     Connections, one thread each (default: 64)
  --surface <NAME>      gate or shield (default: shield)
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
