# Benchmark results

This directory holds the latest measurements of the Rust port against the Zig original. Every file is written by `cargo xtask bench`; nothing here is edited by hand except this README.

| Command | What it measures | Files |
| --- | --- | --- |
| `cargo xtask bench primitives` | The sixteen primitive workloads of the Zig `benchmarks/benchmark.zig`, for the Rust crates and the Zig benchmark binary | `primitives-latest.json`, `primitives-latest.md` |
| `cargo xtask bench product` | Whole daemons under `wrk`, the successor of the Zig `benchmarks/tools.py` | `product-latest.json`, `product-latest.md` |
| `cargo xtask bench latency` | Latency at equal offered load, from an open-loop generator | `latency-latest.json`, `latency-latest.md` |

The `.md` files are the summaries; the `.json` files hold every repetition, the machine and the revision. Git keeps the history, so we keep only the latest files.

## How to reproduce

We need Linux, `taskset` (util-linux) and `wrk` on `PATH`. For a comparison with Zig we also need a Zig release build of the daemon and of its benchmark binary (`zig build -Doptimize=ReleaseFast` in the Zig repository gives `zig-out/bin/sibuna` and `zig-out/bin/sibuna-benchmark`).

```
cargo xtask bench primitives --zig <zig-out/bin/sibuna-benchmark> --zig-daemon <zig-out/bin/sibuna>
cargo xtask bench product --zig <zig-out/bin/sibuna>
cargo xtask bench latency --zig <zig-out/bin/sibuna>
cargo xtask bench help
```

`cargo xtask bench` first builds the daemon with `cargo build --release -p sibuna`, then runs the `sibuna-bench` tool (`tools/bench`) in release mode. The tool finds the Rust daemon beside its own binary; `--rust <path>` overrides it.

The CPU sets matter more than any other setting. By default the daemons run on CPUs `0-3` (`--cpus`, and `--workers` is the size of that set), and `wrk`, the latency generator and the stub origin run on CPUs `8-15` (`--load-cpus`). The primitive suites run on CPU 4 (`--cpu`). On the Ryzen 9 5950X we used, CPUs 0 to 7 are the eight cores of the first CCD and CPUs 8 to 15 those of the second; CPUs 16 to 31 are their SMT siblings. Choose sets that do not share cores on other machines (`lscpu -e`).

## Method

**Primitives.** Each workload runs in seven timed batches after an untimed warm-up of at most 1,000 operations; mutable state (the spent set, the rate limiter) is rebuilt before each batch, outside the timer. We report the median batch per operation and the fastest and slowest batch. Timers surround batches, never single operations. The inputs, iteration counts and order are those of `benchmark.zig`. The Rust suite runs in a child process (`sibuna-bench primitives-run`) and the Zig suite in its own binary, both pinned to the same CPU, and both print the same JSON document.

**Whole product.** For each mode (forward auth, reverse proxy), each surface (Gate, Shield) and each daemon, we start the daemon in memory with the flags of `tools.py` (`--algorithm hashcash --difficulty 8 --rate-limit 100000000 --idle-timeout 5`), obtain a session by solving its Hashcash challenge with `sibuna-pow`, and drive four workloads with `wrk` over keep-alive connections (2 threads, 64 connections, 5 seconds, 3 repetitions by default):

- `admitted`: `GET /private` with a valid session cookie;
- `challenged`: the same request without a cookie (`401` in forward-auth mode, the challenge page in reverse-proxy mode);
- `allowed_static`: `GET /robots.txt` from `curl/8.0`;
- `attack`: a session plus `q=' OR 1=1--`, which only Shield refuses (`403`).

The origin is a stub (`sibuna-bench origin`): standard library only, one thread per connection, keep-alive, the same 41-byte page `caddy respond` served for `tools.py` (`--origin caddy` is still available). CPU time per request is the daemon's user plus system time from `/proc/<pid>/stat` over the run, divided by the requests wrk counted. Peak memory is `VmHWM` from `/proc/<pid>/status`, reset through `/proc/<pid>/clear_refs` before each run so that each run reports its own peak. Every figure is the median of the repetitions, with the minimum and maximum beside it.

**Latency at equal load.** `wrk` keeps 64 requests in flight. A faster daemon therefore receives more requests, and wrk's percentiles leave out the requests it did not send while it waited (coordinated omission). To compare tails at the same load we use an open-loop generator (`sibuna-bench generate`): each of 64 connections sends `GET /private` with a session on a fixed schedule, so the offered rate does not depend on the daemon. When an answer arrives after the next request was due, that request goes out at once and its latency counts from the time it was due, as in wrk2; when the connection was idle at the due time, latency counts from the actual send, so the generator's own sleep overshoot is not charged to the daemon. Both daemons run at the same time on the same CPU set (the idle one uses no CPU), and the generator alternates between them at every rate and repetition, so that slow drift of the machine affects both alike. Percentiles are nearest-rank over every measured request; each figure is the median of three runs.

## JSON shapes

The shapes extend those of the Zig repository, so that the book's Part VIII can render them with small changes.

`primitives-latest.json`:

- `meta`: the machine (`date`, `host`, `cpu`, `logical_cpus`, `os`, `kernel`, `governor`, `boost`, `load_average`), the revision (`git`, `dirty`), the toolchains (`rustc`, `zig`), `pinned_cpu`, the Rust engine sizes (`engine_bytes`, `bot_table_bytes`, `waf_table_bytes`; heap sizes, where Zig reported `@sizeOf` of fixed tables), and the daemons (`binary_bytes` and `idle_rss_kb` of the Rust daemon, as `run.py` named them, and `rust_daemon`, `zig_daemon` with path, size, SHA-256 and idle resident memory). `wasm_bytes` is the browser solver when a release build of it exists.
- `runs`: the Rust rows in the shape of `benchmark.zig` (`impl`, `subsystem`, `workload`, `measured`, `iterations`, `ns_per_op_median`, `ns_per_op_min`, `ns_per_op_max`, `ops_per_sec`, `alloc_bytes`, `bytes_per_op`). `impl` stays `sibuna` (or `sibuna-naive`), so the book's lookups find the Rust rows.
- `zig_baseline`: the Zig binary's own document (`meta`, `runs`), unchanged.
- `comparison`: per row, `rust_ns_per_op_median`, `zig_ns_per_op_median` and `rust_over_zig`.

`product-latest.json` keeps the shape of `tools-comparison-latest.json` (`meta`, `load`, `wrk`, `origin`, `runs`, `limitations`). Each run adds `implementation` (`rust` or `zig`) beside `product` (`sibuna-gate`, `sibuna-shield`), and each workload adds `latency_us_p90_median`, `latency_us_p999_median`, `requests_per_second_min`, `requests_per_second_max` and a `spread` object with the median, minimum and maximum of every figure. `daemon_cpus`, `load_cpus` and `daemons` (path, size and SHA-256 of each binary) record the setup, and `load_average_before` how busy the host was.

`latency-latest.json`: `meta`, `load` (connections, seconds, warm-up, repetitions, rates, workload), `daemons`, `method`, and `runs`, one per daemon and mode, each with `rates`: per offered rate the `achieved_rps`, every `latency_us` percentile (`p50`, `p90`, `p99`, `p999`, `max`, `mean`) and `daemon_cpu_us_per_request` as `{median, min, max}`, `errors_total`, and the individual `repetitions`.

## Provenance and limits

The current files were recorded on 15 October 2026 between 17:03 and 17:27 UTC on `paxos-zig`: an AMD Ryzen 9 5950X (16 cores, 32 threads), Linux 7.0.0-28, `powersave` governor with boost enabled, rustc 1.99.0, Zig 0.16.0. Each JSON file names the exact revision (`git`, with `dirty: true` because the port is in progress) and the SHA-256 of both daemons.

- Rust daemon: `cargo build --release -p sibuna` of the working tree at 17:02 UTC (21,972,408 bytes, SHA-256 `e3369574eed5f7e6...`), copied aside so that later builds could not change it during the runs.
- Zig daemon and benchmark binary: a `ReleaseFast` build of the Zig repository (34,576,440 bytes, SHA-256 `36fc050035555ed6...`).

**The host was shared.** Other agents compiled and tested other crates of this workspace during the runs; the one-minute load average ranged from 7.6 to 59.6, and nothing kept those jobs off the benchmark CPUs. The primitive suites are robust to this (alternating rounds, fastest round per row; the spread across batches is small). The whole-product medians moved by a few percent between runs. The latency tails are not robust: at the same offered rate the p99 of one daemon varied by up to two orders of magnitude between repetitions (see the `p99 min-max` column), so the tail columns above 25,000 requests per second show the host's interference as much as the daemons. Rerun on a quiet machine before drawing conclusions from them.

Headline results of these files:

- Primitives: the Rust port is faster than Zig on 14 of 16 rows (from 0.93 of Zig's time for Hashcash and PoSW verification down to 0.12 for the HTTP parser and 0.16 for the 8 KiB WAF scan with SQL injection audited). The two rate limiter rows are 2.2 times slower than Zig (12.8 against 5.7 ns per check); earlier in the day, before a change to `crates/store/src/limiter.rs` that was in progress during these runs, the same rows measured 6.5 ns.
- Whole product: forward-auth throughput is level with Zig (ratios 0.96 to 1.07) at 0.74 to 0.97 of Zig's CPU time per request; reverse-proxy throughput is 1.14 to 1.23 times Zig's for the admitted and static workloads (the Gate attack row, also proxied, is level at 0.99), with p99 lower in six of eight rows. Peak resident memory is higher: about 52 MiB against 31 MiB, and 41.7 MiB at idle against 11.5 MiB. A Rust build of the same tree two hours earlier idled at 8.0 MiB, so the growth is recent.
- Latency at equal load: at 10,000 requests per second both daemons answer with p50 around 30 us (forward auth) and 55 us (reverse proxy) and median p99 under 100 us. At 25,000 Rust's median p99 is 49 us (forward auth) and 104 us (reverse proxy), Zig's 194 us and 998 us. In forward-auth mode Rust's p50 is 3 to 4 us lower at every rate; in reverse-proxy mode the p50s are within 6 us of each other either way. From 50,000 requests per second on, the host noise dominates the tails (see above). At 150,000 requests per second in reverse-proxy mode both daemons saturate (Rust completes 132,000 and Zig 120,000 per second) and latency grows without bound, as an open-loop test should show.

What these runs do not show: TLS, real networks and real browsers; any product other than the two Sibuna daemons; storage (both daemons run in memory); the browser solver's cost. `product-latest.json` records these limitations with the results.
