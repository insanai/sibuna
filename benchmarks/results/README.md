# Benchmark results

This directory holds Sibuna's latest measurements, and one comparison with Anubis. Every file is written by `cargo xtask bench`; nothing here is edited by hand except this README. Part VIII of the book presents and discusses these files.

| Command | What it measures | Files |
| --- | --- | --- |
| `cargo xtask bench primitives` | Sixteen primitive workloads (proof-of-work verification, matching, tokens, state, HTTP parsing, policy, WAF), plus two rows for the hashed rate limiter path | `primitives-latest.json`, `primitives-latest.md` |
| `cargo xtask bench product` | Whole daemons under `wrk`: four workloads, two modes, Gate and Shield | `product-latest.json`, `product-latest.md` |
| `cargo xtask bench latency` | Latency at equal offered load, from an open-loop generator | `latency-latest.json`, `latency-latest.md` |
| `cargo xtask bench product --anubis <path>` | The whole-product workloads with Anubis as a further product | `comparison-latest.json`, `comparison-latest.md` |
| `cargo xtask bench admission --anubis <path>` | Admission operations per second of Sibuna and Anubis | `admission-latest.json`, `admission-latest.md` |
| `sibuna-browser dashboards` | A functional console run with eight live dashboards | `console-8-dashboards-2026-10-15.md` |

The `.md` files are the summaries; the `.json` files hold every repetition, the machine and the revision. Git keeps the history, so we keep only the latest files.

## How to reproduce

We need Linux, `taskset` (util-linux) and `wrk` on `PATH`.

```
cargo xtask bench primitives
cargo xtask bench product
cargo xtask bench latency
cargo xtask bench help
```

`cargo xtask bench` first builds the daemon with `cargo build --release -p sibuna`, then runs the `sibuna-bench` tool (`tools/bench`) in release mode. The tool finds the daemon beside its own binary; `--rust <path>` overrides it.

The CPU sets matter more than any other setting. By default the daemons run on CPUs `0-3` (`--cpus`, and `--workers` is the size of that set), and `wrk`, the latency generator and the origin run on CPUs `8-15` (`--load-cpus`). The primitive suite runs on CPU 4 (`--cpu`). On the Ryzen 9 5950X we used, CPUs 0 to 7 are the eight cores of the first CCD and CPUs 8 to 15 those of the second; CPUs 16 to 31 are their SMT siblings. On other machines we choose sets that do not share cores (`lscpu -e`).

## Method

**Primitives.** Each workload runs in seven timed batches after an untimed warm-up of at most 1,000 operations; mutable state (the spent set, the rate limiter) is rebuilt before each batch, outside the timer. We report the median batch per operation and the fastest and slowest batch. Timers surround batches, never single operations. The suite runs in a child process (`sibuna-bench primitives-run`) pinned to one CPU, three times (`--rounds`); per row we keep the round with the lowest median.

**Whole product.** For each mode (forward auth, reverse proxy) and each surface (Gate, Shield), we start the daemon in memory with `--algorithm hashcash --difficulty 8 --rate-limit 100000000 --idle-timeout 5`, obtain a session by solving its Hashcash challenge with `sibuna-pow`, and drive four workloads with `wrk` over keep-alive connections (2 threads, 64 connections, 5 seconds, 3 repetitions by default):

- `admitted`: `GET /private` with a valid session cookie;
- `challenged`: the same request without a cookie (`401` in forward-auth mode, the challenge page in reverse-proxy mode);
- `allowed_static`: `GET /robots.txt` from `curl/8.0`;
- `attack`: a session plus `q=' OR 1=1--`, which only Shield refuses (`403`).

The origin is a stub (`sibuna-bench origin`): standard library only, one thread per connection, keep-alive, a 41-byte page (`--origin caddy` uses `caddy respond` instead). CPU time per request is the daemon's user plus system time from `/proc/<pid>/stat` over the run, divided by the requests wrk counted. Peak memory is `VmHWM` from `/proc/<pid>/status`, reset through `/proc/<pid>/clear_refs` before each run so that each run reports its own peak. Every figure is the median of the repetitions, with the minimum and maximum beside it.

**Latency at equal load.** `wrk` keeps 64 requests in flight, so its percentiles leave out the requests it did not send while it waited (coordinated omission). To read tails at a given load we use an open-loop generator (`sibuna-bench generate`): each of 64 connections sends `GET /private` with a session on a fixed schedule, so the offered rate does not depend on the daemon. When an answer arrives after the next request was due, that request goes out at once and its latency counts from the time it was due, as in wrk2; when the connection was idle at the due time, latency counts from the actual send, so the generator's own sleep overshoot is not charged to the daemon. Percentiles are nearest-rank over every measured request; each figure is the median of three runs.

## Sibuna and Anubis

Anubis is a widely deployed proof-of-work gate. To see how Sibuna, a new product, does beside an established one, we measured the official release binary of Anubis v1.27.0 (`anubis-1.27.0-linux-amd64`) on the same host and CPUs, with the same workloads. The binary is not part of this repository. The two files were recorded with:

```
cargo xtask bench product --anubis <path/to/anubis>
cargo xtask bench admission --anubis <path/to/anubis>
```

**Whole products** (`comparison-latest`). Anubis runs after Sibuna's surfaces in each mode, with `--bind`, `--metrics-bind`, `--target=` (empty in forward-auth mode, the origin in reverse-proxy mode), `--difficulty 2`, `--slog-level ERROR`, `--cookie-secure=false`, a policy that challenges every `Mozilla` User-Agent with DNSBL and the honeypot disabled, and `GOMAXPROCS` equal to Sibuna's worker count. Every thread of either product is pinned to the same CPUs. Hashcash work is matched: 8 zero bits for Sibuna, 2 zero hexadecimal digits for Anubis. The harness obtains an Anubis session as a browser would: it fetches the challenge page (decompressing it when gzip-encoded), reads the challenge from `<script id="anubis_challenge">`, finds the nonce whose `SHA-256(randomData || nonce)` starts with `00`, and passes it to `pass-challenge` with the page's verification cookie. In forward-auth mode the `admitted` and `challenged` workloads ask Anubis's check endpoint (`/.within.website/x/cmd/anubis/api/check`). The origin is `caddy respond`, pinned to the load CPUs, and every run waits until fewer than 3,000 sockets are in `TIME_WAIT`, because the Anubis reverse-proxy runs leave tens of thousands behind.

**Admission operations** (`admission-latest`). Each product runs in forward-auth mode on CPUs `0-1` (two Sibuna workers, `GOMAXPROCS=2`); Sibuna with `--idle-timeout 2` and `--challenge-rate-limit 100000000`, Anubis once with its default Ed25519 tokens and once with `--hs512-secret`. Two client threads on the load CPUs, each with one keep-alive connection, time four operations in seven batches: a session check (200 operations per batch), an unauthenticated check (200), a challenge bootstrap (200; the interstitial plus the challenge record for Sibuna, the page with the embedded challenge for Anubis) and the verification of a fresh proof (64, prepared before the batch). Sibuna's proof challenges are issued 25 ms apart, below the 50 per second at which its adaptive difficulty adds bits, so that they stay at 8 bits. The harness re-executes itself under `taskset` so that the clients run on the load CPUs. A batch is timed from the moment both clients hold a connection to the moment the last one finishes; we report the median batch and its min-max.

## JSON shapes

`primitives-latest.json`:

- `meta`: the machine (`date`, `host`, `cpu`, `logical_cpus`, `os`, `kernel`, `governor`, `boost`, `load_average`), the revision (`git`, `dirty`), the toolchains, `pinned_cpu`, the engine sizes (`engine_bytes`, `bot_table_bytes`, `waf_table_bytes`; heap sizes), and the daemon (`binary_bytes`, `idle_rss_kb`, and `rust_daemon` with path, size, SHA-256 and idle resident memory). `wasm_bytes` is the browser solver when a release build of it exists.
- `runs`: one row per workload (`impl`, `subsystem`, `workload`, `measured`, `iterations`, `ns_per_op_median`, `ns_per_op_min`, `ns_per_op_max`, `ops_per_sec`, `alloc_bytes`, `bytes_per_op`); `impl` is `sibuna` (or `sibuna-naive`).
- The current file also holds a second implementation measured in the same run (`zig_baseline`, `zig_daemon`, `comparison`); Part VIII reports Sibuna's rows.

`product-latest.json`: `meta`, `load`, `wrk`, `origin`, `daemon_cpus`, `load_cpus`, `daemons` (path, size and SHA-256 of each binary), `load_average_before`, `runs` and `limitations`. Each run names its `product` (`sibuna-gate`, `sibuna-shield`), `implementation`, `mode`, `workers`, `cpu_affinity`, `binary_bytes`, `idle_rss_kib` and `rss_kib_after_workload`, and per workload the medians (`requests_per_second_median`, `latency_us_p50_median` to `latency_us_p999_median`, `cpu_us_per_request_median`, `cores_busy_median`), `requests_per_second_min` and `_max`, a `spread` object with the median, minimum and maximum of every figure, `peak_rss_kib_max`, `errors_total`, the `samples`, and the `path`, `status`, `expected_status` and `description` of the workload. Runs whose `implementation` is not `rust` belong to a second build measured in the same run.

`comparison-latest.json` has the same shape, with Anubis runs (`product` and `implementation` both `anubis`), `anubis_version`, the Anubis binary under `daemons`, and the limitations of the comparison appended.

`admission-latest.json`: `meta`, `anubis_version`, `daemon_cpus`, `client_cpus`, `daemons`, `runs` and `limitations`. Each run has `product`, `implementation`, `token_scheme` (`blake3`, `ed25519`, `hs512`), `binary` (path, size, SHA-256), `binary_bytes`, `cpu_affinity`, `challenge_rate_limit` for Sibuna, `rss_kib_after_workload`, and one object per operation (`valid_session`, `unauthenticated_check`, `challenge_bootstrap`, `proof_verification`) with `operations_per_second_median`, `_min`, `_max`, `_batches`, `slowest_client_ns_per_operation_median`, `batches`, `operations_per_batch` and `clients`.

`latency-latest.json`: `meta`, `load` (connections, seconds, warm-up, repetitions, rates, workload), `daemons`, `method`, and `runs`, one per daemon and mode, each with `rates`: per offered rate the `achieved_rps`, every `latency_us` percentile (`p50`, `p90`, `p99`, `p999`, `max`, `mean`) and `daemon_cpu_us_per_request` as `{median, min, max}`, `errors_total`, and the individual `repetitions`. Runs whose `implementation` is not `rust` belong to a second build measured in the same run.

## Provenance and limits

All files were recorded on `paxos-zig`: an AMD Ryzen 9 5950X (16 cores, 32 threads), Linux 7.0.0-28, `powersave` governor with boost enabled, rustc 1.99.0. Each JSON file names the revision it was built from and the SHA-256 of every binary it ran.

- Primitives, whole product and latency: 15 October 2026 (22:34:59, 23:15:24 and 23:07:14 UTC). The daemon is `cargo build --release -p sibuna` (49,113,856 bytes, SHA-256 `e4d819b2fae7e6e1...`); the latency and product files name revision `249d913` with a dirty tree, which held the reuse of connection threads, committed next as `215f36e`. The load average recorded in the product file (52 at its start) is the latency generator's 64 threads from the run just before it.
- Comparison with Anubis: 16 October 2026 (00:55:19 and 00:55:44 UTC, the end of each run). The daemon is a release build of revision `54e4ec5` (37,450,232 bytes, SHA-256 `edfd7d68e5466e00...`); the tree was dirty only in `tools/bench`, where the comparison harness was being added. Anubis is v1.27.0 (40,001,698 bytes, SHA-256 `43a02b1d3908d3d7...`). No other job ran on the host.

Headline results of these files:

- Primitives: Hashcash verification takes 70.2 ns, a session token check with the keyed BLAKE3 MAC 155.8 ns, parsing a 400-byte request with a cookie lookup 132.5 ns, a Shield classification 790.8 ns, and an 8 KiB WAF scan 12,784.3 ns. No batch lies more than 2.8% from its row's median.
- Whole product: in forward-auth mode every workload runs at 197,532 to 211,636 requests per second with a p99 of 305 to 327 us, limited by the load generator, at 11.7 to 13.8 us of CPU per request. Proxied requests run at 138,965 to 147,303 per second, CPU bound on four cores. The peak resident set is about 16 MiB.
- Latency at equal load: at 100,000 admitted requests per second the p99.9 is 62 us in forward-auth mode and 150 us in reverse-proxy mode. At 150,000 requests per second in reverse-proxy mode the daemon saturates (it completes 134,344 per second) and latency grows without bound, as an open-loop test should show.
- Five answers in about two million in three reverse-proxy rows were `503`: a connection gave its place under `--max-connections-per-ip` back only after its closing response, and `wrk` reconnected first. The daemon now gives it back before that response (SID 0002, commit `d2dbf89`); these files predate the fix.
- Beside Anubis v1.27.0, in forward-auth mode, Sibuna served 193,087 to 212,569 requests per second and Anubis 36,509 to 113,170; an admitted request cost Sibuna Gate 12.09 us of CPU and Anubis 106.30 us. Behind `caddy respond` in reverse-proxy mode, Sibuna's proxied rows ran at 103,298 to 106,819 per second, limited by the origin, and Anubis's rows at 19,398 to 28,862. Anubis's resident memory rose to about 600 MiB in reverse-proxy mode, from the `challenged` workload on; Sibuna's stayed near 16 MiB.
- Admission operations per second, Sibuna against Anubis with Ed25519 and with HS512 tokens: session check 88,104 against 10,951 and 16,976; unauthenticated check 78,997 against 28,619 and 27,785; challenge bootstrap 42,664 against 7,893 and 7,952; proof verification 57,924 against 12,668 and 19,261.

The Anubis rows are not a claim that Anubis is slow. It signs sessions with Ed25519 by default, runs on a garbage-collected runtime and offers much that these workloads do not exercise; several rows are not like for like (Anubis answers `/robots.txt` and the attack path itself in forward-auth mode, it has no request inspection, and the challenge pages differ). The files record these limitations with the results.

What these runs do not show: TLS, real networks and real browsers; storage (the daemons run in memory); the browser solver's cost; a cluster under load.
