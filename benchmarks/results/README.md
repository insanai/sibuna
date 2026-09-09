# Benchmark results

Run `sh benchmarks/run-all.sh` for primitive measurements and
`python3 benchmarks/distributed.py` for the three-process HTTP/replication matrix.
Both write timestamped results and update their respective `latest` JSON files.

Primitive results contain seven batch measurements after untimed warmup and reset of mutable
state. Timers run around loops, never around individual operations. Compiler barriers prevent
pure verification work from being hoisted. Bot matcher comparisons use identical signatures
and any-match semantics. `alloc_bytes: null` means allocation activity was not instrumented;
source/API review establishes the allocation-free primitive contract. `@sizeOf` reports exact
engine and table sizes. RSS is separately sampled from a healthy process with two workers and
storage compiled in but inactive. The WASM module is rebuilt before its size is recorded.

Distributed results use three real daemon processes and six external Python client processes.
Gate, Shield and clustered Shield run the same forward-auth workloads. Each response is consumed
and status-checked; batch throughput includes client scheduling and loopback overhead. Sessions,
authenticated WAF decisions, cross-node solution rejection in cluster mode, replicated honeypot
bans and one-member-loss serving are checked separately. The cluster uses temporary directories and tests loopback PSK and mutual TLS with ephemeral
CA-signed node certificates. WAN performance, reverse-proxy origin costs and
sustained forensic backlog capacity are not measured here. Rate quotas remain local. Cluster
challenges require issuer routing; spent state is not durable across restarts.

`console-impact-latest.json` is written by `zig build console-impact` (`benchmarks/console_impact.py`).
It builds a console-free and a console binary, runs four daemons at once (console compiled
out, compiled in but disabled, idle with an initialized administrator, and serving eight live
WebSocket dashboards), and interleaves wrk rounds in rotating order over admitted, challenged,
denied and policy-reload workloads. Each configuration is compared with the compiled-out
baseline by median throughput and median p99 with a bootstrap interval; the gate is at most
1% throughput loss and 10% p99 increase. A baseline whose own spread exceeds 1%, or an interval
that straddles the gate, is reported as inconclusive and fails the run rather than passing.
`--cluster` repeats the matrix with three PSK nodes and load on node 1 and writes
`console-impact-cluster-latest.json` instead. Peak RSS is sampled from `ps` every 100 ms. The
host must be declared with `--host-label` and left quiet.

No benchmark hook or timer is linked into request handling. Production metrics, local locks,
reader-count atomics and incident enqueue still have real costs. These tests cannot establish
zero total request overhead, universally optimal algorithms, or global network-edge equivalence.

`zaxonlite-isolation-20260907.json` records the dependency's own three-node, single-client
benchmark and a standalone replication failure. Full-sync 256-byte writes reached 63/s
with TLS and 65/s with PSK on this M1; these are transaction rates, not HTTP or forensic
ingestion rates. See [upstream issue #5](https://github.com/insanai/zaxonlite/issues/5).
The standalone upstream diagnostic has been removed; the historical evidence remains archived.

Earlier committed results containing `anubis-model` are historical, unsupported fixed models,
not measurements of another product. They are not emitted by the corrected harness and must
not support speedup claims. Earlier spent-set batches reused tags, and the two bot matchers did
not search equivalent pattern sets; those rows are not directly comparable to corrected runs.

The v0.6.1 dependency update is validated in
[the follow-up review](../../docs/reviews/2026-09-07-zaxonlite-061.md). Current
`distributed-latest.json` passes Gate, Shield, PSK and mTLS, including ban propagation
after leader loss. Each result now records the dependency URL/hash and externally checks
node logs for chain mismatches. The earlier v0.6.0 failure remains in its timestamped file.
