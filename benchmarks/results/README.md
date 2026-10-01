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

The admission comparison reserves a large challenge budget (`--challenge-rate-limit 100000000`)
so timed issuance and fresh-proof verification batches measure successful operations. The
production limiter check still runs; its default allowance and exhaustion behavior are not
measured by this comparison. The result records the fixture allowance explicitly.

Linux admission and whole-product comparisons pin every product thread to the same allowed
CPU set before warmup: two CPUs for admission, `--workers` CPUs for whole products. This
matches CPU capacity rather than treating Sibuna accept threads as equivalent to Go's
`GOMAXPROCS`. The origin and load generator retain native scheduling, and each product row
records its affinity. On platforms without this API the affinity is null.

Distributed results use three real daemon processes and six external Python client processes.
Gate, Shield and clustered Shield run the same forward-auth workloads. Each response is consumed
and status-checked; batch throughput includes client scheduling and loopback overhead. Sessions,
authenticated WAF decisions, cross-node solution rejection in cluster mode, replicated honeypot
bans and one-member-loss serving are checked separately. The cluster uses temporary directories and tests loopback PSK and mutual TLS with ephemeral
CA-signed node certificates. WAN performance, reverse-proxy origin costs and
sustained forensic backlog capacity are not measured here. Rate quotas remain local. Cluster
challenges require issuer routing; spent state is not durable across restarts.

`console-impact-latest.json` is written by `zig build console-impact` (`benchmarks/console_impact.py`).
It builds a console-free and a console binary, runs one configuration at a time (console
compiled out, compiled in but disabled, idle with an initialized administrator, or serving eight
live WebSocket dashboards), and interleaves wrk rounds in rotating order over admitted, challenged,
denied and policy-reload workloads. Each configuration is compared with the compiled-out
baseline by median throughput and median p99 with a bootstrap interval; the gate is at most
1% throughput loss and 10% p99 increase. A baseline whose own spread exceeds 1%, or an interval
that straddles the gate, is reported as inconclusive and fails the run rather than passing.
`--cluster` repeats the matrix with three PSK nodes and load on node 1 and writes
`console-impact-cluster-latest.json` instead. Peak RSS is sampled from `ps` every 100 ms. The
host must be declared with `--host-label` and left quiet.

Formal verdict versus paired reading: the `verdict` field of a result is the gate's own
answer and is never rewritten. The console-impact records from the deployment host read
inconclusive (single node: baseline spread above 1%) and fail (cluster: compiled-out
comparison). SID 0007 additionally records a paired reading of the same files, comparing the
console enabled and disabled within one binary, under which the console's runtime cost is at
most 0.8% single-node and 0.5% clustered. That reading is a supplementary analysis adopted by
the project owner as a release note; it does not change a verdict and must not be cited as a
pass of the gate.

Currency: the performance figures in the latest files were measured before the request-path changes of 1 October 2026
(work-level session binding, the read-by-read proxy relay, the challenge budget and requirement
tickets). Those changes alter admission and relay work per request, so primitive, whole-product,
distributed and console-impact figures describe the earlier code until the harnesses are rerun.

`linux-functional-review-20261001.json` records verification after those changes: 588 native
tests, the clustered console suite, the shipped Wasm behavior test and functional checks on
three separate physical hosts. `chrome-release-review-20261001.json` records the connected
Chrome walkthrough of evidence states, exact clipboard contents, a private policy preview,
navigation, mobile filters and the moving globe. These records establish the checks stated
within them; they are separate from performance measurements and field browser targets.

The timestamped `console-impact-three-host-*-20261001*.json` records exercise three
unprivileged containers on separate physical hosts with mutual TLS consensus and validated
TLS management transport. The first forward-auth/capture-off record, ending at 14:41 UTC,
overlapped a benchmark job in another container sharing node 3's physical host; retain it as
exploratory, not quiet acceptance evidence. The other three matrices ran after that job stopped.
All four have valid statuses, dashboard delivery and peer coverage, with formal verdicts of
inconclusive. A fifth matrix repeated forward-auth/capture-off without the overlapping job;
it also reports inconclusive, with 2.5–3.9% baseline spread. The four
`console-impact-three-host-*-latest.json` files select that repeat and the other three matrices.
The repeat's active throughput loss is 1.5–3.4% versus compiled out; the supplementary paired
loss versus disabled is 0.9–3.5%. Container CPU controls and host activity remain outside the
fixture's control; these measurements do not isolate a cause or establish performance acceptance.
Their `meta.source_provenance` identifies the exact tested build; `meta.git` in
the original SSH controller identifies its checkout at record time. The supplementary
`linux-launch-harness-20261001.json` preserves the exact fixture controllers and replay inputs
without exporting private keys or temporary credentials.

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
