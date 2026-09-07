#import "theme.typ": *
#import "figures.typ": *

#part_page("VIII", [Empirical Evaluation], [
  We present the benchmark results recorded on bare metal, explain how they were measured,
  and trace each number to the mechanism that produces it.
])

== Methodology

#objectives([
  By the end of this chapter, you should be able to reproduce every number in this part,
  explain what the spread column means, and say precisely which figures are measurements and
  which are source-audited expectations.
])

The suite in `benchmarks/benchmark.zig` is built in `ReleaseFast` and run by
`sh benchmarks/run-all.sh`, which also records the host, CPU, operating system, git revision,
binary and module sizes, and the daemon's idle resident memory, then writes
`benchmarks/results/latest.json`. This chapter renders that file at compile time; nothing here
is typed by hand.

Each workload runs seven independent batches of many thousand operations. The table reports
the per-operation cost of the *median* batch and the *min–max spread* across batches. Timing
every single operation would perturb work that costs tens of nanoseconds, so no per-operation
percentiles are reported; earlier drafts that derived "p99" figures from a multiplier have been
removed.

#callout([Measurement scope], [
  Only local measurements are emitted. Earlier fixed competitor models had no reproducible
  provenance and were removed. Timers surround batches; state resets and warmup are untimed.
  Allocation counts are not instrumented: the allocation-free primitive contract is based on
  API and source review. The harness is a separate executable, with no hooks in the daemon.
], kind: "warning")

#v(4mm)
#benchmark_results_table()
#v(6mm)

== Reading the Numbers

#objectives([
  Trace each measured latency to its mechanism.
])

=== Proof-of-Work Verification

Hashcash verification hashes a challenge, separator and decimal nonce. The sequential-work
verifier checks graph openings; hash invocations and SHA-256 compression counts differ because
inputs vary in length. The table above gives current measurements without treating hardware
results as mathematical constants.

=== Matching, State, and Memory

Dense Aho–Corasick and sequential substring search now use identical patterns and any-match
semantics. State benchmarks reset before every batch, so spent-set measurements include real
insertions rather than duplicate rejection. Fixed-capacity structures need no allocator on
these primitive APIs; the harness records unknown allocation counts rather than fabricating
measurements. Engine/table byte counts come directly from `@sizeOf`. Resident memory includes
runtime and thread costs and is measured separately from the primitives.

=== Distributed HTTP Measurement

`python3 benchmarks/distributed.py` starts three real daemons, first Gate and Shield without
replication, then Shield with replicated storage. Six external client processes generate
keep-alive forward-auth requests. Seven batches report throughput including client and loopback
costs; response statuses are checked. Session portability, WAF denial with a valid session,
issuer-bound challenge rejection, replicated ban propagation and one-member-loss serving are
checked separately. Results are in `benchmarks/results/distributed-latest.json`.

The harness adds no per-request instrumentation to Sibuna. It does not remove the daemon's
production metrics, locks, snapshot atomics or incident enqueue costs. Both development PSK and mutual TLS are exercised on loopback. WAN behavior, global quotas, durable replay state,
reverse-proxy origin latency and sustained overload remain outside these measurements.

#exercise([8.1], [
  Run `sh benchmarks/run-all.sh` on your machine, rebuild the book, and compare the
  Hashcash verification and token verification rows with the reference host. Which of the two
  depends most on hardware hash instructions, and why?
])

#teach_back([
  Explain the difference between a median-of-batches figure and a per-operation p99, and why
  the book reports the former.
])
