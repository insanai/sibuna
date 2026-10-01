#import "theme.typ": *
#import "figures.typ": *

#part_page("VIII", [Empirical Evaluation], [
  We present the measurements recorded by five committed performance harnesses: primitive
  latencies, an admission-only comparison with Anubis, a whole-product comparison under an
  external load generator with CPU and memory accounting, distributed behavior and local
  replicated-cluster costs. The console has a separate isolation acceptance matrix.
  Every number in this part is rendered from a results file at build time. Its header identifies
  the tested revision and host. Historical September records predate the request-path changes
  of 1 October 2026; the October release review regenerates records for that updated path.
  A functional pass and an inconclusive isolation measurement answer different questions.
])

== Methodology

#objectives([
  By the end of this chapter, you should be able to reproduce every number in this part, say
  what each harness includes and excludes, explain what the spread column means, and tell a
  measured figure from a published one.
])

Five performance harnesses live under `benchmarks/`:

#table(
  columns: (1fr, 1.6fr, 1.6fr),
  table.header([*Harness*], [*What it measures*], [*Results file*]),
  [`benchmark.zig` via `run-all.sh`], [Primitive latencies in `ReleaseFast`, seven batches, median with min–max spread; host, binary and module sizes, idle memory], [`results/latest.json`],
  [`compare.py`], [Admission operations per second against a real Anubis binary over loopback HTTP: session check, unauthenticated check, challenge bootstrap, proof verification], [`results/admission-comparison-latest.json`],
  [`tools.py`], [Whole products under `wrk`: throughput, latency percentiles, CPU time per request, peak resident memory, for Sibuna Gate, Sibuna Shield, and Anubis in forward-auth and reverse-proxy modes], [`results/tools-comparison-latest.json`],
  [`distributed.py`], [Three daemons with six client processes: Gate, Shield, and replicated Shield; session portability, WAF denial with a session, ban propagation, leader loss], [`results/distributed-latest.json`],
  [`cluster.py`], [One node and three local replicated nodes under `wrk`, including idle CPU, memory, transport and failover checks], [`results/cluster-latest.json`],
)

The primitive suite times batches of many thousand operations; per-operation percentiles are
not reported because a clock read costs as much as the work. The HTTP harnesses report what
`wrk` reports: request counts, and per-request latency percentiles that `wrk` computes from
its own histogram. CPU time is the product process's accumulated user and system time from
`ps`, read before and after each run; memory is the peak resident set sampled every 100 ms.
On the Linux containers used for the release review, `ps` reports whole CPU seconds, so
short runs cannot resolve small changes in CPU cost. Request rate and latency come from
the load generator's independent wall clock and histogram; CPU-accounting precision does
not change those measurements. Container permissions do not grant control over the host's
processor governor or other tenants. Resource conditions and uncertainty belong with each
record rather than being assumed to match a dedicated machine.

The Linux admission and whole-product comparisons give every product thread the same allowed
CPU set before warmup: two CPUs for admission and four by default for whole products. A Sibuna
accept-thread count is not a CPU budget equivalent to Go's `GOMAXPROCS`. Each product row records
its affinity; the origin and load generator keep native scheduling. Admission issuance reserves
a large challenge allowance to measure successful operations rather than the production
limiter's default exhaustion behavior. The comparison records that allowance explicitly.

#callout([Measurement scope], [
  Only local measurements are emitted. Third-party products are measured only when their
  binary can run on the host: Anubis can, SafeLine (Docker only) and Cloudflare (hosted) cannot,
  and both appear in a "not measured" table with the published facts that stand in for a
  measurement. Timers surround batches; state resets and warmup are untimed. Allocation counts
  are not instrumented: the allocation-free primitive contract is based on API and source
  review. No harness links into the daemon or adds a hook to the request path.
], kind: "warning")

== Primitive Latencies

#benchmark_results_table()
#v(4mm)
#benchmark_chart_block()

=== Proof-of-Work Verification

Hashcash verification hashes a challenge, separator and decimal nonce. The sequential-work
verifier checks graph openings; hash invocations and SHA-256 compression counts differ because
inputs vary in length. The table gives current measurements without treating hardware
results as mathematical constants.

=== Matching, State, and Memory

Dense Aho–Corasick and sequential substring search use identical patterns and any-match
semantics. State benchmarks reset before every batch, so spent-set measurements include real
insertions rather than duplicate rejection. Fixed-capacity structures need no allocator on
these primitive APIs; the harness records unknown allocation counts rather than fabricating
measurements. Engine and table byte counts come directly from `@sizeOf`. Resident memory
includes runtime and thread costs and is measured separately from the primitives.

== Whole-Product Comparison

#objectives([
  Read the throughput, latency, CPU, and memory of Sibuna and Anubis as complete processes,
  understand the four workloads, and see the two design changes this measurement forced.
])

`python3 benchmarks/tools.py --anubis <binary>` starts an origin stub (`caddy respond`), then
each product in turn, obtains a valid session by solving its challenge exactly as a browser
would, and drives four workloads with `wrk` over keep-alive connections:

- *Admitted*: a valid session cookie on a protected path. In reverse-proxy mode the request
  reaches the origin and its answer is relayed; in forward-auth mode the product answers `200`
  itself.
- *Challenged*: no cookie and a browser User-Agent. The product serves its challenge page
  (`200` with HTML in reverse-proxy mode, `401` in forward-auth mode).
- *Allowed static path*: `/robots.txt` from a non-browser client, which both products admit
  without a challenge.
- *SQL injection with session*: a valid cookie plus `q=' OR 1=1--`. Only an inspecting
  product refuses it; the status column records what each product did.

Sibuna uses four accept threads (`--workers 4`) and Anubis uses `GOMAXPROCS=4`; these
settings alone do not impose equal CPU budgets because Sibuna serves bounded connections
on separate threads. On Linux the harness pins every product thread to the same four
allowed logical CPUs before warmup and records the affinity. Other platforms retain native
scheduling. Hashcash difficulty is matched (8 zero bits; 2 zero hex digits), with one fixed
signing secret. Every figure is the median of three five-second runs.

#tools_meta_line()

=== Forward-Auth Mode

The ingress asks the product whether to admit a request; there is no origin and no body relay,
so this is the purest measure of admission cost.

#tools_mode_table("forward_auth")

=== Reverse-Proxy Mode

The product sits in front of the origin stub and relays admitted requests and responses.
Reverse-proxy rows therefore include the origin's own cost and one extra loopback hop.

#tools_mode_table("reverse_proxy")

=== Footprint

#tools_footprint_table()

=== What the Measurement Changed

The first run of this harness measured a version of Sibuna in which each accept thread served
one connection to completion and every proxied response closed the client connection. Under
64 concurrent connections the throughput looked healthy but the 99th-percentile latency was
over 130 ms, because sixty connections waited for four workers, and the reverse-proxy runs
exhausted the host's ephemeral ports with sockets in `TIME_WAIT`. Neither defect was visible
in the primitive suite or in the two-client admission harness. Three changes followed, all
described in Part V: a bounded thread per connection with a `503` overload path, origin
response framing so proxied connections stay open, and a pooled origin connection (the second
run, with framing but a fresh origin connection per request, managed about 1,400 proxied
requests per second before exhausting ephemeral ports). The tables above are from the run
after those changes; the superseded runs are not retained as result files, which is why their
figures appear only in this paragraph, labelled as such.

#callout([Reading the Anubis rows], [
  Anubis is a capable, widely deployed product and this is not a claim that it is slow. It runs
  a garbage-collected runtime, verifies an Ed25519 signature per session check, and keeps
  challenge state in a store; those are design choices with benefits this harness does not
  measure, such as a smaller dependency on the host's threading model. The rows show what a
  request costs each product on one host under one load shape. Its reverse-proxy rows are
  far below its forward-auth rows, with peak memory in the hundreds of megabytes; the most
  likely cause is origin-connection churn under 64 concurrent clients (Go's HTTP transport
  keeps only two idle connections per host by default, and Anubis was run with its default
  flags), but the harness did not confirm that and records only what it observed.
])

=== Not Measured

#tools_not_measured_table()

A row in this table is not a claim about the product's performance. SafeLine's own numbers
concern detection quality, not throughput; Cloudflare publishes plan quotas rather than
per-request costs. Anyone with a Docker host can run SafeLine behind the same `wrk` workloads;
the harness accepts any product that can be started as a process and solved as a browser.

== Admission Comparison

`python3 benchmarks/compare.py --anubis <binary>` measures admission operations with two
Python clients against forward-auth endpoints, so its absolute numbers are limited by the
clients rather than the products. It exists to compare the *shape* of the four operations
across products and token schemes: session check, unauthenticated check, challenge bootstrap
(interstitial plus challenge record), and verification of a fresh proof prepared outside the
timed batch.

#admission_comparison_table()

== A Cluster of Three

#objectives([
  Answer the operator's question directly: does a three-node Sibuna cluster keep the
  security properties, throughput, and latency of one node, and what do replication and
  storage cost in CPU and memory?
])

`python3 benchmarks/cluster.py` runs four cases with the same Shield forward-auth
configuration and two workers per node: one node without storage, one node with the embedded
database, and three replicated nodes over a loopback pre-shared key and then over mutual TLS
with a temporary certificate authority. For each case `wrk` drives node 1 alone and then all
nodes at once (one load generator per node, requests summed, CPU summed over nodes, latency
the worst of the three). Before any load the harness measures ten idle seconds, so the cost of
consensus heartbeats and storage polling appears as a percentage of one core per node.

#cluster_meta_line()

#cluster_throughput_table()

The security checks run on every case before the load: a session minted by node 1 is accepted
by every node (shared seed); a request carrying that valid session but an SQL-injection query
is refused by every node; a solution already spent on node 1 is rejected when replayed to
node 2 (challenges are issuer-bound); a honeypot hit on node 1 bans the address on the other
nodes within the propagation time shown; and after the elected leader is stopped the survivors
keep admitting requests and still propagate a fresh ban.

#cluster_parity_table()

#callout([What the cluster costs], [
  Per-node throughput and tail latency in the cluster rows should be read against the
  single-node rows in the same table, not against the four-worker figures earlier in this
  part. The differences that matter to an operator are the idle CPU and resident memory
  columns, which are what replication and the embedded database add to a quiet node, and the
  all-nodes rows. Three daemons and three load generators share the benchmark host's CPU,
  memory and loopback network; the aggregate does not establish throughput on three separate
  hosts. CPU microseconds per request and idle costs also depend on that host and the
  accounting resolution. Read the measured rows and their provenance without assuming linear
  scaling or identical CPU cost across transports. Cross-host acceptance additionally tests
  the actual network, peer authentication, failover and quorum loss.
])

== Distributed Measurement

`python3 benchmarks/distributed.py` starts three real daemons, first Gate and Shield without
replication, then Shield with replicated storage over a loopback pre-shared key and over
mutual TLS. Six external client processes generate keep-alive forward-auth requests. Seven
batches report throughput including client and loopback costs; response statuses are checked.
Session portability, WAF denial with a valid session, issuer-bound challenge rejection,
replicated ban propagation, and serving after the elected leader is stopped are checked
separately and appear in the last columns.

#distributed_results_table()

The harness adds no per-request instrumentation to Sibuna. It does not remove the daemon's
production metrics, locks, snapshot atomics or incident enqueue costs. WAN behaviour, global
quotas, durable replay state, reverse-proxy origin latency and sustained overload remain
outside these measurements.

#exercise([8.1], [
  Run `sh benchmarks/run-all.sh` on your machine, rebuild the book, and compare the
  Hashcash verification and token verification rows with the reference host. Which of the two
  depends most on hardware hash instructions, and why?
])

#exercise([8.2], [
  In the forward-auth table, divide CPU microseconds per request by the number of cores busy
  and compare with the measured latency. Why is the per-request CPU cost higher than the
  primitive classification cost from the first table, and which components account for the
  difference?
], hint: [List everything between `accept` and the flushed response that the primitive suite does not time.])

#teach_back([
  Explain the difference between a median-of-batches figure and a per-request p99, why the
  primitive table reports the former and the product table the latter, and what each can and
  cannot reveal about a tail-latency defect.
])
