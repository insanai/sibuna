#import "theme.typ": *
#import "figures.typ": *
#import "products.typ": proxy_meta_line, proxy_table
#import "product_admission.typ": admission_meta_line, admission_http_table, admission_operations_table, bootstrap_work_line
#import "crs_request_path.typ": crs_meta_line, crs_table

#part_page("VIII", [Empirical Evaluation], [
  We measure primitive costs, complete HTTP products, admission operations, distributed
  behavior and replicated-cluster costs. The console has a separate isolation acceptance
  matrix. Every number is rendered from a results file at build time; its header identifies
  the tested revision and host. The 4 October three-product comparisons run Sibuna v0.2.0,
  Anubis and BunkerWeb with the products and generator on separate physical hosts.
  The primitive suite identifies its current clean revision and Zig version in the figure
  metadata. It measures primitives with native CRS disabled, not the cost of a loaded CRS
  generation. Earlier loopback product,
  admission, distributed and cluster records retain their historical revisions and do not
  qualify the current release.
  A functional pass and an inconclusive isolation measurement answer different questions.
])

== Methodology

#objectives([
  By the end of this chapter, you should be able to reproduce every number in this part, say
  what each harness includes and excludes, explain what the spread column means, and tell a
  measured figure from a published one.
])

The performance harnesses live under `benchmarks/`:

#table(
  columns: (1fr, 1.6fr, 1.6fr),
  table.header([*Harness*], [*What it measures*], [*Results file*]),
  [`benchmark.zig` via `run-all.sh`], [Primitive latencies in `ReleaseFast`, seven batches, median with min–max spread; host, binary and module sizes, idle memory], [`results/latest.json`],
  [`compare.py`], [Admission operations per second against a real Anubis binary over loopback HTTP: session check, unauthenticated check, challenge bootstrap, proof verification], [`results/admission-comparison-latest.json`],
  [`tools.py`], [Whole products under `wrk`: throughput, latency percentiles, CPU time per request, peak resident memory, for Sibuna Gate, Sibuna Shield, and Anubis in forward-auth and reverse-proxy modes], [`results/tools-comparison-latest.json`],
  [`distributed.py`], [Three daemons with six client processes: Gate, Shield, and replicated Shield; session portability, WAF denial with a session, ban propagation, leader loss], [`results/distributed-latest.json`],
  [`cluster.py`], [One node and three local replicated nodes under `wrk`, including idle CPU, memory, transport and failover checks], [`results/cluster-latest.json`],
  [`bunkerweb.py`], [Three native Linux products: unconditional HTTP/1.1 proxy and inspection profiles, with a separate load host], [`results/products-proxy-two-host-latest.json`],
  [`admission_http.py`], [Real sessions, challenges, allowed paths and attacks under wrk; native proxy and forward-auth modes], [`results/products-admission-http-two-host-latest.json`],
  [`admission_operations.py`], [Native challenge bootstrap, fresh proof and session operations from two remote Python clients], [`results/products-admission-operations-two-host-latest.json`],
  [`crs_request_path.py`], [Native CRS disabled, Audit and Enforce at paranoia 1 and 2; small GET, JSON, multipart and SQL-injection requests with eight dashboards on separate load and service hosts], [`results/crs-request-path-two-host-latest.json`],
)

The primitive suite times batches of many thousand operations; per-operation percentiles are
not reported because a clock read costs as much as the work. The HTTP harnesses report what
`wrk` reports: request counts, and per-request latency percentiles that `wrk` computes from
its own histogram. Except for the three-product and native CRS comparisons described below, CPU
time is the product process's accumulated user and system time from
`ps`, read before and after each run; memory is the peak resident set sampled every 100 ms.
On the Linux containers used for the release review, `ps` reports whole CPU seconds, so
short runs cannot resolve small changes in CPU cost. Request rate and latency come from
the load generator's independent wall clock and histogram; CPU-accounting precision does
not change those measurements. Container permissions do not grant control over the host's
processor governor or other tenants. Resource conditions and uncertainty belong with each
record rather than being assumed to match a dedicated machine.
The three-product and native CRS families instead sum the live product tree's `/proc`
user/system ticks; shared pages may be counted more than once in their peak summed RSS.
Their CPU-accounting interval includes the remote generator invocation, while request
latency and throughput use the generator's own timed workload.

The historical Linux admission and whole-product comparisons give every product thread the same allowed
CPU set before warmup: two CPUs for admission and four by default for whole products. A Sibuna
accept-thread count is not a CPU budget equivalent to Go's `GOMAXPROCS`. Each product row records
its affinity; the origin and load generator keep native scheduling. Admission issuance reserves
a large challenge allowance to measure successful operations rather than the production
limiter's default exhaustion behavior. The comparison records that allowance explicitly.
An idle CPU figure of zero over ten seconds means `ps` did not cross a whole CPU second;
it does not prove that a node performed no background work.

#callout([Measurement scope], [
  Only host measurements are emitted. Anubis runs from its release binary; BunkerWeb runs
  natively from its verified official image in a private mount namespace. SafeLine and
  Cloudflare remain unmeasured in this chapter; their published facts are identified
  separately. Timers surround batches; state resets and warmup are untimed. Allocation counts
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

== Historical Loopback Whole-Product Comparison

These loopback records predate the v0.2.0 request path and use a different fixture from the
current three-product measurements below. They document the earlier design investigation;
compare their rows within their own recorded run.

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

A later run pinned every product to the same four CPUs for an equal budget. It showed
Sibuna's reverse-proxy 99th percentile at 35–45 ms against Anubis's 11 ms, with occasional
stalls of over 100 ms. The cause was the locks on the request path: the origin pool, the rate
limiter's shard, the idle table and the origin attachment were all spinlocks. Every benchmark
request comes from one address, so they all hit one rate-limiter shard. With about seventy
connection threads on four CPUs, a thread could be preempted while holding a lock, and the
waiters then spun through their time slices while the holder waited behind them. These locks
now spin briefly and then sleep on a futex (`core.Lock`), so a preempted holder gets its CPU
back.

The same change enabled `TCP_NODELAY` on client and origin sockets. Without it, an origin that
flushes its head before its body costs every response a delayed acknowledgement, about 40 ms
on Linux. The tables above are from the run after both changes. A separate A/B run measured
the reverse proxy at an equal open-loop rate of 20,000 requests per second with `wrk2`. The
99th percentile was 17–33 ms before the change, 1.9 ms after it, and 5.7 ms for Anubis.
Those equal-rate figures are not in a result file, which is why they appear only in this
paragraph.

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

== Three-Product Proxy and Inspection Comparison

This comparison asks what an HTTP request costs when it is proxied or inspected. It does
not measure browser challenges, AI-bot identification, false positives, or attack-detection
coverage. All three products use unconditional admission policies. Gate and the BunkerWeb
CRS-off profile, together with Anubis, provide proxy baselines; Shield and the two CRS-on
profiles enable inspection.

Sibuna v0.2.0 is built on the product host with Zig 0.17.0 at `ReleaseSafe`, using the
native target, stripped, with storage and console
compiled in but inactive. BunkerWeb 1.6.15 comes from its official Linux amd64 image,
resolved by SHA-256 digest, with nginx 1.30.5 and the shipped OWASP CRS 4.29.0 rules. Its
configuration generator and security modules are unchanged. Anubis uses its verified official
v1.27.0 binary and native Go upstream transport defaults. The BunkerWeb image runs natively
through
`chroot` in a private mount namespace, without Docker, CPU emulation or a container network
bridge. The result file records the immutable image digest, rule revision, configuration,
tool versions, executable digest and source digest.

`python3 benchmarks/bunkerweb.py --rootfs <unpacked-image>/rootfs --image <oci-layout>
--anubis <release-binary> --load-host <ssh-destination> --target-host <product-address>`
starts a separate Caddy origin
and drives four identical requests over HTTP/1.1:
an ordinary GET, an approximately 8 KiB JSON POST, a SQL-injection query and a SQL-injection
JSON POST. The admitted response body is 41 bytes. The JSON fixture fits within Sibuna's
8 KiB inspection prefix; this does not measure large-upload inspection.

The principal comparison runs the products on `10.175.52.18` and the load generator on
`10.175.52.20`, containers on different physical hosts. The origin stays on the product host
and is contacted over loopback by every proxy. The direct-origin row crosses the same
client-to-server network as the product rows. Every product gets four allowed logical CPUs;
the origin gets two different allowed logical CPUs and the remote load generator gets two
on its own host. Runs use 64 keep-alive connections and two load threads,
one second of warmup followed by five timed seconds, repeated five times. Product order
rotates between rounds. Browser challenges, feeds, compression, access and audit logging,
and management services are inactive. BunkerWeb upstream keepalive is explicitly enabled.
Sibuna retains its rate-limit check with a high allowance to avoid quota exhaustion.

#proxy_meta_line()

=== Admitted Requests

#proxy_table()

Throughput is the median with the observed min–max range, not a confidence interval. p99
is the median of each run's histogram percentile under this fixed-concurrency load; it is
not latency at an equal offered request rate. CPU sums live process user/system ticks from
`/proc`, including nginx workers, rather than the master's time alone. Peak summed process
RSS includes shared pages more than once and is not proportional memory. The origin's CPU
is excluded from product rows and measured separately in the direct-origin baseline.
The direct-origin row is a fixture reference, not a mathematical throughput ceiling;
its external transport and two-CPU allowance differ from an origin behind a four-CPU proxy.
In the two-host run, the CPU-accounting interval also brackets the SSH generator invocation;
SSH setup and result transfer are outside wrk's request timing and latency histogram.

=== Rejected Requests and Error Pages

#proxy_table(denied: true)

All inspection profiles return `403` for the two attack fixtures. Proxy-only profiles
return the origin response. Every timed response status is counted by a load-generator
hook; transport failures, unexpected statuses or mismatched functional probes invalidate
the run. The result retains all samples, including the proxy-only attack requests.

Sibuna's denial body is 235 bytes. BunkerWeb's stock denial body is 69,282 bytes and includes
its dynamic error-page rendering cost. A second CRS-on profile uses a 235-byte static page
through supported custom nginx configuration. Its internal URI error redirect converts
POST to GET for the static handler while preserving the final `403`; CRS still decides
whether to block. Reporting both configurations avoids attributing all rejection cost
to inspection. The custom page and configuration are part of the committed fixture.

#callout([Different protection, one request fixture], [
  BunkerWeb's #link("https://docs.bunkerweb.io/1.6.15/features/#modsecurity")[ModSecurity/CRS profile] parses request bodies, evaluates its broader rule set
  and retains response-body inspection. The Sibuna v0.2.0 profiles measured here use bounded
  heuristic detectors without CRS. Version 0.3.0 adds native CRS; its separate measurement
  family below uses a different fixture. These throughput rows cannot establish equivalent
  protection or superior bot detection. The host is an unprivileged container on a shared machine;
  processor frequency and other tenants are outside the fixture's control. Separate logical
  CPU sets do not establish exclusive physical cores. Consult the recorded spread and
  reproduce on your deployment host before using the figures for capacity planning.
  The controller monitored progress and staged verification code over SSH during the network
  run; no compiler or competing product benchmark overlapped it. This is not an isolated
  network-capacity test.
], kind: "warning")

=== Loopback Baseline

An earlier run kept the generator on the product host, with separate logical CPU sets for
product, generator and origin. Its application code, workloads and load settings match
the two-host run. The table shows ordinary GET requests; its result file retains all four
workloads. These measurements answer a different question from requests crossing a network
and are never pooled with the two-host samples.

#proxy_meta_line(loopback: true)
#proxy_table(loopback: true)

The replay procedure is in `benchmarks/results/README.md`. This comparison adds a current
measurement family; it does not rerun or pass the separate console-impact acceptance gate.

== Three-Product Protected HTTP Comparison

`admission_http.py` uses the same two-host topology, origin, CPU allowances and wrk settings
as the proxy comparison. It obtains a genuine session by solving and verifying each
product's native SHA-256 challenge. Work is matched at 16 leading zero bits: Sibuna takes
bits, Anubis takes four hexadecimal digits, and BunkerWeb's shipped JavaScript challenge
requires four zero hexadecimal digits. Solving is outside HTTP timing. Every request uses
the same browser headers, including `Accept-Encoding: gzip`; Anubis's native challenge
compression stays active. Synthetic forwarded addresses are trusted only inside this fixture.

The four workloads are a protected request with a valid session, the same request without
a session, an explicitly allowed static path and a SQL-injection query with a valid session.
Sibuna Shield and BunkerWeb with CRS must deny the attack. All other admitted proxy responses
must match the origin body exactly. Timed and warmup response counts, transport errors and
positive/negative probes are checked; a failure prevents publishing the record.

#admission_meta_line()

=== Reverse-Proxy Mode

With no session, Sibuna and Anubis serve challenge HTML (`200`). BunkerWeb returns a `302`
redirect to `/challenge`; its following HTML request is part of bootstrap in the operation
comparison below. The initial-response rows have different byte counts and work, so they do
not rank a complete browser challenge journey.

#admission_http_table("reverse_proxy", ("admitted", "challenged"))
#v(4mm)
#admission_http_table("reverse_proxy", ("allowed_static", "attack"))

=== Native Forward-Auth Mode

Sibuna and Anubis answer authorization checks without an origin relay; missing sessions
return `401`. BunkerWeb has no native forward-auth endpoint in this fixture and is omitted
from this table rather than treating its proxy response as equivalent.

#admission_http_table("forward_auth", ("admitted", "challenged", "allowed_static", "attack"))

== Three-Product Admission Operations

`admission_operations.py` runs two Python client processes on the separate generator host.
It reports seven batches of 200 operations for session checks, missing-session checks and
complete bootstrap journeys, and seven batches of 32 fresh proofs. SHA-256 proofs are solved
at 16 bits before timing and verified once. Bootstrap includes two HTTP requests for Sibuna
(HTML and JSON), one for Anubis (HTML), and two for BunkerWeb (redirect and HTML). Request
counts and native expected statuses are retained, as is the observed adaptive issuance
range for Sibuna's bootstrap workload.

#admission_meta_line(operations: true)
#admission_operations_table(("valid_session", "unauthenticated_check"))
#v(4mm)
#admission_operations_table(("proof_verification", "challenge_bootstrap"))
#bootstrap_work_line()

Sibuna and Anubis use forward-auth here. BunkerWeb session checks include the origin relay;
its proxy rows are not pure authorization costs. Anubis's Ed25519 and optional HS512 session
schemes are separate cases. Operation rates include Python, IPC, connection setup and HTTP,
so they describe the whole journey with two clients, not native verifier speed or maximum
server capacity. SSH transfer and proof solving are outside the generator's clock. CPU
accounting includes the controller's SSH interval; tick deltas too small to resolve are
reported as unresolved. No per-operation percentile is inferred from these batch rates.

The replay commands and every sample are in `benchmarks/results/README.md`. These fresh
HTTP and admission families do not rerun primitive, cluster or console-impact acceptance
matrices, and they do not measure detection quality.

== Native CRS Request Path

`benchmarks/crs_request_path.py` measures what SID 0010's native Core Rule Set costs on the
request path. One console-enabled binary runs every profile with eight signed-in dashboards:
CRS disabled, then Audit and Enforce at paranoia levels one and two with stock CRS 4.30.0,
default thresholds and the default 128-million-unit work budget. The lightweight inspector
stays disabled, so the rows isolate CRS evaluation. Sibuna runs on `10.175.52.18` with four
allowed logical CPUs and a Caddy origin on two others; `wrk` runs on `10.175.52.20`, a
different physical host, over HTTP/1.1 with 16 keep-alive connections. Profile order rotates
between rounds and response hooks validate every status.

The workloads are a small GET, an 8 KiB JSON POST, a 16 KiB multipart upload with one text
file, and a SQL-injection query. Enforce answers the last with 403 and closes the connection,
so that row includes a reconnect per request; Audit relays it. Peak RSS is summed over the
process tree.

#crs_meta_line()
#crs_table(("disabled", "audit-pl1", "enforce-pl1"))
#v(4mm)
#crs_table(("audit-pl2", "enforce-pl2"))

The disabled JSON and multipart rows are bounded by the network between the hosts, as in the
three-product JSON rows, so their CPU column is the better baseline. No sample exhausted the
work budget, and Audit and Enforce cost the same on admitted traffic.
Body cost scales with inspected bytes: paranoia level one charges about 1,800 work units per
byte of free text, and most of that time is regex scanning and transform pipelines per rule
and value. Peak RSS rises by 29 to 36 MiB over the disabled profile. Slot reservations are
address space, and a page becomes resident only when a transaction touches it.

The measurement changed the implementation. Safe builds fill every new allocation with
`0xAA`, so the first run kept the whole 1 GiB slot reservation resident (920 MiB); slot
scratch is now reserved without that fill. Stack sampling then showed that CRS 941010's tag
exclusion made every later rule merge the transaction view and copy its tags, that the DFA
paid a function call and a budget check per cached byte, and that kernel sorting cleared
scratch on every call. Removing those raised small-GET throughput at paranoia one from about
8,000 to 10,800 requests per second without changing any decision on the engine corpus;
charged work there fell 22% because the skipped merges and tag copies are no longer billed.

These rows are not a comparison with BunkerWeb's CRS profile: that family used 64
connections and a different fixture. Concurrency beyond the slot pool, where CRS sheds load
with 503 after a 50 ms wait, is not measured here.
The recorded revision predates subsequent scratch-initialization, compressed-slot and
startup-restoration corrections. The figures describe that executable; they do not establish
the performance of a later release binary.

== Historical Loopback Admission Comparison

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
