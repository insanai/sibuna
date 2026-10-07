# Benchmark results

Run `sh benchmarks/run-all.sh` for primitive measurements and
`python3 benchmarks/distributed.py` for the three-process HTTP/replication matrix.
Both write timestamped results and update their respective `latest` JSON files.

## Primitive baseline

`latest.json` and `latest-release-030-20261007.json` record clean revision
`d461e7fee9622f5f365fdb37b18acc77dc56608f`, measured on the Linux service container
with Zig 0.17.0 at ReleaseFast. Each row retains seven-batch median, minimum and maximum
latencies. Storage and console are compiled in but inactive; native CRS is disabled.
The idle process measurement uses two workers without a data directory or console listener.
The record identifies the source, executable, dependency and solver module. Its ReleaseFast
executable differs from the ReleaseSafe native-CRS measurements below; idle RSS is 9,996 KiB.

These primitive timings and idle memory do not measure a loaded CRS generation, console
isolation or production throughput. The three-product families below remain measurements
of v0.2.0 and must not be relabelled as native CRS comparisons.

## Native CRS request path

`crs-request-path-two-host-latest.json` and its timestamped copy record clean revision
`d461e7fee9622f5f365fdb37b18acc77dc56608f` (v0.3.0), built on the product host with Zig
0.17.0 at ReleaseSafe. Sibuna runs on `insan@10.175.52.18` with four logical CPUs and a
Caddy origin on two others; `wrk` runs on `insan@10.175.52.20` with 16 connections. Five
profiles (CRS disabled, Audit and Enforce at paranoia 1 and 2, stock CRS 4.30.0, default
thresholds and 128-million-unit work budget) and four workloads (small GET, 8 KiB JSON,
16 KiB multipart, SQL injection in the query) run for five rotated rounds with eight
signed-in dashboards. Every status is validated; no sample reached the work limit.

```sh
python3 benchmarks/crs_request_path.py --candidate <signed-candidate> \
    --load-host <ssh-destination> --target-host <product-address>
```

At paranoia 1 the small GET runs at 10,787 req/s (370 µs CPU per request) against 47,311
with CRS disabled, the 8 KiB JSON POST at 1,151 req/s and the multipart upload at 4,248.
Peak summed RSS is 133.8–140.5 MiB against 104 MiB disabled. Enforce closes the connection after
a denial, so its SQL-injection row includes a reconnect per request. The disabled JSON and
multipart rows are limited by the network between the hosts. This family measures the
request path only; it is not a comparison with the BunkerWeb CRS profile below.
The executable SHA-256 is
`6556a59f140e76b190e1fa582a4cea72c0f1372b37027fd70f610570b0ba81e2`.
The final run followed the scratch-initialization, compressed-slot, startup-restoration and
console-stack corrections, with no competing build or benchmark. Earlier timestamped
records retain their own source and executable identities. Containers still share their
physical hosts; CPU frequency and unrelated host activity are uncontrolled. This family
does not establish the separate SID 0007 console-impact target.

## Three-product comparisons

The fresh 4 October 2026 families use Sibuna v0.2.0 built with Zig 0.17.0 at ReleaseSafe,
Anubis's verified official v1.27.0 Linux amd64 binary, and BunkerWeb's verified official
1.6.15 Linux amd64 image. Products run sequentially on `insan@10.175.52.18`, with the load
clients on `insan@10.175.52.20`, containers on different physical hosts. Every family records
source and executable digests, artifact versions, configuration, affinity and individual samples.

- `products-proxy-two-host-latest.json`: seven unconditional proxy/inspection profiles,
  four workloads, five rounds; 140 validated samples. Adds Anubis to the fixture below.
- `products-admission-http-two-host-latest.json`: genuine sessions, no-session protected
  responses, explicitly allowed static paths and SQL injection with a session. Five native
  reverse-proxy profiles and three native forward-auth profiles, five rounds; 160 samples.
- `products-admission-operations-two-host-latest.json`: session and missing-session checks,
  fresh proof verification and complete challenge bootstrap from two remote Python clients.
  Six product/mode/token configurations, seven batches; 168 operation samples.

Protected comparisons match SHA-256 proof work at 16 leading zero bits (four zero hex digits).
The BunkerWeb JavaScript challenge has that fixed requirement in the shipped image; neither
its challenge code nor its verifier is modified. Every session comes from a real solved proof.
Proof solving is untimed. Synthetic signing secrets and a trusted forwarded address belong to
this private fixture, not a deployment recipe. All protected requests advertise gzip; Anubis's
native challenge compression remains active. Probes decode gzip to validate content.
The unconditional proxy comparison requests identity encoding.

A missing session returns challenge HTML for Sibuna/Anubis reverse proxies, a challenge
redirect for BunkerWeb and 401 for the native forward-auth checks. All timed and warmup HTTP
statuses are counted, transport errors must be zero, and pre/post probes verify the response
class and origin body. BunkerWeb has no native forward-auth endpoint in this fixture, so it
is explicitly omitted from that mode. Its operation session checks include origin relay;
these costs are not interchangeable with pure authorization costs.

Operation batches have 200 operations, or 32 fresh proofs, each split between two remote
Python processes. An operation is the complete native journey: bootstrap has two requests
for Sibuna (HTML + JSON), one for Anubis (HTML) and two for BunkerWeb (redirect + HTML).
Cookies from a bootstrap response are carried into the next request. Every prepared proof
is consumed once; all request counts and statuses are checked. The record retains Sibuna's
observed adaptive issuance difficulty during bootstrap. Two-client rates include Python,
IPC, connection setup and HTTP; they are not server saturation or native verifier timings.
Anubis Ed25519 and optional HS512 sessions have separate rows. CPU intervals include SSH
invocation and tick changes below 0.01 seconds are unresolved; SSH and proof solving are
outside the generator's operation clock.

The earlier `bunkerweb-two-host-latest.json` records the comparison with the products on
`insan@10.175.52.18` and wrk on `insan@10.175.52.20`, containers on different physical hosts.
`bunkerweb-comparison-latest.json` is the separate loopback baseline. Both retain five
five-second samples per workload after one second of warmup, rotating product order,
64 connections and two load threads. The product gets four logical CPUs; the Caddy origin
gets two different logical CPUs on the product host. The generator gets two logical CPUs
on its own host, or two further CPUs for the loopback baseline. Samples are not pooled.

The Sibuna executable is the v0.2.0 application built on the product host with Zig 0.17.0
at `ReleaseSafe`, using the default native target, stripped, with storage and console compiled in but inactive. BunkerWeb is the official
`bunkerity/bunkerweb:1.6.15` Linux amd64 image, with nginx 1.30.5 and CRS 4.29.0. The recorded
manifest and layer digests identify the downloaded artifacts; the fixture does not patch
its configuration generator, ModSecurity or CRS. It runs natively from an unpacked image
inside a private mount namespace, with no Docker daemon or CPU emulation. The scheduler,
database and management UI are not launched.

The six profiles are direct origin, Sibuna Gate, BunkerWeb with ModSecurity/CRS disabled,
Sibuna Shield, BunkerWeb with ModSecurity/CRS enabled, and CRS enabled with a small custom
error page. Each receives the same benign GET, approximately 8 KiB JSON POST, SQL-injection
query and SQL-injection JSON POST. Admission is unconditional; browser challenges are off.
The two attacks must return 403 for every inspection profile and 200 for proxy-only profiles.
Functional probes check the origin body and denial body; a wrk response hook counts every
timed status. A transport failure or unexpected status prevents publication.

The stock BunkerWeb denial body is 69,282 bytes, versus Sibuna's 235 bytes. The additional
CRS profile uses a 235-byte static error page through custom server configuration. Its URI
error redirect changes POST to GET for the static handler and retains status 403. The
shipped `ERRORS` named-location route preserves POST and returned 405 in the preliminary
test, so that route is not used. Both stock and custom-page costs are reported. BunkerWeb
upstream keepalive is explicitly enabled. Access and audit logging, feeds and compression
are disabled; Sibuna keeps its native rate check with a high allowance.

CPU sums `/proc` user/system ticks over the live product process tree, including nginx
workers. Membership changes invalidate the sample. The accounting interval brackets the
generator invocation, including SSH setup for the remote generator; wrk's own duration and
histogram exclude SSH setup and result transfer. Peak summed RSS is sampled every 100 ms
and counts shared pages more than once. Throughput is the median with observed min–max
spread; p99 is the median of the five run percentiles at fixed concurrency, not an
equal-rate latency comparison or a confidence interval.
The direct-origin row has two allowed CPUs and receives external traffic itself; it is a
fixture reference, not a mathematical ceiling for a four-CPU proxy whose origin uses loopback.
The controller monitored progress and staged verification code over SSH during the network
run. Neither a compiler nor another product benchmark overlapped it, but it was not an
isolated network-capacity test.

These shared containers do not control physical-host activity or CPU frequency. HTTP/1.1
proxy and inspection cost is measured; TLS, large uploads, bot-detection accuracy and false
positives are not. BunkerWeb's broader CRS rules, body parsing and response inspection are
not equivalent to the bounded heuristics in the measured Sibuna v0.2.0 profiles. The separate
native CRS family measures v0.3.0 under different workloads and concurrency; it does not
establish a matched BunkerWeb comparison. The fresh three-product families supersede
the older loopback Anubis comparisons for this fixture; historical records remain separate. None passes the console-impact acceptance gate.

Replay on a disposable Linux amd64 benchmark filesystem with Python 3, wrk, Caddy,
`taskset`, `umoci`, and sudo access to `unshare`, `mount` and `chroot`:

```sh
zig build -Doptimize=safe -Dstrip=true -j2
python3 benchmarks/bunkerweb_test.py
python3 benchmarks/bunkerweb_image.py /tmp/bunkerweb-benchmark/image \
  --reference sha256:1b96f672660cc32bfae93604ac297371222dc9039b2b09b8eee5e40ba9d35c35
umoci unpack --rootless --image /tmp/bunkerweb-benchmark/image:benchmark \
  /tmp/bunkerweb-benchmark/bundle
python3 benchmarks/bunkerweb.py \
  --rootfs /tmp/bunkerweb-benchmark/bundle/rootfs \
  --image /tmp/bunkerweb-benchmark/image \
  --anubis /path/to/anubis-1.27.0-linux-amd64/bin/anubis
```

For a separate load host, add `--load-host user@host --target-host <product-address>`.
The generator needs Python 3 and wrk, verified SSH host keys and existing key authentication
from the controller; agent forwarding can supply authentication without copying private
keys. `--load-wrk` and `--load-library-dir` select an existing runtime. The recorded run uses
`/home/insan/sibuna-launch-20261001/runtime/wrk` and its `lib` directory on `.20`.
`--ssh-known-hosts` can select a dedicated file containing the already verified public host
key. The remote profile listens on the product host's network interfaces, so use an isolated
benchmark network. HTTP load goes directly between the hosts, not through SSH.
Run one comparison at a time, with no concurrent builds or other benchmark jobs.

Run `admission_http.py` and then `admission_operations.py` with the same rootfs, image,
Anubis binary and SSH load arguments. The former uses five rounds, 64 connections and the
same five-second timed/one-second warmup settings; the latter uses its seven-batch operation
budgets above. Both products and generator retain the same CPU allowances. For example:

```sh
python3 benchmarks/admission_http.py \
  --rootfs /tmp/bunkerweb-benchmark/bundle/rootfs \
  --image /tmp/bunkerweb-benchmark/image \
  --anubis /path/to/anubis-1.27.0-linux-amd64/bin/anubis \
  --load-host user@load-host --target-host product-address
python3 benchmarks/admission_operations.py \
  --rootfs /tmp/bunkerweb-benchmark/bundle/rootfs \
  --image /tmp/bunkerweb-benchmark/image \
  --anubis /path/to/anubis-1.27.0-linux-amd64/bin/anubis \
  --load-host user@load-host --target-host product-address
```

The two-host records use four product CPUs, two distinct origin CPUs and two generator
CPUs. They refresh HTTP/admission comparisons, not the primitive, cluster or console-impact
matrices. The shared-host caveats below apply to all three families.


The helper downloads and verifies the official OCI image; `umoci` performs extraction.
The namespace wrapper confines every temporary mount to its private namespace and drops
privileges before running the image command. It does not install host packages or change
host services. Fixture daemons and generator temporary files are stopped or removed on exit;
the unpacked image and JSON measurements remain for reproduction.

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

Historical Linux admission and whole-product comparisons pin every product thread to the same allowed
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
answer and is never rewritten. The September console-impact records from the deployment host read
inconclusive (single node: baseline spread above 1%) and fail (cluster: compiled-out
comparison). SID 0007 additionally records a paired reading of the same files, comparing the
console enabled and disabled within one binary, under which the console's runtime cost is at
most 0.8% single-node and 0.5% clustered. That reading is a supplementary analysis adopted by
the project owner as a release note; it does not change a verdict and must not be cited as a
pass of the gate.
`console-impact-cluster-latest.json` retains that historical local-cluster run. Current
cross-host measurements use the separate `console-impact-three-host-*-latest.json` names;
they do not overwrite a file whose topology and fixture differ.

Currency: all five core benchmark families were regenerated
on 1 October 2026 after work-level session binding, the read-by-read proxy relay, the challenge
budget and requirement tickets. The Linux benchmark checkout is `54f2e6a`; its application
code matches `669229c`, with subsequent changes confined to harnesses and documentation.
The recorded dirty flag reflects generated result files and is retained unchanged.
All four single-node mode/capture matrices are also fresh and inconclusive. Baseline
throughput spread ranges from 0.9% to 7.4%; a steadier baseline does not pass when its
confidence interval crosses the gate. All 360 samples pass their post-sample response-state checks and all
active dashboards satisfy delivery and query coverage without transport or subscription errors.
The four selected three-host matrices likewise verify 360 samples and all six peer directions.
All 54 non-baseline configuration comparisons in each topology remain inconclusive.
`linux-launch-review-20261002.json` links every current record with its digest, functional
checks, supplementary paired readings and verified process cleanup. Its performance acceptance
field is false. The five core families and eight impact matrices were current for the 1 October code. Binary sizes are those of the recorded build, including its
symbols and embedded assets; the 34.5 MB Linux binary is not the earlier 3.3 MB macOS artifact.
On 2 October 2026 the request path changed again. Chunked request bodies are accepted (SID
0009), an adaptive lock replaces the request-path spinlocks, and `TCP_NODELAY` is set on client
and origin sockets. The whole-product comparison was regenerated from a clean checkout of
`2e1a7f8` (`tools-comparison-latest-20261002T014905Z.json`). The other four core families, the
eight impact matrices and `linux-launch-review-20261002.json` predate that change and were
not rerun. Rerun them before citing them for the current code.
The primitive suite was regenerated on 3 October for Zig 0.17.0 from clean revision
`b1da948` on the same Linux container. `latest.json` and
`latest-20261003T082823Z.json` identify the source digest and executable. Source manifest
version 3 includes the explicitly migrated Zaxonlite and Paxos 0.7.0 snapshots in `vendor/`;
the original package pins and the compatibility source path are recorded separately.
The earlier Zig 0.16 measurement remains in its timestamped file. Admission, distributed,
cluster and console-impact measurements were not rerun for v0.2.0. Their recorded revisions
and verdicts remain authoritative; this release does not claim the formal impact gate passed.

The whole-product run verifies all 24 expected workload statuses without transport failures.
Its four-CPU allowance applies to both products; request-rate comparisons remain specific to
the supplied Anubis version, configuration, fixture origin and declared host.

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
