#let sid-number = "0002"
#let sid-title = "Sibuna: Foundation Architecture, Delivery Plan, and Performance Contract"
#let sid-state = "published"
#let sid-created = "2026-09-07"
#let sid-discussion = "Foundational architectural specification, zero-allocation pipeline, two-tier proof-of-work engine, keyed-hash session tokens, product surfaces, measured performance contract, and delivery record for the Sibuna pure-Zig monorepo"
#let sid-labels = ("architecture", "firewall", "pow", "performance",)
#let sid-authors = ("Sibuna Contributors <team@sibuna.local>",)
#let sid-category = "Architectural Specification"
#let sid-status = "Published"
#let sid-last-updated = "2026-10-03"

#import "../../shared/sid.typ": sid-document

#let ink = rgb("172033")
#let blue = rgb("0284c7")
#let blue-light = rgb("f0f9ff")
#let green = rgb("16a34a")
#let green-light = rgb("f0fdf4")
#let amber = rgb("d97706")
#let amber-light = rgb("fffbeb")
#let red = rgb("dc2626")
#let red-light = rgb("fef2f2")
#let gray = rgb("64748b")
#let rule = rgb("cbd5e1")

#let callout(title, body, fill: blue-light, stroke: blue) = block(
  width: 100%,
  breakable: true,
  inset: 10pt,
  radius: 6pt,
  fill: fill,
  stroke: 0.8pt + stroke,
)[
  #text(weight: "bold", fill: stroke)[#title]
  #v(0.3em)
  #body
]

#let milestone(name, outcome, exit, state: "delivered") = block(
  width: 100%,
  breakable: true,
  inset: 10pt,
  radius: 6pt,
  stroke: 0.7pt + rule,
)[
  #text(weight: "bold", fill: blue)[#name]
  #h(6pt)
  #box(inset: (x: 5pt, y: 2pt), radius: 3pt, fill: if state == "delivered" { green-light } else { amber-light })[
    #text(size: 8.5pt, weight: "bold", fill: if state == "delivered" { green } else { amber })[#state]
  ]
  #v(0.2em)
  *Outcome:* #outcome \
  *Exit criterion:* #exit
]

#show: doc => sid-document(
  sid-number,
  sid-title,
  doc,
  authors: sid-authors,
  state: sid-state,
  created: sid-created,
  discussion: sid-discussion,
  labels: sid-labels,
  category: sid-category,
  status: sid-status,
  last-updated: sid-last-updated,
)

#callout([Implementation review — 2026-09-07], [
  This revision follows code review and regression tests. Performance results live in
  `benchmarks/results/latest.json` and `distributed-latest.json`; earlier fixed latency tables
  and unsupported competitor cost models have been removed. Measurements are host-specific,
  not proofs of optimality or deployment capacity.
])

#callout([Whole-product measurement — 2026-09-07, later the same day], [
  Driving the daemon with an external load generator (`benchmarks/tools.py`, results in
  `tools-comparison-latest.json`) exposed three limits invisible to the primitive suite:
  accept threads served one connection to completion (tail latency over 100 ms at 64
  clients), every proxied response closed the client connection, and every proxied request
  opened a new origin connection (about 1,400 requests per second before ephemeral-port
  exhaustion). The request contract below now describes bounded per-connection threads with a
  `503` overload path, origin response framing, and a pooled origin connection with one safe
  retry.
])

= Decision

Sibuna provides two product surfaces from one Zig binary. Persistent storage and distributed
edge deployment are options for these surfaces, not a third product.

#table(
  columns: (1fr, 2fr, 2fr),
  table.header([*Capability*], [*Gate (`--gate`)*], [*Shield (`--shield`, default)*]),
  [Admission], [Hashcash or sequential-work browser challenge; bound session token], [Same],
  [Policy], [Declarative rules, bot signatures, CIDR reputation], [Same],
  [Flood controls], [GCRA, honeypot, temporary bans], [Same],
  [Payload inspection], [Disabled], [SQL injection, XSS, traversal, command-injection heuristics],
  [Deployment], [Reverse proxy or forward auth], [Reverse proxy or forward auth],
  [Optional state], [Embedded persistent policy and reputation], [Also WAF incident forensics],
  [Distributed deployment], [Cluster build and configured members], [Same],
)

= Request contract

The server runs bounded blocking accept threads (`--workers`, one per CPU by default). Each
accepted connection is served on its own thread with a one-megabyte stack, so a slow or idle
peer never delays another connection; the number of connection threads is bounded by
`--max-connections` (1,024 by default), beyond which the accept loop answers `503` and closes
the socket without spawning, counting the event in `sibuna_overloaded_total`. Pre-parse
refusals render into a bounded buffer and share a 100 ms send/lingering-close budget, draining
at most 64 KiB of late input so ordinary clients receive the response before closure. A peer
that withholds input or close cannot hold the accept loop indefinitely. A finished
connection thread still owns its stack until it is joined, and it is joined when its slot is
next taken, so slots are taken lowest first and the number of allocated stacks follows the
connections currently open rather than the number served. The idle reaper
closes connections silent for longer than `--idle-timeout`. Each active connection owns a
64 KB read buffer, with a 16 KB head limit, and bounded write buffers. HTTP/1.0 and HTTP/1.1 are supported.
Chunked request bodies are decoded in place and re-framed for the origin (SID 0009); other
transfer codings are refused with 501. Invalid header
names, request-line control bytes, conflicting lengths, and invalid decimal lengths are refused.
Truncated bodies fail closed. Requests whose declared body exceeds the buffered prefix do not
reuse the client connection after a local response.

The response path applies these checks in order:

+ Local ban table.
+ Reserved internal routes (assets, challenge issuance, verification, honeypot, health, metrics).
+ Local GCRA admission.
+ Active policy snapshot: Shield inspection, reputation, ordered rules, scoring, static paths,
  bot signatures and default admission.
+ A valid session satisfies an admission challenge; it never overrides a denial or WAF finding.
+ An admitted reverse-proxy request streams to the origin; forward auth returns a verdict.
  The proxy reads the origin's response head (at most 16 KB), classifies the body framing
  by RFC 9112 (no body, `Content-Length`, chunked, or close-delimited), relays it exactly, and
  keeps the client connection open unless the response was close-delimited. Origin sockets
  left at a clean boundary by a persistent response return to a fixed pool of 256; a pooled
  socket the origin has closed is retried once on a fresh connection before any byte reaches
  the client, and only when the request body was fully buffered.

The server's primitive parsing, evaluation and verification routines take no allocator.
This is a source/API contract, not a claim that the networking runtime, thread creation,
startup, or persistent storage perform no allocation. Benchmark instrumentation is linked
only into the standalone benchmark executable. Production metrics and snapshot reader counts
still have real atomic costs; they are not benchmark overhead.

= Authentication and work

A 32-byte master seed derives independent token, challenge, fingerprint and signing keys.
The normal token is a 40-byte payload (version, the work level the holder solved, timestamp,
expiry, rule hash, fingerprint) plus a 16-byte keyed BLAKE3 tag, URL-safe base64 encoded; a
session admits only routes whose demanded work level it reaches (amended 2026-10-01).
Ed25519 is an optional asymmetric token format. Tokens are bound to client address and
User-Agent and expire. Trust forwarded identity only behind an ingress that overwrites it.

Issuing a challenge stores no entry. Successful verification inserts the authenticated tag
into a 16-shard spent set. Failed bounded insertions leave every live tag intact and refuse
admission. The set is per process and disappears on restart. In cluster mode, challenge keys
are additionally derived from the node id at startup, while token keys remain shared.
Challenge issuance and solution submission must reach the same node; the resulting token
works on every member with the same seed. Distinct cluster node ids are required. This avoids
cross-node replay without a request-path consensus transaction. It does not make replay state
durable across restarts.

Tier 1 verifies `SHA256(challenge || ":" || decimal(nonce))` with bit-level difficulty.
Tier 2 labels the sequential-work graph in `libs/crypto/src/posw.zig`; both native verification
and the WASM prover import the same source. SID 0006 separates graph/hash evaluations from
SHA-256 compression counts and states the research assumptions. Tests against a reference
labeller are correctness evidence, not an independent cryptographic audit.

= Policy and memory

The engine owns fixed-capacity rules, a radix trie, and dense Aho–Corasick tables. Signature
capacity is one plus the sum of pattern lengths: no trie can require more states. This retains
one transition lookup per input byte while avoiding the former oversized tables. Exact engine
and table sizes are emitted by the benchmark using `@sizeOf`.

Dynamic storage owns two engine slots and an arena dedicated to each slot. A slot's arena is
reset only when that slot is inactive and prior readers have drained. Response rule names are copied into a bounded 128-byte buffer,
then the reader releases its slot before any proxy I/O. Pointer publication and
reader-counter operations use sequential consistency so the cross-atomic ordering argument is
valid. Storage polling, SQL, vector search and persistence stay on the storage thread.

= Measurement gates

```
zig build fmt
zig build test
zig build test -Dstorage=false
zig build test -Dcluster=true
sh benchmarks/run-all.sh
python3 benchmarks/distributed.py
zig build sid
```

The primitive harness warms inputs, resets mutable stores outside the timer before each of
seven batches, and prevents pure work from being hoisted out of loops. No operation reads a
clock. Its bot implementations search identical pattern sets with equivalent any-match
semantics. Allocation values are source-audited expectations, not allocator measurements.

The distributed harness starts three actual daemon processes and six external client
processes. It checks status codes, sessions across nodes, authenticated WAF denial, issuer-bound
challenge rejection, reputation propagation, and continued HTTP service with one member down.
Batch timings include client and loopback costs. The harness tests loopback PSK and mutual TLS. WAN behavior needs separate measurements.

= Release toolchain

Version 0.3.1 uses checksum-pinned Zig 0.17.0 on every release platform. macOS packages
explicitly target version 15, matching this compiler's minimum OS contract. Build configuration
uses lazy paths and deferred command arguments; source code uses the compiler's field names,
field types and attributes directly. The console exports only its declared browser ABI,
excluding compiler runtime globals. Compatibility changes preserve the HTTP, challenge,
console and storage wire formats. The primitive benchmark record identifies its own source
revision and compiler; platform qualification and performance acceptance are separate gates.

Zaxonlite and Paxos 0.7.0 do not yet publish Zig 0.17 packages. Their MIT library sources are
included in `vendor/`, with original archive hashes and file digests. Library-only build
entry points retain SQLite, sqlite-vec and optional OpenSSL configuration. No generated source
or compiler-cache file is patched. Replace these snapshots with upstream compatible packages
only after storage replay, cluster and native-platform qualification.

= Native platforms and release boundaries

The packaged engine targets Linux x86-64 and ARM64, macOS Intel and Apple Silicon, and
native Windows x86-64. Every platform runs the same HTTP parser, inspection and proof
protocol. Platform code supplies bounded socket operations, process resource gauges and
termination notification; it does not change policy or challenge semantics.

The application-independent `socket` library supplies native lifetime operations to both the
HTTP service and streaming relay. Windows uses AFD handles owned by Zig's native Io backend,
not Winsock socket identifiers.
Each bounded operation owns a completion event. A timeout cancels and joins the outstanding
driver request before any caller buffer can be reused. Shutdown and idle expiry use abortive
Windows disconnects to release already pending reads; handles remain owned until their worker
closes them, and shared state remains alive until the worker joins. Ordinary reply delivery and upgrade half-closes remain graceful.
The upgraded byte relay keeps its
existing bounded buffers and one connection worker. Ctrl+C and Ctrl+Break request ordered
shutdown; forcibly terminating a process is not that shutdown contract. Private credential
files use owner-only POSIX permissions or Windows DACLs permitting the owner, SYSTEM and
Administrators. Unknown grant forms and absent ACLs fail closed.

The default release includes storage and the opt-in console but no cluster transport.
Cluster deployments use a separate build with OpenSSL 3. Release archives carry the target,
compiler, source commit and binary digest; native functional qualification is required before
a platform archive is published. Cross-compilation alone does not qualify a native port.

= Remaining limits

Shield is a bounded heuristic inspector, not a full SQL/HTML parser. Only the first 8 KB of
body is inspected, and encoded fields longer than the canonical buffer are inspected raw.
There is no HTTP/2, native TLS termination, global rate quota, durable replay set, native
service manager integration, or measured volumetric network mitigation. Forward-auth inspection sees only bytes the
ingress sends. Blocking workers and slow origins limit concurrency. No claim of full managed
edge-service equivalence follows from a local benchmark.
