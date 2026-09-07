#let sid-number = "0002"
#let sid-title = "Sibuna: Foundation Architecture, Delivery Plan, and Performance Contract"
#let sid-state = "published"
#let sid-created = "2026-09-07"
#let sid-discussion = "Foundational architectural specification, zero-allocation pipeline, two-tier proof-of-work engine, keyed-hash session tokens, product surfaces, measured performance contract, and delivery record for the Sibuna pure-Zig monorepo"
#let sid-labels = ("architecture", "firewall", "pow", "performance",)
#let sid-authors = ("Sibuna Contributors <team@sibuna.local>",)
#let sid-category = "Architectural Specification"
#let sid-status = "Published"
#let sid-last-updated = "2026-09-07"

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

#callout([Revision note (2026-09-07)], [
  This record was revised after the implementation review of 2026-09-07. The earlier text
  described intended subsystems (HashX, Argon2id, an `io_uring` event loop, HTTP/2, a "sliding
  window" limiter) that the code never contained, and it quoted performance figures that were not
  measured. Every number below is either taken from `benchmarks/results/latest.json` as recorded
  on the host named there, or is explicitly marked as a reference model. Sections marked
  _future work_ are not implemented.
], fill: amber-light, stroke: amber)

= Decision summary

Build a web firewall and anti-crawler daemon named *Sibuna* as a pure Zig 0.16 monorepo.
Sibuna terminates HTTP/1.1, classifies each request without a heap allocation, and admits a
client either because a policy rule admits it or because the client has proved work: a
Cohen–Pietrzak proof of sequential work or a bit-level Hashcash solution, verified on native
silicon and exchanged for a keyed-hash session token. Human browsers clear the interstitial in
tens to a few hundred milliseconds inside a Web Worker; automated harvesters pay that cost per
session and cannot amortise it across a botnet because tokens are bound to the client identity.

The architecture rests on five commitments:

1. *A zero-allocation hot path.* Parsing, policy evaluation, semantic inspection, token
   verification, and proof verification slice over one per-connection stack buffer. The only
   dynamic memory in the daemon is startup configuration and the off-path storage thread.
2. *Native verification, research-grade puzzles.* The server never runs a virtual machine to
   verify work. Tier 1 is SHA-256 Hashcash on the hardware SHA extensions Zig's standard library
   dispatches to; Tier 2 is a proof of sequential work with a published security proof in the
   random-oracle and quantum-random-oracle models (SID 0006).
3. *Symmetric authentication.* Issuer and verifier are the same daemon (or a cluster sharing
   one seed), so session tokens and challenge identifiers are keyed BLAKE3 tags, not signatures.
4. *Automata, not regular expressions.* Bot signatures and attack signatures are single-pass
   Aho–Corasick automata; structural attack detection is a set of single-pass tokenizers.
5. *One toolchain.* `zig build` produces the daemon, the benchmark suite, the documents, and the
   browser solver, and the browser solver compiles the same `posw.zig` and `pow.zig` sources
   the server verifies with, so prover and verifier cannot drift.

#callout([Product surfaces], [
  Sibuna ships one binary with three surfaces selected at runtime and build time:
  - *Gate* (`--gate`): proof-of-work admission only, comparable in scope to an Anubis
    deployment. Full classification of a browser request costs 295 ns.
  - *Shield* (`--shield`, the default): Gate plus the semantic WAF, GCRA rate limiting, the
    honeypot, and the ban table. Full classification costs 1.46 µs.
  - *Edge* (`--data-dir`, optionally `--cluster-*`): Shield plus the Zaxonlite storage layer
    for dynamic policies, replicated reputation, and incident forensics (SID 0005).
])

== Product principles

+ *Asymmetry as defence.* The work a client must perform to obtain a session is tens of
  thousands of hash compressions; verifying it costs the daemon 63 ns (Hashcash) or 17 µs
  (PoSW). The daemon stores nothing for an unsolved challenge, so an adversary cannot consume
  memory without first paying for it.
+ *Zero allocations in the hot path.* Every heap allocation during request evaluation is a
  denial-of-service lever; the per-connection buffer is 64 KB of stack and every table is
  fixed-capacity.
+ *Proofs before folklore.* Puzzle and token constructions are chosen for published security
  arguments, not for popularity in cryptocurrency mining (SID 0006).
+ *Zero-friction human experience.* The interstitial solves in a Web Worker, falls back to a
  byte-identical JavaScript prover when WebAssembly is unavailable, and reloads the page.
+ *Two deployment modes.* Autonomous reverse proxy, or forward-auth subrequest engine behind
  Nginx, Caddy, or Traefik.

= Reference model of a Go-based challenge proxy

Sibuna's design targets the structural costs that a Go implementation of the same product
(`TecharoHQ/anubis`) pays: a WebAssembly runtime hosted in the server for verification, per-request
allocation of request objects and header maps, sequential regular-expression scans, and JSON Web
Tokens parsed by reflection. The table records the design response. The Anubis column is a
_reference model_: fixed per-call costs taken from public profiling of those components. It was
not measured on the benchmark host, and the benchmark suite labels every such row
`anubis-model` with `measured = false`.

#table(
  columns: (1.1fr, 1.7fr, 2fr),
  stroke: 0.5pt + rule,
  fill: (x, y) => if y == 0 { blue-light } else if calc.even(y) { luma(99%) } else { white },
  [*Subsystem*], [*Reference model (Go + Wazero)*], [*Sibuna (measured)*],
  [Proof verification],
  [WASM bytecode executed in-process; modelled at 12.5 µs and 4 KB per call.],
  [Hashcash 62.6 ns, PoSW(13, 16) 16.9 µs, zero allocation.],
  [Session token],
  [JWT decoded into a map by reflection; modelled at 62.5 µs.],
  [Keyed BLAKE3 tag over a 32-byte payload: 134 ns. Ed25519 option: 52.8 µs.],
  [Bot signatures],
  [Sequential compiled regexps; modelled at 1.7 µs for 40 patterns.],
  [Dense-table Aho–Corasick, one pass: 85 ns for 40 patterns.],
  [IP classification],
  [Slice of `net.IPNet`; modelled at 380 ns.],
  [128-bit radix trie with an IPv4 root shortcut: 45 ns IPv4, 80 ns IPv6.],
  [Challenge state],
  [Mutex-guarded map of every issued challenge; modelled at 2.1 µs.],
  [Robin Hood spent set holding only _solved_ challenges: 23 ns.],
  [Request parsing],
  [`net/http` request and header map allocation; modelled at 3.5 µs.],
  [Zero-copy slices into the connection buffer: 733 ns including cookie lookup.],
)

= System architecture

== Process topology

The daemon binds one listening socket and runs `--workers` accept loops (default: one per
CPU). Each loop accepts a connection, serves up to 256 HTTP/1.1 requests on it with keep-alive,
and closes it. A connection owns a 64 KB stack buffer for request heads and bodies and a 16 KB
write buffer; nothing about a request is copied out of that buffer. Proxied requests are streamed
to the origin with hop-by-hop headers stripped and audit headers injected, bodies larger than the
buffer are relayed in 16 KB chunks, and the connection closes after the origin response because
the origin's framing is passed through untouched.

#callout([Future work: event loop and HTTP/2], [
  The accept loops are blocking threads, not an `io_uring`/`kqueue` reactor, and the parser
  accepts HTTP/1.0 and HTTP/1.1 only. Both are compatible with the zero-allocation contract and
  remain open items; neither affects the measured per-request costs, which are dominated by
  classification rather than I/O dispatch.
], fill: amber-light, stroke: amber)

== Request lifecycle

```
 [Client request]
        │
        ▼
 [Zero-copy HTTP/1.1 parser]  (head ≤ 16 KB, body ≤ 64 KB buffered, rest relayed)
        │
        ├─ ban table hit? ──────────────────────────► 403
        ├─ /__sibuna/* internal route? ─────────────► assets, challenge.json,
        │                                              verify, honeypot, health, metrics
        ├─ GCRA limit exceeded? ────────────────────► 429 + Retry-After
        ├─ valid session cookie? ───────────────────► forward (PASS, rule = session)
        ▼
 [Policy engine — one RequestView, zero allocation]
        ├── 0. Semantic WAF (signature automaton + tokenizers) ──► DENY
        ├── 1. Reputation trie: deny or allow verdict ──────────► DENY / ALLOW
        ├── 2. Declarative rules in order; WEIGH accumulates ────► first terminal match
        ├── 3. Accumulated score vs thresholds ─────────────────► ALLOW / CHALLENGE / DENY
        ├── 4. Static bypass paths ─────────────────────────────► ALLOW
        ├── 5. Reputation trie: challenge verdict
        ├── 6. Bot-signature automaton ─────────────────────────► CHALLENGE
        └── 7. Default action (challenge) ─────────────────────► CHALLENGE
        │
        ├── ALLOW ────► stream to origin with X-Forwarded-For, X-Real-IP,
        │               X-Sibuna-Status, X-Sibuna-Rule  (forward-auth: 200 + headers)
        ├── DENY ─────► 403 (+ incident record when the WAF fired)
        └── CHALLENGE ► HTML interstitial (Accept: text/html), 401 JSON otherwise,
                        401 in forward-auth mode
```

The interstitial fetches `/__sibuna/challenge.json?path=<original path>`, so the rule that
protects the original path chooses difficulty and algorithm, and the challenge carries that
rule's hash. The Web Worker solves it and posts `{"challenge_id", "nonce" | "proof"}` to
`/__sibuna/verify`; a `200` sets the session cookie and the page reloads.

== Dual operating modes

1. *Reverse proxy* (`--mode reverse_proxy`): terminates the client connection, classifies, and
   streams admitted requests to `--upstream-host:--upstream-port`.
2. *Forward auth* (`--mode forward_auth`): answers the ingress subrequest with `200` plus
   `X-Sibuna-Status`, `X-Sibuna-Rule`, and `X-Sibuna-Rule-Hash`, `403` for denials, and `401`
   when a challenge is required. Forwarded client addresses are trusted in this mode by default
   (`--trust-forwarded` controls it in either mode).

= Proof-of-work engine

Two tiers are implemented. The mathematics, the security arguments, and the rejection of the
alternatives are the subject of SID 0006; this section records the engineering contract.

#table(
  columns: (1fr, 1.6fr, 1.6fr),
  table.header([*Property*], [*Tier 1: Hashcash (`hashcash`)*], [*Tier 2: PoSW (`posw`, default)*]),
  [Statement], [challenge id string], [challenge id string],
  [Client work], [$2^b$ expected SHA-256 compressions, geometric variance], [$2^(n+1)-1$ sequential SHA-256 labels, deterministic],
  [Difficulty knob], [`bits` $b$ (default 16)], [depth $n = b - 3$ so both tiers cost about the same wall-clock],
  [Server verification], [one compression, 62.6 ns measured], [$t(n+1)$ compressions, 16.9 µs at $n=13, t=16$],
  [Proof size], [decimal nonce], [$32(1 + t(n+1))$ bytes, 7.2 KB at $n=13$],
  [Parallel speed-up for an attacker], [unbounded (GPU, ASIC)], [none: the labelling is inherently sequential],
  [Client memory], [constant], [$O(2^m + n)$ labels, about 90 KB],
  [Security argument], [random-oracle preimage search], [Cohen–Pietrzak 2018; quantum: Blocki–Lee–Zhou 2021],
)

Difficulty may be raised per rule, by WEIGH scores, and by the load-adaptive controller, which
adds $ceil(log_2 (1 + lambda / lambda_0))$ bits (capped at 6) when the smoothed challenge issue
rate $lambda$ exceeds the baseline $lambda_0$.

#callout([Rejected constructions], [
  *Argon2id* was rejected because verification costs the same memory-hard computation as
  solving: a submission that fails verification still costs the server milliseconds and tens of
  megabytes, inverting the asymmetry the product exists to create. *HashX* has no published
  security reduction. *Equihash* (generalised birthday) is GPU-efficient, carries a
  cryptocurrency lineage, and admits quantum $k$-XOR speed-ups; it was prototyped and withdrawn.
  See SID 0006 for the full comparison.
], fill: red-light, stroke: red)

== Browser client

`apps/wasm-pow/src/entry.zig` compiles to `wasm32-freestanding` in `ReleaseSmall` and imports
`libs/crypto/src/pow.zig` and `libs/crypto/src/posw.zig` unchanged. The module measures
*8,831 bytes* with both solvers. `apps/web/src/worker.js` drives it and carries JavaScript
implementations of both provers that produce byte-identical output (verified against the module
under V8), so browsers without WebAssembly still pass. Measured under V8: PoSW depth 13 solves in
15 ms, depth 16 in 138 ms; Hashcash 16 bits solves in about 20 ms. The JavaScript fallback is
roughly sixty times slower.

= Session authentication

== Key schedule

One 32-byte master seed (`--secret-file`, the `SIBUNA_SECRET` environment variable, or a random
value drawn at startup with a banner warning) is expanded with keyed BLAKE3 into four purpose
keys: token MAC, challenge PRF, Ed25519 seed, and client fingerprint. A cluster agrees on the
seed and thereby on every token and challenge.

== Tokens

The payload is 32 big-endian bytes: issue time, expiry, rule hash, client fingerprint. The
default token appends a 16-byte keyed BLAKE3 tag (48 bytes, 64 URL-safe base64 characters) and
verifies in 134 ns with a constant-time comparison. `--token-scheme ed25519` appends a 64-byte
signature instead (128 characters, 52.8 µs) for deployments whose verifiers must not hold
minting capability. The fingerprint is a keyed hash of client address and User-Agent, so a token
copied to another client is inert.

== Stateless challenges

A challenge identifier is a 36-byte payload (version, algorithm, difficulty, opening count, issue
time, fingerprint, PRF nonce, rule hash) plus a 16-byte tag, 70 characters in total. Issuing one
writes nothing. Only a _solved_ challenge enters the spent set, a 16-shard Robin Hood table keyed
by the tag, so the daemon's state is bounded by work the client actually performed.

= Monorepo structure

```
sibuna/
├── build.zig / build.zig.zon    # -Dstorage (default on), -Dcluster; zaxonlite v0.6.0 dependency
├── apps/
│   ├── sibuna/src/              # main.zig, server.zig, storage.zig, persistent.zig, e2e_test.zig
│   ├── wasm-pow/src/entry.zig   # browser solver: hashcash + PoSW exports (8,831 bytes)
│   └── web/src/                 # challenge.html interstitial, worker.js provers
├── libs/
│   ├── core/                    # config, diagnostics, Elm-style error explanations, logging
│   ├── crypto/                  # keys, pow (hashcash), posw, token (MAC + Ed25519)
│   ├── net/                     # zero-copy parser, response builders, streaming proxy
│   ├── policy/                  # aho_corasick, radix_trie, rule, loader, engine, waf, normalizer, embedding
│   ├── challenge/               # stateless coordinator, adaptive difficulty
│   └── store/                   # challenge_store (spent set), rate_limiter (GCRA), ban_list, ring
├── benchmarks/                  # benchmark.zig, run-all.sh, results/latest.json
├── docs/                        # SIDs, the book, shared Typst theme
└── tools/                       # sid.zig, style checkers
```

= Performance contract

Measured on the host recorded in `benchmarks/results/latest.json` (Apple M1, Zig 0.16.0,
`ReleaseFast`, seven batches, median per operation, zero heap allocation in every measured row):

#table(
  columns: (1.6fr, 1fr, 1fr),
  table.header([*Workload*], [*ns / op*], [*ops / s*]),
  [Hashcash verification, 16 bits], [62.6], [15.98 M],
  [PoSW verification, depth 13, 16 openings], [16,920], [59.1 K],
  [Bot automaton, 40 signatures], [85.3], [11.7 M],
  [IPv4 / IPv6 trie lookup], [45.2 / 79.9], [22.1 M / 12.5 M],
  [BLAKE3 MAC token verification], [134.1], [7.46 M],
  [Ed25519 token verification], [52,778], [18.9 K],
  [Robin Hood spend + lookup], [22.8], [43.8 M],
  [GCRA rate check], [4.8], [209 M],
  [HTTP parse + cookie lookup], [732.5], [1.37 M],
  [Full classification, Gate surface], [295.0], [3.39 M],
  [Full classification, Shield surface], [1,460], [685 K],
  [Semantic scan of an 8 KB body], [23,702], [42.2 K],
)

Static figures from the same run: daemon binary 4.25 MB (`ReleaseFast`, storage linked), WASM
solver 8,831 bytes, idle resident set 7.6 MB without a data directory and 12–14.5 MB with the
Zaxonlite store open.

#callout([Contract gates], [
  - Server verification of any proof $< 50$ µs: met (17 µs worst case, PoSW).
  - Classification of a browser request $< 2$ µs on the Shield surface, $< 300$ ns on Gate: met.
  - Zero heap allocation on the request path: met; the storage layer allocates only on its own
    thread.
  - Idle resident set $< 15$ MB: met with and without storage.
  - Throughput $>= 100,000$ requests/s per core and P99 $< 250$ µs under load: *not yet
    measured* with a load generator against the daemon; only the per-primitive costs above are
    recorded.
], fill: green-light, stroke: green)

= Delivery record

#milestone(
  "Phase 0: Cryptographic primitives",
  "Hashcash with bit-level difficulty, PoSW prover and verifier, keyed BLAKE3 tokens, Ed25519 tokens, key schedule, WASM solver sharing the native sources.",
  "Tests pass; the WASM module verifies against native test vectors; module size 8,831 bytes.",
)
#milestone(
  "Phase 1: Network and proxy layer",
  "Zero-copy HTTP/1.1 parser with smuggling defences, keep-alive connection loop, streaming proxy with audit headers and chunked body relay, forward-auth mode.",
  "Nine end-to-end HTTP scenarios pass against the live daemon and a stub origin.",
)
#milestone(
  "Phase 2: Pattern matcher and policy engine",
  "Tagged Aho–Corasick automata, IPv4/IPv6 radix trie, declarative rules with WEIGH scoring, JSON loader.",
  "Full classification measured at 295 ns (Gate) and 1.46 µs (Shield).",
)
#milestone(
  "Phase 3: Challenge and verification pipeline",
  "Stateless challenges, both tiers verified natively, interstitial and worker with JavaScript fallback.",
  "PoSW verification 16.9 µs; the fallback provers are byte-identical to the module.",
)
#milestone(
  "Phase 4: State, rate limiting, and sessions",
  "Robin Hood spent set, GCRA limiter, lock-free ban table, MAC tokens bound to fingerprint and rule.",
  "Replay, binding, and double-spend rejection covered end to end.",
)
#milestone(
  "Phase 5: Hardening, observability, benchmark gate",
  "Prometheus counters at /__sibuna/metrics, load-adaptive difficulty, honest benchmark suite with recorded host metadata.",
  "Comparative measurement against a running Anubis binary has not been performed; its column remains a reference model.",
  state: "partial",
)

== Open items

- JA4H fingerprinting is not implemented; the client fingerprint is address plus User-Agent.
- HTTP/2 and an `io_uring`/`kqueue` reactor are not implemented.
- SIMD literal prefiltering for very long bodies is not implemented; the dense automaton runs at
  about 2.9 ns per byte on 8 KB bodies, which is adequate for header-dominated traffic.
- A load-generator benchmark of end-to-end throughput and tail latency is not recorded.

= Verification gates

`zig build test` runs 80 tests: unit tests in every library, the WASM entry tests on the host,
the server helpers, nine end-to-end HTTP scenarios (interstitial and static bypass; Hashcash
issue/solve/verify/cookie/proxy with replay and binding rejection; PoSW through forward-auth with
Ed25519 tokens; policy and WAF denials, honeypot bans, and rate limiting; keep-alive; malformed,
smuggled, oversized, and unknown requests; asset serving), and the Zaxonlite storage test (schema,
dynamic policy reload through the RCU slot, reputation bans, forensics, campaign clustering).
`zig build fmt` enforces `zig fmt`, the 70-line function limit, the 99-column limit, and the
1408-line file limit. `sh benchmarks/run-all.sh` regenerates `latest.json`, which the book renders.

= Definition of done

- SID records 0001–0006 published and consistent with the code.
- `zig build test` and `zig build fmt` pass.
- The WASM solver is under 10 KB and passes in browsers with and without WebAssembly.
- Measured performance rows are recorded with host metadata; modelled rows are labelled.
