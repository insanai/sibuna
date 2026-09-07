#let sid-number = "0002"
#let sid-title = "Sibuna: Foundation Architecture, Delivery Plan, and Performance Contract"
#let sid-state = "published"
#let sid-created = "2026-09-07"
#let sid-discussion = "Foundational architectural specification, Anubis comparative analysis, and product delivery plan for the Sibuna pure-Zig monorepo"
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

#let milestone(name, outcome, exit) = block(
  width: 100%,
  breakable: true,
  inset: 10pt,
  radius: 6pt,
  stroke: 0.7pt + rule,
)[
  #text(weight: "bold", fill: blue)[#name]
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

= Decision summary

Build an ultra-high-performance Web AI Firewall and anti-crawler daemon named *Sibuna*
(Anubis reversed), implemented as a pure Zig 0.16 monorepo. Sibuna intercepts incoming HTTP
traffic, evaluates multi-dimensional bot policies in sub-microsecond time, and imposes
asymmetric cryptographic Proof-of-Work (PoW) computational friction on unverified automated
scrapers while allowing legitimate human users and authorized crawlers to pass with zero friction.

Sibuna is engineered from the ground up to eliminate the severe runtime bottlenecks, memory
churn, and CPU penalties found in existing Go-based tools such as `TecharoHQ/anubis`. It achieves
this through:

1. *A Zero-Allocation Hot Path:* Requests are classified, cookies verified, and tokens parsed
   without a single dynamic heap allocation.
2. *Bare-Metal Cryptographic Verification:* The server validates PoW solutions natively using
   host CPU hardware extensions (x86 SHA-NI, ARM NEON, native C/Zig HashX, and Argon2id), completely
   eliminating Anubis's in-Go WebAssembly runtime overhead.
3. *Single-Pass SIMD Multi-Pattern Matching:* Hundreds of crawler signatures are evaluated
   simultaneously in a single pass using SIMD-accelerated Aho-Corasick automata.
4. *Zero-Copy Radix Trie IP Filtering:* IPv4 and IPv6 CIDR blocks are evaluated via bitwise
   trie traversal in $O(1)$ to $O(k)$ operations.
5. *Unified Zig Toolchain:* A single toolchain (`zig build`) compiles the high-throughput server daemon,
   the native cryptographic modules, and the browser-side WebAssembly solver (`wasm32-freestanding`),
   eradicating dependencies on Node.js, Rust, or Go toolchains.

#callout([Performance Contract Gate], [
  Sibuna does not merely aim to be a Zig clone of Anubis. It establishes non-negotiable benchmark
  gates:
  - Throughput: $>= 100,000$ requests/sec per core on classification hot-paths.
  - Server PoW Verification: $< 50$ microseconds per solution (compared to 5--20 milliseconds in Anubis's Wazero VM).
  - Memory Footprint: $< 15$ MB RSS static resident set under sustained high-concurrency attack.
  - Tail Latency: P99 classification latency $< 250$ microseconds under $50,000$ req/s load.
], fill: amber-light, stroke: amber)

== Product principles

+ *Asymmetry as defense.* The computational cost imposed on the crawler must be $10,000 times$
  to $100,000 times$ higher than the cost incurred by the firewall server to issue and verify the challenge.
+ *Zero allocations in the hot path.* Every byte allocated on the heap during request evaluation
  is a potential Denial-of-Service vector under crawler flood conditions. Buffer pools and ring buffers
  are pre-allocated at startup.
+ *Native silicon execution.* Never run an interpreted or JIT-emulated virtual machine on the server
  when native hardware instructions exist.
+ *Zero-friction human UX.* Legitimate browsers solve challenges transparently in a background
  Web Worker in 100--500ms, receive a cryptographically bound cookie, and experience no CAPTCHAs
  or blocking interstitials on subsequent requests.
+ *Dual deployment flexibility.* Run either as an autonomous reverse proxy or as a lightweight
  forward-auth subrequest engine behind Nginx, Caddy, or Traefik.

= Comparative Analysis: TecharoHQ/anubis Bottlenecks

An architectural audit of `TecharoHQ/anubis` reveals several structural bottlenecks that limit its
throughput and cause instability under severe scraper floods:

#table(
  columns: (1.2fr, 1.8fr, 2fr),
  stroke: 0.5pt + rule,
  fill: (x, y) => if y == 0 { blue-light } else if calc.even(y) { luma(99%) } else { white },
  [*Subsystem*], [*Anubis (Go)*], [*Sibuna (Zig)*],
  [Server PoW Verification],
  [Executes compiled WASM binaries inside Go using the `wazero` runtime interpreter/JIT for HashX and Argon2id.],
  [Direct native execution utilizing hardware SIMD instructions (x86 SHA-NI, ARM NEON) and native C/Zig code. Verification takes $< 50$ microseconds with zero VM overhead.],

  [Memory & GC Churn],
  [Go garbage-collected runtime. Every request allocates `http.Request`, slices, maps, regex matches, and Prometheus label strings. Suffers GC pause spikes under crawler floods.],
  [Manual, deterministic memory model. Fixed-capacity connection rings, stack arenas, and slice references. Zero GC pauses; static $< 15$ MB memory footprint.],

  [Pattern Matching],
  [Sequential execution of compiled Go `regexp` patterns (`O(N)` regex checks per request). Scales linearly with policy count.],
  [SIMD-accelerated Aho-Corasick multi-string automaton. Scans User-Agent strings in a single pass ($100$--$300$ ns) across thousands of patterns.],

  [IP / CIDR Filtering],
  [Go BART trie library with multiple pointer indirections and heap allocations on IP string parsing.],
  [Zero-allocation Radix Trie for IPv4 (direct table / compact trie) and IPv6 (128-bit Patricia trie). Lookup in $<= 40$ ns.],

  [Token & Cookie Auth],
  [JSON Web Tokens parsed via `golang-jwt`, deserializing claims into generic `map[string]any` via reflection.],
  [Compact binary token (Ed25519 or HMAC-BLAKE3) or zero-allocation JWT parser reading directly into stack structs. Validation in $< 1$ microsecond.],

  [Decay Map Cache],
  [Standard Go map protected by a single `sync.RWMutex` with a channel-based cleanup worker. High lock contention under concurrent load.],
  [Sharded, lock-free or cache-line partitioned Robin Hood hash table with atomic timestamps and lockless expiry.],

  [Toolchain & Build],
  [Fragmented toolchain: Go + Rust (`wasm-pack`) + Node/TypeScript (`npm`) + Wazero.],
  [Single unified toolchain: Zig 0.16 compiles daemon, native crypto, C bindings, and browser WASM target (`wasm32-freestanding`).],
)

= System Architecture

== Process Topology and I/O Loop

Sibuna utilizes an asynchronous, non-blocking event loop tailored to the host operating system:
- `io_uring` on modern Linux kernels (with fallback to `epoll`).
- `kqueue` on macOS and FreeBSD.

Each worker thread is pinned to a dedicated CPU core and manages a disjoint set of non-blocking
client sockets. Worker threads own fixed pre-allocated arenas and connection buffers, eliminating
inter-thread cache bouncing and lock contention.

== Request Lifecycle Pipeline

```
 [Client Request]
        │
        ▼
 [Zero-Copy HTTP Parser] ──(Parse headers into string slices)
        │
        ├──► [Cookie / Token Check]
        │         │
        │         ├── Valid Token & Policy Match? ──► [Zero-Copy Forward to Origin]
        │         ▼
        │    (Missing or Expired)
        │
        ▼
 [Policy Evaluator]
        ├── 1. Exact Match / Bypass Table (Favicon, robots.txt, /.well-known) ──► ALLOW
        ├── 2. Radix CIDR Table (IPv4/IPv6 IP Reputation / Allowlist)
        ├── 3. SIMD Aho-Corasick Matcher (User-Agent bot signatures)
        ├── 4. Header & Path Matchers (Exact and byte-level matching)
        ├── 5. JA4H Fingerprint Calculator
        └── 6. Dynamic Score Aggregator (WEIGH adjustments & Thresholds)
        │
        ├── Action == ALLOW ──────► [Forward to Origin]
        ├── Action == DENY ───────► [403 Forbidden Response]
        └── Action == CHALLENGE ──► [Issue PoW Challenge]
                                          │
                                          ▼
                                   [Serve HTML / WASM]
                                          │
    [Client Submits Solution (nonce, hash)]
        │
        ▼
 [Native SIMD PoW Verifier]
        │
        ├── Valid Solution? ──► [Mint Ed25519 Token Cookie] ──► [Redirect / 200 OK]
        └── Invalid Solution ─► [400 Bad Request / Strike]
```

== Dual Operating Modes

1. *Standalone Reverse Proxy Mode:*
   Sibuna listens on the public HTTP port, terminates HTTP/1.1 (and HTTP/2), classifies requests,
   and streams approved traffic to the upstream backend service via zero-copy socket proxying. It injects
   diagnostic audit headers (`X-Sibuna-Status: PASS`, `X-Sibuna-Rule: bot/gptbot`).

2. *Forward-Auth / Subrequest Mode:*
   Designed for deployment alongside existing reverse proxies (Nginx `auth_request`, Traefik `forward_auth`,
   Caddy `forward_auth`). Sibuna responds with:
   - `200 OK` (with upstream auth headers) if the client has a valid session token or matches an `ALLOW` rule.
   - `403 Forbidden` if explicitly denied.
   - `401 Unauthorized` or serves the Challenge page if verification is required.

= Cryptographic Proof-of-Work Engine

== Multi-Algorithm Architecture

Sibuna implements three distinct tiers of computational friction:

+ *Tier 1: Fast SHA-256 (Hashcash)*
  - Formula: $"SHA-256"("Challenge" || "Nonce")$ must have $D$ leading zero hex characters.
  - Server Verification: Evaluates a single SHA-256 block using hardware acceleration (`x86 SHA-NI` or `ARM NEON crypto`).
  - Cost: Server verifies in $approx 180$ nanoseconds. Client computes $16^D$ hashes ($100$ms to $2$s in Web Worker).
+ *Tier 2: Tor-Compatible HashX*
  - Designed specifically to be ASIC-resistant and CPU-bound, utilizing dynamic instruction generation, branching,
    and cache-dependent lookups.
  - Server Verification: Native C/Zig implementation compiled directly into the binary.
  - Cost: Server verifies in $< 20$ microseconds.
+ *Tier 3: Memory-Hard Argon2id*
  - Imposes strict RAM allocation requirements on the client (e.g., 8 MB--32 MB memory window), making massive
    parallel cloud scraping economically devastating.
  - Server Verification: Optimized native Argon2id single-pass verification.

== Zero-WASM Server Verification Contract

Unlike Anubis, which instantiates `wazero` and runs WASM bytecode on the server to verify solutions,
Sibuna compiles all verification routines natively into the host binary. The server never executes
WebAssembly.

== Browser Client (Pure Zig WASM)

The browser solver is authored in pure Zig (`apps/wasm-pow/src/entry.zig`) and compiled using:
```sh
zig build -Dtarget=wasm32-freestanding -Doptimize=ReleaseSmall
```
The resulting WebAssembly module is $< 10$ KB. A minimal vanilla JavaScript driver (`< 2` KB, zero external
npm dependencies) spawns a Web Worker, initiates the WASM solver, updates a smooth client-side progress UI,
and posts the nonce back to Sibuna.

= Token and Session Authentication

1. *Token Architecture:*
   Sibuna supports two zero-allocation token formats:
   - *Compact Ed25519 Token:* 64-byte Ed25519 signature over a 32-byte binary payload containing
     `[Timestamp(8) | Expiry(8) | RuleHash(8) | ClientFingerprint(8)]`, encoded as URL-safe base64.
   - *Strict Compact JWT:* For drop-in compatibility with downstream tools, parsed in-place without JSON allocations.
2. *Anti-Replay & Client Binding:*
   The token payload binds to a hash of the client's network identity (`X-Real-IP` or JA4H fingerprint)
   and the specific bot rule that triggered the challenge. Tokens cannot be smuggled or shared between
   different scrapers.

= Monorepo Structure

```
sibuna/
├── build.zig                   # Root build script orchestrating all libs, apps, and wasm
├── build.zig.zon               # Package manifest
├── apps/
│   ├── sibuna/                 # Main firewall daemon binary
│   ├── wasm-pow/               # Browser-side PoW solver (wasm32-freestanding)
│   └── web/                    # Client static assets, worker scripts, and templates
├── libs/
│   ├── core/                   # Arena allocators, configuration, logging, time
│   ├── crypto/                 # SHA-256 SIMD, HashX, Argon2id, Ed25519, tokens
│   ├── net/                    # Zero-copy HTTP/1.1 & HTTP/2 parser, proxy, subrequest
│   ├── policy/                 # SIMD Aho-Corasick, Radix CIDR trie, JA4H, scoring
│   ├── challenge/              # Challenge coordinator & dynamic difficulty
│   └── store/                  # Lockless sharded decay map, Valkey/Redis client
├── docs/                       # Shibuna Discussions (SID) and manuals
│   ├── shared/                 # Shared Typst templates & themes
│   └── sid/                    # RFC/RFD discussion records and registry
└── tools/
    ├── sid.zig                 # SID management CLI tool
    └── bench/                  # High-concurrency benchmark and simulation suite
```

= Delivery Plan

#milestone(
  "Phase 0: Risky Boundaries & Cryptographic Primitives",
  "Implement native SIMD SHA-256, HashX, Ed25519 signing, and the wasm32-freestanding browser solver.",
  "Cryptographic test suite passes; browser solver verified against native test vectors; WASM binary size < 10 KB."
)

#milestone(
  "Phase 1: High-Performance Network & Proxy Layer",
  "Implement zero-copy HTTP/1.1 parser, streaming reverse proxy, and forward-auth subrequest engine.",
  "Echo proxy handles 100,000 req/s with zero heap allocations during sustained streaming."
)

#milestone(
  "Phase 2: Pattern Matcher & Bot Policy Engine",
  "Implement Radix IPv4/IPv6 CIDR trie, SIMD Aho-Corasick multi-string pattern matcher, and JA4H calculator.",
  "Single-pass matching against 500 bot signatures executes in under 300 nanoseconds per request."
)

#milestone(
  "Phase 3: Proof-of-Work Challenge & Verification Pipeline",
  "Connect challenge issuance, HTML/WASM page delivery, and native server verification.",
  "End-to-end browser flow completes in < 500ms; server verification latency < 50 microseconds."
)

#milestone(
  "Phase 4: State Store, Rate Limiting & Session Tokens",
  "Implement the lockless sharded decay map, compact binary token minting, and cookie binding.",
  "Zero lock contention under 100,000 concurrent session validations."
)

#milestone(
  "Phase 5: Production Hardening, Observability & Benchmark Gate",
  "Implement Prometheus metrics, dynamic difficulty auto-tuning, and automated comparative benchmarking against Anubis.",
  "Comprehensive benchmark suite proves > 10x throughput, > 50x lower verification latency, and < 15MB RSS memory."
)

= Mandatory Integration Tests & Verification Gates

The following automated verification gates are enforced before release:

1. *Zero-Allocation Leak Check:* Run $1,000,000$ simulated classified requests through the hot path
   under `std.testing.FailingAllocator`. The test must pass with zero allocations.
2. *SIMD Pattern Correctness:* Fuzz the Aho-Corasick matcher with $100,000$ generated user-agent strings
   and assert exact equivalence against naive substring searches.
3. *Double-Spend & Replay Resistance:* Concurrently submit the same valid PoW solution from $100$ threads;
   exactly one must succeed and receive a signed token; $99$ must be rejected.
4. *Anubis Performance Gate:* Run concurrent `wrk` benchmarks comparing Sibuna and Anubis on the same
   hardware. Sibuna must demonstrate at least $10 times$ higher request throughput and $< 10%$ of Anubis's
   memory consumption.

= Definition of Done

A release is considered complete when:
- All SID records through SID 0002 are published and up to date.
- `zig build test` passes with zero failures across all packages (`libs/core`, `libs/crypto`, `libs/net`, `libs/policy`, `libs/challenge`, `libs/store`).
- The browser WASM binary compiles to $< 10$ KB and functions in Firefox, Chromium, Safari, and mobile browsers.
- The Anubis performance gate assertions are fully validated and documented.
