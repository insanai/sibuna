#import "theme.typ": *

#title_page()
#pagebreak()

#align(center)[
  #text(size: 16pt, weight: "bold")[About This Book]
]

This book explains the architecture, cryptographic foundations, and implementation of
*Sibuna*—an ultra-high-performance Web AI Firewall and anti-crawler daemon written in pure
Zig. It also provides an exhaustive empirical evaluation comparing Sibuna against *Anubis*,
the Go-based reverse proxy upon which its operational model was originally conceived.

The two systems share an ambition: to protect open web content from predatory, unconsented AI
scrapers and distributed crawler botnets without forcing human users to solve degrading
CAPTCHAs. But their internal machinery belongs to two completely different engineering
universes. Anubis relies on the Go runtime, dynamic garbage-collected heap allocations,
reflection-based JSON Web Tokens, and an in-process WebAssembly virtual machine (`wazero`)
to execute cryptographic routines. Sibuna eliminates every intermediate layer: requests are
evaluated without a single heap allocation, bot signatures are scanned across hundreds of
patterns in a single SIMD-ready pass, and Proof-of-Work solutions are validated directly on host
silicon in nanoseconds.

#v(4mm)
#book_quote([
  In Egyptian mythology, Anubis weighed the deceased's heart against the feather of Ma'at.
  If the heart was heavier than truth, the soul was consumed. In Sibuna, the balance is reversed:
  the burden of computational heat is cast upon the predatory machine, while the legitimate human
  passes unfettered.
], [Sibuna Engineering Manifesto])

#v(8mm)
#callout([The Core Promise], [
  A careful reader of this book will understand the economics of automated web scraping,
  derive the mathematics of client-side Proof-of-Work friction, trace the zero-allocation
  HTTP parsing and policy pipeline down to CPU cache lines, inspect the 6.9 KB browser
  WebAssembly solver, and deploy Sibuna in production either as an autonomous reverse proxy
  or as a forward-auth engine behind Nginx, Caddy, Traefik, or Envoy.
], kind: "idea")

#v(1fr)
#align(center, text(size: 8.5pt, fill: gray)[
  Version 0.1.0 · Monorepo Commit Attributed · Built with Typst 0.15+
])

#pagebreak()

= Preface

The open web is undergoing an unprecedented tragedy of the commons. Modern Large Language
Model (LLM) providers, academic labs, commercial data brokers, and private automated agents
deploy relentless, distributed crawler botnets that traverse public web infrastructure around
the clock. These automated scrapers consume gigabytes of bandwidth, exhaust database connection
pools, cause latency spikes for real users, and monetize copyrighted publications without
consent or attribution.

For two decades, web administrators relied on two primary defensive mechanisms:

1. *The `robots.txt` Standard:* An honor-system convention created in 1994. Predatory crawlers
   routinely bypass, ignore, or strip this header entirely.
2. *CAPTCHAs:* Systems such as reCAPTCHA and hCaptcha that force users to identify traffic
   lights, crosswalks, or distorted letters. Today, multi-modal vision models solve these tests
   faster and more reliably than humans, leaving legitimate users frustrated and accessibility-impaired.

Traditional Web Application Firewalls (WAFs) rely on IP reputation lists and rate limits.
However, in an era of cheap residential proxy pools and serverless IP rotation, an attacker can
originate each request from a distinct IP address across hundreds of cloud regions, rendering IP
rate limits ineffective.

== The Thermodynamic Solution: Computational Asymmetry

The only viable defense against distributed automated scraping is *economic and thermodynamic
friction*. If requesting an article costs the scraper $0.000001$ cents in electricity, scraping
one billion pages costs ten dollars. If every request is conditioned upon solving a cryptographic
Proof-of-Work (PoW) puzzle that demands 100 milliseconds of dedicated CPU core time, scraping
that same dataset demands months of continuous compute and thousands of dollars in energy costs.
The economic model of automated mass harvesting collapses.

For the legitimate human user browsing twenty articles in an evening, an invisible Web Worker
solving a 150-millisecond background challenge creates imperceptible overhead. Once solved,
a cryptographically signed session cookie is minted, allowing subsequent navigation with zero
latency.

== Why Anubis Needed Re-architecting

In 2024, `TecharoHQ/anubis` popularized this concept by implementing a PoW reverse proxy in Go.
While its conceptual vision was brilliant, its implementation in Go suffered from structural
runtime limitations:
- *The WebAssembly Virtual Machine Tax:* To evaluate custom cryptographic proofs such as HashX
  or Argon2id, Anubis hosted Wazero (a WebAssembly interpreter/JIT written in pure Go) inside
  the server daemon. Every verification incurred context-switching overhead, bounds checking,
  and memory copying, taking 12 to 25 microseconds per solution.
- *Garbage Collection Jitter:* Under high-concurrency crawler floods (50,000+ req/s), Go's
  `net/http` request objects, string slices, regex match contexts, and `golang-jwt` map allocations
  triggered frequent GC sweep cycles, causing tail latencies to surge past hundreds of milliseconds.
- *Memory Footprint:* Anubis requires 45 to 80 megabytes of resident memory just to service basic
  loads, making lightweight edge sidecar deployment expensive.

Sibuna is the answer to these bottlenecks. By building on bare-metal Zig 0.16, Sibuna:
1. Validates Proof-of-Work solutions directly using host silicon hardware instructions (such as
   ARM NEON and x86 SHA-NI), dropping verification time to *under 75 nanoseconds* (a 175x speedup).
2. Operates with *zero dynamic heap allocations* on the request classification and verification
   hot path.
3. Evaluates 40+ bot signatures simultaneously in a single pass using a case-insensitive
   Aho-Corasick automaton with comptime tables (*59.6 ns* per User-Agent).
4. Emits a freestanding browser WebAssembly solver measuring only *6.9 KB* with mathematical
   prefix pre-hashing that doubles browser solver speed.
5. Runs in a static memory footprint of *less than 5 MB RSS*.

Let us explore how this is achieved.
