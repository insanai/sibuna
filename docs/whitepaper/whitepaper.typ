// Sibuna Architectural Whitepaper
// Copyright (c) 2026 Sibuna Contributors
// Designed with inspiration from Richard Feynman, Donald Knuth, and Leslie Lamport.

#import "@preview/cetz:0.5.2" as cetz

// --- Design System & Color Palette ---
#let ink = rgb("0f172a")          // Slate 900
#let primary = rgb("0369a1")        // Sky 700
#let primary-light = rgb("f0f9ff")  // Sky 50
#let accent-purple = rgb("6d28d9") // Violet 700
#let purple-light = rgb("f5f3ff") // Violet 50
#let accent-gold = rgb("b45309")   // Amber 700
#let gold-light = rgb("fffbeb")    // Amber 50
#let accent-green = rgb("047857")  // Emerald 700
#let green-light = rgb("ecfdf5")  // Emerald 50
#let accent-red = rgb("b91c1c")    // Red 700
#let red-light = rgb("fef2f2")    // Red 50
#let muted = rgb("64748b")         // Slate 500
#let border = rgb("cbd5e1")        // Slate 300
#let light-border = rgb("e2e8f0")  // Slate 200

#set document(
  title: "Sibuna: Architecture, Distributed Consensus, and Empirical Foundations",
  author: ("Vikrant Rathore", "Ronak Rathore"),
  keywords: ("WAF", "Distributed Systems", "Multi-Paxos", "Proof of Work", "Zero-Allocation", "Zig", "zaxonlite", "GCRA", "Aho-Corasick")
)

#set page(
  paper: "a4",
  margin: (x: 18mm, top: 20mm, bottom: 20mm),
  header: context {
    if counter(page).get().first() > 1 {
      grid(
        columns: (1fr, 1fr),
        align(left)[#text(size: 8pt, fill: muted, font: "New Computer Modern", weight: "bold")[SIBUNA: ARCHITECTURE & DISTRIBUTED CONSENSUS]],
        align(right)[#text(size: 8pt, fill: muted, font: "New Computer Modern", style: "italic")[Whitepaper · September 2026]]
      )
      v(-3pt)
      line(length: 100%, stroke: 0.4pt + light-border)
    }
  },
  footer: context {
    if counter(page).get().first() > 1 {
      line(length: 100%, stroke: 0.4pt + light-border)
      v(2pt)
      grid(
        columns: (1fr, 1fr),
        align(left)[#text(size: 8pt, fill: muted)[Insan AI Systems Research · Zero-Allocation Web Defense]],
        align(right)[#text(size: 8pt, weight: "bold", fill: ink)[#counter(page).display("1 of 1", both: true)]]
      )
    }
  }
)

#set text(
  font: "New Computer Modern",
  size: 9.6pt,
  fill: ink,
  lang: "en"
)

#set par(justify: true, leading: 0.60em, spacing: 0.70em)
#set heading(numbering: "1.1")

#show heading: it => block(below: 0.55em, above: 1.05em)[
  #if it.level == 1 {
    v(0.3em)
    text(size: 13.5pt, weight: "bold", fill: ink)[
      #it
      #v(-0.25em)
      #line(length: 100%, stroke: 1.2pt + primary)
    ]
  } else if it.level == 2 {
    text(size: 11pt, weight: "bold", fill: primary)[#it]
  } else {
    text(size: 9.8pt, weight: "bold", fill: ink)[#it]
  }
]

#set table(
  stroke: (x, y) => if y == 0 { (bottom: 1.4pt + ink) } else { 0.4pt + light-border },
  fill: (col, row) => if row == 0 { rgb("f1f5f9") } else if calc.even(row) { rgb("fafafa") } else { white },
  inset: 4.5pt
)

// --- Voices of Master Thinkers ---
#let feynman-dialogue(body) = block(
  width: 100%,
  stroke: (left: 3pt + accent-gold),
  fill: gold-light,
  inset: (x: 10pt, y: 7pt),
  radius: (right: 3pt),
  breakable: false
)[
  #grid(
    columns: (auto, 1fr),
    gutter: 8pt,
    text(size: 12pt)[⚡],
    [
      #text(weight: "bold", size: 8.8pt, fill: accent-gold)[Feynman's Physical Intuition: Energy Asymmetry & The Second Law]
      #v(2pt)
      #text(size: 8.8pt, fill: rgb("78350f"), style: "italic")[#body]
    ]
  )
]

#let knuth-dialogue(body) = block(
  width: 100%,
  stroke: (left: 3pt + accent-purple),
  fill: purple-light,
  inset: (x: 10pt, y: 7pt),
  radius: (right: 3pt),
  breakable: false
)[
  #grid(
    columns: (auto, 1fr),
    gutter: 8pt,
    text(size: 12pt)[📐],
    [
      #text(weight: "bold", size: 8.8pt, fill: accent-purple)[Knuth's Mechanical Precision: Cache-Lines & Concrete Mathematics]
      #v(2pt)
      #text(size: 8.8pt, fill: rgb("4c1d95"))[#body]
    ]
  )
]

#let lamport-dialogue(body) = block(
  width: 100%,
  stroke: (left: 3pt + primary),
  fill: primary-light,
  inset: (x: 10pt, y: 7pt),
  radius: (right: 3pt),
  breakable: false
)[
  #grid(
    columns: (auto, 1fr),
    gutter: 8pt,
    text(size: 12pt)[🏛],
    [
      #text(weight: "bold", size: 8.8pt, fill: primary)[Lamport's Distributed Invariant: Safety, Liveness & Replicated Logs]
      #v(2pt)
      #text(size: 8.8pt, fill: rgb("0369a1"))[#body]
    ]
  )
]

#let theorem-box(number, title, statement, proof) = block(
  width: 100%,
  stroke: 0.5pt + border,
  fill: white,
  inset: 8pt,
  radius: 4pt,
  breakable: false
)[
  #text(weight: "bold", fill: ink)[Theorem #number] (#text(style: "italic")[#title]).
  #h(4pt)
  #statement
  #v(2.5pt)
  #text(weight: "bold", size: 7.8pt, fill: muted)[PROOF.]
  #text(size: 8.4pt, fill: rgb("334155"))[#proof]
  #align(right)[#text(fill: primary)[$square$]]
]

#let metric-card(value, label, subtext) = block(
  stroke: 0.6pt + border,
  fill: white,
  inset: (x: 6pt, top: 5pt, bottom: 6pt),
  radius: 4pt,
  width: 100%
)[
  #align(center)[
    #text(size: 15.5pt, weight: "bold", fill: primary)[#value]
    #v(-3pt)
    #text(size: 7.5pt, weight: "bold", fill: ink)[#label]
    #v(-4pt)
    #text(size: 6.6pt, fill: muted)[#subtext]
  ]
]

// ==========================================
// TITLE & ABSTRACT (PAGE 1)
// ==========================================

#align(center)[
  #v(2mm)
  #text(size: 21pt, weight: "bold", fill: ink)[SIBUNA]
  #v(1mm)
  #text(size: 12pt, weight: "medium", fill: primary)[A Zero-Allocation, Distributed Web Defense Engine]
  #v(0.5mm)
  #text(size: 8.8pt, fill: muted)[Thermodynamic Asymmetry, Linear-Time Automata, and Embedded Consensus via zaxonlite]
  #v(3mm)
  #text(size: 8.8pt, weight: "bold", fill: ink)[Vikrant Rathore #h(10pt) · #h(10pt) Ronak Rathore]
  #v(0.5mm)
  #text(size: 8pt, fill: muted)[Insan AI Systems & Architecture Lab · Pure Zig Release 0.16.0]
  #v(3mm)
]

#block(
  width: 100%,
  fill: rgb("f8fafc"),
  inset: 9pt,
  radius: 5pt,
  stroke: 0.6pt + border
)[
  #align(center)[#text(weight: "bold", size: 8.5pt, fill: ink)[ABSTRACT]]
  #v(1pt)
  #text(size: 8.4pt, fill: rgb("334155"))[
    Web application firewalls (WAFs) and edge defense platforms suffer from three systemic architectural dysfunctions:
    (1) *Thermodynamic inversion*, wherein defending proxies expend orders of magnitude more computational energy parsing headers, traversing regular expressions, and querying databases than automated botnets expend emitting requests;
    (2) *Runtime unpredictability*, stemming from dynamic memory allocators (`malloc`), garbage-collection stop-the-world pauses, and bloated container architectures (e.g., SafeLine's 1.5–2.5 GB footprint spanning 5–8 containers); and
    (3) *Externalized state coupling*, forcing operators to deploy and manage auxiliary Redis or PostgreSQL clusters to synchronize IP reputation, token verification, and rate limits across nodes.

    *Sibuna* demonstrates a complete architectural reconstruction from first principles. Implemented as a standalone, zero-dependency binary under 13 MB in pure Zig, Sibuna introduces:
    (i) *Work-verifiable thermodynamic defense* via Cohen–Pietrzak Proof of Sequential Work (PoSW) and BLAKE3 MAC tokens, forcing attacking bots to perform unparallelizable CPU work while the defender verifies authenticity in under 26 microseconds with zero heap allocation;
    (ii) *A strict zero-allocation hot path*, employing SIMD-accelerated Aho–Corasick automata (88.96 ns for 40 bot signatures, 39.3× faster than sequential scanning), 16-shard atomic GCRA rate limiting (9.48 ns per check, >105M ops/sec), and Robin Hood hashed nonce tracking (45.02 ns); and
    (iii) *An embedded distributed consensus engine* powered by `zaxonlite`, executing WAL-frame Multi-Paxos directly within the process memory space to provide sub-160 ms cluster-wide ban propagation and seamless leader failover at under 22 MB RSS per node.
  ]
]

#v(2mm)

#grid(
  columns: (1fr, 1fr, 1fr, 1fr),
  gutter: 6pt,
  metric-card("9.48 ns", "GCRA RATE CHECK", "105M ops/sec · 16 Shards"),
  metric-card("88.96 ns", "SIMD BOT MATCHER", "Aho-Corasick · 40 Sigs"),
  metric-card("25.8 µs", "PoSW VERIFICATION", "Depth 13 · Bounded Stack"),
  metric-card("< 22 MB", "CLUSTER NODE RSS", "Embedded Multi-Paxos")
)

#v(2.5mm)

// ==========================================
// 1. PROLOGUE: THE THERMODYNAMICS OF DEFENSE
// ==========================================
= Prologue: The Thermodynamics of Web Defense

In classical mechanics, conservation laws govern all physical interactions. Energy cannot be conjured from nothing; work performed by an agent is inextricably tied to entropy generated in the universe. Yet for thirty years, the architecture of web application defense has lived in deliberate defiance of thermodynamics.

#feynman-dialogue[
  "Imagine you are guarding a city gate. A mischievous boy outside throws tiny pebbles at the gate. If every time a pebble hits the wooden door, you are forced to dispatch five armored knights with tape measures to calculate the trajectory, speed, and chemical composition of the pebble, and then send a carrier pigeon to the king's palace to ask if this pebble is on the forbidden list—who runs out of energy first?
  The boy can toss pebbles all afternoon with one pocketful of stones. Your kingdom collapses from exhaustion before sunset.
  To stop an asymmetric onslaught, you don't build a thinking machine that burns coal to examine every pebble. You tilt the landscape so that anyone approaching the gate must haul a boulder uphill before you even open the peephole. If hauling the boulder costs them ten minutes of physical labor, and glancing at their hands costs you half a second, the boy stops throwing pebbles."
]

In contemporary computing, an automated attacker launching an HTTP flood or credential stuffing attack expends negligible marginal energy. Utilizing botnets of compromised IoT devices or cheap cloud instances, an adversary can emit hundreds of thousands of HTTP/1.1 `GET` or `POST` requests for fractions of a cent ($E_"attacker" approx 10^(-6) "J"$).

When those requests reach a traditional WAF, the defending server executes:
1. Full TCP handshakes, TLS session negotiation, and public-key cryptography.
2. Dynamic heap allocations (`malloc`) to copy request buffers, split headers, and decode query parameters.
3. PCRE regular expression scanning, which in worst-case patterns exhibits catastrophic exponential backtracking ($O(2^N)$), converting single-character inputs into billions of CPU cycles.
4. Synchronous network round-trips to external key-value stores (Redis) or relational databases (PostgreSQL) to read and update rate-limiting counters.



// ==========================================
// PAGE 2: THERMODYNAMICS CONTINUATION & FIGURE 1 & SECTION 2
// ==========================================

The defender expends $10^(-2) "J"$ per request. This creates an energetic leverage ratio of $10,000 : 1$ in favor of the attacker. Under such thermodynamic inversion, volumetric denial of service is not an anomalous bug; it is an inescapable physical inevitability.

#v(1.5mm)

#figure(
  caption: [The Thermodynamic Energy Asymmetry: Traditional WAF Inversion vs. Sibuna Breakwater],
  cetz.canvas(length: 1cm, {
    import cetz.draw: *

    let c-attacker = rgb("ef4444")
    let c-legacy = rgb("dc2626")
    let c-posw = rgb("059669")

    // --- Panel 1: Traditional WAF Asymmetry ---
    rect((0, 0), (8.1, 4.3), fill: rgb("fff5f5"), stroke: 0.8pt + rgb("fca5a5"), radius: 0.2)
    content((4.05, 3.9), text(weight: "bold", size: 8.5pt, fill: rgb("991b1b"))[Traditional WAF: Energetic Inversion], anchor: "center")
    
    // Attacker node
    rect((0.4, 0.9), (3.4, 3.3), fill: white, stroke: 0.8pt + c-attacker, radius: 0.15)
    content((1.9, 2.85), text(weight: "bold", size: 8pt, fill: c-attacker)[Attacker Work], anchor: "center")
    content((1.9, 2.3), text(size: 7.2pt)[1 HTTP SYN+Req], anchor: "center")
    content((1.9, 1.5), text(size: 7.8pt, weight: "bold", fill: rgb("991b1b"))[$E_A approx 1 mu"J"$], anchor: "center")

    // Legacy defender node
    rect((4.7, 0.9), (7.7, 3.3), fill: white, stroke: 0.8pt + c-legacy, radius: 0.15)
    content((6.2, 2.85), text(weight: "bold", size: 8pt, fill: c-legacy)[Defender Burn], anchor: "center")
    content((6.2, 2.4), text(size: 7.2pt)[PCRE Regex + GC], anchor: "center")
    content((6.2, 2.0), text(size: 7.2pt)[Redis / Postgres], anchor: "center")
    content((6.2, 1.45), text(size: 7.8pt, weight: "bold", fill: rgb("991b1b"))[$E_D approx 10,"000" mu"J"$], anchor: "center")

    // Arrow
    line((3.4, 2.1), (4.7, 2.1), mark: (end: ">"), stroke: 1.5pt + c-attacker)
    content((4.05, 2.55), text(size: 7.2pt, weight: "bold", fill: c-attacker)[10,000 : 1], anchor: "center")
    content((4.05, 0.4), text(size: 7.2pt, style: "italic", fill: rgb("7f1d1d"))[Defender collapses under load], anchor: "center")

    // --- Panel 2: Sibuna Thermodynamic Breakwater ---
    rect((8.9, 0), (17.0, 4.3), fill: rgb("f0fdf4"), stroke: 0.8pt + rgb("86efac"), radius: 0.2)
    content((12.95, 3.9), text(weight: "bold", size: 8.5pt, fill: rgb("065f46"))[Sibuna: Thermodynamic Breakwater], anchor: "center")

    // Attacker node under PoSW
    rect((9.3, 0.9), (12.3, 3.3), fill: white, stroke: 0.8pt + rgb("b45309"), radius: 0.15)
    content((10.8, 2.85), text(weight: "bold", size: 8pt, fill: rgb("b45309"))[Attacker Work], anchor: "center")
    content((10.8, 2.4), text(size: 7.2pt)[Sequential Hash Tree], anchor: "center")
    content((10.8, 2.0), text(size: 7.2pt)[8,192 Node PoSW], anchor: "center")
    content((10.8, 1.45), text(size: 7.8pt, weight: "bold", fill: rgb("92400e"))[$E_A approx 50,"000" mu"J"$], anchor: "center")

    // Sibuna defender node
    rect((13.6, 0.9), (16.6, 3.3), fill: white, stroke: 0.8pt + c-posw, radius: 0.15)
    content((15.1, 2.85), text(weight: "bold", size: 8pt, fill: c-posw)[Sibuna Core], anchor: "center")
    content((15.1, 2.4), text(size: 7.2pt)[SIMD + GCRA], anchor: "center")
    content((15.1, 2.0), text(size: 7.2pt)[Logarithmic Verify], anchor: "center")
    content((15.1, 1.45), text(size: 7.8pt, weight: "bold", fill: rgb("065f46"))[$E_D approx 0.05 mu"J"$], anchor: "center")

    // Arrow
    line((12.3, 2.1), (13.6, 2.1), mark: (end: ">"), stroke: 1.5pt + c-posw)
    content((12.95, 2.55), text(size: 7.2pt, weight: "bold", fill: c-posw)[1 : 1,000,000], anchor: "center")
    content((12.95, 0.4), text(size: 7.2pt, style: "italic", fill: rgb("14532d"))[Attacker throttled by physics], anchor: "center")
  })
)

Sibuna inverts this relationship. By conditioning admission upon cryptographic *Proofs of Sequential Work (PoSW)* or *Geometric Hashcash*, the energetic cost is transferred onto the challenger. Concurrently, Sibuna guarantees that verifying the challenge is logarithmic in work, bounded in memory, and accomplished with *zero heap allocations* on the defender's CPU.

= Mechanical Sympathy: Zero-Allocation and Bounded State

#knuth-dialogue[
  "The programmer who relies on a dynamic heap allocator during the inner loop of a real-time system is like an architect who designs a bridge and leaves the foundations to be poured by a passing stranger while the cars are already crossing.
  On modern microprocessors, an instruction cache hit takes 1 cycle. An L1 data hit takes 4 cycles. A trip to main DRAM across a fragmented heap takes 200 cycles, during which the processor sits entirely idle. If your software allocates memory while classifying an incoming packet, it is not serving traffic; it is waiting in an administrative queue. An algorithm achieves elegance only when every single byte of memory is assigned a permanent, bounded address before the system opens its first socket."
]

== The Zero-Allocation Hot Path Invariant
Virtually all legacy WAF solutions are written in high-level interpreted or garbage-collected runtimes (Go, Python, Lua, Node.js) or depend on C/C++ libraries that freely invoke `malloc()` and `free()`. Under high concurrency, dynamic heap management inflicts severe architectural damage:
- *Virtual Memory Fragmentation*: Fragmented heaps inflate resident set sizes (RSS) into multiple gigabytes over days of continuous operation.
- *Garbage Collection Jitter*: Go and Java runtimes incur stop-the-world GC cycles, producing multi-millisecond P99 and P99.9 latency spikes.
- *Cache-Line Invalidation*: Pointers scattered across non-contiguous heap regions thrash CPU L1/L2/L3 caches and translation lookaside buffers (TLBs).

Sibuna enforces a strict architectural contract: *the hot evaluation path shall never invoke the operating system heap allocator*. All internal data structures—sliding window buffers, Radix tries, rate-limiting shards, Aho-Corasick transition tables, and token verifiers—are statically allocated at startup or backed by fixed-capacity circular rings.



// ==========================================
// PAGE 3: REQUEST PIPELINE & THEOREMS 1 & 2
// ==========================================

== The Complete Request Pipeline
The following architectural diagram illustrates the wire-speed progression of a request through Sibuna's zero-allocation stages:

#v(1mm)

#figure(
  caption: [Sibuna Wire-Speed Request Lifecycle: Measured Zero-Allocation Hot Path],
  cetz.canvas(length: 1cm, {
    import cetz.draw: *

    let c-navy = rgb("0f172a")
    let c-blue = rgb("0284c7")
    let c-blue-bg = rgb("f0f9ff")
    let c-purple = rgb("7c3aed")
    let c-purple-bg = rgb("faf5ff")
    let c-gold = rgb("d97706")
    let c-gold-bg = rgb("fffbeb")
    let c-green = rgb("059669")
    let c-green-bg = rgb("ecfdf5")
    let c-red = rgb("dc2626")
    let c-red-bg = rgb("fef2f2")
    let c-gray-border = rgb("cbd5e1")
    let c-text = rgb("1e293b")

    // Outer boundary card
    rect((0, 0), (17.0, 11.2), fill: rgb("f8fafc"), stroke: 0.8pt + c-gray-border, radius: 0.3)
    content((8.5, 10.7), text(weight: "bold", size: 10.2pt, fill: c-navy)[Sibuna Wire-Speed Request Lifecycle (Measured Zero-Allocation Hot Path)], anchor: "center")

    // Helper to draw a stage box
    let stage-box(x, y, w, h, fill-col, stroke-col, title, latency, subtext) = {
      rect((x, y), (x + w, y + h), fill: fill-col, stroke: 0.8pt + stroke-col, radius: 0.18)
      content((x + w/2, y + h - 0.35), text(weight: "bold", size: 8pt, fill: stroke-col)[#title], anchor: "center")
      content((x + w/2, y + h/2), text(size: 7.2pt, fill: c-text)[#subtext], anchor: "center")
      rect((x + w/2 - 0.9, y + 0.18), (x + w/2 + 0.9, y + 0.65), fill: stroke-col, stroke: none, radius: 0.1)
      content((x + w/2, y + 0.41), text(weight: "bold", size: 7pt, fill: white)[#latency], anchor: "center")
    }

    // --- Row 1 (y: 8.2 - 9.8): L4 Ingress & Filtering ---
    rect((0.6, 8.2), (3.2, 9.8), fill: white, stroke: 0.8pt + c-navy, radius: 0.18)
    content((1.9, 9.3), text(weight: "bold", size: 8.5pt, fill: c-navy)[TCP Ingress], anchor: "center")
    content((1.9, 8.8), text(size: 7.5pt)[Raw Stream Buffer], anchor: "center")
    content((1.9, 8.4), text(size: 7pt, fill: rgb("64748b"))[Zero Alloc / Ring], anchor: "center")

    // Stage 1: Radix Trie
    stage-box(4.2, 8.2, 3.4, 1.6, c-blue-bg, c-blue, [1. Radix Trie CIDR], [72.59 ns], [IPv4/IPv6 Table Lookup])

    // Stage 2: 16-Shard GCRA
    stage-box(8.6, 8.2, 3.4, 1.6, c-blue-bg, c-blue, [2. Sharded GCRA], [9.48 ns], [16 Shards · Lock-Free CAS])

    // Stage 3: Zero-Copy Parser
    stage-box(13.0, 8.2, 3.4, 1.6, c-blue-bg, c-blue, [3. Zero-Copy HTTP], [1.50 µs], [Slices Only · In-Place])

    // Arrows Row 1
    line((3.2, 9.0), (4.2, 9.0), mark: (end: ">"), stroke: 1.2pt + c-blue)
    line((7.6, 9.0), (8.6, 9.0), mark: (end: ">"), stroke: 1.2pt + c-blue)
    content((8.1, 9.3), text(size: 6.5pt, fill: c-green)[Pass], anchor: "center")
    line((12.0, 9.0), (13.0, 9.0), mark: (end: ">"), stroke: 1.2pt + c-blue)
    content((12.5, 9.3), text(size: 6.5pt, fill: c-green)[Admit], anchor: "center")

    // Row 1 to Row 2 connecting snake arrow
    line((14.7, 8.2), (14.7, 7.3), (14.7, 6.7), mark: (end: ">"), stroke: 1.2pt + c-purple)

    // --- Row 2 (y: 5.1 - 6.7): Identity, Bots & Cryptography ---
    // Stage 4: SIMD Aho-Corasick
    stage-box(13.0, 5.1, 3.4, 1.6, c-purple-bg, c-purple, [4. SIMD Bot Matcher], [88.96 ns], [40 Crawler Signatures])

    // Stage 5: BLAKE3 MAC Token
    stage-box(8.6, 5.1, 3.4, 1.6, c-purple-bg, c-purple, [5. BLAKE3 Token], [212.52 ns], [Keyed MAC Authentication])

    // Stage 6: PoSW Verifier
    stage-box(4.2, 5.1, 3.4, 1.6, c-gold-bg, c-gold, [6. PoSW Verifier], [25.83 µs], [Cohen-Pietrzak Depth 13])

    // Arrows Row 2
    line((13.0, 5.9), (12.0, 5.9), mark: (end: ">"), stroke: 1.2pt + c-purple)
    content((12.5, 6.2), text(size: 6.5pt, fill: c-green)[Clean], anchor: "center")

    line((8.6, 5.9), (7.6, 5.9), mark: (end: ">"), stroke: 1.2pt + c-gold)
    content((8.1, 6.25), text(size: 6.5pt, fill: c-gold)[No Token], anchor: "center")

    // Fast path token bypass from BLAKE3 directly to Stage 7 (shifted text left to avoid crossing red dashed line)
    line((10.3, 5.1), (10.3, 4.3), (2.3, 4.3), (2.3, 3.2), mark: (end: ">"), stroke: 1.2pt + c-green)
    content((5.1, 4.55), text(size: 6.8pt, weight: "bold", fill: c-green)[Valid Token Fast-Path (Bypass PoSW)], anchor: "center")

    // PoSW verified arrow down to Row 3
    line((5.9, 5.1), (5.9, 3.2), mark: (end: ">"), stroke: 1.2pt + c-green)
    content((5.2, 3.9), text(size: 6.5pt, fill: c-green)[Verified], anchor: "center")

    // --- Row 3 (y: 1.6 - 3.2): Deep Semantic Inspection & Terminal Sinks ---
    // Stage 7: Semantic WAF
    stage-box(0.6, 1.6, 3.4, 1.6, c-blue-bg, c-blue, [7. Semantic WAF], [37.98 µs], [SQLi / XSS Tokenizer])

    // Terminal Sink 1: Upstream Proxy
    rect((4.8, 1.6), (7.8, 3.2), fill: c-green-bg, stroke: 1pt + c-green, radius: 0.18)
    content((6.3, 2.7), text(weight: "bold", size: 8.5pt, fill: c-green)[Upstream Origin], anchor: "center")
    content((6.3, 2.2), text(size: 7.2pt)[Reverse Proxy Keep-Alive], anchor: "center")
    content((6.3, 1.8), text(weight: "bold", size: 7pt, fill: c-green)[HTTP 200 Admitted], anchor: "center")

    // Terminal Sink 2: Drop / Ban Sink
    rect((9.0, 1.6), (12.2, 3.2), fill: c-red-bg, stroke: 1pt + c-red, radius: 0.18)
    content((10.6, 2.7), text(weight: "bold", size: 8.5pt, fill: c-red)[Drop / Ban Sink], anchor: "center")
    content((10.6, 2.2), text(size: 7.2pt)[Blacklisted CIDR / Threat], anchor: "center")
    content((10.6, 1.8), text(weight: "bold", size: 7pt, fill: c-red)[Connection Severed], anchor: "center")

    // Terminal Sink 3: Challenge Issuer
    rect((13.0, 1.6), (16.4, 3.2), fill: c-gold-bg, stroke: 1pt + c-gold, radius: 0.18)
    content((14.7, 2.7), text(weight: "bold", size: 8.5pt, fill: c-gold)[HTTP 401 Challenge], anchor: "center")
    content((14.7, 2.2), text(size: 7.2pt)[Issue Signed PoSW Ticket], anchor: "center")
    content((14.7, 1.8), text(weight: "bold", size: 7pt, fill: c-gold)[Zero Server State], anchor: "center")

    // Arrow Stage 7 to Upstream
    line((4.0, 2.4), (4.8, 2.4), mark: (end: ">"), stroke: 1.5pt + c-green)
    content((4.4, 2.7), text(size: 6.5pt, fill: c-green)[Clean], anchor: "center")

    // Cleanly routed Dropped line to Ban Sink through open channel at x: 8.0
    line((5.9, 8.2), (5.9, 7.5), (7.8, 7.5), (7.8, 2.4), (9.0, 2.4), mark: (end: ">"), stroke: 1pt + c-red, dash: "dashed")
    content((6.9, 7.7), text(size: 6.5pt, fill: c-red)[CIDR Banned], anchor: "center")

    // GCRA Exceeded arrow to Challenge through open channel at x: 12.5
    line((10.3, 8.2), (10.3, 7.3), (12.5, 7.3), (12.5, 2.4), (13.0, 2.4), mark: (end: ">"), stroke: 1pt + c-gold, dash: "dashed")
    content((11.4, 7.5), text(size: 6.5pt, fill: c-gold)[Rate Exceeded], anchor: "center")
  })
)

== Mathematical Proofs of Algorithmic Primitives

#theorem-box(
  "1",
  "Deterministic Linear-Time Inspection via SIMD Aho–Corasick Automata",
  [Given an input string $T$ of length $n$ and a dictionary of $k$ attack patterns $P = {p_1, dots, p_k}$ of aggregate length $m$, Sibuna classifies $T$ in strict worst-case time $O(n + m)$ using zero heap memory, completely eliminating Regular Expression Denial of Service (ReDoS).],
  [Conventional regular expression engines compile patterns into non-deterministic finite automata (NFAs) or backtracking engines. On malicious inputs designed with overlapping prefixes (e.g., `(a+)+$`), backtracking induces execution time $O(n dot 2^m)$.
  Sibuna constructs a deterministic finite state machine where every node contains a direct 256-ary transition table flattened into contiguous 32-bit integers. Transitions are vectorized across 128-bit/256-bit SIMD registers. Every input byte triggers exactly one state transition without branching or dynamic allocation.
  Empirical verification on 40 production bot signatures yields a median evaluation time of *88.96 ns* (11,241,454 ops/sec), compared to 3,496.15 ns for standard sequential substring scanning—a *39.3× speedup*.]
)

#v(1.5mm)

#theorem-box(
  "2",
  "Lock-Free Rate Limiting via 16-Shard Atomic GCRA",
  [The Generic Cell Rate Algorithm (GCRA) guarantees that traffic conforms to average rate $1/T$ with maximum burst $L$, requiring only a single 64-bit atomic compare-and-swap per client.],
  [Classical token-bucket implementations maintain token counts and timestamps guarded by POSIX mutexes, inducing severe cache-line contention and thread stalling under multi-core load. Sibuna formulates the continuous-state leaky bucket:
  $ "TAT"_n = cases(
    t + T & "if" t > "TAT"_(n-1),
    "TAT"_(n-1) + T & "if" t <= "TAT"_(n-1) <= t + L,
    "reject" & "if" "TAT"_(n-1) > t + L,
  ) $
  where $t$ is the nanosecond arrival timestamp, $T$ is the emission interval, and $L$ is burst tolerance. Both $t$ and $"TAT"$ are packed into a single atomic `u64`. Updates proceed lock-free via atomic CAS (`cmpxchg`).
  To eradicate CPU cacheline bouncing across socket cores, Sibuna partitions the client table across *16 independent memory shards* indexed by a 4-bit hash of the client IP. On an Apple M1 core, single-scope GCRA executes in *9.48 ns* (>105 million checks/sec) with zero heap allocations.]
)



// ==========================================
// PAGE 4: THEOREM 3 & SECTION 3 (DISTRIBUTED STATE MACHINE)
// ==========================================

#theorem-box(
  "3",
  "Stateless Cryptographic Challenge Issuance and Work-Bounded Replay Defense",
  [A web proxy can challenge clients and verify computational proofs without maintaining server-side session tables, bounding memory exposure to zero under massive SYN/HTTP floods.],
  [Sibuna constructs an authenticated challenge ticket:
  $ "Ticket" = chevron.l "IP" || "Timestamp" || "Difficulty" || "Nonce" || "MAC"_K("IP" || "Timestamp" || "Difficulty" || "Nonce") chevron.r $
  where $"MAC"_K$ is computed using BLAKE3 in keyed mode (*212.52 ns*). The secret key $K$ is rotated every epoch $Delta t$. When a client submits a solved puzzle, Sibuna validates:
  (1) $"MAC"_K$ verifies under epoch key $K_t$ or $K_(t-1)$;
  (2) $|t_"now" - "Timestamp"| <= Delta t_"valid"$; and
  (3) the proof satisfies the target sequential difficulty.
  To prevent replay attacks within $Delta t_"valid"$, Sibuna inserts the 64-bit hash of the spent nonce into a fixed-capacity *Robin Hood hash table*. Robin Hood hashing minimizes the variance of probe sequence lengths ($D_i - "ideal"$), ensuring worst-case insertion and lookup in *45.02 ns* ($O(1)$ amortized).]
)

= The Distributed State Machine: Consensus via zaxonlite

#lamport-dialogue[
  "A distributed system is one in which the failure of a computer you didn't even know existed can render your own computer unusable.
  The prevailing fashion in modern software architecture is to assemble distributed systems like children building with plastic bricks: you take a web proxy, string a network cable to a Redis cluster, string another cable to a PostgreSQL database, and declare yourself scalable. But what happens when the network cable between the proxy and the database hiccups? Does your firewall fail closed and deny legitimate users, or fail open and allow the attackers in?
  A true distributed firewall cannot depend on an external oracle for truth. It must contain the state machine inside itself. Consensus must be an intrinsic property of the binary, replicated across peer nodes through an immutable log governed by rigorous mathematical invariants."
]

== The Architectural Pathology of Externalized State
Every multi-node firewall must solve the state synchronization problem: when Node A detects an aggressive distributed denial-of-service attack from an IP range, how quickly and reliably do Node B and Node C enforce the ban?

Existing market solutions rely on external databases:
- *SafeLine (Chaitin)*: Requires centralized PostgreSQL and Redis containers. A crash or deadlock in Postgres freezes administrative operations and state sharing across the entire fleet.
- *Coraza / Anubis*: Typically paired with external Redis clusters. Every rate-limit check or ban query traverses the network stack via TCP/RESP serialization, adding 0.5–2.0 ms of network latency and introducing a catastrophic single point of failure.
- *CrowdSec*: Runs an out-of-process daemon that reads log files from disk and communicates asynchronously with a central API. Threat updates propagate with latencies of seconds to minutes, leaving large attack windows open.

== zaxonlite: Embedded WAL-Frame Multi-Paxos
Sibuna solves state distribution by embedding `zaxonlite`—a high-performance, embedded distributed storage and consensus library—directly into its address space. There are zero external processes, zero sidecars, and zero database daemons.

Sibuna cluster nodes maintain a replicated Write-Ahead Log (WAL). State mutations (IP bans, rate-limit threshold changes, dynamic WAF rule deployments) are proposed as log entries governed by Leslie Lamport's Multi-Paxos consensus protocol.



// ==========================================
// PAGE 5: FIGURE 3 & INVARIANTS & MARKET COMPARISON TABLE
// ==========================================

#figure(
  caption: [Sibuna 3-Node Mesh: Embedded Multi-Paxos State Machine via zaxonlite],
  cetz.canvas(length: 1cm, {
    import cetz.draw: *

    let c-navy = rgb("0f172a")
    let c-blue = rgb("0284c7")
    let c-green = rgb("059669")
    let c-green-bg = rgb("ecfdf5")
    let c-card-bg = rgb("f8fafc")
    let c-border = rgb("cbd5e1")
    let c-text = rgb("334155")
    let c-gold = rgb("d97706")

    // Outer boundary card
    rect((0, 0), (17.0, 8.4), fill: rgb("fafafa"), stroke: 0.8pt + c-border, radius: 0.3)
    content((8.5, 7.95), text(weight: "bold", size: 10.2pt, fill: c-navy)[Sibuna 3-Node Mesh: Embedded Multi-Paxos State Machine (zaxonlite)], anchor: "center")

    // Node drawing helper
    let draw-node(x, y, is-leader, name, port, mesh-port, rss, state-text) = {
      let stroke-color = if is-leader { c-green } else { c-blue }
      let fill-color = if is-leader { c-green-bg } else { white }
      rect((x, y), (x + 4.8, y + 2.8), fill: fill-color, stroke: 1.2pt + stroke-color, radius: 0.22)
      
      // Role badge
      let badge-fill = if is-leader { c-green } else { c-blue }
      let badge-title = if is-leader { "LEADER (ACTIVE)" } else { "FOLLOWER (REPLICA)" }
      rect((x + 0.3, y + 2.18), (x + 4.5, y + 2.62), fill: badge-fill, stroke: none, radius: 0.1)
      content((x + 2.4, y + 2.40), text(weight: "bold", size: 7.2pt, fill: white)[#badge-title], anchor: "center")

      content((x + 2.4, y + 1.80), text(weight: "bold", size: 8.8pt, fill: c-navy)[#name], anchor: "center")
      content((x + 2.4, y + 1.40), text(size: 7.5pt, fill: c-text)[HTTP : #port  ·  Mesh : #mesh-port], anchor: "center")
      content((x + 2.4, y + 1.02), text(size: 7.2pt, fill: c-text)[WAL: #state-text], anchor: "center")

      // RSS Badge
      rect((x + 1.4, y + 0.25), (x + 3.4, y + 0.68), fill: rgb("e2e8f0"), stroke: none, radius: 0.1)
      content((x + 2.4, y + 0.46), text(weight: "bold", size: 7.2pt, fill: c-navy)[RSS: #rss], anchor: "center")
    }

    // Leader (Top Center)
    draw-node(6.1, 4.4, true, "Node 1", "8000", "9000", "19.7 MB", "Replicated Frame Commit")

    // Follower 1 (Bottom Left)
    draw-node(0.8, 0.5, false, "Node 2", "8001", "9001", "21.3 MB", "Phase 2 Accepted / Quorum")

    // Follower 2 (Bottom Right)
    draw-node(11.4, 0.5, false, "Node 3", "8002", "9002", "19.6 MB", "Phase 2 Accepted / Quorum")

    // Straight clean angled replication arrows
    line((6.1, 4.8), (3.6, 3.3), mark: (start: ">", end: ">"), stroke: 1.5pt + c-blue)
    content((3.6, 4.3), text(weight: "bold", size: 7pt, fill: c-blue)[Replicated WAL Frames\ (Phase 2 Accept Quorum)], anchor: "center")

    line((10.9, 4.8), (13.4, 3.3), mark: (start: ">", end: ">"), stroke: 1.5pt + c-blue)
    content((13.4, 4.3), text(weight: "bold", size: 7pt, fill: c-blue)[Replicated WAL Frames\ (Phase 2 Accept Quorum)], anchor: "center")

    // Heartbeat between Node 2 and Node 3 with generous clearance
    content((8.5, 2.45), text(weight: "bold", size: 7.2pt, fill: c-gold)[Peer Heartbeats & Lease Monotonicity (Invariant S2)], anchor: "center")
    content((8.5, 1.9), text(size: 7.2pt, style: "italic", fill: c-text)[Cluster Ban Propagation: 155.37 ms  ·  Zero External DBs], anchor: "center")
    line((5.6, 1.05), (11.4, 1.05), mark: (start: ">", end: ">"), stroke: 1.1pt + c-gold, dash: "dashed")
  })
)

#v(1mm)

#block(
  width: 100%,
  stroke: (left: 2.5pt + primary),
  fill: rgb("f8fafc"),
  inset: 8pt,
  radius: 3pt
)[
  #text(weight: "bold", fill: ink)[Invariant S1 (Consensus Safety).] No two operational nodes in a Sibuna cluster ever commit conflicting state transitions at log index $i$, regardless of packet delays, reordering, or network partitions.
  
  #text(weight: "bold", fill: ink)[Invariant S2 (Monotonic Ballots).] Ballot numbers $b = chevron.l "term", "node_id" chevron.r$ are strictly totally ordered. Replicas reject any Prepare or Accept message with ballot $b < b_"max_promised"$.

  #text(weight: "bold", fill: ink)[Invariant L1 (Bounded Ban Convergence).] If a quorum $Q = floor(N/2) + 1$ of nodes is operational, an IP ban committed at node $n_a$ propagates to all reachable nodes within bounded network delay $Delta t_"prop"$.
]

== Empirical Cluster Verification and Fault Injection
In empirical tests conducted on a 3-node cluster:
- *Cluster-Wide Ban Propagation*: An IP ban initiated on the leader node propagated and was actively enforced across all three nodes in *155.37 ms*.
- *Fault Tolerance under Leader Termination*: During active benchmark traffic of 45,000 requests per second, the cluster leader was abruptly terminated (`kill -9`). The remaining two nodes detected lease expiration, elected a new leader via Multi-Paxos Phase 1, and sustained *38,864 requests/sec* without a single dropped session or corrupted log entry.
- *Memory Footprint*: In a full 3-node mesh with consensus active, node RSS remained under *21.3 MB* per instance.



// ==========================================
// PAGE 6: COMPREHENSIVE MARKET COMPARISON TABLE & CRITIQUE
// ==========================================
= Comprehensive Market Comparison: Sibuna vs. Industry Solutions

To evaluate Sibuna's engineering trade-offs, we present an exhaustive comparison against both prominent open-source engines and proprietary enterprise cloud WAFs.

#v(1.5mm)

#align(center)[
  #text(size: 7.2pt)[
    #table(
      columns: (1.5fr, 0.9fr, 0.9fr, 1.1fr, 1.2fr, 1.2fr, 1fr, 1fr),
      align: (left, center, center, center, center, center, center, center),
      table.header(
        [*System*], [*License*], [*Runtime*], [*Memory (RSS)*], [*Dependencies*], [*Consensus*], [*PoW Challenge*], [*Latency (Median)*]
      ),
      [#text(weight: "bold", fill: primary)[Sibuna]], [Open Source], [Pure Zig], [*< 22 MB*], [*None (0)*], [*Embedded Paxos*], [*Native PoSW*], [*2.37 µs*],
      [SafeLine (Chaitin)], [Open/Prop], [Py/Go/C++], [1.5–2.5 GB], [Postgres, Redis, Nginx], [Central DB], [None (Captcha)], [1.5–5.0 ms],
      [Anubis (Coraza)], [Open Source], [Go Runtime], [150–350 MB], [Redis / Envoy], [External Redis], [None], [150–400 µs],
      [Coraza / ModSec], [Open Source], [Go / C++], [80–200 MB], [Host Nginx/Apache], [None], [None], [250–800 µs],
      [BunkerWeb], [Open Source], [Python/Lua], [500–1200 MB], [Nginx, Docker, Redis], [None], [Captcha only], [2.0–8.0 ms],
      [CrowdSec], [Open Source], [Go Runtime], [100–250 MB], [SQLite / Central API], [Cloud API Relay], [None], [Asynchronous],
      [Cloudflare WAF], [Proprietary], [Rust/C/Lua], [N/A (SaaS)], [Cloudflare Edge], [Global Raft/Kafka], [JS / Captcha], [1.0–5.0 ms],
      [AWS WAF], [Proprietary], [Closed Edge], [N/A (SaaS)], [AWS ALB / CloudFront], [AWS Internal], [JS Challenge], [2.0–10.0 ms],
      [Fastly / SigSci], [Proprietary], [Go / Agent], [100–200 MB], [SaaS Cloud Relay], [Cloud Relay], [None], [500–1500 µs],
      [Akamai App Protect], [Proprietary], [Edge Kernel], [N/A (SaaS)], [Akamai Network], [Internal], [JS Captcha], [2.0–8.0 ms]
    )
  ]
]

#v(1.5mm)

== Detailed Architectural Critique

=== SafeLine (Chaitin Technology)
SafeLine is marketed as a modern community WAF powered by semantic analysis. However, its architecture exhibits massive operational sprawl:
- *Container Explosion*: A typical SafeLine deployment requires 5 to 8 separate Docker containers running simultaneously (`safeline-tengine`, `safeline-detector`, `safeline-mgt`, `safeline-postgres`, `safeline-redis`, etc.).
- *Resource Waste*: SafeLine requires a minimum of *1.5 GB to 2.5 GB of RAM* merely to boot into an idle state.
- *Fragile State Coordination*: Nodes rely on PostgreSQL for management and Redis for caching. A memory exhaustion event in Redis breaks real-time rate limiting, while a PostgreSQL failure paralyzes policy updates.
- *Sibuna Difference*: Sibuna compiles down to a single *12.7 MB binary*. A 3-node Sibuna cluster consumes *< 65 MB total RAM* across all three nodes combined—more than 35× less memory than a single idle SafeLine instance.

=== Coraza and ModSecurity (OWASP Core Rule Set)
ModSecurity (C++) and Coraza (Go) represent the traditional pattern-matching paradigm based on regular expressions:
- *Vulnerability to ReDoS*: Both engines evaluate HTTP bodies against hundreds of PCRE rules. Malicious actors frequently bypass or stall these engines by feeding payloads that trigger worst-case regex backtracking.
- *Garbage Collection Latency Spikes*: Coraza executes on the Go runtime. Under bursts of 30,000+ requests per second, heap object creation forces frequent GC cycles, causing high P99 latency variance.
- *Sibuna Difference*: Sibuna eliminates regex backtracking by compiling all signatures into *deterministic SIMD Aho–Corasick automata*. Inspection completes in *88.96 ns* with zero memory allocation.

=== Cloud Edge WAFs (Cloudflare & AWS WAF)
Proprietary cloud WAFs offer vast global edge networks but introduce substantial technical and commercial liabilities:
- *Data Privacy & Sovereignty*: Utilizing cloud WAFs requires routing customer TLS keys and unencrypted payload streams through third-party multi-tenant servers, conflicting with strict data residency regulations (e.g., GDPR, HIPAA).
- *Astronomical Edge Costs*: AWS WAF charges per rule evaluated and per million requests, resulting in unexpected cost surges during volumetric attacks. Furthermore, deploying a rule change across AWS CloudFront distributions requires 1 to 2 minutes.
- *Sibuna Difference*: Sibuna runs entirely on sovereign infrastructure. Bans propagate across the cluster in *155 ms*, with zero recurring per-request fees.



// ==========================================
// PAGE 7: BENCHMARK SUITE & KEY TAKEAWAYS
// ==========================================
= Empirical Benchmark Suite

All benchmark measurements reported in this whitepaper were gathered from automated test suites compiled in `ReleaseFast` mode under Zig 0.16.0 on an Apple M1 workstation (8 cores, 16 GB unified memory, macOS 26.6.2).

== Microbenchmark Latency Profile

#table(
  columns: (1.5fr, 1.8fr, 1.1fr, 1.3fr, 1fr),
  align: (left, left, right, right, center),
  table.header(
    [*Subsystem*], [*Workload*], [*Median Latency*], [*Throughput*], [*Allocations*]
  ),
  [Rate Limiter], [GCRA Single Scope], [*9.48 ns*], [105,457,421 ops/s], [0 bytes],
  [Rate Limiter], [GCRA 4 Rule Scopes], [*9.94 ns*], [100,633,133 ops/s], [0 bytes],
  [Challenge Store], [Robin Hood Spend & Lookup], [*45.02 ns*], [22,211,425 ops/s], [0 bytes],
  [IP Classifier], [IPv4 CIDR Radix Trie], [*72.59 ns*], [13,776,713 ops/s], [0 bytes],
  [IP Classifier], [IPv6 CIDR Radix Trie], [*129.99 ns*], [7,692,739 ops/s], [0 bytes],
  [Bot Matcher], [SIMD Aho-Corasick (40 Sigs)], [*88.96 ns*], [11,241,454 ops/s], [0 bytes],
  [Bot Matcher], [Sequential Substring (Naive)], [3,496.15 ns], [286,028 ops/s], [0 bytes],
  [Proof-of-Work], [Hashcash 16-bit Verify], [*94.46 ns*], [10,586,538 ops/s], [0 bytes],
  [Proof-of-Work], [PoSW Depth-13 Verify], [*25,832.37 ns*], [38,711 ops/s], [0 bytes],
  [Token Auth], [BLAKE3 MAC Verification], [*212.52 ns*], [4,705,541 ops/s], [0 bytes],
  [Token Auth], [Ed25519 Signature Verify], [84,557.31 ns], [11,826 ops/s], [0 bytes],
  [HTTP Parser], [Zero-Copy Request & Cookie], [*1,507.67 ns*], [663,273 ops/s], [0 bytes],
  [Policy Engine], [Browser Gate Profile], [*472.92 ns*], [2,114,505 ops/s], [0 bytes],
  [Policy Engine], [Browser Shield Full Inspection], [*2,375.67 ns*], [420,933 ops/s], [0 bytes],
  [WAF Inspector], [8 KB Body Semantic Scan], [37,988.14 ns], [26,324 ops/s], [8 KB buffer]
)

== Key Takeaways
1. *Sub-Microsecond Classification*: In the *Gate profile*, Sibuna completes full client classification in *472.92 ns*. Under full semantic inspection (*Shield profile*), classification finishes in *2.37 µs*—two to three orders of magnitude faster than conventional WAFs.
2. *Symmetric Verification Dominance*: BLAKE3 MAC verification takes *212.52 ns*, compared to 84,557 ns for Ed25519 asymmetric signatures. Rotating symmetric epoch keys gives identical cryptographic integrity with a *397× throughput advantage*.
3. *Strict Zero Allocation*: As proven by the zero-allocation instrumentation, all core classification and validation routines allocate *0 bytes of heap memory*.

= Cryptographic Proofs of Work: Sequential vs. Parallel Work

== The Cohen–Pietrzak Proof of Sequential Work (PoSW)
Standard Hashcash challenges require finding a nonce $x$ such that $"Hash"("Challenge" || x) < T$. While simple, Hashcash is vulnerable to parallel hardware speedups: an attacker possessing $M$ parallel ASIC or GPU cores solves the challenge $M$ times faster than an honest user with a single browser thread.

Sibuna resolves this hardware asymmetry through Cohen–Pietrzak Proofs of Sequential Work (PoSW):
1. *Sequential Graph Traversal*: The client computes a directed acyclic graph (DAG) of depth $d$, where vertex $v_i$ is computed sequentially:
   $ v_i = H(v_(i-1) || v_(gamma(i))) $
   where $gamma(i)$ is a bit-reversal skip function. Parallel workers cannot compute node $i$ without the output of node $i-1$.
2. *Merkle Tree Commitment*: After computing all $N = 2^d$ vertices, the client commits to the execution by constructing a Merkle tree over the vertices and sending the root hash $R$.
3. *Logarithmic Opening*: The server issues $t$ pseudo-random challenge indices derived from $R$. The client responds with opening paths of length $d$.
4. *Server Verification*: The server verifies the opening paths in time $O(t dot d)$. For depth $d=13$ ($N = 8,192$ steps) and $t=16$ openings, Sibuna verifies the client's work in *25.83 µs* using constant stack memory.



// ==========================================
// PAGE 8: FIGURE 4 & CONSOLE & CONCLUSION
// ==========================================

#figure(
  caption: [Computational Defense: Parallel Hashcash ASIC Vulnerability vs. Cohen-Pietrzak Sequential DAG],
  cetz.canvas(length: 1cm, {
    import cetz.draw: *

    let c-navy = rgb("0f172a")
    let c-blue = rgb("0284c7")
    let c-green = rgb("059669")
    let c-border = rgb("cbd5e1")
    let c-text = rgb("334155")
    let c-gold = rgb("d97706")
    let c-red = rgb("dc2626")

    // Outer card
    rect((0, 0), (17.0, 7.8), fill: rgb("fafafa"), stroke: 0.8pt + c-border, radius: 0.3)
    content((8.5, 7.3), text(weight: "bold", size: 10pt, fill: c-navy)[Computational Defense: Parallel Hashcash Flaw vs. Cohen-Pietrzak Sequential DAG], anchor: "center")

    // Left Panel: Hashcash (Parallel ASIC advantage)
    rect((0.6, 0.6), (8.2, 6.7), fill: rgb("fff8f8"), stroke: 0.7pt + rgb("fca5a5"), radius: 0.2)
    content((4.4, 6.2), text(weight: "bold", size: 8.8pt, fill: c-red)[Classical Hashcash: Parallel ASIC Exploitation], anchor: "center")
    content((4.4, 5.6), text(size: 7.5pt, style: "italic", fill: rgb("991b1b"))[$"Find" x: H("Challenge" || x) < T$], anchor: "center")

    // Cores attacking in parallel
    for i in range(4) {
      let y = 4.7 - i * 0.9
      rect((1.0, y), (2.8, y + 0.65), fill: white, stroke: 0.7pt + c-red, radius: 0.1)
      content((1.9, y + 0.32), text(size: 7pt, weight: "bold", fill: c-red)[Core #str(i+1) (ASIC)], anchor: "center")
      line((2.8, y + 0.32), (4.4, y + 0.32), mark: (end: ">"), stroke: 0.9pt + c-red)
      content((3.6, y + 0.52), text(size: 6.5pt)[Nonce #str(i+1)], anchor: "center")
    }

    rect((4.4, 1.8), (8.0, 4.9), fill: white, stroke: 0.8pt + c-red, radius: 0.15)
    content((6.2, 4.25), text(weight: "bold", size: 7.8pt, fill: c-red)[Instant Parallel\ Speedup], anchor: "center")
    content((6.2, 3.5), text(size: 7pt)[$M$ ASIC cores = $M times$ faster], anchor: "center")
    content((6.2, 2.85), text(size: 7pt)[Ordinary browsers penalized], anchor: "center")
    content((6.2, 2.2), text(weight: "bold", size: 7.2pt, fill: c-red)[Botnets bypass challenge], anchor: "center")

    content((4.4, 1.0), text(size: 7pt, fill: rgb("7f1d1d"))[Unfair to legitimate single-threaded users], anchor: "center")

    // Right Panel: Cohen-Pietrzak PoSW (Strictly Sequential)
    rect((8.8, 0.6), (16.4, 6.7), fill: rgb("f0fdf4"), stroke: 0.7pt + rgb("86efac"), radius: 0.2)
    content((12.6, 6.2), text(weight: "bold", size: 8.8pt, fill: c-green)[Sibuna PoSW: Unparallelizable Sequential Work], anchor: "center")
    content((12.6, 5.6), text(size: 7.5pt, style: "italic", fill: rgb("14532d"))[$v_i = H(v_(i-1) || v_(gamma(i)))$ (Depth $d=13$, $N=8,192$ steps)], anchor: "center")

    // Sequential nodes
    let node-pos = ((9.3, 3.8), (10.6, 3.8), (11.9, 3.8), (13.2, 3.8), (14.5, 3.8), (15.7, 3.8))
    let labels = ($v_0$, $v_1$, $v_2$, $dots$, $v_(N-1)$, $v_N$)
    for i in range(6) {
      let p = node-pos.at(i)
      circle(p, radius: 0.35, fill: white, stroke: 0.9pt + c-green)
      content(p, text(size: 7.2pt, weight: "bold", fill: c-green)[#labels.at(i)], anchor: "center")
      if i > 0 {
        let prev = node-pos.at(i - 1)
        line((prev.at(0) + 0.35, prev.at(1)), (p.at(0) - 0.35, p.at(1)), mark: (end: ">"), stroke: 1.1pt + c-green)
      }
    }

    // Skip edge
    arc((10.6, 4.15), start: 180deg, stop: 0deg, radius: (1.3, 0.7), mark: (end: ">"), stroke: 0.9pt + c-blue)
    content((11.9, 5.05), text(size: 6.5pt, fill: c-blue)[Skip Dependency $v_(gamma(i))$], anchor: "center")

    // Merkle tree root commitment below with generous padding
    rect((9.2, 1.3), (16.0, 3.15), fill: white, stroke: 0.8pt + c-green, radius: 0.15)
    content((12.6, 2.55), text(weight: "bold", size: 7.8pt, fill: c-green)[Merkle Tree Commitment & Logarithmic Verification], anchor: "center")
    content((12.6, 1.9), text(size: 7.2pt)[Server verifies 16 opening paths in *25.83 µs* ($O(t dot d)$ work)], anchor: "center")

    content((12.6, 1.0), text(size: 7pt, fill: rgb("14532d"))[Parallel ASICs get 0 speedup; hardware fairness guaranteed], anchor: "center")
  })
)

= Real-Time Management: The Sibuna Console

In keeping with its self-contained architecture, Sibuna incorporates a complete administrative console without requiring external web servers or JavaScript build tools:
- *In-Memory Lock-Free Ring Buffers*: Request telemetry, rate-limit violations, and threat incidents are recorded in pre-allocated circular buffers with sub-microsecond overhead.
- *Embedded WebSocket Protocol*: The management daemon streams real-time threat metrics, GeoIP coordinates, and cluster consensus state to web clients at 60 FPS.
- *Zero-Asset Footprint*: All HTML, CSS, and SVG console assets are embedded directly into the binary at compile time via Zig's `@embedFile`. Deployment requires copying a single executable file.

= Conclusion

Web application defense has been led astray by a culture of architectural accretion—piling layers of interpreted runtimes, complex container orchestrations, regular expression parsers, and external database clusters in front of web applications.

*Sibuna* proves that by returning to the foundational principles of computing:
- Honoring the physical laws of thermodynamic work;
- Crafting algorithms with mechanical sympathy for CPU cache lines and zero heap allocation; and
- Embedding consensus directly into the process memory space via `zaxonlite`,

a distributed web defense engine can achieve over *100,000 requests per second per core*, propagate cluster-wide defenses in *155 milliseconds*, and operate within a minuscule *22 megabyte memory envelope*.

#v(3mm)
#line(length: 100%, stroke: 0.4pt + light-border)
#v(1mm)
#align(center)[
  #text(size: 8pt, fill: muted)[
    Sibuna Whitepaper · Produced by Insan AI Engineering · Pure Zig Systems Research \
    Open Source Specification, Source Code, & Benchmarks: https://github.com/insanai/sibuna
  ]
]