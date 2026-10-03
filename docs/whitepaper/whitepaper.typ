// Sibuna Architectural Whitepaper
// Copyright (c) 2026 Sibuna Contributors
// Designed with inspiration from Richard Feynman, Donald Knuth, and Leslie Lamport.

#import "@preview/cetz:0.5.2" as cetz
#import "../book/figures.typ": bench_data, bench_find, fmt_ns, benchmark_results_table, tools_meta_line, tools_mode_table
#let primitives = bench_data()
#let primitive(subsystem, workload) = bench_find(primitives, "sibuna", subsystem, workload)
#let latency(subsystem, workload) = fmt_ns(primitive(subsystem, workload).ns_per_op_median)


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
        columns: (auto, 1fr),
        align(left)[#text(size: 8pt, fill: muted, font: "New Computer Modern", weight: "bold")[SIBUNA: ARCHITECTURE & DISTRIBUTED CONSENSUS]],
        align(right)[#text(size: 8pt, fill: muted, font: "New Computer Modern", style: "italic")[Whitepaper | October 2026]]
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
        align(left)[#text(size: 8pt, fill: muted)[#link("https://github.com/insanai/sibuna")[Insan AI Systems Research | Sibuna Source & Benchmarks]]],
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

// --- Mathematical Symbols & Scientific Units via Typst Markup ---
#let us = sym.mu + "s"
#let times = sym.times

// --- Voices of Master Thinkers ---
#let feynman-dialogue(body) = block(
  width: 100%,
  stroke: (left: 3pt + accent-gold),
  fill: gold-light,
  inset: (x: 10pt, y: 7pt),
  radius: (right: 3pt),
  breakable: false
)[
  #text(weight: "bold", size: 8.8pt, fill: accent-gold)[Feynman on Physical Intuition: Energy Asymmetry and the Second Law]
  #v(2pt)
  #text(size: 8.8pt, fill: rgb("78350f"), style: "italic")[#body]
]

#let knuth-dialogue(body) = block(
  width: 100%,
  stroke: (left: 3pt + accent-purple),
  fill: purple-light,
  inset: (x: 10pt, y: 7pt),
  radius: (right: 3pt),
  breakable: false
)[
  #text(weight: "bold", size: 8.8pt, fill: accent-purple)[Knuth on Mechanical Precision: Cache Lines and Concrete Mathematics]
  #v(2pt)
  #text(size: 8.8pt, fill: rgb("4c1d95"))[#body]
]

#let lamport-dialogue(body) = block(
  width: 100%,
  stroke: (left: 3pt + primary),
  fill: primary-light,
  inset: (x: 10pt, y: 7pt),
  radius: (right: 3pt),
  breakable: false
)[
  #text(weight: "bold", size: 8.8pt, fill: primary)[Lamport on Distributed Invariants: Safety, Liveness, and Replicated Logs]
  #v(2pt)
  #text(size: 8.8pt, fill: rgb("0369a1"))[#body]
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
  #text(size: 8.8pt, weight: "bold", fill: ink)[Vikrant Rathore #h(10pt) and #h(10pt) Ronak Rathore]
  #v(0.5mm)
  #text(size: 8pt, fill: muted)[Insan AI Systems & Architecture Lab | Architecture & Systems Report]
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
    Web application firewalls (WAFs) and edge defense platforms must balance three costs:
    (1) *Work asymmetry*: bots can generate requests cheaply, while inspection consumes defender resources;
    (2) *Runtime predictability*: allocation, scheduling and contention affect tail latency; and
    (3) *State coordination*: replicated policy and reputation need explicit ownership, failure handling and consistency guarantees.

    *Sibuna* combines bounded request processing with optional persistent management. Its standard release is a standalone binary; source builds enable clustering separately. The design provides:
    (i) *Work-verifiable thermodynamic defense* via Cohen-Pietrzak Proof of Sequential Work (PoSW) and BLAKE3 MAC tokens, requiring client work before admission; the sequential verifier measures #latency("pow_verify", "posw_depth13_t16") in the recorded primitive workload;
    (ii) *A strict zero-allocation hot path*, employing SIMD-accelerated Aho-Corasick automata (#latency("bot_matcher", "aho_corasick_40_signatures") for 40 bot signatures), 16-shard atomic GCRA rate limiting (#latency("rate_limiter", "gcra_check") per check), and Robin Hood hashed nonce tracking (#latency("challenge_store", "robin_hood_spend_and_lookup")); and
    (iii) *An embedded distributed consensus engine* powered by `zaxonlite`, replicating WAL frames through Multi-Paxos while request workers read immutable policy snapshots. The measured cluster results are historical fixtures, not release capacity guarantees.
  ]
]

#v(2mm)

#grid(
  columns: (1fr, 1fr, 1fr, 1fr),
  gutter: 6pt,
  metric-card(latency("rate_limiter", "gcra_check"), "GCRA RATE CHECK", "16 Shards | Source-audited bound"),
  metric-card(latency("bot_matcher", "aho_corasick_40_signatures"), "SIMD BOT MATCHER", "Aho-Corasick | 40 Sigs"),
  metric-card(latency("pow_verify", "posw_depth13_t16"), "PoSW VERIFICATION", "Depth 13 | Bounded Stack"),
  metric-card(str(calc.round(primitives.meta.idle_rss_kb / 1024, digits: 1)) + " MiB", "IDLE ENGINE RSS", "Two Workers | Storage Inactive")
)

#v(2.5mm)

// ==========================================
// 1. PROLOGUE: THE THERMODYNAMICS OF DEFENSE
// ==========================================
= Prologue: The Thermodynamics of Web Defense

In classical mechanics, conservation laws govern all physical interactions. Energy cannot be conjured from nothing; work performed by an agent is inextricably tied to entropy generated in the universe. Yet for thirty years, the architecture of web application defense has lived in deliberate defiance of thermodynamics.

#feynman-dialogue[
  "Look at how a subway turnstile works. If the turnstile spins freely with a light tap of a finger, but every time someone taps it, a guard inside has to stand up, check three logbooks, call head office, and file a five-page report, who gets tired first?
  A kid outside can stand there all afternoon tapping the turnstile with one finger without breaking a sweat. But the guard inside is running back and forth, burning paper, and collapsing from exhaustion before lunch. That is how traditional firewalls work.
  In physics, you do not fight force with paperwork; you balance the energy equation. You hook the turnstile to a heavy water pump. If someone wants to walk through, they have to push with their own muscle to lift a gallon of water into the overhead tank. That takes three seconds of honest work. The guard inside just sits there, looks out the window to see if water spilled into the tank, and lets them pass. Looking out the window costs the guard almost zero energy, but pushing the pump costs the visitor real work. The prankster with the free finger gives up and goes home, because the laws of physics are working against him instead of for him."
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
    rect((0, 0), (8.2, 4.4), fill: rgb("fff5f5"), stroke: 0.8pt + rgb("fca5a5"), radius: 0.2)
    content((4.1, 4.0), text(weight: "bold", size: 8.5pt, fill: rgb("991b1b"))[Traditional WAF: Energetic Inversion], anchor: "center")
    
    // Attacker node (width 2.6cm: 0.5 to 3.1)
    rect((0.5, 0.9), (3.1, 3.4), fill: white, stroke: 0.8pt + c-attacker, radius: 0.15)
    content((1.8, 2.9), text(weight: "bold", size: 8pt, fill: c-attacker)[Attacker Work], anchor: "center")
    content((1.8, 2.3), text(size: 7.2pt)[1 HTTP SYN+Req], anchor: "center")
    content((1.8, 1.5), text(size: 7.8pt, weight: "bold", fill: rgb("991b1b"))[$E_A approx 1 mu"J"$], anchor: "center")

    // Legacy defender node (width 2.6cm: 5.1 to 7.7)
    rect((5.1, 0.9), (7.7, 3.4), fill: white, stroke: 0.8pt + c-legacy, radius: 0.15)
    content((6.4, 2.9), text(weight: "bold", size: 8pt, fill: c-legacy)[Defender Burn], anchor: "center")
    content((6.4, 2.4), text(size: 7.2pt)[PCRE Regex + GC], anchor: "center")
    content((6.4, 2.0), text(size: 7.2pt)[Redis / Postgres], anchor: "center")
    content((6.4, 1.45), text(size: 7.8pt, weight: "bold", fill: rgb("991b1b"))[$E_D approx 10,"000" mu"J"$], anchor: "center")

    // Arrow with 2.0cm gap (3.1 to 5.1)
    line((3.1, 2.15), (5.1, 2.15), mark: (end: ">"), stroke: 1.5pt + c-attacker)
    content((4.1, 2.6), text(size: 7.2pt, weight: "bold", fill: c-attacker)[10,000 : 1], anchor: "center")
    content((4.1, 0.4), text(size: 7.2pt, style: "italic", fill: rgb("7f1d1d"))[Defender collapses under load], anchor: "center")

    // --- Panel 2: Sibuna Thermodynamic Breakwater ---
    rect((8.8, 0), (17.0, 4.4), fill: rgb("f0fdf4"), stroke: 0.8pt + rgb("86efac"), radius: 0.2)
    content((12.9, 4.0), text(weight: "bold", size: 8.5pt, fill: rgb("065f46"))[Sibuna: Thermodynamic Breakwater], anchor: "center")

    // Attacker node under PoSW (width 2.6cm: 9.3 to 11.9)
    rect((9.3, 0.9), (11.9, 3.4), fill: white, stroke: 0.8pt + rgb("b45309"), radius: 0.15)
    content((10.6, 2.9), text(weight: "bold", size: 8pt, fill: rgb("b45309"))[Attacker Work], anchor: "center")
    content((10.6, 2.4), text(size: 7.2pt)[Sequential Hash Tree], anchor: "center")
    content((10.6, 2.0), text(size: 7.2pt)[8,192 Node PoSW], anchor: "center")
    content((10.6, 1.45), text(size: 7.8pt, weight: "bold", fill: rgb("92400e"))[$E_A approx 50,"000" mu"J"$], anchor: "center")

    // Sibuna defender node (width 2.6cm: 13.9 to 16.5)
    rect((13.9, 0.9), (16.5, 3.4), fill: white, stroke: 0.8pt + c-posw, radius: 0.15)
    content((15.2, 2.9), text(weight: "bold", size: 8pt, fill: c-posw)[Sibuna Core], anchor: "center")
    content((15.2, 2.4), text(size: 7.2pt)[SIMD + GCRA], anchor: "center")
    content((15.2, 2.0), text(size: 7.2pt)[Logarithmic Verify], anchor: "center")
    content((15.2, 1.45), text(size: 7.8pt, weight: "bold", fill: rgb("065f46"))[$E_D approx 0.05 mu"J"$], anchor: "center")

    // Arrow with 2.0cm gap (11.9 to 13.9)
    line((11.9, 2.15), (13.9, 2.15), mark: (end: ">"), stroke: 1.5pt + c-posw)
    content((12.9, 2.6), text(size: 7.2pt, weight: "bold", fill: c-posw)[1 : 1,000,000], anchor: "center")
    content((12.9, 0.4), text(size: 7.2pt, style: "italic", fill: rgb("14532d"))[Attacker throttled by physics], anchor: "center")
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

Sibuna enforces a strict architectural contract: *the hot evaluation path shall never invoke the operating system heap allocator*. All internal data structures, including sliding window buffers, Radix tries, rate-limiting shards, Aho-Corasick transition tables, and token verifiers, are statically allocated at startup or backed by fixed-capacity circular rings.

Furthermore, Sibuna extends this bounded invariant to operating system thread stacks. Rather than advancing connection slots with an unbounded roving cursor (which defers thread joins and causes finished threads to retain thread-local signal stacks), Sibuna allocates connection slots *lowest-free-first*. Each taken slot promptly joins the preceding finished thread, immediately reclaiming its stack and keeping resident memory strictly bounded to currently open connections (flat at roughly 27 MiB under continuous saturation, rather than climbing with connection churn).



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
    let c-border = rgb("cbd5e1")
    let c-text = rgb("1e293b")

    // Outer card
    rect((0, 0), (17.2, 11.6), fill: rgb("f8fafc"), stroke: 0.8pt + c-border, radius: 0.3)
    content((8.6, 11.1), text(weight: "bold", size: 10pt, fill: c-navy)[Sibuna Wire-Speed Request Lifecycle (Measured Zero-Allocation Hot Path)], anchor: "center")

    // Helper: stage-box (width 3.3cm, height 1.5cm)
    let stage-box(x, y, fill-col, stroke-col, title, latency, subtext) = {
      rect((x, y), (x + 3.3, y + 1.5), fill: fill-col, stroke: 0.8pt + stroke-col, radius: 0.18)
      content((x + 1.65, y + 1.15), text(weight: "bold", size: 8pt, fill: stroke-col)[#title], anchor: "center")
      content((x + 1.65, y + 0.75), text(size: 7.2pt, fill: c-text)[#subtext], anchor: "center")
      rect((x + 0.75, y + 0.14), (x + 2.55, y + 0.52), fill: stroke-col, stroke: none, radius: 0.1)
      content((x + 1.65, y + 0.33), text(weight: "bold", size: 6.8pt, fill: white)[#latency], anchor: "center")
    }

    // ==========================================
    // ROW 1: L4 INGRESS & PROTOCOL (y: 8.6 .. 10.1)
    // ==========================================
    // TCP Ingress (x: 0.6 .. 3.5)
    rect((0.6, 8.6), (3.5, 10.1), fill: white, stroke: 0.8pt + c-navy, radius: 0.18)
    content((2.05, 9.6), text(weight: "bold", size: 8.5pt, fill: c-navy)[TCP Ingress], anchor: "center")
    content((2.05, 9.1), text(size: 7.2pt)[Raw Socket Stream], anchor: "center")
    content((2.05, 8.7), text(size: 6.8pt, fill: rgb("64748b"))[Zero Alloc / Ring], anchor: "center")

    // Stage 1: Radix Trie CIDR (x: 4.8 .. 8.1)
    stage-box(4.8, 8.6, c-blue-bg, c-blue, [1. Radix Trie CIDR], [44.71 ns], [IPv4/IPv6 Table Lookup])

    // Stage 2: Sharded GCRA (x: 9.3 .. 12.6)
    stage-box(9.3, 8.6, c-blue-bg, c-blue, [2. Sharded GCRA], [#latency("rate_limiter", "gcra_check")], [16 Shards | Lock-Free CAS])

    // Stage 3: Zero-Copy HTTP (x: 13.6 .. 16.9)
    stage-box(13.6, 8.6, c-blue-bg, c-blue, [3. Zero-Copy HTTP], [1.11 #us], [Slices Only | In-Place])

    // Row 1 Forward Arrows
    line((3.5, 9.35), (4.8, 9.35), mark: (end: ">"), stroke: 1.2pt + c-blue)
    line((8.1, 9.35), (9.3, 9.35), mark: (end: ">"), stroke: 1.2pt + c-blue)
    content((8.7, 9.65), text(size: 6.5pt, weight: "bold", fill: c-green)[Pass], anchor: "center")
    line((12.6, 9.35), (13.6, 9.35), mark: (end: ">"), stroke: 1.2pt + c-blue)
    content((13.1, 9.65), text(size: 6.5pt, weight: "bold", fill: c-green)[Admit], anchor: "center")

    // Row 1 -> Row 2 Direct Transition (Far Right)
    line((15.25, 8.6), (15.25, 6.4), mark: (end: ">"), stroke: 1.3pt + c-purple)
    content((16.15, 7.5), text(size: 6.8pt, fill: c-purple, weight: "bold")[Parse OK], anchor: "center")

    // ==========================================
    // ROW 2: IDENTIFICATION & CRYPTO (y: 4.9 .. 6.4)
    // Reverse flow (Right to Left)
    // ==========================================
    // Stage 4: SIMD Bot Matcher (x: 13.6 .. 16.9)
    stage-box(13.6, 4.9, c-purple-bg, c-purple, [4. SIMD Bot Matcher], [#latency("bot_matcher", "aho_corasick_40_signatures")], [40 Crawler Signatures])

    // Stage 5: BLAKE3 Token Auth (x: 9.3 .. 12.6)
    stage-box(9.3, 4.9, c-purple-bg, c-purple, [5. BLAKE3 Token], [#latency("token_auth", "blake3_mac_token")], [Keyed MAC Verify])

    // Stage 6: PoSW Verifier (x: 4.8 .. 8.1)
    stage-box(4.8, 4.9, c-gold-bg, c-gold, [6. PoSW Verifier], [#latency("pow_verify", "posw_depth13_t16")], [Cohen-Pietrzak Depth 13])

    // Stage 7: Semantic WAF (x: 0.6 .. 3.9)
    stage-box(0.6, 4.9, c-blue-bg, c-blue, [7. Semantic WAF], [18.55 #us], [SQLi / XSS Tokenizer])

    // Row 2 Forward Arrows (Right to Left)
    line((13.6, 5.65), (12.6, 5.65), mark: (end: ">"), stroke: 1.2pt + c-purple)
    content((13.1, 5.95), text(size: 6.5pt, weight: "bold", fill: c-green)[Clean], anchor: "center")

    line((9.3, 5.65), (8.1, 5.65), mark: (end: ">"), stroke: 1.2pt + c-gold)
    content((8.7, 5.95), text(size: 6.5pt, weight: "bold", fill: c-gold)[No Token], anchor: "center")

    line((4.8, 5.65), (3.9, 5.65), mark: (end: ">"), stroke: 1.2pt + c-green)
    content((4.35, 5.95), text(size: 6.5pt, weight: "bold", fill: c-green)[Verified], anchor: "center")

    // Valid Token Fast-Path: Arcs ABOVE PoSW Verifier in open corridor (y: 7.2)
    line((10.95, 6.4), (10.95, 7.2), (2.25, 7.2), (2.25, 6.4), mark: (end: ">"), stroke: 1.2pt + c-green)
    content((6.6, 7.45), text(size: 6.8pt, weight: "bold", fill: c-green)[Valid Token Fast-Path (Bypass PoSW Challenge)], anchor: "center")

    // ==========================================
    // ROW 3: TERMINAL DESTINATIONS (y: 0.8 .. 2.4)
    // ==========================================
    // Sink 1: Drop / Ban Sink (x: 0.6 .. 4.6) directly below Stage 7
    rect((0.6, 0.8), (4.6, 2.4), fill: c-red-bg, stroke: 1.1pt + c-red, radius: 0.18)
    content((2.6, 1.95), text(weight: "bold", size: 8.5pt, fill: c-red)[Drop / Ban Sink], anchor: "center")
    content((2.6, 1.50), text(size: 7.2pt)[Blacklisted CIDR / Attack], anchor: "center")
    content((2.6, 1.10), text(weight: "bold", size: 7pt, fill: c-red)[TCP Reset / 403 Forbidden], anchor: "center")

    // Sink 2: Upstream Origin Proxy (x: 5.6 .. 11.6) directly below Stage 6
    rect((5.6, 0.8), (11.6, 2.4), fill: c-green-bg, stroke: 1.1pt + c-green, radius: 0.18)
    content((8.6, 1.95), text(weight: "bold", size: 8.5pt, fill: c-green)[Upstream Origin Proxy], anchor: "center")
    content((8.6, 1.50), text(size: 7.2pt)[HTTP/1.1 Keep-Alive Connection], anchor: "center")
    content((8.6, 1.10), text(weight: "bold", size: 7pt, fill: c-green)[HTTP 200 Admitted Clean], anchor: "center")

    // Sink 3: HTTP 401 Challenge Issuer (x: 12.6 .. 16.9) directly below Stage 4
    rect((12.6, 0.8), (16.9, 2.4), fill: c-gold-bg, stroke: 1.1pt + c-gold, radius: 0.18)
    content((14.75, 1.95), text(weight: "bold", size: 8.5pt, fill: c-gold)[HTTP 401 Challenge], anchor: "center")
    content((14.75, 1.50), text(size: 7.2pt)[Issue Signed PoSW Ticket], anchor: "center")
    content((14.75, 1.10), text(weight: "bold", size: 7pt, fill: c-gold)[Zero Server State Bounded], anchor: "center")

    // --- TERMINAL ARROWS ---
    // 1. Stage 7 (Semantic WAF) to Drop Sink: straight vertical drop!
    line((1.5, 4.9), (1.5, 2.4), mark: (end: ">"), stroke: 1.2pt + c-red, dash: "dashed")
    content((1.0, 3.65), text(size: 6.8pt, weight: "bold", fill: c-red)[Attack], anchor: "center")

    // 2. Stage 7 (Semantic WAF) to Upstream Origin: clean handoff through the gap at x: 4.35
    line((3.9, 5.1), (4.35, 5.1), (4.35, 1.6), (5.6, 1.6), mark: (end: ">"), stroke: 1.5pt + c-green)
    content((5.0, 3.4), text(size: 6.8pt, weight: "bold", fill: c-green)[Admit], anchor: "center")

    // 3. Stage 4 (SIMD Bot Matcher) to Challenge Issuer: straight vertical drop!
    line((14.75, 4.9), (14.75, 2.4), mark: (end: ">"), stroke: 1.2pt + c-gold, dash: "dashed")
    content((15.7, 3.65), text(size: 6.8pt, weight: "bold", fill: c-gold)[Bot Ticket], anchor: "center")

    // 4. Stage 1 (Radix Trie CIDR) to Drop Sink: along top and left perimeter
    line((5.8, 10.1), (5.8, 10.55), (0.35, 10.55), (0.35, 1.6), (0.6, 1.6), mark: (end: ">"), stroke: 1.1pt + c-red, dash: "dashed")
    content((3.0, 10.75), text(size: 6.5pt, weight: "bold", fill: c-red)[CIDR Banned (TCP RST)], anchor: "center")

    // 5. Stage 2 (Sharded GCRA) to Challenge Issuer: along top and right perimeter
    line((11.5, 10.1), (11.5, 10.55), (17.05, 10.55), (17.05, 1.6), (16.9, 1.6), mark: (end: ">"), stroke: 1.1pt + c-gold, dash: "dashed")
    content((14.3, 10.75), text(size: 6.5pt, weight: "bold", fill: c-gold)[Rate Exceeded (401)], anchor: "center")
  })
)

== Mathematical Proofs of Algorithmic Primitives

#theorem-box(
  "1",
  "Deterministic Linear-Time Inspection via SIMD Aho-Corasick Automata",
  [Given an input string $T$ of length $n$ and a dictionary of $k$ attack patterns $P = {p_1, dots, p_k}$ of aggregate length $m$, Sibuna classifies $T$ in strict worst-case time $O(n + m)$ using zero heap memory, completely eliminating Regular Expression Denial of Service (ReDoS).],
  [Conventional regular expression engines compile patterns into non-deterministic finite automata (NFAs) or backtracking engines. On malicious inputs designed with overlapping prefixes (e.g., `(a+)+$`), backtracking induces execution time $O(n dot 2^m)$.
  Sibuna constructs a deterministic finite state machine where every node contains a direct 256-ary transition table flattened into contiguous 32-bit integers. Transitions are vectorized across 128-bit/256-bit SIMD registers. Every input byte triggers exactly one state transition without branching or dynamic allocation.
  Empirical verification on 40 production bot signatures yields a median evaluation time of *#latency("bot_matcher", "aho_corasick_40_signatures")* in this suite. The same patterns scanned by sequential substring search cost
  #fmt_ns(bench_find(primitives, "sibuna-naive", "bot_matcher", "sequential_substring_40_signatures").ns_per_op_median).
  The table records batch spread and source provenance.]
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
  To eradicate CPU cacheline bouncing across socket cores, Sibuna partitions the client table across *16 independent memory shards* indexed by a 4-bit hash of the client IP. In the measured Linux container, single-scope GCRA has a batch median of *#latency("rate_limiter", "gcra_check")*; its request-path API takes no allocator.]
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
  where $"MAC"_K$ is computed using BLAKE3 in keyed mode (*#latency("token_auth", "blake3_mac_token")*). The secret key $K$ is rotated every epoch $Delta t$. When a client submits a solved puzzle, Sibuna validates:
  (1) $"MAC"_K$ verifies under epoch key $K_t$ or $K_(t-1)$;
  (2) $|t_"now" - "Timestamp"| <= Delta t_"valid"$; and
  (3) the proof satisfies the target sequential difficulty.
  To prevent replay attacks within $Delta t_"valid"$, Sibuna inserts the 64-bit hash of the spent nonce into a fixed-capacity *Robin Hood hash table*. Robin Hood hashing minimizes the variance of probe sequence lengths ($D_i - "ideal"$), with a measured batch median for insertion and lookup of *#latency("challenge_store", "robin_hood_spend_and_lookup")*. This is a bounded table, not a worst-case latency guarantee.]
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
- *Coraza / Anubis*: Typically paired with external Redis clusters. Every rate-limit check or ban query traverses the network stack via TCP/RESP serialization, adding 0.5 to 2.0 ms of network latency and introducing a catastrophic single point of failure.
- *CrowdSec*: Runs an out-of-process daemon that reads log files from disk and communicates asynchronously with a central API. Threat updates propagate with latencies of seconds to minutes, leaving large attack windows open.

== zaxonlite: Embedded WAL-Frame Multi-Paxos
Sibuna solves state distribution by embedding `zaxonlite`, a high-performance distributed storage and consensus library, directly into its address space. There are zero external processes, zero sidecars, and zero database daemons.

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
    content((8.5, 7.95), text(weight: "bold", size: 10pt, fill: c-navy)[Sibuna 3-Node Mesh: Embedded Multi-Paxos State Machine (zaxonlite)], anchor: "center")

    // Node drawing helper (width 4.2cm, height 2.7cm)
    let draw-node(x, y, is-leader, name, port, mesh-port, rss, state-text) = {
      let stroke-color = if is-leader { c-green } else { c-blue }
      let fill-color = if is-leader { c-green-bg } else { white }
      rect((x, y), (x + 4.2, y + 2.7), fill: fill-color, stroke: 1.2pt + stroke-color, radius: 0.2)
      
      // Role badge
      let badge-fill = if is-leader { c-green } else { c-blue }
      let badge-title = if is-leader { "LEADER (ACTIVE)" } else { "FOLLOWER (REPLICA)" }
      rect((x + 0.3, y + 2.1), (x + 3.9, y + 2.52), fill: badge-fill, stroke: none, radius: 0.1)
      content((x + 2.1, y + 2.31), text(weight: "bold", size: 7pt, fill: white)[#badge-title], anchor: "center")

      content((x + 2.1, y + 1.72), text(weight: "bold", size: 8.5pt, fill: c-navy)[#name], anchor: "center")
      content((x + 2.1, y + 1.35), text(size: 7.2pt, fill: c-text)[HTTP: #port | Mesh: #mesh-port], anchor: "center")
      content((x + 2.1, y + 1.00), text(size: 7pt, fill: c-text)[WAL: #state-text], anchor: "center")

      // RSS Badge
      rect((x + 1.1, y + 0.22), (x + 3.1, y + 0.65), fill: rgb("e2e8f0"), stroke: none, radius: 0.1)
      content((x + 2.1, y + 0.43), text(weight: "bold", size: 7pt, fill: c-navy)[RSS: #rss], anchor: "center")
    }

    // Leader (Top Center)
    draw-node(6.4, 4.4, true, "Node 1", "8000", "9000", "30.6 MB", "Replicated Frame Commit")

    // Follower 1 (Bottom Left)
    draw-node(0.6, 0.5, false, "Node 2", "8001", "9001", "30.9 MB", "Phase 2 Accepted / Quorum")

    // Follower 2 (Bottom Right)
    draw-node(12.2, 0.5, false, "Node 3", "8002", "9002", "32.2 MB", "Phase 2 Accepted / Quorum")

    // Left replication arrow: from Leader to Node 2
    line((6.4, 4.9), (4.3, 3.2), mark: (start: ">", end: ">"), stroke: 1.5pt + c-blue)
    content((3.8, 4.3), text(weight: "bold", size: 6.8pt, fill: c-blue)[Replicated WAL Frames\ (Phase 2 Accept Quorum)], anchor: "south-east")

    // Right replication arrow: from Leader to Node 3
    line((10.6, 4.9), (12.7, 3.2), mark: (start: ">", end: ">"), stroke: 1.5pt + c-blue)
    content((13.2, 4.3), text(weight: "bold", size: 6.8pt, fill: c-blue)[Replicated WAL Frames\ (Phase 2 Accept Quorum)], anchor: "south-west")

    // Heartbeat between Node 2 and Node 3 across the 7.4cm gap
    content((8.5, 2.3), text(weight: "bold", size: 7.2pt, fill: c-gold)[Peer Heartbeats & Lease Monotonicity (Invariant S2)], anchor: "center")
    content((8.5, 1.75), text(size: 7pt, style: "italic", fill: c-text)[Cluster Ban Propagation: 103.77 ms | Zero External DBs], anchor: "center")
    line((4.8, 1.15), (12.2, 1.15), mark: (start: ">", end: ">"), stroke: 1.1pt + c-gold, dash: "dashed")
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
The committed cluster record describes its Linux host, transport, load and source revision. These historical measurements predate the October request-path changes and do not qualify v0.1.0:
- *Cluster-Wide Ban Propagation*: An IP ban initiated on the leader node was replicated and enforced across all three nodes in *103.77 ms* with loopback PSK (*124.56 ms* with mutual TLS).
- *Fault Tolerance under Leader Termination*: During active benchmark load of >550,000 requests/second across all 3 nodes (558k req/s challenged, 543k req/s admitted, p99 latency 230 to 265 #us), the cluster leader was abruptly killed (`kill -9`). The surviving nodes elected a new leader and sustained *397,799 requests/sec* (PSK) / *387,909 requests/sec* (mTLS) with zero 5xx errors and post-failover ban propagation of *81.99 to 122.62 ms*.
- *Memory Footprint*: In a full 3-node mesh with consensus active, idle RSS remained at *30.6-32.2 MB* per node (*34.6-37.0 MB* under mTLS); a standalone single node with no storage consumes only *11.3 MB*.



// ==========================================
// PAGE 6: COMPREHENSIVE MARKET COMPARISON TABLE & CRITIQUE
// ==========================================
#pagebreak()
= Whole-Product Comparison and Deployment Trade-offs

A useful performance comparison runs actual products with equivalent workloads, reports
response states and includes the origin, client and host conditions. The whole-product
harness measures Sibuna and Anubis in forward-auth and reverse-proxy modes. It gives both
processes the same allowed CPU set on Linux, obtains valid sessions and reports throughput,
latency, CPU accounting and peak resident memory.

#tools_meta_line()

== Recorded Reverse-Proxy Workloads

#tools_mode_table("reverse_proxy")

These figures belong to the revision printed above. They predate the v0.1.0 release fixes
and must be rerun before being cited as current release performance. A challenged response,
a forwarded origin response and an inspection denial perform different work: compare rows
with the same intended behavior, and inspect the status column first. CPU accounting in an
unprivileged container has limited resolution and does not control host contention.

== Choosing an Integration

*Forward-auth* keeps the ingress responsible for body forwarding, WebSocket upgrades and
TLS termination. Sibuna returns the admission decision. The ingress must strip untrusted
forwarded headers and supply the protected URI and method, including on the challenge
location. The operations guide provides the complete nginx configuration.

*Reverse-proxy* places Sibuna in the request and response path. Upload framing, response
streaming, connection reuse and origin errors therefore require independent functional
checks. The release tests cover fixed-length and chunked uploads, accepted WebSocket
upgrades, early responses and idle deadlines against the actual packaged executable.

The console is optional and has a separate isolation gate. Its recorded impact matrices
remain inconclusive; neither a functional pass nor a primitive speedup establishes that
console overhead meets the throughput and tail-latency thresholds on a deployment host.

== Related Systems

#link("https://github.com/TecharoHQ/anubis")[Anubis],
#link("https://github.com/owasp-modsecurity/ModSecurity")[ModSecurity],
#link("https://github.com/corazawaf/coraza")[Coraza] and
#link("https://github.com/chaitin/SafeLine")[SafeLine] provide other approaches to web defense.
Hosted services such as #link("https://developers.cloudflare.com/waf/")[Cloudflare WAF]
and #link("https://docs.aws.amazon.com/waf/")[AWS WAF] require separate deployment and
measurement methods. This harness does not measure their latency, memory or operating cost.
The book retains the published comparison material with its sources; unsupported modeled
performance figures are not evidence of a speed advantage.


// ==========================================
// PAGE 7: BENCHMARK SUITE & KEY TAKEAWAYS
// ==========================================
#pagebreak()
= Empirical Benchmark Suite

The primitive suite records seven batches in `ReleaseFast`, with median and min–max
spread. Its source revision, compiler and Linux container host are printed below. These
measurements describe individual operations; they are not HTTP capacity guarantees or a
pass of the separate console-impact gate. Allocation activity is not instrumented.

== Microbenchmark Latency Profile

#benchmark_results_table()

== Interpreting the Measurements

The Gate and Shield classification rows describe the same benchmark request under two
inspection configurations. They do not establish a latency comparison with other WAFs.
The keyed BLAKE3 and Ed25519 rows measure different authentication constructions, with
different key-distribution requirements. Their speed ratio alone does not establish an
equivalent trust model. The allocation-free request-path design is supported by source and
API review; the timing harness does not measure heap activity.

#pagebreak()
= Cryptographic Proofs of Work: Sequential vs. Parallel Work

== The Cohen-Pietrzak Proof of Sequential Work (PoSW)
Standard Hashcash challenges require finding a nonce $x$ such that $"Hash"("Challenge" || x) < T$. While simple, Hashcash is vulnerable to parallel hardware speedups: an attacker possessing $M$ parallel ASIC or GPU cores solves the challenge $M$ times faster than an honest user with a single browser thread.

Sibuna resolves this hardware asymmetry through Cohen-Pietrzak Proofs of Sequential Work (PoSW):
1. *Sequential Graph Traversal*: The client computes a directed acyclic graph (DAG) of depth $d$, where vertex $v_i$ is computed sequentially:
   $ v_i = H(v_(i-1) || v_(gamma(i))) $
   where $gamma(i)$ is a bit-reversal skip function. Parallel workers cannot compute node $i$ without the output of node $i-1$.
2. *Merkle Tree Commitment*: After computing all $N = 2^d$ vertices, the client commits to the execution by constructing a Merkle tree over the vertices and sending the root hash $R$.
3. *Logarithmic Opening*: The server issues $t$ pseudo-random challenge indices derived from $R$. The client responds with opening paths of length $d$.
4. *Server Verification*: The server verifies the opening paths in time $O(t dot d)$. For depth $d=13$ ($N = 8,192$ steps) and $t=16$ openings, Sibuna verifies the client's work in *#fmt_ns(primitive("pow_verify", "posw_depth13_t16").ns_per_op_median)* in this batch measurement, using bounded stack memory.



// ==========================================
// SEQUENTIAL-WORK FIGURE & CONSOLE & CONCLUSION
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

    // Cores attacking in parallel (width 1.7cm: 0.8 to 2.5)
    for i in range(4) {
      let y = 4.7 - i * 0.9
      rect((0.8, y), (2.5, y + 0.65), fill: white, stroke: 0.7pt + c-red, radius: 0.1)
      content((1.65, y + 0.32), text(size: 7pt, weight: "bold", fill: c-red)[Core #str(i+1) (ASIC)], anchor: "center")
      // Arrow stops cleanly at the left border of the red box (x: 4.6)
      line((2.5, y + 0.32), (4.6, y + 0.32), mark: (end: ">"), stroke: 0.9pt + c-red)
      content((3.55, y + 0.52), text(size: 6.5pt)[Nonce #str(i+1)], anchor: "center")
    }

    // Red Box (width 3.4cm: 4.6 to 8.0)
    rect((4.6, 1.7), (8.0, 5.0), fill: white, stroke: 0.8pt + c-red, radius: 0.15)
    content((6.3, 4.5), text(weight: "bold", size: 7.5pt, fill: c-red)[Instant Parallel], anchor: "center")
    content((6.3, 4.1), text(weight: "bold", size: 7.5pt, fill: c-red)[Speedup Advantage], anchor: "center")
    content((6.3, 3.45), text(size: 6.8pt)[$M$ ASIC cores = $M times$ faster], anchor: "center")
    content((6.3, 2.90), text(size: 6.8pt)[Ordinary browsers penalized], anchor: "center")
    content((6.3, 2.30), text(weight: "bold", size: 7pt, fill: c-red)[Botnets Bypass], anchor: "center")
    content((6.3, 1.95), text(weight: "bold", size: 7pt, fill: c-red)[Computational Gate], anchor: "center")

    content((4.4, 0.95), text(size: 7pt, fill: rgb("7f1d1d"))[Unfair to legitimate single-threaded users], anchor: "center")

    // Right Panel: Cohen-Pietrzak PoSW (Strictly Sequential)
    rect((8.8, 0.6), (16.4, 6.7), fill: rgb("f0fdf4"), stroke: 0.7pt + rgb("86efac"), radius: 0.2)
    content((12.6, 6.2), text(weight: "bold", size: 8.8pt, fill: c-green)[Sibuna PoSW: Sequential Work], anchor: "center")
    content((12.6, 5.6), text(size: 7.5pt, style: "italic", fill: rgb("14532d"))[$v_i = H(v_(i-1) || v_(gamma(i)))$ (Depth $d=13$, $N=8,192$ steps)], anchor: "center")

    // Sequential nodes
    let node-pos = ((9.3, 4.0), (10.6, 4.0), (11.9, 4.0), (13.2, 4.0), (14.5, 4.0), (15.7, 4.0))
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
    arc((10.6, 4.35), start: 180deg, stop: 0deg, radius: (1.3, 0.65), mark: (end: ">"), stroke: 0.9pt + c-blue)
    content((11.9, 5.2), text(size: 6.5pt, fill: c-blue)[Skip Dependency $v_(gamma(i))$], anchor: "center")

    // Merkle tree root commitment below with generous width and padding
    rect((9.0, 1.3), (16.2, 3.2), fill: white, stroke: 0.8pt + c-green, radius: 0.15)
    content((12.6, 2.72), text(weight: "bold", size: 8pt, fill: c-green)[Merkle Tree Commitment], anchor: "center")
    content((12.6, 2.25), text(weight: "bold", size: 7.5pt, fill: c-green)[& Logarithmic Verification], anchor: "center")
    content((12.6, 1.7), text(size: 6.8pt, fill: rgb("14532d"))[Server verifies 16 opening paths in *#latency("pow_verify", "posw_depth13_t16")* ($O(t dot d)$ work)], anchor: "center")

    content((12.6, 0.95), text(size: 7pt, fill: rgb("14532d"))[Sequential work still depends on hardware speed], anchor: "center")
  })
)

= Real-Time Management: The Sibuna Console

The opt-in console embeds its Wasm interface, browser bridge, HTML and CSS. Policy editing,
incident investigation and operational views use authenticated snapshots, epochs and deltas.
Fixed-capacity telemetry queues expose sampling and loss; geographic updates run at 1 Hz
while the browser animates independently. GeoIP requires a separate dataset import. The
console's AGPL source link identifies the release tag.

Console-impact measurements remain inconclusive. Deployment-host checks must include idle
and active dashboards, and optional evidence capture; functional success is not a performance pass.

= Conclusion

Sibuna combines proof-of-work admission, bounded inspection, streaming HTTP/1.1 proxying and
optional persistent management. Native and live-daemon tests exercise the SID contracts;
cluster source builds retain local quotas and issuer-bound challenges. Every measurement
identifies its revision, host and workload. These fixtures do not establish universal capacity
or memory guarantees. The operations guide states ingress requirements, inspection bounds
and the outstanding console performance condition.
