// Sibuna Architectural Whitepaper
// Copyright (c) 2026 Sibuna Contributors
// Definitions and proofs below refer to the implemented contracts and their stated assumptions.

#import "@preview/cetz:0.5.2" as cetz
#import "../book/figures.typ": bench_data, bench_find, fmt_ns, benchmark_results_table, tools_meta_line, tools_mode_table
#import "../book/crs_request_path.typ": crs_meta_line, crs_table
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
        align(left)[#text(size: 8pt, fill: muted)[#link("https://github.com/insanai/sibuna")[Sibuna Source and Benchmark Records]]],
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

// --- Explanatory notes ---
#let work-note(body) = context {
  if target() == "html" {
    return html.elem("aside", attrs: (class: "callout warning"))[
      #html.elem("strong", [A practical view of admission work])
      #html.elem("div", body)
    ]
  }
  block(
  width: 100%,
  stroke: (left: 3pt + accent-gold),
  fill: gold-light,
  inset: (x: 10pt, y: 7pt),
  radius: (right: 3pt),
  breakable: false
)[
  #text(weight: "bold", size: 8.8pt, fill: accent-gold)[A practical view of admission work]
  #v(2pt)
  #text(size: 8.8pt, fill: rgb("78350f"), style: "italic")[#body]
]
}

#let memory-note(body) = context {
  if target() == "html" {
    return html.elem("aside", attrs: (class: "callout idea"))[
      #html.elem("strong", [Why reserve memory before processing a request])
      #html.elem("div", body)
    ]
  }
  block(
  width: 100%,
  stroke: (left: 3pt + accent-purple),
  fill: purple-light,
  inset: (x: 10pt, y: 7pt),
  radius: (right: 3pt),
  breakable: false
)[
  #text(weight: "bold", size: 8.8pt, fill: accent-purple)[Why reserve memory before processing a request]
  #v(2pt)
  #text(size: 8.8pt, fill: rgb("4c1d95"))[#body]
]
}

#let consensus-note(body) = context {
  if target() == "html" {
    return html.elem("aside", attrs: (class: "callout note"))[
      #html.elem("strong", [What consensus does and does not provide])
      #html.elem("div", body)
    ]
  }
  block(
  width: 100%,
  stroke: (left: 3pt + primary),
  fill: primary-light,
  inset: (x: 10pt, y: 7pt),
  radius: (right: 3pt),
  breakable: false
)[
  #text(weight: "bold", size: 8.8pt, fill: primary)[What consensus does and does not provide]
  #v(2pt)
  #text(size: 8.8pt, fill: rgb("0369a1"))[#body]
]
}

#let theorem-box(number, title, statement, proof) = context {
  if target() == "html" {
    return html.elem("aside", attrs: (class: "callout theorem"))[
      #html.elem("strong", [Theorem #number: #title])
      #html.elem("div", statement)
      #html.elem("strong", [Proof])
      #html.elem("div", proof)
    ]
  }
  block(
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
}

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
  #text(size: 12pt, weight: "medium", fill: primary)[Bounded Web Protection and Proof-of-Work Admission]
  #v(0.5mm)
  #text(size: 8.8pt, fill: muted)[Client Work, Native Inspection, and Embedded Consensus]
  #v(3mm)
  #text(size: 8.8pt, weight: "bold", fill: ink)[Vikrant Rathore #h(10pt) and #h(10pt) Ronak Rathore]
  #v(0.5mm)
  #text(size: 8pt, fill: muted)[Insan AI | Architecture and Systems Report]
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
    Web protection has to balance the work done by a visitor with the resources needed to
    process a request. Automated clients can repeat requests cheaply. A proof-of-work
    challenge raises the expected work of gaining admission while keeping verification
    comparatively cheap. A session reuses that admission for a limited time;
    policy and inspection still apply to its requests.

    *Sibuna* combines this admission mechanism with bounded native inspection and optional
    persistent management. It supports SHA-256 Hashcash and Cohen–Pietrzak Proof of
    Sequential Work (PoSW). Its request evaluation uses caller-owned memory, prepared
    literal matchers, sharded GCRA rate limits and bounded replay tracking. The recorded
    PoSW verifier operation takes #latency("pow_verify", "posw_depth13_t16"). This measures
    one primitive, not a complete HTTP request.

    Version 0.3.0 also includes an optional native OWASP Core Rule Set (CRS) interpreter.
    Immutable rule generations and leased transaction slots separate management work
    from request processing. The opt-in console provides authenticated management and
    investigation. Cluster source builds embed Zaxonlite storage and Multi-Paxos; the
    standard packages run as a single node. This report gives the algorithms, their
    assumptions, the resource bounds and the limits of the available measurements.

  ]
]

#v(2mm)

#grid(
  columns: (1fr, 1fr, 1fr, 1fr),
  gutter: 6pt,
  metric-card(latency("rate_limiter", "gcra_check"), "GCRA RATE CHECK", "16 Shards | Adaptive Locks"),
  metric-card(latency("bot_matcher", "aho_corasick_40_signatures"), "LITERAL BOT MATCHER", "Aho-Corasick | 40 Sigs"),
  metric-card(latency("pow_verify", "posw_depth13_t16"), "PoSW VERIFICATION", "Depth 13 | Bounded Stack"),
  metric-card(str(calc.round(primitives.meta.idle_rss_kb / 1024, digits: 1)) + " MiB", "IDLE ENGINE RSS", "Two Workers | Storage Inactive")
)

#v(2.5mm)

// ==========================================
// 1. PROLOGUE: THE THERMODYNAMICS OF DEFENSE
// ==========================================
= Admission Work and the Cost of Web Protection

A site pays to accept connections, parse requests, inspect input and run its application.
An automated client can repeat that work at a rate which the site cannot afford. The
imbalance matters even when each request is valid HTTP. It appears in scraping,
credential stuffing and application-layer floods, as well as in malformed requests.

#work-note[
  A turnstile gives a useful analogy. A visitor presents a ticket. The admission mechanism is designed so checking a proof
  takes less work than creating one is expected to take. Sibuna's ticket is a computational proof. A client creates
  the proof, the server checks it, and a short-lived session avoids charging the same
  admission work on every request. The server still pays for connections, inspection and
  application responses. The proof helps change that balance; it does not remove those costs.
]

Sibuna uses two kinds of proof. Hashcash searches for a nonce whose hash meets a target.
Under an ideal-hash model, a $b$-bit target takes $2^b$ candidate trials on average, while
checking a submitted candidate takes one trial. At $b=16$, the expected search is 65,536
trials. A lucky candidate can succeed immediately, so this is an expectation rather than
a minimum charge for every proof. PoSW instead labels a dependency graph and supplies a small set of openings.
The verifier checks those openings without reproducing the whole computation.

This is a computational comparison. It is not a claim about a fixed energy ratio, money
spent, or wall-clock delay. Hardware, browser implementation, difficulty and session
lifetime affect what visitors and automated clients actually pay. A bot can solve a
challenge, and a slow device can struggle with one. Operators should choose a difficulty
which protects the application without making ordinary use impractical.

A useful server-side model separates early gate work from full processing. Let $G$ be the
cost of rejecting a request at the gate, $D$ the cost of admitting and processing it, and
$p$ the fraction rejected early. The average server work is
$ (1-p) D + p G. $
If $G < D$ and $p>0$, this is less than $D$. The model assumes comparable requests and
ignores fixed deployment costs. It does not predict visitor latency or network saturation.
TCP and TLS resources still need appropriate ingress limits.

#v(1.5mm)

#figure(
  caption: [Admission work: ordinary request processing and proof-backed admission],
  cetz.canvas(length: 1cm, {
    import cetz.draw: *

    let c-attacker = accent-red
    let c-legacy = accent-red
    let c-posw = accent-green

    // --- Panel 1: Ordinary request work ---
    rect((0, 0), (8.2, 4.4), fill: rgb("fff5f5"), stroke: 0.8pt + rgb("fca5a5"), radius: 0.2)
    content((4.1, 4.0), text(weight: "bold", size: 8.5pt, fill: rgb("991b1b"))[Request processing without an admission proof], anchor: "center")
    
    // Attacker node (width 2.6cm: 0.5 to 3.1)
    rect((0.5, 0.9), (3.1, 3.4), fill: white, stroke: 0.8pt + c-attacker, radius: 0.15)
    content((1.8, 2.9), text(weight: "bold", size: 8pt, fill: c-attacker)[Client Work], anchor: "center")
    content((1.8, 2.3), text(size: 7.2pt)[Create a request], anchor: "center")
    content((1.8, 1.5), text(size: 7.8pt, weight: "bold", fill: rgb("991b1b"))[Repeat cheaply], anchor: "center")

    // Server node (width 2.6cm: 5.1 to 7.7)
    rect((5.1, 0.9), (7.7, 3.4), fill: white, stroke: 0.8pt + c-legacy, radius: 0.15)
    content((6.4, 2.9), text(weight: "bold", size: 8pt, fill: c-legacy)[Server Work], anchor: "center")
    content((6.4, 2.4), text(size: 7.2pt)[Parse and inspect], anchor: "center")
    content((6.4, 2.0), text(size: 7.2pt)[Run the application], anchor: "center")
    content((6.4, 1.45), text(size: 7.8pt, weight: "bold", fill: rgb("991b1b"))[Process each\ request], anchor: "center")

    // Arrow with 2.0cm gap (3.1 to 5.1)
    line((3.1, 2.15), (5.1, 2.15), mark: (end: ">"), stroke: 1.5pt + c-attacker)
    content((4.1, 2.6), text(size: 7.2pt, weight: "bold", fill: c-attacker)[Request], anchor: "center")
    content((4.1, 0.4), text(size: 7.2pt, style: "italic", fill: rgb("7f1d1d"))[Capacity depends on the work each request triggers], anchor: "center")

    // --- Panel 2: Proof-backed admission ---
    rect((8.8, 0), (17.0, 4.4), fill: rgb("f0fdf4"), stroke: 0.8pt + rgb("86efac"), radius: 0.2)
    content((12.9, 4.0), text(weight: "bold", size: 8.5pt, fill: rgb("065f46"))[Proof-backed admission in Sibuna], anchor: "center")

    // Attacker node under PoSW (width 2.6cm: 9.3 to 11.9)
    rect((9.3, 0.9), (11.9, 3.4), fill: white, stroke: 0.8pt + rgb("b45309"), radius: 0.15)
    content((10.6, 2.9), text(weight: "bold", size: 8pt, fill: rgb("b45309"))[Client Work], anchor: "center")
    content((10.6, 2.4), text(size: 7.2pt)[Solve the challenge], anchor: "center")
    content((10.6, 2.0), text(size: 7.2pt)[Then reuse a session], anchor: "center")
    content((10.6, 1.45), text(size: 7.8pt, weight: "bold", fill: rgb("92400e"))[Expected\ proof work], anchor: "center")

    // Sibuna defender node (width 2.6cm: 13.9 to 16.5)
    rect((13.9, 0.9), (16.5, 3.4), fill: white, stroke: 0.8pt + c-posw, radius: 0.15)
    content((15.2, 2.9), text(weight: "bold", size: 8pt, fill: c-posw)[Server Check], anchor: "center")
    content((15.2, 2.4), text(size: 7.2pt)[Check the proof], anchor: "center")
    content((15.2, 2.0), text(size: 7.2pt)[Then apply policy], anchor: "center")
    content((15.2, 1.45), text(size: 7.8pt, weight: "bold", fill: rgb("065f46"))[Cheap\ proof checks], anchor: "center")

    // Arrow with 2.0cm gap (11.9 to 13.9)
    line((11.9, 2.15), (13.9, 2.15), mark: (end: ">"), stroke: 1.5pt + c-posw)
    content((12.9, 2.6), text(size: 7.2pt, weight: "bold", fill: c-posw)[Proof], anchor: "center")
    content((12.9, 0.4), text(size: 7.2pt, style: "italic", fill: rgb("14532d"))[Hardware and difficulty determine the actual costs], anchor: "center")
  })
)

A valid session can satisfy an admission challenge if it carries enough paid work for the
route. It does not bypass a policy denial or enforcing inspection. Rate limits continue to
bound admitted traffic. This matters because one solved challenge can authorize many
requests during a session, and a proof alone cannot make those requests safe.

= Memory Ownership and Bounded State

#memory-note[
  Memory reserved before a request arrives makes its limits visible. A parser borrows slices
  from a connection buffer. A matcher reads a prepared table. A CRS transaction leases a
  fixed slot. When capacity is exhausted, the service reports a refusal or recorded loss
  instead of growing a queue without a bound. Startup, storage and management can still allocate.
]

== The Zero-Allocation Hot Path Invariant

Parsing, policy evaluation, proof and cookie verification do not call the general-purpose
heap allocator. Prepared engines own their tables. Workers borrow immutable generations,
use stack or connection buffers, and release each borrow before its owner can reuse memory.
The optional CRS executor follows the same rule with pre-reserved transaction scratch.
Preparing rules, updating GeoIP, writing storage and rendering management responses are
separate operations with explicit allocators and limits.

Avoiding request-time allocation removes one source of unpredictable work. It does not
eliminate cache misses, scheduler delays or lock contention. Nor does reservation equal
resident memory: pages in a large scratch reservation become resident as transactions touch
them. Safe-build initialization must leave no read-before-write gaps when avoiding an
otherwise eager fill. The regression tests seed scratch to check these ownership boundaries.

Connection slots use lowest-free-first reuse and join a finished worker before replacing it.
This reclaims the worker's resources promptly under connection churn. A connection quota
bounds the number of live workers; deadlines bound stalled work. An active stream can last
longer than the idle timeout because progress refreshes it. Its slot still counts toward the
quota. Memory depends on open connections, inspected input and enabled services, so a small
fixture's RSS is not a universal deployment bound.

== The Complete Request Pipeline

The diagram separates a protected request from the challenge exchange. Most requests do
not run a PoSW verifier. Only a submitted solution does that work. A protected request first
passes the configured admission and inspection gates, then policy decides whether it may
proceed, must be challenged, or must be denied.

#figure(
  caption: [Request-protection components and their interactions],
  cetz.canvas(length: 1cm, {
    import cetz.draw: *

    let c-navy = rgb("0f172a")
    let c-blue = primary
    let c-blue-bg = rgb("f0f9ff")
    let c-purple = rgb("7c3aed")
    let c-purple-bg = rgb("faf5ff")
    let c-gold = accent-gold
    let c-gold-bg = rgb("fffbeb")
    let c-green = accent-green
    let c-green-bg = rgb("ecfdf5")
    let c-red = accent-red
    let c-red-bg = rgb("fef2f2")
    let c-border = rgb("cbd5e1")
    let c-text = rgb("1e293b")

    // Outer card
    rect((0, 0), (17.2, 11.6), fill: rgb("f8fafc"), stroke: 0.8pt + c-border, radius: 0.3)
    content((8.6, 11.1), text(weight: "bold", size: 10pt, fill: c-navy)[Sibuna Request Protection: Components and Decisions], anchor: "center")

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
    content((2.05, 8.7), text(size: 6.8pt, fill: rgb("64748b"))[Quota / Deadlines], anchor: "center")

    // HTTP head fields (x: 4.8 .. 8.1)
    stage-box(4.8, 8.6, c-blue-bg, c-blue, [HTTP Head], [Borrowed], [Client + HTTP Fields])

    // Local admission (x: 9.3 .. 12.6)
    stage-box(9.3, 8.6, c-blue-bg, c-blue, [Local Admission], [Shard Lock], [Bans + Global GCRA])

    // Optional request CRS (x: 13.6 .. 16.9)
    stage-box(13.6, 8.6, c-blue-bg, c-blue, [Optional Request CRS], [Leased Scratch], [Headers / Bounded Body])

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
    // Inspection and policy (x: 13.6 .. 16.9)
    stage-box(13.6, 4.9, c-purple-bg, c-purple, [Inspection + Policy], [Ordered Rules], [Allow / Deny / Challenge])

    // Session authentication (x: 9.3 .. 12.6)
    stage-box(9.3, 4.9, c-purple-bg, c-purple, [Session MAC], [Authenticate], [Challenge Routes Only])

    // Paid-work comparison (x: 4.8 .. 8.1)
    stage-box(4.8, 4.9, c-gold-bg, c-gold, [Paid Work Level], [Compare], [Only After a Valid MAC])

    // Handoff (x: 0.6 .. 3.9)
    stage-box(0.6, 4.9, c-blue-bg, c-blue, [Handoff], [Mode-Specific], [Origin / Auth Response])

    // Row 2 Forward Arrows (Right to Left)
    line((13.6, 5.65), (12.6, 5.65), mark: (end: ">"), stroke: 1.2pt + c-purple)
    content((13.1, 5.95), text(size: 6.5pt, weight: "bold", fill: c-green)[Challenge], anchor: "center")

    line((9.3, 5.65), (8.1, 5.65), mark: (end: ">"), stroke: 1.2pt + c-gold)
    content((8.7, 5.95), text(size: 6.5pt, weight: "bold", fill: c-gold)[MAC Valid], anchor: "center")

    line((4.8, 5.65), (3.9, 5.65), mark: (end: ">"), stroke: 1.2pt + c-green)
    content((4.35, 5.95), text(size: 6.5pt, weight: "bold", fill: c-green)[Paid], anchor: "center")

    // Policy ALLOW route: arc above the conditional session check in open corridor (y: 7.2)
    line((10.95, 6.4), (10.95, 7.2), (2.25, 7.2), (2.25, 6.4), mark: (end: ">"), stroke: 1.2pt + c-green)
    content((6.6, 7.45), text(size: 6.8pt, weight: "bold", fill: c-green)[Policy ALLOW Route (No Admission Challenge)], anchor: "center")

    // ==========================================
    // ROW 3: TERMINAL DESTINATIONS (y: 0.8 .. 2.4)
    // ==========================================
    // Sink 1: HTTP refusal (x: 0.6 .. 4.6) directly below Stage 7
    rect((0.6, 0.8), (4.6, 2.4), fill: c-red-bg, stroke: 1.1pt + c-red, radius: 0.18)
    content((2.6, 1.95), text(weight: "bold", size: 8.5pt, fill: c-red)[HTTP Refusal], anchor: "center")
    content((2.6, 1.50), text(size: 7.2pt)[Policy / Ban / Rate Limit], anchor: "center")
    content((2.6, 1.10), text(weight: "bold", size: 7pt, fill: c-red)[403 Forbidden / 429 Limited], anchor: "center")

    // Sink 2: Upstream Origin Proxy (x: 5.6 .. 11.6) directly below Stage 6
    rect((5.6, 0.8), (11.6, 2.4), fill: c-green-bg, stroke: 1.1pt + c-green, radius: 0.18)
    content((8.6, 1.95), text(weight: "bold", size: 8.5pt, fill: c-green)[Upstream Origin Proxy], anchor: "center")
    content((8.6, 1.50), text(size: 7.2pt)[HTTP/1.1 Keep-Alive Connection], anchor: "center")
    content((8.6, 1.10), text(weight: "bold", size: 7pt, fill: c-green)[Origin Status / Auth Decision], anchor: "center")

    // Sink 3: HTTP 401 Challenge Issuer (x: 12.6 .. 16.9) directly below Stage 4
    rect((12.6, 0.8), (16.9, 2.4), fill: c-gold-bg, stroke: 1.1pt + c-gold, radius: 0.18)
    content((14.75, 1.95), text(weight: "bold", size: 8.5pt, fill: c-gold)[HTTP 401 Challenge], anchor: "center")
    content((14.75, 1.50), text(size: 7.2pt)[Client Solves Separate Proof], anchor: "center")
    content((14.75, 1.10), text(weight: "bold", size: 7pt, fill: c-gold)[No Per-Issued Ticket Table], anchor: "center")

    // --- TERMINAL ARROWS ---
    // 1. Decision components to HTTP refusal: straight vertical drop!
    line((1.5, 4.9), (1.5, 2.4), mark: (end: ">"), stroke: 1.2pt + c-red, dash: "dashed")
    content((1.0, 3.65), text(size: 6.8pt, weight: "bold", fill: c-red)[Deny], anchor: "center")

    // 2. Handoff to upstream origin: clean handoff through the gap at x: 4.35
    line((3.9, 5.1), (4.35, 5.1), (4.35, 1.6), (5.6, 1.6), mark: (end: ">"), stroke: 1.5pt + c-green)
    content((5.0, 3.4), text(size: 6.8pt, weight: "bold", fill: c-green)[Admit], anchor: "center")

    // 3. Unpaid challenge route to issuance: straight vertical drop!
    line((14.75, 4.9), (14.75, 2.4), mark: (end: ">"), stroke: 1.2pt + c-gold, dash: "dashed")
    content((15.7, 3.65), text(size: 6.8pt, weight: "bold", fill: c-gold)[Unpaid], anchor: "center")

    // 4. Local ban interaction with refusal: along top and left perimeter
    line((5.8, 10.1), (5.8, 10.55), (0.35, 10.55), (0.35, 1.6), (0.6, 1.6), mark: (end: ">"), stroke: 1.1pt + c-red, dash: "dashed")
    content((3.0, 10.75), text(size: 6.5pt, weight: "bold", fill: c-red)[Local Ban (403)], anchor: "center")

    // 5. Rate refusal follows the outer perimeter: along top and right perimeter
    line((11.5, 10.1), (11.5, 10.55), (17.05, 10.55), (17.05, 0.45), (2.6, 0.45), (2.6, 0.8), mark: (end: ">"), stroke: 1.1pt + c-gold, dash: "dashed")
    content((14.3, 10.75), text(size: 6.5pt, weight: "bold", fill: c-gold)[Rate Exceeded (429)], anchor: "center")
  })
)

This is a component overview. Its arrows group interactions, not the exact instruction
order of every request. Policy ALLOW skips the admission challenge. A challenged route
checks its session MAC, then its paid work; missing or insufficient work leads to the separate
challenge exchange. Solved proofs run the PoSW verifier on submission, not on each protected
request. The diagram contains no per-stage latency estimate. Internal challenge routes have their own
rate budget. Native CRS request headers can reject before the ordinary preflight; full
request bodies are acquired only after that preflight admits the request. Reverse-proxy
response headers and eligible bounded bodies run later phases before publication. Streaming
and upgraded connections release their transaction resources early and report the excluded
coverage. Forward-auth sees the trusted metadata supplied by ingress; it does not see an
origin response which ingress handles itself.

== Mathematical Proofs of Algorithmic Primitives

The statements below separate algorithmic bounds from timings. A benchmark can support a
cost estimate for its own fixture. It cannot prove a complexity bound or establish behavior
for every deployment.

#theorem-box(
  "1", "Linear first-match scanning for a prepared literal dictionary",
  [Let $m$ be the total length of a finite literal dictionary and $n$ the input length.
  With $S<=1+m$ active states and a fixed 256-byte alphabet, preparing the dense
  Aho–Corasick transitions takes $O(m+256S)$ time. A reserved capacity of $C$ states
  uses $O(256C)$ table space and initialization time. Its ordinary first-match scan takes
  $O(n)$ time and no request-time heap allocation.],
  [The trie has at most $1+m$ states. Breadth-first preparation fills a 256-entry successor
  table for each state and resolves failure transitions in advance. Since the alphabet is
  fixed and $S<=1+m$, this is $O(m)$ preparation. Reserving a larger fixed capacity
  costs space and initialization time proportional to that capacity, not to the number of
  patterns actually used. The ordinary scan folds each byte through a
  fixed case table, loads one `u16` successor and checks the state's output. It performs
  at most $n$ such steps. It stops on a match or exhaustion of input, proving the scan bound.
  The prepared arrays own their memory before scanning starts.

  This statement covers literal first-match scanning, not arbitrary regular expressions or
  the selected-category helper, which may inspect bounded suffix outputs. The measured
  40-signature scan takes #latency("bot_matcher", "aho_corasick_40_signatures"). Sequential
  substring search on that fixture takes
  #fmt_ns(bench_find(primitives, "sibuna-naive", "bot_matcher", "sequential_substring_40_signatures").ns_per_op_median).
  SIMD helpers used elsewhere do not turn this state-dependent scan into a parallel automaton.]
)

#theorem-box(
  "2", "A burst envelope for sharded GCRA",
  [For a single key, let the emission interval be $T>0$ and burst tolerance be
  $tau=(N-1)T$. With serialized updates, nondecreasing arrival times and no arithmetic
  overflow, accepted arrivals $t_1,dots,t_k$ satisfy
  $ t_k-t_1 >= (k-1)T-tau. $
  Thus an interval of length $L$ contains at most $N+floor(L/T)$ accepted arrivals.],
  [Admission tests $"TAT" <= t+tau$ and then writes
  $ "TAT"' = max("TAT",t)+T. $
  After the first accepted arrival, $"TAT">=t_1+T$. Every later accepted update adds at
  least $T$, so immediately before arrival $k$ the state is at least $t_1+(k-1)T$.
  Admission requires this value to be no greater than $t_k+tau$. Rearranging gives the
  inequality and the count bound.

  Sibuna computes $T=max(1,ceil(W/N))$ in milliseconds. Its 16 shards each use `core.Lock`
  to serialize lookup and the complete read–modify–write operation. The lock tries a short
  spin before parking through Zig's I/O mutex; the limiter is not a lock-free single-CAS
  algorithm. Cells with $"TAT"<=t$ can be reclaimed because their debt has drained.
  Probe and table capacities are bounded; capacity refusal must not be mistaken for an
  address-wide ban. The measured check takes #latency("rate_limiter", "gcra_check") in
  the primitive fixture. Saturating runtime arithmetic handles extreme inputs separately
  from the unsaturated model proved here.]
)

#theorem-box(
  "3", "Authenticated issuance without a per-issued challenge table",
  [Assume the keyed authenticator is a secure pseudorandom function. A challenge's
  authenticity and client binding can be checked from its payload and tag without a
  table entry for every issued challenge. For $q$ fresh forgery attempts against a
  128-bit tag, the ideal forgery probability is at most $q 2^(-128)$, plus the
  authenticator's pseudorandom-function advantage.],
  [The authenticated payload includes its nonce, timestamp, difficulty, algorithm,
  fingerprint and rule identity. The verifier checks the tag before accepting these
  fields. Guessing a fresh ideal tag has probability $2^(-128)$ per attempt; the union
  bound gives $q 2^(-128)$. Replacing the ideal function with the keyed implementation
  adds its security advantage. An authentic but old, incorrectly bound or malformed
  submission still fails the age, fingerprint or proof checks.

  A requirement ticket records the protected request's chosen work requirement. Issuance
  honors it rather than recomputing from the browser's background request. Domain-separated
  keys keep requirement tickets, challenges and sessions distinct. This release derives
  those keys from the configured master secret. Key rotation is an operational change to
  that secret rather than an automatic current/previous epoch window. The client fingerprint
  binds address and User-Agent, not a human identity. Clients behind the same address with
  the same User-Agent can share that binding.

  Replay defense is deliberately stateful. A valid proof must enter a bounded spent-nonce
  table before a session is minted. The table has a fixed capacity and probe bound, with
  a recorded insertion/lookup median of #latency("challenge_store", "robin_hood_spend_and_lookup").
  Connection slots, rate tables, CRS scratch and telemetry also retain bounded state.
  Stateless issuance therefore does not mean zero server memory under a flood.]
)

The challenge record is a 36-byte payload with a 16-byte tag, encoded as 70 URL-safe
Base64 characters. A session token is 56 bytes including its tag, encoded as 75 characters.
Cheap structural, authentication, age and binding checks precede proof verification.
Cluster startup derives issuer-specific challenge authentication, while valid sessions can
be checked across the configured trust domain. Replay tracking stays local because another
node does not accept the issuing node's challenge.


== Immutable Publication and Borrowed Memory

A request worker pins an immutable engine slot. It loads the current pointer, increments
that slot's reader count, and rechecks the pointer before reading the engine. If publication
changed it, the worker releases the count and retries. A serialized publisher prepares the
other slot, publishes it and waits for old readers before rebuilding the old engine.

#theorem-box(
  "4", "Safe reuse of an immutable engine slot",
  [With stable slot addresses, serialized writers, sequentially consistent pointer/count
  operations, and no engine access before the pin recheck, an engine is not rebuilt while
  a reader which validated its pin still borrows it.],
  [A reader whose recheck precedes publication already incremented the old count, so the
  writer must observe it before reuse and wait for its release. A reader whose recheck
  follows publication sees a changed pointer and touches no old engine data. Even if its
  initial load preceded publication and its increment arrives late, the recheck prevents
  an invalid borrow. Stable slot cells keep the counter itself alive. If the same slot is
  published again, its replacement was fully prepared before that publication and the
  successful pin protects that replacement. These ordering and ownership conditions are
  essential; an atomic pointer alone does not make arbitrary reclamation safe.]
)


This protocol separates rule preparation from request evaluation. It does not make storage
commits and runtime publication one atomic operation. Management records intent, expected
revision and application completion separately, so a committed policy can be distinguished
from the revision a particular node has applied.

= The Distributed State Machine: Consensus via Zaxonlite

#consensus-note[
  Replication lets nodes agree on durable changes, but agreement and availability are
  different properties. A partitioned node must not invent a committed edit. It can
  continue evaluating requests against its last immutable policy, subject to its local
  quotas. The interface must show whether an edit committed and which nodes applied it.
]

== Choosing Where State Lives

A multi-node installation must decide which state is shared. Sibuna replicates durable
policy and management records through Zaxonlite. Request-time rate limits and spent
challenges remain local. Console telemetry uses a separate peer channel and is not part of
consensus. Missing peers appear as missing coverage, rather than zero traffic.

An external database is also a valid design. It introduces a separate service to operate,
while an embedded database puts storage and consensus lifecycle inside the daemon. Neither
choice removes failure modes. Sibuna's approach avoids a required external database process,
but operators still need durable storage, a reachable quorum and correct peer authentication.
Other products have their own integration choices; these are not measured by a diagram.

== Embedded WAL-Frame Multi-Paxos

Cluster source builds embed Zaxonlite. Its replication layer orders write-ahead-log (WAL)
frames with Multi-Paxos and applies chosen frames to replicas. A frame records a database
change; it is not a distributed transaction across runtime engines. Storage starts before
console management, and shutdown joins console work before releasing storage.

A quorum contains $floor(N/2)+1$ members. Quorum intersection is the starting point for
agreement, not a complete safety proof. Promises, accepted values, recovery and durable
ordering must preserve the same chosen value across ballots. The following diagram shows
roles and message paths. Its ports are illustrative; peer transport must authenticate the
configured members.

#figure(
  caption: [Three-node replication: chosen WAL frames and local runtime application],
  cetz.canvas(length: 1cm, {
    import cetz.draw: *

    let c-navy = rgb("0f172a")
    let c-blue = primary
    let c-green = accent-green
    let c-green-bg = rgb("ecfdf5")
    let c-card-bg = rgb("f8fafc")
    let c-border = rgb("cbd5e1")
    let c-text = rgb("334155")
    let c-gold = accent-gold

    // Outer boundary card
    rect((0, 0), (17.0, 8.4), fill: rgb("fafafa"), stroke: 0.8pt + c-border, radius: 0.3)
    content((8.5, 7.95), text(weight: "bold", size: 10pt, fill: c-navy)[Three-node replication through embedded Zaxonlite], anchor: "center")

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
      content((x + 2.1, y + 0.43), text(weight: "bold", size: 7pt, fill: c-navy)[RSS Varies], anchor: "center")
    }

    // Leader (Top Center)
    draw-node(6.4, 4.4, true, "Node 1", "8000", "9000", "fixture-specific", "Chosen frames / applied locally")

    // Follower 1 (Bottom Left)
    draw-node(0.6, 0.5, false, "Node 2", "8001", "9001", "fixture-specific", "Accept, learn, apply")

    // Follower 2 (Bottom Right)
    draw-node(12.2, 0.5, false, "Node 3", "8002", "9002", "fixture-specific", "Accept, learn, apply")

    // Left replication arrow: from Leader to Node 2
    line((6.4, 4.9), (4.3, 3.2), mark: (start: ">", end: ">"), stroke: 1.5pt + c-blue)
    content((3.8, 4.3), text(weight: "bold", size: 6.8pt, fill: c-blue)[Accept Proposals\ Chosen-Frame Notices], anchor: "south-east")

    // Right replication arrow: from Leader to Node 3
    line((10.6, 4.9), (12.7, 3.2), mark: (start: ">", end: ">"), stroke: 1.5pt + c-blue)
    content((13.2, 4.3), text(weight: "bold", size: 6.8pt, fill: c-blue)[Accept Proposals\ Chosen-Frame Notices], anchor: "south-west")

    // Heartbeat between Node 2 and Node 3 across the 7.4cm gap
    content((8.5, 2.3), text(weight: "bold", size: 7.2pt, fill: c-gold)[Authenticated heartbeats and recovery messages], anchor: "center")
    content((8.5, 1.75), text(size: 7pt, style: "italic", fill: c-text)[A chosen edit and each node's applied revision are separate states], anchor: "center")
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
  #text(weight: "bold", fill: ink)[Invariant S1 (Consensus Safety).] Under the protocol's durable-state and authenticated-membership assumptions, no two replicas choose different values at log index $i$. Network delay and partitions must not violate this safety condition.
  
  #text(weight: "bold", fill: ink)[Invariant S2 (Monotonic Ballots).] Ballot numbers $b = chevron.l "term", "node_id" chevron.r$ are totally ordered. A replica's promised ballot does not decrease, and it rejects Prepare or Accept messages below that promise. Historical chosen commits do not establish current leadership.

  #text(weight: "bold", fill: ink)[Condition L1 (Eventual Convergence).] A chosen durable edit eventually reaches a recovering member if a stable leader can communicate with a quorum and the recovering member, storage and scheduling make progress, and recovery retries continue. A fixed convergence deadline needs additional latency and resource assumptions; quorum presence alone supplies none.
]

== Empirical Cluster Verification and Fault Injection
The committed cluster record describes its Linux host, transport, load and source revision. The source is `benchmarks/results/cluster-latest-20260912T072156Z.json`, recorded on
12 September 2026 at revision `41925ddb`. These historical measurements predate the October
request-path changes and do not qualify v0.3.0:
- *Cluster-Wide Ban Propagation*: An IP ban initiated on the leader node was replicated and enforced across all three nodes in *103.77 ms* with loopback PSK (*124.56 ms* with mutual TLS).
- *Post-Stop Failover*: The full-node rounds measured 558k challenged requests per second
  and 543k admitted requests per second, with p99 latency of 230–265 #us. After those rounds,
  the harness stopped the leader with SIGTERM, escalating to SIGKILL only on timeout. It
  then measured the surviving nodes at *397,799 requests/sec* (PSK) and *387,909 requests/sec*
  (mTLS), with zero 5xx errors and post-failover ban propagation of *81.99–122.62 ms*.
  This is a post-stop fixture, not a measurement of abrupt termination during sustained load.
- *Memory Footprint*: In a full 3-node mesh with consensus active, idle RSS remained at *30.6–32.2 MiB* per node (*34.6–37.0 MiB* under mTLS); the corresponding standalone fixture with storage disabled used *11.3 MiB*.



== Current Release Recovery Checks

The 0.3.0 review runs the management scenario twice across three containers on different
physical hosts. Both runs qualify edits, failover, lost quorum, rejoin, revocation and CRS
rollback, and all owned daemon stops return cleanly. The final two restart stages take
3.48 and 2.82 seconds in run 1, and 3.90 and 4.86 seconds in run 2. Earlier leader-restoration
stages take about 11.9 and 11.7 seconds. These are functional fixtures, not
new cluster throughput results.

The review found a leadership defect in historical commit handling. A duplicate chosen
commit from an old leader could restore that sender as the leader hint and reset election
progress. The correction keeps historical chosen-state updates separate from evidence of
current leadership. Focused protocol regressions and the two live scenarios exercise that
ordering. The full `crs-three-host-release-030-20261007-run1.json` and `run2.json` reports are
retained beside the benchmarks with source and executable identities.

// ==========================================
// PAGE 6: COMPREHENSIVE MARKET COMPARISON TABLE & CRITIQUE
// ==========================================
= Whole-Product Measurements and Deployment Choices

A useful comparison runs the actual products under comparable conditions. It reports
response states and identifies the origin, client and service hosts. The whole-product
harness measures Sibuna and Anubis in forward-auth and reverse-proxy modes. It gives both
processes the same allowed CPU set on Linux, obtains valid sessions and reports throughput,
latency, CPU accounting and peak resident memory.

#tools_meta_line()

== Recorded Reverse-Proxy Workloads

#tools_mode_table("reverse_proxy")

These figures belong to the revision printed above. They predate the current release fixes
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

The console is optional and has a separate performance acceptance gate. Its recorded impact matrices
remain inconclusive; neither a functional pass nor a primitive speedup establishes that
console overhead meets the throughput and tail-latency thresholds on a deployment host.

== Related Systems

#link("https://github.com/TecharoHQ/anubis")[Anubis],
#link("https://github.com/owasp-modsecurity/ModSecurity")[ModSecurity],
#link("https://github.com/corazawaf/coraza")[Coraza] 
#link("https://github.com/chaitin/SafeLine")[SafeLine] and
#link("https://github.com/bunkerity/bunkerweb")[BunkerWeb] provide other approaches to web defense.
Hosted services such as #link("https://developers.cloudflare.com/waf/")[Cloudflare WAF]
and #link("https://docs.aws.amazon.com/waf/")[AWS WAF] require separate deployment and
measurement methods. This harness does not measure their latency, memory or operating cost.
The book retains the published comparison material with its sources; unsupported modeled
performance figures are not evidence of a speed advantage.


// ==========================================
// PAGE 7: BENCHMARK SUITE & KEY TAKEAWAYS
// ==========================================
= Native Core Rule Set Inspection

CRS is optional. Packages include the native engine, but the operator chooses whether it
is Off, Audit or Enforce. The lightweight inspector and proof-of-work gate remain separate
controls. Turning CRS off does not remove their protection; turning it on adds a broader
rule set and a larger inspection cost.

== Prepared Rules and Transaction State

Preparation verifies a signed upstream package, parses supported directives and builds an
immutable program. Unsupported operators, invalid expressions or exhausted preparation
capacity reject the candidate before publication. A candidate can be inspected without
activating it. CLI and console changes use expected revisions, record intent and select a
prepared generation. Restart verifies the retained source and rebuilds it rather than
trusting unauthenticated compiled state.

Each request leases bounded scratch. Collections retain duplicate form and JSON fields;
transformations, captures and transaction variables have explicit owners and lifetimes.
Chained actions take effect only when their chain succeeds, except for evidence whose
semantics require recording an earlier match. Dynamic tag exclusions affect later rules.
The implementation preserves ordered captures and control flow, not just a Boolean answer
for a regex. A work ledger bounds transforms, operators and collection walks.

#theorem-box(
  "5", "Bounded execution is distinct from a non-match",
  [Let a transaction start with a work budget $B$. If every bounded operation charges its
  declared cost before exceeding the remaining budget, the sum of accepted charges is at
  most $B$. An attempted excess produces incomplete inspection, never a successful non-match.],
  [Initially the remaining balance is $B$. A successful charge of $c$ requires $c<=r$ and
  replaces $r$ with $r-c$. Induction gives $r>=0$ and total accepted charges $B-r<=B$.
  A refused charge leaves the transaction in an explicit failure state. The mode then
  determines the response: Enforce refuses; Audit records incomplete coverage and may
  continue to the origin. The ledger is a bound on declared work units, not a theorem
  that every CPU instruction, I/O wait or wall-clock second is charged. Slot quotas and
  absolute inspection deadlines provide separate bounds.]
)

Request wire length and decoded length have different limits. A small compressed request
can expand beyond the small slot tier, so an unknown decoded length reserves the full
configured tier. Gzip and zlib validation check their framing and checksums within the same
work budget. The proxy replays the original encoded representation to the origin; inspection
uses the decoded view. XML acquisition disables external entities. Multipart file data is
not silently reclassified as ordinary argument text.

== Response Coverage and Refusal

Reverse-proxy inspection runs response-header rules before publication. Eligible bounded
bodies are retained for body rules. Streaming and upgraded connections have explicit
coverage exclusions and release their inspection slots before indefinite I/O. Forward-auth
cannot inspect a response which the ingress receives directly. The console shows incomplete
or excluded coverage; it must not describe those requests as fully inspected.

The actual-daemon FTW review runs 5,193 pinned cases in each mode with saved findings and
origin delivery checks. The strict derived report qualifies 5,074 complete Audit contracts
and 4,993 complete Enforce contracts. The other cases have named acquisition refusals,
connector refusals, bounded-work refusal, representation refusals, evidence limitations or
independent-oracle differences. They are not converted into complete inspection claims.
All 4,792 request-stage Enforce refusals deliver zero requests to the origin. This includes
4,724 terminal policy denials and 68 incomplete fail-closed refusals.

One hostile argument exhausts the default 128-million-unit budget. Audit reports the
incomplete result; Enforce refuses before origin delivery. Two origin fixtures declare
Gzip but return invalid entities, so their body inspection is incomplete. A bodyless request
which declares an empty Deflate stream is also refused under the current strict
representation profile. That last behavior is a documented compatibility deviation, not a
claim that HTTP framing requires a body. Exact wire inputs, independent decoder proofs,
raw reports and classification sources are retained for these exceptions. Unknown
incomplete results fail the qualification gate.

== Current CRS Measurements

The fresh request-path suite uses the final ReleaseSafe executable, CRS 4.30.0 and the
128-million-unit budget. Sibuna runs on one physical host with four allowed logical CPUs;
the load comes from a different physical host over 16 HTTP/1.1 keep-alive connections.
Eight dashboards are signed in. Five rounds rotate profile order. The origin receives
admitted requests; Enforce refuses the SQL-injection query with 403 and closes its connection,
so that row includes a reconnect per request.

#crs_meta_line()
#crs_table(("disabled", "audit-pl1", "enforce-pl1"))
#v(3mm)
#crs_table(("audit-pl2", "enforce-pl2"))

The JSON and multipart baselines are network-limited in this fixture. CPU cost is more
useful for comparing inspection work there. No sample exhausts its work budget. Peak RSS
rises by about 30–37 MiB over the disabled profile; reservations are address space, and
resident pages depend on what a transaction touches. These results are not a matched
comparison with BunkerWeb's earlier profile, which used different concurrency and inputs.
Physical-host contention and CPU frequency remain uncontrolled. They also do not establish
the separate console-impact acceptance target.

= Empirical Benchmark Suite

The primitive suite records seven batches in `ReleaseFast`, with median and min–max
spread. Its source revision, compiler and Linux container host are printed below. These
measurements describe individual operations; they are not HTTP capacity guarantees or a
pass of the separate console-impact gate. Allocation activity is not instrumented.

== Microbenchmark Latency Profile

#benchmark_results_table()

== Interpreting the Measurements

The Gate and Shield classification rows use the same benchmark request under two
inspection configurations. They do not establish a latency comparison with other WAFs.
The keyed BLAKE3 and Ed25519 rows measure different authentication constructions, with
different key-distribution requirements. Their speed ratio alone does not establish an
equivalent trust model. The allocation-free request-path design is supported by source and
API review; the timing harness does not measure heap activity.

= Cryptographic Proofs of Work: Sequential vs. Parallel Work

== Hashcash and the Cohen–Pietrzak Construction

Hashcash candidate trials are independent. With $M$ equally fast workers and ideal hashing,
aggregate trial rate can approach $M$ times a single worker's rate, subject to coordination
and hardware limits. The target still costs work; parallelism changes the elapsed time to
find a proof. It does not make admission free or prove that every bot defeats the gate.

PoSW adds dependencies within one statement. Sibuna labels a complete binary tree of depth
$n$ in depth-first post-order. A node $v$ is named by its binary path from the root, and its
32-byte label includes the statement $chi$ and the node address:

- An internal node hashes both children:
  $ ell_v = H(chi, v, ell_(v 0), ell_(v 1)). $
- A leaf $u=u_1 dots u_n$ hashes the left siblings of its ancestors wherever its path turns
  right, in root-to-leaf order:
  $ ell_u = H(chi,u, [ell_(u_1 dots u_(i-1) 0): u_i=1]). $

The bracketed leaf input is an ordered list, not an unordered set. The implementation
encodes each node address as its depth and a little-endian index.

An honest labeling therefore computes left subtrees before the dependent right leaves.
There are $2^n$ leaves and $2^(n+1)-1$ total labels. At depth 13 these are 8,192 leaves and
16,383 labels, not 8,192 total hash steps. A label can span several compression blocks.
The root label $phi$ is the commitment to this same labeled tree.

For opening $i$, Fiat–Shamir derives
$ gamma_i = H(chi || phi || i) mod 2^n. $
The proof gives that leaf's label and the $n$ sibling labels. Verification recomputes the
leaf's dependency hash, then walks upward to the root. It checks $t(n+1)$ labels, plus
challenge-index derivation. Depth 13 with 16 openings gives 224 checked labels and
$32(1+16(13+1))=7200$ proof bytes. The measured native verifier takes
#latency("pow_verify", "posw_depth13_t16") in the primitive fixture.

The prover retains the top $m=min(n,10)$ levels and a sibling stack. Opening construction
may recompute a subtree below those levels. Its workspace is $O(2^m+n)$ labels plus the
bounded proof output; the implementation uses under 100 KiB. This space–time trade-off
avoids retaining the entire depth-13 tree in a browser.

#theorem-box(
  "6", "A conditional opening-sampling bound",
  [For a fixed commitment with a detectable bad fraction $alpha$, if each of $t$ openings
  samples uniformly and independently, the probability of missing every bad location is
  $(1-alpha)^t$.],
  [Each sample misses with probability $1-alpha$. Independence makes the joint miss
  probability the product of $t$ such terms. For $alpha=0.1$ and $t=16$, this is about
  0.185; for 32 openings it is about 0.034. The premise fixes the commitment before
  sampling. Grinding many commitments, correlated failures or adaptive selection do not
  satisfy that elementary premise. It is not a complete sequentiality or Fiat–Shamir
  security proof. The published Cohen–Pietrzak construction supplies the oracle-model
  analysis; this calculation only explains the role of additional openings.]
)

The sequential-work argument uses the hash-oracle assumptions of that construction. It
limits parallel speedup within one statement under that model. Faster processors still
finish sooner, and an adversary can solve different statements on different machines.
Operators must tune admission requirements for their visitors, not infer identical delay
from the word “sequential.”

#figure(
  caption: [Independent Hashcash trials and PoSW dependency order (schematic)],
  cetz.canvas(length: 1cm, {
    import cetz.draw: *

    let c-navy = rgb("0f172a")
    let c-blue = primary
    let c-green = accent-green
    let c-border = rgb("cbd5e1")
    let c-text = rgb("334155")
    let c-gold = accent-gold
    let c-red = accent-red

    // Outer card
    rect((0, 0), (17.0, 7.8), fill: rgb("fafafa"), stroke: 0.8pt + c-border, radius: 0.3)
    content((8.5, 7.3), text(weight: "bold", size: 10pt, fill: c-navy)[Hashcash Trial Parallelism and PoSW Label Dependencies], anchor: "center")

    // Left Panel: independent Hashcash candidate trials
    rect((0.6, 0.6), (8.2, 6.7), fill: rgb("fff8f8"), stroke: 0.7pt + rgb("fca5a5"), radius: 0.2)
    content((4.4, 6.2), text(weight: "bold", size: 8.8pt, fill: c-red)[Hashcash: Independent Candidate Trials], anchor: "center")
    content((4.4, 5.6), text(size: 7.5pt, style: "italic", fill: rgb("991b1b"))[$"Find" x: H("Challenge" || x) < T$], anchor: "center")

    // Cores attacking in parallel (width 1.7cm: 0.8 to 2.5)
    for i in range(4) {
      let y = 4.7 - i * 0.9
      rect((0.8, y), (2.5, y + 0.65), fill: white, stroke: 0.7pt + c-red, radius: 0.1)
      content((1.65, y + 0.32), text(size: 7pt, weight: "bold", fill: c-red)[Worker #str(i+1)], anchor: "center")
      // Arrow stops cleanly at the left border of the red box (x: 4.6)
      line((2.5, y + 0.32), (4.6, y + 0.32), mark: (end: ">"), stroke: 0.9pt + c-red)
      content((3.55, y + 0.52), text(size: 6.5pt)[Nonce #str(i+1)], anchor: "center")
    }

    // Red Box (width 3.4cm: 4.6 to 8.0)
    rect((4.6, 1.7), (8.0, 5.0), fill: white, stroke: 0.8pt + c-red, radius: 0.15)
    content((6.3, 4.5), text(weight: "bold", size: 7.5pt, fill: c-red)[Independent], anchor: "center")
    content((6.3, 4.1), text(weight: "bold", size: 7.5pt, fill: c-red)[Candidate Trials], anchor: "center")
    content((6.3, 3.45), text(size: 6.8pt)[More workers raise trial rate], anchor: "center")
    content((6.3, 2.90), text(size: 6.8pt)[Rate depends on hardware], anchor: "center")
    content((6.3, 2.30), text(weight: "bold", size: 7pt, fill: c-red)[Every Proof], anchor: "center")
    content((6.3, 1.95), text(weight: "bold", size: 7pt, fill: c-red)[Still Needs Work], anchor: "center")

    content((4.4, 0.95), text(size: 7pt, fill: rgb("7f1d1d"))[Expected work is not a fixed time or energy charge], anchor: "center")

    // Right Panel: schematic dependency order of PoSW labels
    rect((8.8, 0.6), (16.4, 6.7), fill: rgb("f0fdf4"), stroke: 0.7pt + rgb("86efac"), radius: 0.2)
    content((12.6, 6.2), text(weight: "bold", size: 8.8pt, fill: c-green)[PoSW: Dependent Label Computation], anchor: "center")
    content((12.6, 5.6), text(size: 7.5pt, style: "italic", fill: rgb("14532d"))[Depth 13: 8,192 leaves / 16,383 total labels], anchor: "center")

    // Sequential nodes
    let node-pos = ((9.3, 4.0), (10.6, 4.0), (11.9, 4.0), (13.2, 4.0), (14.5, 4.0), (15.7, 4.0))
    let labels = ($ell_0$, $ell_1$, $ell_2$, $dots$, $ell_(N-2)$, $ell_(N-1)$)
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
    content((11.9, 5.2), text(size: 6.5pt, fill: c-blue)[Left-Sibling Dependency], anchor: "center")

    // Root label commitment below with generous width and padding
    rect((9.0, 1.3), (16.2, 3.2), fill: white, stroke: 0.8pt + c-green, radius: 0.15)
    content((12.6, 2.72), text(weight: "bold", size: 8pt, fill: c-green)[Root Label Commitment], anchor: "center")
    content((12.6, 2.25), text(weight: "bold", size: 7.5pt, fill: c-green)[& Sampled Path Verification], anchor: "center")
    content((12.6, 1.7), text(size: 6.8pt, fill: rgb("14532d"))[16 openings: $t(n+1)$ checked labels plus index hashes], anchor: "center")

    content((12.6, 0.95), text(size: 7pt, fill: rgb("14532d"))[Dependency order is schematic; actual labels form a tree], anchor: "center")
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

= Deployment and Verification Limits

Sibuna aims to make protection straightforward for a single site while offering richer
inspection and management when they are needed. Proof-of-work admission raises the expected
work of creating a proof while keeping verification comparatively cheap. Session reuse keeps
that cost from being charged on every request, while policy, local quotas and inspection
continue to protect the application.

The runtime is an HTTP/1.1 reverse proxy or forward-auth service. TLS can terminate at a
trusted ingress; it is not a general TCP or UDP firewall. HTTP/2 at the ingress is a
separate deployment layer. Uploads, response streams and WebSocket upgrades have their own
framing and lifecycle tests. Body limits and coverage exclusions remain relevant to each
application's upload and streaming behavior.

Native and actual-daemon tests exercise the specified contracts. Cluster source builds
retain local limits and issuer-bound challenges. Each measurement identifies its revision,
host and workload, and the operations guide explains required forwarded metadata and
origin isolation. The console performance gate remains unresolved for the recorded host
class. Production deployments should qualify that overhead on their own hardware before
enabling the console beside a busy data plane.

== Sources and Further Detail

The #link("https://github.com/insanai/sibuna")[source repository] contains the book, SIDs,
regressions, raw benchmark records and replay tools. The book develops these algorithms
step by step. SID 0006 states the mathematical assumptions; SID 0007 defines the console;
SID 0010 defines native CRS preparation, execution and activation.

The principal published constructions are Aho and Corasick's
#link("https://doi.org/10.1145/360825.360855")[Efficient String Matching (1975)], Cohen and
Pietrzak's #link("https://eprint.iacr.org/2018/183")[Simple Proofs of Sequential
Work (2018)], and Lamport's #link("https://lamport.azurewebsites.net/pubs/paxos-simple.pdf")[Paxos
Made Simple (2001)]. OWASP's #link("https://github.com/coreruleset/coreruleset")[Core Rule Set]
and its pinned FTW corpus provide the policy sources and interoperability fixtures.
These references supply background and formal assumptions; their existence is not a proof
that every integration detail is correct. The implementation-specific arguments and tests
remain part of the evidence.
