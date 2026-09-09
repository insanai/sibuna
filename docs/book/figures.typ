#import "@preview/fletcher:0.5.8" as fletcher: diagram, node, edge
#import "@preview/cetz:0.5.2" as cetz
#import "theme.typ": blue, blue_light, green, green_light, amber, amber_light, red, red_light, gray, rule

// ------------------------------------------------------------ formatting

#let fmt_int(v) = {
  if v == none { return [-] }
  let s = str(calc.round(v))
  let out = ""
  let i = 0
  for c in s.rev() {
    if i != 0 and calc.rem(i, 3) == 0 { out = "," + out }
    out = c + out
    i += 1
  }
  out
}

#let fmt_ms(us) = {
  if us == none { [-] }
  else if us >= 1000 { [#calc.round(us / 1000, digits: 2) ms] }
  else { [#calc.round(us, digits: 0) µs] }
}

#let fmt_mib(kib) = if kib == none { [-] } else { [#calc.round(kib / 1024, digits: 1) MiB] }
#let fmt_dec(v, digits: 1) = if v == none { [-] } else { [#calc.round(v, digits: digits)] }


#let node_style = (
  fill: blue_light,
  stroke: 0.8pt + blue,
  corner-radius: 3pt,
  inset: 7pt,
)
#let good_style = (fill: green_light, stroke: 0.8pt + green, corner-radius: 3pt, inset: 7pt)
#let warn_style = (fill: amber_light, stroke: 0.8pt + amber, corner-radius: 3pt, inset: 7pt)
#let bad_style = (fill: red_light, stroke: 0.8pt + red, corner-radius: 3pt, inset: 7pt)

// ------------------------------------------------------------------ pipeline

#let fit(body, pct) = scale(x: pct, y: pct, reflow: true, body)

#let probability_contours() = cetz.canvas(length: 1cm, {
  import cetz.draw: *
  line((0,0),(9,0), stroke: 0.7pt + gray)
  line((0,0),(0,3.4), stroke: 0.7pt + gray)
  for i in range(5) {
    let x = i * 2.1
    line((x,0),(x,3), stroke: 0.3pt + rule)
    content((x,-0.3), text(size: 8pt)[#i])
  }
  for (value,label) in ((1,[1.0]),(0.5,[0.5]),(0,[0])) {
    content((-0.45,value*3), text(size: 8pt)[#label])
  }
  let points = ()
  for k in range(101) {
    let x = k / 25
    points.push((x*2.1,calc.exp(-x)*3))
  }
  line(..points, stroke: 1.5pt + blue)
  circle((2.1,calc.exp(-1)*3), radius: 0.06, fill: amber, stroke: none)
  content((4.9,2.2), text(size: 9pt)[$P(K>x E[K]) approx e^(-x)$])
  content((4.2,-0.8), text(size: 8pt)[Trials / expected trials])
})

#let pipeline_flow() = fit(diagram(
  spacing: (24mm, 18mm),
  edge-stroke: 0.8pt + gray,
  node((0,0), [Request], ..node_style),
  node((1,0), [Local bans #linebreak() and rate limit], ..node_style),
  node((2,0), [Inspection #linebreak() and policy], ..node_style),
  node((3,0), [Deny], ..bad_style),
  node((1,1), [Origin / auth #linebreak() success], ..good_style),
  node((2,1), [Session MAC #linebreak() if challenged], ..warn_style),
  node((2,2), [Issue puzzle], ..warn_style),
  edge((0,0),(1,0), "-|>"),
  edge((1,0),(2,0), "-|>", [within limits]),
  edge((2,0),(3,0), "-|>", [DENY]),
  edge((2,0),(2,1), "-|>", [CHALLENGE], label-side: left),
  edge((2,1),(1,1), "-|>", [valid]),
  edge((2,1),(2,2), "-|>", [missing / invalid], label-side: right),
  edge((2,0),(1,1), "-|>", [ALLOW], bend: 15deg),
), 85%)

#let challenge_round_trip() = fit(diagram(
  spacing: (14mm, 11mm),
  node-stroke: 0.8pt + blue,
  edge-stroke: 0.8pt + gray,
  node((0, 0), [Browser #linebreak() navigation], ..node_style),
  node((1, 0), [Interstitial #linebreak() (HTTP 200)], ..warn_style),
  node((2, 0), [`GET /__sibuna/challenge.json?path=`], ..node_style),
  node((3, 0), [Stateless id: #linebreak() payload + tag], ..good_style),
  node((3, 1), [Web Worker #linebreak() WASM / JS prover], ..node_style),
  node((2, 1), [`POST /__sibuna/verify`], ..node_style),
  node((1, 1), [Verify, spent set, #linebreak() mint MAC token], ..good_style),
  node((0, 1), [`Set-Cookie` #linebreak() then reload], ..warn_style),
  edge((0, 0), (1, 0), "-|>"),
  edge((1, 0), (2, 0), "-|>"),
  edge((2, 0), (3, 0), "-|>"),
  edge((3, 0), (3, 1), "-|>", [solve]),
  edge((3, 1), (2, 1), "-|>", [nonce or proof]),
  edge((2, 1), (1, 1), "-|>"),
  edge((1, 1), (0, 1), "-|>"),
  edge((0, 1), (0, 0), "-|>", [session], bend: 30deg),
), 78%)

// ----------------------------------------------------------------- PoSW tree

#let posw_tree() = cetz.canvas(length: 1cm, {
  import cetz.draw: *
  let pos(d, i) = {
    let width = 12.0
    let n = calc.pow(2, d)
    ((i + 0.5) * width / n - width / 2, 3.6 - d * 1.2)
  }
  // edges from children to parents (labels flow upward)
  for d in range(1, 4) {
    for i in range(calc.pow(2, d)) {
      let child = pos(d, i)
      let parent = pos(d - 1, calc.quo(i, 2))
      line(child, parent, stroke: 0.6pt + gray)
    }
  }
  // left-sibling edges into leaf 5 = 101: turns right at depth 1 and 3
  let leaf = pos(3, 5)
  for (d, sib) in ((1, 0), (3, 4)) {
    line(pos(d, sib), leaf, stroke: (paint: red, thickness: 0.9pt, dash: "dashed"), mark: (end: ">"))
  }
  // opening path for leaf 5 highlighted
  for (d, i) in ((3, 5), (2, 2), (1, 1), (0, 0)) {
    circle(pos(d, i), radius: 0.28, fill: amber_light, stroke: 1pt + amber)
  }
  for (d, i) in ((3, 4), (2, 3), (1, 0)) {
    circle(pos(d, i), radius: 0.28, fill: green_light, stroke: 1pt + green)
  }
  for d in range(0, 4) {
    for i in range(calc.pow(2, d)) {
      if not ((d, i) in ((3, 5), (2, 2), (1, 1), (0, 0), (3, 4), (2, 3), (1, 0))) {
        circle(pos(d, i), radius: 0.28, fill: white, stroke: 0.8pt + blue)
      }
      content(pos(d, i), text(size: 6.5pt)[#d.#i])
    }
  }
  content((-6.6, 3.6), anchor: "east", text(size: 7pt, fill: gray)[root $phi$])
  content((-6.6, 0.0), anchor: "east", text(size: 7pt, fill: gray)[leaves])
  content((0, -0.9), text(size: 7.5pt)[
    #box(width: 0.3cm, height: 0.3cm, fill: amber_light, stroke: 1pt + amber) path of leaf 3.5
    #h(6pt)
    #box(width: 0.3cm, height: 0.3cm, fill: green_light, stroke: 1pt + green) siblings sent in the opening
    #h(6pt)
    #text(fill: red)[dashed] left-sibling edges hashed into the leaf
  ])
})

// -------------------------------------------------------------- wire formats

#let bytes_row(y, fields, total_label) = {
  import cetz.draw: *
  let x = 0.0
  for (label, width, fill, stroke) in fields {
    rect((x, y), (x + width, y + 0.9), fill: fill, stroke: 0.8pt + stroke, radius: 2pt)
    content((x + width / 2, y + 0.45), text(size: 7pt, weight: "bold", fill: stroke)[#label])
    x += width
  }
  content((x / 2, y - 0.35), text(size: 7.5pt, fill: gray)[#total_label])
}

#let wire_formats() = cetz.canvas(length: 1cm, {
  import cetz.draw: *
  let f = 0.26
  bytes_row(2.6, (
    ([ver 1], 1 * f + 0.3, blue_light, blue), ([alg 1], 1 * f + 0.3, blue_light, blue),
    ([diff 1], 1 * f + 0.3, blue_light, blue), ([t 1], 1 * f + 0.3, blue_light, blue),
    ([issued_at 8], 8 * f, blue_light, blue), ([fingerprint 8], 8 * f, blue_light, blue),
    ([nonce 8], 8 * f, blue_light, blue), ([rule_hash 8], 8 * f, blue_light, blue),
    ([BLAKE3 tag 16], 16 * f, green_light, green),
  ), [Challenge identifier: 36-byte payload + 16-byte keyed tag = 52 bytes, 70 URL-safe base64 characters])
  bytes_row(0.6, (
    ([timestamp 8], 8 * f, blue_light, blue), ([expiry 8], 8 * f, blue_light, blue),
    ([rule_hash 8], 8 * f, blue_light, blue), ([fingerprint 8], 8 * f, blue_light, blue),
    ([BLAKE3 tag 16], 16 * f, green_light, green),
  ), [Session token: 32-byte payload + 16-byte keyed tag = 48 bytes, 64 URL-safe base64 characters])
})

// ------------------------------------------------------------------- GCRA

#let gcra_timeline() = cetz.canvas(length: 1cm, {
  import cetz.draw: *
  let x0 = 0.6
  let scale = 8.0 / 1000.0
  line((x0, 0), (x0 + 8.6, 0), stroke: 0.8pt + gray, mark: (end: ">"))
  for t in (0, 200, 400, 600, 800, 1000) {
    let x = x0 + t * scale
    line((x, -0.1), (x, 0.1), stroke: 0.6pt + gray)
    content((x, -0.4), text(size: 6.5pt, fill: gray)[#t ms])
  }
  // burst of 5 at t=0 admitted, 6th rejected, then one every 200 ms
  for k in range(5) {
    let x = x0 + k * 0.08
    line((x, 0.15), (x, 1.0), stroke: 1.2pt + green)
  }
  line((x0 + 0.45, 0.15), (x0 + 0.45, 1.0), stroke: (paint: red, thickness: 1.2pt, dash: "dashed"))
  content((x0 + 0.5, 1.2), anchor: "west", text(size: 6.8pt, fill: red)[6th arrival rejected: TAT $> t + tau$])
  for t in (200, 400, 600, 800, 1000) {
    let x = x0 + t * scale
    line((x, 0.15), (x, 1.0), stroke: 1.2pt + green)
    line((x - 0.06, 0.15), (x - 0.06, 1.0), stroke: (paint: red, thickness: 1.2pt, dash: "dashed"))
  }
  content((x0 + 4.3, 1.75), text(size: 7pt)[rate = 5 per 1000 ms, so $T$ = 200 ms and $tau$ = 800 ms: a burst of five, then one admission per $T$])
  // TAT curve
  let pts = ((0, 1000), (200, 1200), (400, 1400), (600, 1600), (800, 1800), (1000, 2000))
  content((x0 + 4.3, -0.85), text(size: 6.8pt, fill: blue)[green: admitted; dashed red: rejected. TAT after the $k$-th admission is $t_1 + k T$, so any interval of length $L$ admits at most $N + floor(L \/ T)$])
})

// ------------------------------------------------------------------- RCU

#let rcu_swap() = fit(diagram(
  spacing: (16mm, 11mm),
  node-stroke: 0.8pt + blue,
  edge-stroke: 0.8pt + gray,
  node((0, 0), [Worker thread #linebreak() `acquireEngine`], ..node_style),
  node((1, 0), [`slot` pointer #linebreak() atomic], ..warn_style),
  node((2, 0), [Slot A: engine, #linebreak() readers = 3], ..good_style),
  node((2, 1), [Slot B: engine, #linebreak() readers = 0], ..node_style),
  node((0, 1), [Storage thread #linebreak() rebuild B, swap, #linebreak() wait A.readers = 0], ..node_style),
  edge((0, 0), (1, 0), "-|>", [load]),
  edge((1, 0), (2, 0), "-|>", [pin, re-check]),
  edge((0, 1), (2, 1), "-|>", [build]),
  edge((0, 1), (1, 0), "-|>", [swap to B], bend: 20deg),
  edge((0, 1), (2, 0), "--|>", [drain], bend: -10deg),
), 85%)

// --------------------------------------------------------------- storage

#let storage_architecture() = fit(diagram(
  spacing: (12mm, 11mm),
  node-stroke: 0.8pt + blue,
  edge-stroke: 0.8pt + gray,
  node((0, 0), [Workers #linebreak() (hot path)], ..node_style),
  node((1, 0), [MPSC ring #linebreak() 512 incidents], ..warn_style),
  node((2, 0), [Storage thread #linebreak() drain + poll], ..node_style),
  node((3, 0), [Zaxonlite #linebreak() SQLite + Paxos], ..good_style),
  node((3, 1), [`policies`, `ip_reputation`, #linebreak() `security_incidents`, FTS5, vec0], ..good_style),
  node((2, 1), [Rebuild spare #linebreak() engine slot], ..node_style),
  node((1, 1), [`publishEngine` #linebreak() RCU swap], ..warn_style),
  node((0, 1), [Other cluster #linebreak() nodes], ..node_style),
  edge((0, 0), (1, 0), "-|>", [push]),
  edge((1, 0), (2, 0), "-|>", [pop]),
  edge((2, 0), (3, 0), "-|>", [batched SQL]),
  edge((3, 0), (3, 1), "-|>"),
  edge((3, 1), (2, 1), "-|>", [changed?]),
  edge((2, 1), (1, 1), "-|>"),
  edge((1, 1), (0, 0), "-|>", [new rules], bend: 20deg),
  edge((3, 0), (0, 1), "<-|>", [Multi-Paxos], bend: 30deg),
), 80%)

// --------------------------------------------------------- Aho-Corasick

#let aho_corasick_graph() = diagram(
  spacing: (20mm, 14mm),
  node-stroke: 0.8pt + blue,
  edge-stroke: 0.8pt + gray,
  node((0, 0), [Root (0)], ..node_style),
  node((1, -1), [G], ..node_style),
  node((2, -1), [GP], ..node_style),
  node((3, -1), [GPTBot], fill: red_light, stroke: 0.8pt + red, corner-radius: 3pt, inset: 6pt),
  node((1, 1), [C], ..node_style),
  node((2, 1), [Cl], ..node_style),
  node((3, 1), [ClaudeBot], fill: red_light, stroke: 0.8pt + red, corner-radius: 3pt, inset: 6pt),
  edge((0, 0), (1, -1), "-|>", [g]),
  edge((1, -1), (2, -1), "-|>", [p]),
  edge((2, -1), (3, -1), "-|>", [tbot]),
  edge((0, 0), (1, 1), "-|>", [c]),
  edge((1, 1), (2, 1), "-|>", [l]),
  edge((2, 1), (3, 1), "-|>", [audebot]),
  edge((2, -1), (0, 0), "--|>", [fail], stroke: 0.7pt + amber, bend: 30deg),
  edge((2, 1), (0, 0), "--|>", [fail], stroke: 0.7pt + amber, bend: -30deg),
)

// ------------------------------------------------------------- benchmarks

#let stat_tile(number, label, detail, fill: blue_light, stroke: blue) = block(
  breakable: false,
  fill: fill,
  stroke: 0.8pt + stroke,
  radius: 4pt,
  inset: 8pt,
  width: 100%,
)[
  #text(size: 18pt, weight: "bold", fill: stroke)[#number]\
  #text(size: 8.5pt, weight: "bold")[#label]\
  #text(size: 7.2pt, fill: gray)[#detail]
]

#let bench_data() = json("/benchmarks/results/latest.json")

#let bench_find(data, impl, subsystem, workload) = data.runs.find(run =>
  run.impl == impl and run.subsystem == subsystem and run.workload == workload)

#let fmt_ns(v) = {
  if v == none { [-] }
  else if v >= 1000000 { [#calc.round(v / 1000000, digits: 2) ms] }
  else if v >= 1000 { [#calc.round(v / 1000, digits: 2) µs] }
  else { [#calc.round(v, digits: 1) ns] }
}

#let benchmark_rows() = (
  ("Hashcash verify (16 bits)", "pow_verify", "hashcash_16_bits", true),
  ("PoSW verify (depth 13, t = 16)", "pow_verify", "posw_depth13_t16", false),
  ("Bot signatures (40, Aho-Corasick)", "bot_matcher", "aho_corasick_40_signatures", true),
  ("IPv4 CIDR lookup", "ip_filter", "ipv4_cidr_classification", true),
  ("IPv6 CIDR lookup", "ip_filter", "ipv6_cidr_classification", false),
  ("Session token (keyed BLAKE3)", "token_auth", "blake3_mac_token", true),
  ("Session token (Ed25519)", "token_auth", "ed25519_compact_token", false),
  ("Spent set (Robin Hood)", "challenge_store", "robin_hood_spend_and_lookup", true),
  ("Rate limiter (GCRA)", "rate_limiter", "gcra_check", false),
  ("HTTP parse + cookie", "http_parser", "zero_copy_request_and_cookie", true),
  ("Classification, Gate profile", "policy_engine", "browser_request_gate_profile", false),
  ("Classification, Shield profile", "policy_engine", "browser_request_full_classification", false),
  ("WAF body scan (8 KB)", "waf_inspect", "8kb_body_semantic_scan", false),
)

#let benchmark_log_chart() = {
  let data = bench_data()
  let items = benchmark_rows().map(((label, sub, wl, has_model)) => (
    label,
    bench_find(data, "sibuna", sub, wl),
    none,
  ))
  cetz.canvas(length: 1cm, {
    import cetz.draw: *
    let x0 = 4.4
    let xw = 9.2
    let lmin = 0.5
    let lmax = 5.0
    let row_h = 0.62
    let bar_h = 0.18
    let height = items.len() * row_h
    let xpos(v) = {
      let lv = calc.log(calc.max(v, 3.2), base: 10)
      x0 + ((lv - lmin) / (lmax - lmin)) * xw
    }
    for exp in range(1, 6) {
      let val = calc.pow(10, exp)
      let x = xpos(val)
      line((x, 0.2), (x, -height - 0.2), stroke: (paint: rule, thickness: 0.4pt, dash: "dashed"))
      let label_str = if exp == 1 { "10 ns" } else if exp == 2 { "100 ns" } else if exp == 3 { "1 µs" } else if exp == 4 { "10 µs" } else { "100 µs" }
      content((x, 0.45), text(size: 6.8pt, fill: gray)[#label_str])
    }
    rect((x0, 1.0), (x0 + 0.35, 0.8), fill: blue, stroke: none)
    content((x0 + 0.45, 0.9), anchor: "west", text(size: 7.2pt, weight: "bold", fill: blue)[Sibuna, measured on this host])
    for (i, (label, sib, model)) in items.enumerate() {
      let y = -(i + 0.5) * row_h
      content((x0 - 0.15, y), anchor: "east", text(size: 7pt, weight: "bold")[#label])
      if sib != none {
        let x_s = xpos(sib.ns_per_op_median)
        rect((x0, y + 0.02), (x_s, y + bar_h + 0.02), fill: blue, stroke: none)
        content((x_s + 0.08, y + bar_h / 2 + 0.02), anchor: "west", text(size: 5.8pt, fill: blue)[#fmt_ns(sib.ns_per_op_median)])
      }
      if model != none {
        let x_m = xpos(model.ns_per_op_median)
        rect((x0, y - bar_h - 0.02), (x_m, y - 0.02), fill: red, stroke: none)
        content((x_m + 0.08, y - bar_h / 2 - 0.02), anchor: "west", text(size: 5.8pt, fill: red)[#fmt_ns(model.ns_per_op_median)])
      }
    }
  })
}

#let benchmark_results_table() = {
  let data = bench_data()
  let meta = data.meta
  let dirty_tag = if "dirty" in meta and meta.dirty { [ · modified tree] } else { [] }
  let rows = benchmark_rows().map(((label, sub, wl, has_model)) => {
    let sib = bench_find(data, "sibuna", sub, wl)
    let model = none
    (
      [#label],
      [#fmt_ns(if sib != none { sib.ns_per_op_median } else { none })],
      [#fmt_ns(if sib != none { sib.ns_per_op_min } else { none }) – #fmt_ns(if sib != none { sib.ns_per_op_max } else { none })],
      [#fmt_int(if sib != none { sib.ops_per_sec } else { none })],
    )
  }).flatten()
  let naive = bench_find(data, "sibuna-naive", "bot_matcher", "sequential_substring_40_signatures")
  let ac = bench_find(data, "sibuna", "bot_matcher", "aho_corasick_40_signatures")
  [
    #text(size: 8pt, fill: gray)[
      Recorded #meta.date · #meta.host · #meta.cpu · #meta.os · revision
      #raw(meta.git)#dirty_tag · Zig #meta.zig · ReleaseFast · 7 batches, median with min–max spread
    ]
    #v(6pt)
    #grid(
      columns: (1fr, 1fr, 1fr, 1fr),
      gutter: 6pt,
      stat_tile([#fmt_ns(bench_find(data, "sibuna", "pow_verify", "hashcash_16_bits").ns_per_op_median)], [Hashcash verify],
        [Hardware SHA-256, zero allocation], fill: blue_light, stroke: blue),
      stat_tile([#fmt_ns(bench_find(data, "sibuna", "token_auth", "blake3_mac_token").ns_per_op_median)], [Session token check],
        [Keyed BLAKE3, 64-character cookie], fill: green_light, stroke: green),
      stat_tile([#calc.round(meta.idle_rss_kb / 1024, digits: 1) MB], [Idle resident memory],
        [Daemon after start, storage off], fill: amber_light, stroke: amber),
      stat_tile([#calc.round(meta.binary_bytes / 1048576, digits: 1) MB], [Daemon binary],
        [WASM solver #meta.wasm_bytes bytes], fill: rgb("f5f3ff"), stroke: rgb("7c3aed")),
    )
    #v(8pt)
    #block(width: 100%, inset: 10pt, radius: 5pt, fill: blue_light, stroke: 0.5pt + rule)[
      #text(size: 11pt, weight: "bold")[Measured latency per operation]
      #linebreak()
      #text(size: 8pt, fill: gray)[Only measured primitive latencies are shown. Allocation activity is not instrumented.]
      #v(5pt)
      #table(
        columns: (1.6fr, 0.8fr, 1fr, 0.8fr),
        table.header([*Workload*], [*Median*], [*Spread*], [*ops/s*]),
        ..rows,
      )
      #v(4pt)
      #text(size: 8pt, fill: gray)[For scale, the same 40 bot signatures scanned by sequential substring search on this host cost #fmt_ns(naive.ns_per_op_median) against #fmt_ns(ac.ns_per_op_median) for the automaton.]
    ]
  ]
}

#let benchmark_chart_block() = block(
  width: 100%, inset: 10pt, radius: 5pt, fill: blue_light, stroke: 0.5pt + rule, breakable: false,
)[
  #text(size: 11pt, weight: "bold")[Measured latency on a logarithmic scale]
  #linebreak()
  #text(size: 8pt, fill: gray)[Lower is better · log-10 scale · every bar is a measurement from the run above]
  #v(5pt)
  #align(center, fit(benchmark_log_chart(), 88%))
]

// ------------------------------------------------------------ lineage

#let design_lineage() = fit(diagram(
  spacing: (7mm, 9mm),
  edge-stroke: 0.7pt + gray,
  node-corner-radius: 3pt,
  node((0,0), [Dwork–Naor #linebreak() 1992], ..node_style),
  node((1,0), [Hashcash #linebreak() 1997], ..node_style),
  node((2,0), [Juels–Brainard #linebreak() 1999], ..node_style),
  node((3,0), [Mahmoody et al. #linebreak() 2013], ..node_style),
  node((4,0), [Cohen–Pietrzak #linebreak() 2018], ..node_style),
  node((5,0), [Blocki–Lee–Zhou #linebreak() 2021], ..node_style),
  node((0,1), [Aho–Corasick #linebreak() 1975], ..good_style),
  node((1,1), [ModSecurity, CRS #linebreak() 2002], ..good_style),
  node((2,1), [libinjection #linebreak() 2012], ..good_style),
  node((3,1), [Hyperscan #linebreak() 2019], ..good_style),
  node((4,1), [GCRA #linebreak() ATM Forum 1996], ..good_style),
  node((5,1), [Multi-Paxos #linebreak() Lamport 1998], ..good_style),
  node((1,2), [Anubis #linebreak() interstitial], ..warn_style),
  node((2,2), [SafeLine #linebreak() semantic WAF], ..warn_style),
  node((4,2), [Cloudflare #linebreak() hosted edge], ..warn_style),
  node((3,3), text(fill: white)[*Sibuna* #linebreak() Gate · Shield · Edge], fill: blue,
    stroke: 1pt + blue, inset: 8pt, corner-radius: 3pt),
  edge((0,0),(1,0), "-|>"), edge((1,0),(2,0), "-|>"), edge((2,0),(3,0), "-|>"),
  edge((3,0),(4,0), "-|>"), edge((4,0),(5,0), "-|>"),
  edge((1,1),(2,1), "-|>"), edge((0,1),(3,1), "-|>", bend: -20deg),
  edge((1,0),(1,2), "-|>"), edge((2,1),(2,2), "-|>"),
  edge((1,0),(3,3), "-|>", bend: -12deg), edge((4,0),(3,3), "-|>"), edge((5,0),(3,3), "-|>", bend: 20deg),
  edge((0,1),(3,3), "-|>", bend: 25deg), edge((2,1),(3,3), "-|>"), edge((4,1),(3,3), "-|>"),
  edge((5,1),(3,3), "-|>", bend: 15deg),
  edge((1,2),(3,3), "-|>"), edge((2,2),(3,3), "-|>"), edge((4,2),(3,3), "-|>"),
), 78%)

// ------------------------------------------------------------ whole-product comparison

#let tools_data() = json("/benchmarks/results/tools-comparison-latest.json")

#let product_label(p) = if p == "sibuna-gate" { [Sibuna Gate] } else if p == "sibuna-shield" { [Sibuna Shield] } else if p == "anubis" { [Anubis] } else { [#p] }

#let workload_label(w) = (
  admitted: [Admitted (session)], challenged: [Challenged (no session)],
  allowed_static: [Allowed static path], attack: [SQL injection with session],
).at(w, default: [#w])

#let tools_mode_table(mode) = {
  let data = tools_data()
  let rows = ()
  for run in data.runs.filter(r => r.mode == mode) {
    for (name, w) in run.workloads.pairs() {
      let numeric = type(w.status) == int
      let status_color = if not numeric or w.status >= 400 { red } else { green }
      let status_text = if numeric { [#w.status] } else { [failed] }
      let failed = "failed" in w and w.failed
      rows.push((
        product_label(run.product), workload_label(name),
        text(fill: status_color, weight: "bold")[#status_text],
        if failed { text(fill: red)[load generator #linebreak() could not connect] } else { [#fmt_int(w.requests_per_second_median)] },
        [#fmt_ms(w.latency_us_p50_median)], [#fmt_ms(w.latency_us_p99_median)],
        [#fmt_dec(w.cpu_us_per_request_median)],
        [#fmt_dec(w.cores_busy_median, digits: 2)],
        [#fmt_mib(w.peak_rss_kib_max)],
      ))
    }
  }
  set text(size: 7.6pt)
  table(
    columns: (1fr, 1.35fr, 0.55fr, 0.75fr, 0.65fr, 0.65fr, 0.6fr, 0.5fr, 0.6fr),
    inset: 4pt, stroke: 0.4pt + rule,
    fill: (col, row) => if row == 0 { blue_light } else { none },
    table.header([*Product*], [*Workload*], [*Status*], [*req/s*], [*p50*], [*p99*], [*CPU µs/req*], [*Cores*], [*Peak RSS*]),
    ..rows.flatten(),
  )
}

#let tools_footprint_table() = {
  let data = tools_data()
  let seen = ()
  let rows = ()
  for run in data.runs {
    if run.product in seen { continue }
    seen.push(run.product)
    rows.push((product_label(run.product), [#fmt_int(run.binary_bytes / 1024) KiB],
      [#fmt_mib(run.idle_rss_kib)], [#fmt_mib(run.rss_kib_after_workload)]))
  }
  set text(size: 8pt)
  table(
    columns: (1fr, 1fr, 1fr, 1fr), inset: 4.5pt, stroke: 0.4pt + rule,
    fill: (col, row) => if row == 0 { blue_light } else { none },
    table.header([*Product*], [*Binary*], [*Idle RSS*], [*RSS after workloads*]),
    ..rows.flatten(),
  )
}

#let tools_not_measured_table() = {
  let data = tools_data()
  let rows = ()
  for item in data.not_measured {
    let facts = item.published.pairs().map(((k, v)) => [*#k.replace("_", " ")*: #v]).join(linebreak())
    rows.push(([#item.product #linebreak() #text(size: 7pt, fill: gray)[#item.version_checked]], [#item.reason], facts))
  }
  set text(size: 7.8pt)
  set par(justify: false)
  table(
    columns: (0.8fr, 1.6fr, 1.6fr), inset: 4.5pt, stroke: 0.4pt + rule,
    fill: (col, row) => if row == 0 { blue_light } else { none },
    table.header([*Product*], [*Why it is not measured here*], [*Published facts a reader can check*]),
    ..rows.flatten(),
  )
}

#let tools_meta_line() = {
  let data = tools_data()
  let m = data.meta
  text(size: 8pt, fill: gray)[
    Recorded #m.date · #m.host · #m.cpu · #m.os · revision #raw(m.git) · #data.wrk ·
    #data.load.threads threads, #data.load.connections connections, #data.load.seconds s ×
    #data.load.repetitions repetitions, median · origin: #data.origin · #data.anubis_version
  ]
}

// ------------------------------------------------------------ distributed and admission results

#let distributed_results_table() = {
  let data = json("/benchmarks/results/distributed-latest.json")
  let rows = ()
  for run in data.runs {
    let cluster = if run.clustered { [Yes, #run.transport] } else { [No] }
    let rss = run.rss_kb.map(k => fmt_mib(k)).join([ #sym.slash ])
    let ban = if "ban_propagation_ms" in run { [#calc.round(run.ban_propagation_ms, digits: 0) ms] } else { [-] }
    let down = if "one_node_down" in run { [#fmt_int(run.one_node_down.requests_per_second_median)] } else { [-] }
    rows.push(([#run.profile], cluster, [#run.nodes × #run.workers_per_node],
      [#fmt_int(run.admitted.requests_per_second_median)],
      [#fmt_int(run.challenged.requests_per_second_median)], [#rss], ban, down,
      text(fill: if run.status == "passed" { green } else { red }, weight: "bold")[#run.status]))
  }
  set text(size: 7.6pt)
  table(
    columns: (0.6fr, 0.9fr, 0.7fr, 0.8fr, 0.8fr, 1.3fr, 0.7fr, 0.8fr, 0.6fr),
    inset: 4pt, stroke: 0.4pt + rule,
    fill: (col, row) => if row == 0 { blue_light } else { none },
    table.header([*Profile*], [*Replicated*], [*Nodes × workers*], [*Admitted req/s*], [*Challenged req/s*],
      [*RSS per node*], [*Ban propagation*], [*req/s, one node down*], [*Checks*]),
    ..rows.flatten(),
  )
}

#let admission_comparison_table() = {
  let data = json("/benchmarks/results/admission-comparison-latest.json")
  let rows = ()
  for run in data.runs {
    rows.push(([#product_label(run.product) (#run.token_scheme)],
      [#fmt_int(run.valid_session.operations_per_second_median)],
      [#fmt_int(run.unauthenticated_check.operations_per_second_median)],
      [#fmt_int(run.challenge_bootstrap.operations_per_second_median)],
      [#fmt_int(run.proof_verification.operations_per_second_median)],
      [#fmt_mib(run.rss_kib_after_workload)]))
  }
  set text(size: 7.8pt)
  table(
    columns: (1.3fr, 0.9fr, 0.9fr, 0.9fr, 0.9fr, 0.8fr), inset: 4.5pt, stroke: 0.4pt + rule,
    fill: (col, row) => if row == 0 { blue_light } else { none },
    table.header([*Product (token)*], [*Session check ops/s*], [*Unauthenticated ops/s*],
      [*Bootstrap ops/s*], [*Proof verification ops/s*], [*RSS*]),
    ..rows.flatten(),
  )
}

// ------------------------------------------------------------ cluster of three

#let cluster_data() = json("/benchmarks/results/cluster-latest.json")

#let cluster_cell(s, key, fmt) = if s == none or s.failed { text(fill: red)[failed] } else { fmt(s.at(key)) }

#let cluster_throughput_table() = {
  let data = cluster_data()
  let rows = ()
  for c in data.cases.filter(c => c.status == "passed") {
    for (scope, group) in (([node 1 alone], c.per_node), ([all nodes at once], c.at("all_nodes", default: none))) {
      if group == none { continue }
      for (label, name) in (("admitted", [Admitted (session)]), ("challenged", [Challenged]), ("attack", [SQL injection, session])) {
        let s = group.at(label, default: none)
        rows.push((
          [#c.case], scope, name,
          cluster_cell(s, "requests_per_second_median", v => [#fmt_int(v)]),
          cluster_cell(s, "latency_us_p99_median", v => [#fmt_ms(v)]),
          cluster_cell(s, "cpu_us_per_request_median", v => [#fmt_dec(v)]),
          cluster_cell(s, "cores_busy_total_median", v => [#fmt_dec(v, digits: 2)]),
          cluster_cell(s, "peak_rss_kib_per_node_max", v => v.map(k => fmt_mib(k)).join([ #sym.slash ])),
        ))
      }
    }
  }
  set text(size: 7.6pt)
  table(
    columns: (1.15fr, 0.85fr, 1fr, 0.7fr, 0.6fr, 0.6fr, 0.5fr, 1.2fr),
    inset: 4pt, stroke: 0.4pt + rule,
    fill: (col, row) => if row == 0 { blue_light } else { none },
    table.header([*Case*], [*Load on*], [*Workload*], [*req/s*], [*p99*], [*CPU µs/req*], [*Cores*], [*Peak RSS per node*]),
    ..rows.flatten(),
  )
}

#let cluster_parity_table() = {
  let data = cluster_data()
  let mark(v) = if v == true { text(fill: green, weight: "bold")[passed] } else if v == false { text(fill: red, weight: "bold")[failed] } else { [-] }
  let rows = ()
  for c in data.cases.filter(c => c.status == "passed") {
    let ch = c.checks
    let idle = c.idle
    let fail = c.at("failover", default: none)
    rows.push((
      [#c.case],
      [#idle.cpu_cores_per_node.map(v => str(calc.round(v * 100, digits: 1))).join([ #sym.slash ]) %],
      idle.rss_kib_per_node.map(k => fmt_mib(k)).join([ #sym.slash ]),
      mark(ch.cross_node_session), mark(ch.waf_denial_with_session),
      mark(ch.at("solution_replay_rejected_on_other_node", default: none)),
      if "ban_propagation_ms" in ch { [#calc.round(ch.ban_propagation_ms, digits: 0) ms] } else { [-] },
      if fail == none { [-] } else { [node #fail.stopped_leader_node stopped: #fmt_int(fail.admitted_all_survivors.requests_per_second_median) req/s, ban #calc.round(fail.post_failover_ban_propagation_ms, digits: 0) ms] },
      mark(ch.storage_chain_log_clean),
    ))
  }
  set text(size: 7.4pt)
  set par(justify: false)
  table(
    columns: (1.1fr, 0.8fr, 0.9fr, 0.55fr, 0.55fr, 0.6fr, 0.6fr, 1.3fr, 0.55fr),
    inset: 4pt, stroke: 0.4pt + rule,
    fill: (col, row) => if row == 0 { blue_light } else { none },
    table.header([*Case*], [*Idle CPU per node*], [*Idle RSS per node*], [*Session on every node*], [*WAF denies with session*], [*Replay on other node rejected*], [*Ban propagation*], [*Leader stopped*], [*Storage log clean*]),
    ..rows.flatten(),
  )
}

#let cluster_meta_line() = {
  let data = cluster_data()
  let m = data.meta
  text(size: 8pt, fill: gray)[
    Recorded #m.date · #m.host · #m.cpu · revision #raw(m.git) · #data.wrk ·
    #data.load.threads threads, #data.load.connections connections per node, #data.load.seconds s ×
    #data.load.repetitions repetitions, median · two workers per node · Shield, forward auth
  ]
}
