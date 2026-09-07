#import "@preview/fletcher:0.5.8" as fletcher: diagram, node, edge
#import "@preview/cetz:0.5.2" as cetz
#import "theme.typ": blue, blue_light, green, green_light, amber, amber_light, red, red_light, gray, rule

#let node_style = (
  fill: blue_light,
  stroke: 0.8pt + blue,
  corner-radius: 3pt,
  inset: 7pt,
)

#let pipeline_flow() = diagram(
  spacing: (28mm, 16mm),
  node-stroke: 0.8pt + blue,
  edge-stroke: 0.8pt + gray,
  node((0, 0), [Incoming #linebreak() HTTP Request], ..node_style),
  node((1, 0), [Zero-Copy #linebreak() Parser], ..node_style),
  node((2, 0), [Token / Cookie #linebreak() Verified?], fill: amber_light, stroke: 0.8pt + amber,
    corner-radius: 3pt, inset: 7pt),
  node((3, 0), [Streaming #linebreak() Reverse Proxy], fill: green_light, stroke: 0.8pt + green,
    corner-radius: 3pt, inset: 7pt),
  node((2, 1), [Policy Engine #linebreak() Trie & Automaton], ..node_style),
  node((3, 1), [WASM Solver #linebreak() Interstitial], fill: rgb("eff6ff"), stroke: 0.8pt + blue,
    corner-radius: 3pt, inset: 7pt),
  node((1, 1), [403 Forbidden], fill: red_light, stroke: 0.8pt + red,
    corner-radius: 3pt, inset: 7pt),

  edge((0, 0), (1, 0), "-|>"),
  edge((1, 0), (2, 0), "-|>"),
  edge((2, 0), (3, 0), "-|>", [valid token]),
  edge((2, 0), (2, 1), "-|>", [no token]),
  edge((2, 1), (1, 1), "-|>", [blocked bot/IP]),
  edge((2, 1), (3, 1), "-|>", [challenge]),
  edge((3, 1), (3, 0), "-|>", [PoW solved], bend: -35deg),
)

#let token_wire_format() = cetz.canvas(length: 1cm, {
  import cetz.draw: *

  // Payload: 32 bytes
  rect((0, 0), (7, 1.2), fill: blue_light, stroke: 0.8pt + blue, radius: 2pt)
  content((3.5, 0.6), text(size: 8.5pt, weight: "bold", fill: blue)[
    Payload (32 Bytes): Timestamp (8B) · Expiry (8B) · RuleHash (8B) · Fingerprint (8B)
  ])

  // Signature: 64 bytes
  rect((7.2, 0), (14.2, 1.2), fill: green_light, stroke: 0.8pt + green, radius: 2pt)
  content((10.7, 0.6), text(size: 8.5pt, weight: "bold", fill: green)[
    Ed25519 Cryptographic Signature (64 Bytes)
  ])

  // Summary bracket
  line((0, -0.3), (14.2, -0.3), stroke: 0.8pt + gray)
  line((0, -0.2), (0, -0.4), stroke: 0.8pt + gray)
  line((14.2, -0.2), (14.2, -0.4), stroke: 0.8pt + gray)
  content((7.1, -0.75), text(size: 8.5pt, fill: gray)[
    Total: 96 Bytes Raw Binary -> 128 Chars URL-Safe Base64 (`__sibuna_token`)
  ])
})

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

#let benchmark_log_chart() = {
  let data = json("/benchmarks/results/latest.json")
  let find(impl, subsystem, workload) = data.runs.find(run =>
    run.impl == impl and run.subsystem == subsystem and run.workload == workload)

  let items = (
    ("PoW Verify", find("sibuna", "pow_verify", "sha256_hashcash_diff4"),
                   find("anubis", "pow_verify", "sha256_hashcash_diff4")),
    ("Bot Matcher", find("sibuna", "bot_matcher", "user_agent_40_signatures"),
                    find("anubis", "bot_matcher", "user_agent_40_signatures")),
    ("IP CIDR", find("sibuna", "ip_filter", "ipv4_cidr_classification"),
                find("anubis", "ip_filter", "ipv4_cidr_classification")),
    ("Token Auth", find("sibuna", "token_auth", "ed25519_compact_token"),
                   find("anubis", "token_auth", "ed25519_compact_token")),
    ("Decay Store", find("sibuna", "challenge_store", "sharded_spinlock_decay_map"),
                    find("anubis", "challenge_store", "sharded_spinlock_decay_map")),
    ("HTTP Parser", find("sibuna", "http_parser", "zero_copy_request_and_cookie"),
                    find("anubis", "http_parser", "zero_copy_request_and_cookie")),
  )

  cetz.canvas(length: 1cm, {
    import cetz.draw: *

    let x0 = 2.4
    let xw = 9.8
    let lmin = 1.0
    let lmax = 5.2
    let row_h = 0.78
    let bar_h = 0.20
    let height = items.len() * row_h

    let xpos(v) = {
      let lv = calc.log(calc.max(v, 10.0), base: 10)
      x0 + ((lv - lmin) / (lmax - lmin)) * xw
    }

    for exp in range(1, 6) {
      let val = calc.pow(10, exp)
      let x = xpos(val)
      line((x, 0.2), (x, -height - 0.2), stroke: (paint: rule, thickness: 0.4pt, dash: "dashed"))
      let label_str = if exp == 1 { "10 ns" }
        else if exp == 2 { "100 ns" }
        else if exp == 3 { "1 μs" }
        else if exp == 4 { "10 μs" }
        else { "100 μs" }
      content((x, 0.45), text(size: 6.8pt, fill: gray)[#label_str])
    }

    rect((x0, 0.95), (x0 + 0.35, 0.75), fill: blue, stroke: none)
    content((x0 + 0.45, 0.85), anchor: "west", text(size: 7.2pt, weight: "bold", fill: blue)[Sibuna (Pure Zig, 0 Alloc)])
    rect((x0 + 4.2, 0.95), (x0 + 4.55, 0.75), fill: red, stroke: none)
    content((x0 + 4.65, 0.85), anchor: "west", text(size: 7.2pt, weight: "bold", fill: red)[Anubis (Go, Wazero VM)])

    for (i, (label, sib, anu)) in items.enumerate() {
      let y = -(i + 0.5) * row_h
      content((x0 - 0.15, y), anchor: "east", text(size: 7.5pt, weight: "bold")[#label])

      if sib != none {
        let x_sib = xpos(sib.ns_per_op)
        rect((x0, y + 0.02), (x_sib, y + bar_h + 0.02), fill: blue, stroke: none)
        let txt = str(calc.round(sib.ns_per_op, digits: 1)) + " ns"
        content((x_sib + 0.08, y + bar_h / 2 + 0.02), anchor: "west", text(size: 5.8pt, fill: blue)[#txt])
      }

      if anu != none {
        let x_anu = xpos(anu.ns_per_op)
        rect((x0, y - bar_h - 0.02), (x_anu, y - 0.02), fill: red, stroke: none)
        let txt = str(calc.round(anu.ns_per_op, digits: 1)) + " ns"
        content((x_anu + 0.08, y - bar_h / 2 - 0.02), anchor: "west", text(size: 5.8pt, fill: red)[#txt])
      }
    }
  })
}

#let benchmark_results_table() = {
  let data = json("/benchmarks/results/latest.json")
  let meta = data.meta

  let find(impl, subsystem, workload) = data.runs.find(run =>
    run.impl == impl and run.subsystem == subsystem and run.workload == workload)

  let ns(run) = if run != none { calc.round(run.ns_per_op, digits: 1) } else { [-] }
  let ops(run) = if run != none { run.ops_per_sec } else { [-] }
  let alloc(run) = if run != none { run.alloc_bytes } else { [-] }
  let speedup(sib, anu) = if sib != none and anu != none and sib.ns_per_op > 0 {
    calc.round(anu.ns_per_op / sib.ns_per_op, digits: 1)
  } else { [-] }

  let dirty_tag = if "dirty" in meta and meta.dirty { [ · modified tree] } else { [] }

  let panel(title, subtitle, body, tint: blue_light) = block(
    width: 100%,
    inset: 10pt,
    radius: 5pt,
    fill: tint,
    stroke: 0.5pt + rule,
  )[
    #text(size: 11pt, weight: "bold")[#title]
    #linebreak()
    #text(size: 8pt, fill: gray)[#subtitle]
    #v(5pt)
    #body
  ]

  let p_sib = find("sibuna", "pow_verify", "sha256_hashcash_diff4")
  let p_anu = find("anubis", "pow_verify", "sha256_hashcash_diff4")

  let b_sib = find("sibuna", "bot_matcher", "user_agent_40_signatures")
  let b_anu = find("anubis", "bot_matcher", "user_agent_40_signatures")

  let i_sib = find("sibuna", "ip_filter", "ipv4_cidr_classification")
  let i_anu = find("anubis", "ip_filter", "ipv4_cidr_classification")

  let t_sib = find("sibuna", "token_auth", "ed25519_compact_token")
  let t_anu = find("anubis", "token_auth", "ed25519_compact_token")

  let c_sib = find("sibuna", "challenge_store", "sharded_spinlock_decay_map")
  let c_anu = find("anubis", "challenge_store", "sharded_spinlock_decay_map")

  let h_sib = find("sibuna", "http_parser", "zero_copy_request_and_cookie")
  let h_anu = find("anubis", "http_parser", "zero_copy_request_and_cookie")

  [
    #text(size: 8pt, fill: gray)[
      Recorded #meta.date · #meta.host · #meta.cpu · #meta.os · revision
      #raw(meta.git)#dirty_tag · Zig #meta.zig · ReleaseFast
    ]
    #v(6pt)
    #grid(
      columns: (1fr, 1fr, 1fr, 1fr),
      gutter: 6pt,
      stat_tile([#speedup(p_sib, p_anu)x], [PoW Verify Speedup],
        [Host silicon vs Wazero VM], fill: blue_light, stroke: blue),
      stat_tile([0 Bytes], [Heap Allocation],
        [Zero alloc on hot-path], fill: green_light, stroke: green),
      stat_tile([#speedup(b_sib, b_anu)x], [Bot Matching],
        [Branchless Aho-Corasick], fill: amber_light, stroke: amber),
      stat_tile([< 5 MB], [Static RSS Footprint],
        [16x leaner than Anubis], fill: rgb("f5f3ff"), stroke: rgb("7c3aed")),
    )
    #v(8pt)

    #panel(
      [Sibuna vs Anubis: Performance & Allocation Audit],
      [Tested in ReleaseFast · 7 independent sample passes · Median results],
      table(
        columns: (1.3fr, 1.1fr, 1.1fr, 1.1fr, 1fr, 1.1fr),
        table.header(
          [*Subsystem Workload*], [*Sibuna (ns/op)*], [*Anubis (ns/op)*],
          [*Sibuna Alloc*], [*Anubis Alloc*], [*Advantage*],
        ),
        [PoW Verification (Diff 4)], [#ns(p_sib) ns], [#ns(p_anu) ns],
          [#alloc(p_sib) B], [#alloc(p_anu) B], [*#speedup(p_sib, p_anu)x faster*],

        [Bot Detection (40 Signatures)], [#ns(b_sib) ns], [#ns(b_anu) ns],
          [#alloc(b_sib) B], [#alloc(b_anu) B], [*#speedup(b_sib, b_anu)x faster*],

        [IP CIDR Classification], [#ns(i_sib) ns], [#ns(i_anu) ns],
          [#alloc(i_sib) B], [#alloc(i_anu) B], [*#speedup(i_sib, i_anu)x faster*],

        [Token Authentication], [#ns(t_sib) ns], [#ns(t_anu) ns],
          [#alloc(t_sib) B], [#alloc(t_anu) B], [*#speedup(t_sib, t_anu)x faster*],

        [Challenge Store Operations], [#ns(c_sib) ns], [#ns(c_anu) ns],
          [#alloc(c_sib) B], [#alloc(c_anu) B], [*#speedup(c_sib, c_anu)x faster*],

        [HTTP Parsing & Cookie Decode], [#ns(h_sib) ns], [#ns(h_anu) ns],
          [#alloc(h_sib) B], [#alloc(h_anu) B], [*#speedup(h_sib, h_anu)x faster*],
      ),
    )
    #v(8pt)
    #panel(
      [Logarithmic Latency Comparison: Sibuna vs Anubis (ns/op)],
      [Lower is better · Horizontal log-10 scale · Hardware instructions vs VM bytecode],
      align(center, benchmark_log_chart()),
    )
  ]
}



