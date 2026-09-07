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
      columns: (1fr, 1fr, 1fr),
      gutter: 6pt,
      box(inset: 7pt, radius: 4pt, fill: blue_light)[
        #text(size: 7pt, weight: "bold", fill: blue)[TIMED BARE-METAL]
        #linebreak()
        #text(size: 8pt)[Native execution on host CPU hardware instructions]
      ],
      box(inset: 7pt, radius: 4pt, fill: green_light)[
        #text(size: 7pt, weight: "bold", fill: green)[ZERO HEAP ALLOCATION]
        #linebreak()
        #text(size: 8pt)[0 bytes allocated dynamically on request hot-path]
      ],
      box(inset: 7pt, radius: 4pt, fill: amber_light)[
        #text(size: 7pt, weight: "bold", fill: amber)[DIRECT COMPARISON]
        #linebreak()
        #text(size: 8pt)[Measured against Anubis Go / Wazero VM architecture]
      ],
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
  ]
}
