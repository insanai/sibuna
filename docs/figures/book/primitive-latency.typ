// Book Part VIII: the primitive timings of benchmarks/results/primitives-latest.json on a
// logarithmic scale. A bar is the median of the batches; the whisker spans their minimum
// and maximum. The figure reads the file, so a new run redraws it.

#import "@preview/cetz:0.5.2"
#import "../style.typ": *

#show: figure-page
#let w = words("primitive-latency")
#let data = json("/benchmarks/results/primitives-latest.json")

// The rows in the order of the book's table: implementation, workload and group.
#let rows = (
  ("sibuna", "hashcash_16_bits", "work"),
  ("sibuna", "posw_depth13_t16", "work"),
  ("sibuna", "aho_corasick_40_signatures", "match"),
  ("sibuna-naive", "sequential_substring_40_signatures", "match"),
  ("sibuna", "ipv4_cidr_classification", "match"),
  ("sibuna", "ipv6_cidr_classification", "match"),
  ("sibuna", "blake3_mac_token", "token"),
  ("sibuna", "ed25519_compact_token", "token"),
  ("sibuna", "robin_hood_spend_and_lookup", "state"),
  ("sibuna", "gcra_check", "state"),
  ("sibuna", "gcra_four_rule_scopes", "state"),
  ("sibuna", "gcra_check_hashed", "state"),
  ("sibuna", "gcra_four_rule_scopes_hashed", "state"),
  ("sibuna", "zero_copy_request_and_cookie", "request"),
  ("sibuna", "browser_request_full_classification", "request"),
  ("sibuna", "browser_request_gate_profile", "request"),
  ("sibuna", "8kb_body_semantic_scan", "request"),
  ("sibuna", "8kb_body_sqli_audit_other_enforce", "request"),
)

#let paints = (
  work: (amber-mid, amber),
  match: (blue-mid, blue),
  token: (violet-light.darken(8%), violet),
  state: (green-mid, green),
  request: (red-mid, red),
)

#let find(implementation, workload) = data.runs.find(run =>
  run.impl == implementation and run.workload == workload)

// A duration in nanoseconds, in the unit that keeps it between 1 and 1000.
#let duration(ns) = if ns >= 1000 {
  num(ns / 1000, digits: 1) + " µs"
} else {
  num(ns, digits: 1) + " ns"
}

#with-notes(cetz.canvas(length: 1cm, {
  import cetz.draw: *
  let x0 = 0
  let span = 9.6
  let (low, high) = (0, 5)
  let x(ns) = x0 + (calc.log(ns, base: 10) - low) / (high - low) * span
  let row = 0.46
  let n = rows.len()
  let bottom = -n * row

  // Decades.
  let decades = ("1 ns", "10 ns", "100 ns", "1 µs", "10 µs", "100 µs")
  for (i, label) in decades.enumerate() {
    let gx = x(calc.pow(10, i))
    line((gx, 0.15), (gx, bottom - 0.05), stroke: 0.4pt + faint.darken(8%))
    content((gx, 0.36), anchor: "base", small(text(fill: muted, latin(label))))
  }

  for (i, (implementation, workload, group)) in rows.enumerate() {
    let run = find(implementation, workload)
    let y = -(i + 0.5) * row
    let (paper, edge) = paints.at(group)
    content((x0 - 0.2, y), anchor: "east", text(size: 8pt, w.rows.at(workload)))
    rect((x0, y - 0.15), (x(run.ns_per_op_median), y + 0.15), fill: paper,
      stroke: 0.6pt + edge)
    line((x(run.ns_per_op_min), y), (x(run.ns_per_op_max), y), stroke: 0.9pt + ink)
    content((x(run.ns_per_op_max) + 0.12, y), anchor: "west",
      text(size: 7.5pt, fill: edge.darken(20%), latin(duration(run.ns_per_op_median))))
  }
  line((x0, 0.15), (x0, bottom - 0.05), stroke: 0.7pt + muted)

}),
  legend(..("work", "match", "token", "state", "request").map(group =>
    (swatch-box(..paints.at(group)), w.groups.at(group)))),
  note(phrase(w.source, (date: latin(data.meta.date.slice(0, 10)), cpu: data.meta.cpu))),
)
