// benchmarks.rst: the primitive timings of benchmarks/results/primitives-latest.json, as
// a dot plot on a logarithmic axis. A dot is the median of the batches. The chart reads
// its copy of the file in ../data, so a new run redraws it.

#import "../chart.typ": *

#let data = json("../data/primitives-latest.json")

// The groups of rows, in the order of the book's table. A row names its implementation
// and its workload.
#let groups = (
  ("work", (("sibuna", "hashcash_16_bits"), ("sibuna", "posw_depth13_t16"))),
  ("match", (("sibuna", "aho_corasick_40_signatures"),
    ("sibuna-naive", "sequential_substring_40_signatures"),
    ("sibuna", "ipv4_cidr_classification"), ("sibuna", "ipv6_cidr_classification"))),
  ("token", (("sibuna", "blake3_mac_token"), ("sibuna", "ed25519_compact_token"))),
  ("state", (("sibuna", "robin_hood_spend_and_lookup"), ("sibuna", "gcra_check"),
    ("sibuna", "gcra_four_rule_scopes"), ("sibuna", "gcra_check_hashed"),
    ("sibuna", "gcra_four_rule_scopes_hashed"))),
  ("request", (("sibuna", "zero_copy_request_and_cookie"),
    ("sibuna", "browser_request_full_classification"),
    ("sibuna", "browser_request_gate_profile"), ("sibuna", "8kb_body_semantic_scan"),
    ("sibuna", "8kb_body_sqli_audit_other_enforce"))),
)

#let find(implementation, workload) = data.runs.find(run =>
  run.impl == implementation and run.workload == workload)

// The largest distance of any batch from its row's median, as a share of the median.
#let spread = groups.map(((_, rows)) => rows).flatten().chunks(2).map(((i, wl)) => {
  let run = find(i, wl)
  calc.max(run.ns_per_op_max - run.ns_per_op_median,
    run.ns_per_op_median - run.ns_per_op_min) / run.ns_per_op_median
}).fold(0, calc.max)

// A duration in nanoseconds with three significant digits, in the unit that keeps it
// between 1 and 1000. Needs `context`.
#let duration(ns) = {
  let (value, unit) = if ns >= 1000 { (ns / 1000, "µs") } else { (ns, "ns") }
  let digits = if value >= 100 { 0 } else { 1 }
  latin(num(value, digits: digits) + "\u{2009}" + unit)
}

#let plot(w) = context {
  // The row labels set the width of the label column.
  let names = groups.map(((_, rows)) => rows.map(((_, wl)) => w.rows.at(wl))).flatten()
  let label-width = calc.max(..names.map(n => measure(annotate(n)).width / 1cm)) + 0.25
  cetz.canvas(length: 1cm, {
    import cetz.draw: *
    // The plot takes what the labels leave of about 14 cm, between 6 and 8.2 cm.
    let span = calc.max(6.0, calc.min(8.2, 12.9 - label-width))
    let (low, high) = (0, 5)
    let x(ns) = (calc.log(ns, base: 10) - low) / (high - low) * span
    let (row, head) = (0.42, 0.52)
    let rows-total = groups.map(((_, rows)) => rows.len()).sum()
    let bottom = -(rows-total * row + groups.len() * head)

    // Decades, labelled above and below.
    let decades = ("1 ns", "10 ns", "100 ns", "1 µs", "10 µs", "100 µs")
    for (i, name) in decades.enumerate() {
      let gx = x(calc.pow(10, i))
      line((gx, 0.1), (gx, bottom), stroke: grid-stroke)
      content((gx, 0.16), anchor: "south", tick(latin(name)))
      content((gx, bottom - 0.06), anchor: "north", tick(latin(name)))
    }
    line((0, 0.1), (0, bottom), stroke: axis-stroke)

    let y = 0
    for (group, rows) in groups {
      y -= head
      // A group's name stands at the start of the line, above its rows.
      let (title-x, title-anchor) = if is-rtl() { (-0.2, "south-east") } else {
        (-label-width, "south-west")
      }
      content((title-x, y - 0.04), anchor: title-anchor, group-title(w.groups.at(group)))
      for (implementation, workload) in rows {
        y -= row
        let cy = y + row / 2
        let run = find(implementation, workload)
        let ours = implementation == "sibuna"
        let (paint, _) = series.at(if ours { "sibuna" } else { "other" })
        content((-0.2, cy), anchor: "east", annotate(w.rows.at(workload)))
        let at = (x(run.ns_per_op_median), cy)
        // A dotted guide from the axis leads the eye from the name to its dot.
        line((0, cy), at, stroke: (paint: rule, thickness: 0.5pt, dash: "dotted"))
        circle(at, radius: 0.08, fill: if ours { paint } else { white },
          stroke: if ours { 1pt + white } else { bold + paint })
        let value = duration(run.ns_per_op_median)
        let note = if ours { value } else { value + [ ] + w.baseline }
        content((at.at(0) + 0.16, cy), anchor: "west",
          text(size: 8pt, fill: if ours { ink } else { slate }, note))
      }
    }
  })
}

#let draw() = context {
  let w = words("primitive-latency")
  with-notes(plot(w), phrase(w.source, (date: latin(data.meta.date.slice(0, 10)),
    cpu: data.meta.cpu, spread: num(spread * 100, digits: 1))))
}
