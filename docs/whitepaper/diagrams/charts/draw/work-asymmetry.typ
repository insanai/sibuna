// index.rst, the prologue: who does the work. A defense that inspects first spends its
// own work on every request; Sibuna asks the sender for 2^b expected hash trials and
// checks the answer with one hash. The sender is a party outside Sibuna (slate) in both
// rows; the defense is an ordinary component above and Sibuna, the accent, below. Each
// meter takes its owner's colour, so the reader sees the full meter move from one side
// to the other. The meters are a model, not a measurement, except the verification
// time, which the chart reads from its copy of the primitive results.

#import "../chart.typ": *

#let data = json("../data/primitives-latest.json")
#let hashcash = data.runs.find(run => run.workload == "hashcash_16_bits")

#let side = 4.3cm
#let middle = 4.6cm
#let gutter = 0.3cm

// A party's box in the tone `kind`. Both boxes of a row take the taller one's height;
// a party outside Sibuna is a pill.
#let party-box(kind, body, height) = {
  let (fill, edge) = tones.at(kind)
  block(width: side, height: height, inset: 6pt, fill: fill, stroke: thin + edge,
    radius: if kind == "party" { height / 2 } else { 4pt }, align(center + horizon, body))
}

// The request from the sender to the defense: its label above an arrow that points from
// the sender's side to the defense's, the other way round in right-to-left text.
#let request(body) = stack(spacing: 4pt,
  block(width: middle, align(center, text(size: 8pt, rich(body)))),
  cetz.canvas(length: 1cm, {
    import cetz.draw: *
    let ends = ((0, 0), (middle / 1cm, 0))
    let (from, to) = if is-rtl() { (ends.at(1), ends.at(0)) } else { ends }
    line(from, to, stroke: thin + line-ink, mark: (end: "stealth", fill: line-ink,
      scale: 0.6))
  }))

// A work meter under a party: a share of one full scale, and a note on what the work is.
// The bar grows from the start of the line (style.typ names a node `start`, so the
// alignment is spelled out).
#let meter(paint, share, body) = stack(spacing: 4pt,
  box(width: side, height: 0.28cm, radius: 2pt, fill: white, stroke: thin + rule,
    align(if is-rtl() { right } else { left }, box(width: calc.max(0.03, share) * side,
      height: 100%, radius: 2pt, fill: paint))),
  block(width: side, text(size: 8pt, fill: quiet, rich(body))))

// One row: a title with its verdict, then the two parties with their meters. `defense`
// is the tone of the defense: "step" or "accent".
#let lane(title, verdict, sender, arrow, defender, defense, sender-work, defense-work,
  sender-note, defense-note) = {
  let face(body) = text(size: 9.5pt, rich(body))
  let height = calc.max(
    measure(block(width: side, inset: 6pt, face(sender))).height,
    measure(block(width: side, inset: 6pt, face(defender))).height)
  let defense-paint = tones.at(defense).at(1)
  block(width: 2 * side + middle + 2 * gutter + 0.6cm, inset: 0.3cm, radius: 5pt,
    fill: paper, stroke: thin + rule, {
      text(size: 9.5pt, weight: "semibold", rich(title))
      h(0.6em)
      text(size: 8pt, fill: quiet, rich(verdict))
      v(6pt)
      grid(columns: (side, middle, side), column-gutter: gutter, row-gutter: 5pt,
        // The meters line up at the top, whatever the length of their notes.
        align: (x, y) => if y == 0 { center + horizon } else { center + top },
        party-box("party", face(sender), height), request(arrow),
        party-box(defense, face(defender), height),
        meter(slate, sender-work, sender-note), [],
        meter(defense-paint, defense-work, defense-note))
    })
}

#let draw() = context {
  let w = words("work-asymmetry")
  stack(spacing: 0.3cm,
    lane(w.inspect-title, w.inspect-verdict, w.inspect-sender, w.inspect-arrow,
      w.inspect-defense, "step", 0.02, 1.0, w.inspect-sender-work, w.inspect-defense-work),
    lane(w.work-title, w.work-verdict, w.work-sender, w.work-arrow, w.work-defense,
      "accent", 1.0, 0.02,
      phrase(w.work-sender-work, (power: $2^b$, trials: num(65536))),
      phrase(w.work-defense-work, (ns: num(hashcash.ns_per_op_median, digits: 1)))))
}
