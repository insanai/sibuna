// Whitepaper prologue: who does the work. A defense that inspects first spends its own
// work on every request; Sibuna asks the sender for 2^b expected hash trials and checks
// the answer with one hash. Each party keeps one colour in both rows, the sender amber
// and the defense blue, so the reader sees the full meter move from one side to the
// other. The meters are a model, not a measurement, except the verification time.
// Boxes and notes are laid out by Typst and grow with their words in every language.

#import "@preview/cetz:0.5.2"
#import "../style.typ": *

#show: figure-page
#let w = words("work-asymmetry")
#let data = json("/benchmarks/results/primitives-latest.json")
#let hashcash = data.runs.find(run => run.workload == "hashcash_16_bits")

#let sender-paint = (edge: amber, paper: amber-light, fill: amber)
#let defense-paint = (edge: blue, paper: blue-light, fill: blue)
#let side = 4.7cm
#let middle = 5.6cm
#let gutter = 0.3cm

// A party's box. Both boxes of a row take the taller one's height.
#let party(paint, label, height) = block(width: side, height: height, inset: 7pt,
  radius: 4pt, fill: paint.paper, stroke: 0.9pt + paint.edge,
  align(center + horizon, label))

// The request from the sender to the defense: its label above an arrow that points from
// the sender's side to the defense's, the other way round in right-to-left text.
#let request(label) = stack(spacing: 4pt,
  block(width: middle, align(center, text(size: 7.5pt, fill: ink, label))),
  cetz.canvas(length: 1cm, {
    import cetz.draw: *
    let ends = ((0, 0), (middle / 1cm, 0))
    let (from, to) = if rtl { (ends.at(1), ends.at(0)) } else { ends }
    line(from, to, stroke: 1pt + muted, mark: (end: "stealth", fill: muted, scale: 0.8))
  }))

// A work meter under a party: a share of one full scale, and a note on what the work is.
#let meter(paint, share, note-text) = stack(spacing: 4pt,
  box(width: side, height: 0.3cm, radius: 2pt, fill: white, stroke: 0.5pt + rule,
    align(start, box(width: calc.max(0.03, share) * side, height: 100%, radius: 2pt,
      fill: paint.fill))),
  block(width: side, text(size: 7pt, fill: muted, note-text)))

// One row: a title with its verdict, then the two parties with their meters.
#let lane(title, verdict, sender, arrow-label, defense, sender-work, defense-work,
  sender-note, defense-note) = context {
  let label(body) = text(size: 8pt, body)
  let height = calc.max(
    measure(block(width: side, inset: 7pt, label(sender))).height,
    measure(block(width: side, inset: 7pt, label(defense))).height)
  block(width: 2 * side + middle + 2 * gutter + 0.6cm, inset: 0.3cm, radius: 5pt,
    fill: faint, stroke: 0.6pt + rule, {
      text(size: 8.5pt, weight: "bold", title)
      h(0.6em)
      text(size: 8pt, fill: muted, verdict)
      v(6pt)
      grid(columns: (side, middle, side), column-gutter: gutter, row-gutter: 5pt,
        // The meters line up at the top, whatever the length of their notes.
        align: (x, y) => if y == 0 { center + horizon } else { center + top },
        party(sender-paint, label(sender), height), request(arrow-label),
        party(defense-paint, label(defense), height),
        meter(sender-paint, sender-work, sender-note), [],
        meter(defense-paint, defense-work, defense-note))
    })
}

#stack(spacing: 0.3cm,
  lane(w.inspect-title, w.inspect-verdict, w.inspect-sender, w.inspect-arrow,
    w.inspect-defense, 0.02, 1.0, w.inspect-sender-work, w.inspect-defense-work),
  lane(w.work-title, w.work-verdict, w.work-sender, w.work-arrow, w.work-defense, 1.0, 0.02,
    phrase(w.work-sender-work, (power: $2^b$, trials: num(65536))),
    phrase(w.work-defense-work, (ns: num(hashcash.ns_per_op_median, digits: 1)))))
