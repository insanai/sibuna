// Whitepaper prologue: where the work goes. A defense that inspects first spends its own
// work on every request; Sibuna asks the sender for 2^b expected hash trials and checks
// the answer with one hash. The meters compare the two sides of each row; they are a
// model, not a measurement, except the verification time.

#import "@preview/cetz:0.5.2"
#import "../style.typ": *

#show: figure-page
#let w = words("work-asymmetry")
#let data = json("/benchmarks/results/primitives-latest.json")
#let hashcash = data.runs.find(run => run.workload == "hashcash_16_bits")

#let lane(y, title, paint, paper, sender, arrow-label, defender, sender-work, defender-work,
  sender-note, defender-note) = {
  import cetz.draw: *
  let (width, height) = (15.4, 3.1)
  rect((0, y - height), (width, y), radius: 0.18, fill: paper, stroke: 0.7pt + paint.lighten(45%))
  content((start-x(0.3, width - 0.3), y - 0.22), anchor: start-anchor("north"), text(size: 8.5pt, weight: "bold",
    fill: paint.darken(10%), title))
  // The two parties.
  let party(x, label) = {
    rect((x, y - 1.75), (x + 4.4, y - 0.7), radius: 0.12, fill: white, stroke: 0.8pt + paint)
    content((x + 2.2, y - 1.22), box(width: 3.9cm, align(center, text(size: 8pt, label))))
  }
  party(0.3, sender)
  party(10.7, defender)
  line((4.8, y - 1.22), (10.6, y - 1.22), stroke: 1pt + paint,
    mark: (end: "stealth", fill: paint, scale: 0.8))
  content((7.7, y - 1.1), anchor: "south", box(width: 5.6cm, align(center,
    text(size: 7.5pt, fill: paint.darken(10%), arrow-label))))
  // Work meters under each party: a share of a common full scale.
  let meter(x, share, note-text) = {
    rect((x, y - 2.2), (x + 4.4, y - 1.98), radius: 0.05, fill: white, stroke: 0.5pt + rule)
    rect((x, y - 2.2), (x + calc.max(0.06, 4.4 * share), y - 1.98), radius: 0.05,
      fill: paint, stroke: none)
    content((x, y - 2.32), anchor: "north-west", box(width: 4.4cm,
      text(size: 7pt, fill: muted, note-text)))
  }
  meter(0.3, sender-work, sender-note)
  meter(10.7, defender-work, defender-note)
}

#cetz.canvas(length: 1cm, {
  lane(0, w.inspect-title, red, red-light, w.inspect-sender, w.inspect-arrow,
    w.inspect-defense, 0.02, 1.0, w.inspect-sender-work, w.inspect-defense-work)
  lane(-3.4, w.work-title, green, green-light, w.work-sender, w.work-arrow,
    w.work-defense, 1.0, 0.02, phrase(w.work-sender-work, (power: $2^b$, trials: num(65536))),
    phrase(w.work-defense-work, (ns: num(hashcash.ns_per_op_median, digits: 1))))
})
