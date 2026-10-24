// Book Part I: the probability that a hash search is still running after x times its
// expected number of trials, with the large-work approximation P(K > x/p) ~ e^(-x).

#import "@preview/cetz:0.5.2"
#import "../style.typ": *

#show: figure-page
#let w = words("survival")

#cetz.canvas(length: 1cm, {
  import cetz.draw: *
  let (sx, sy) = (2.6, 4.6)
  let at(x, y) = (x * sx, y * sy)
  let curve = range(0, 161).map(i => at(i / 40, calc.exp(-i / 40)))

  // Grid and axes.
  for y in (0.25, 0.5, 0.75, 1.0) {
    line(at(0, y), at(4, y), stroke: 0.4pt + faint.darken(6%))
  }
  for x in (1, 2, 3, 4) {
    line(at(x, 0), at(x, 1.0), stroke: 0.4pt + faint.darken(6%))
  }
  line(..curve, at(4, 0), at(0, 0), close: true, fill: blue-light, stroke: none)
  line(at(0, 0), at(4.15, 0), stroke: 0.7pt + muted, mark: (end: "stealth", fill: muted))
  line(at(0, 0), at(0, 1.1), stroke: 0.7pt + muted, mark: (end: "stealth", fill: muted))
  for x in range(0, 5) {
    line(at(x, 0), (x * sx, -0.08), stroke: 0.7pt + muted)
    content((x * sx, -0.3), small(str(x)))
  }
  for y in (0, 0.5, 1.0) {
    line(at(0, y), (-0.08, y * sy), stroke: 0.7pt + muted)
    content((-0.15, y * sy), small(num(y, digits: 1)), anchor: "east")
  }
  content((2 * sx, -0.75), w.x-axis)
  content((-1.0, 0.5 * sy), angle: 90deg, w.y-axis)

  // The curve.
  line(..curve, stroke: 1.6pt + blue)

  // At the mean: e^(-1).
  let p1 = calc.exp(-1)
  line(at(1, 0), at(1, p1), stroke: (paint: amber, thickness: 0.8pt, dash: "dashed"))
  line(at(0, p1), at(1, p1), stroke: (paint: amber, thickness: 0.8pt, dash: "dashed"))
  circle(at(1, p1), radius: 0.09, fill: amber, stroke: white + 1pt)
  content((1 * sx + 0.25, p1 * sy + 0.2), anchor: "south-west",
    box(width: 4.6cm, text(size: 8pt, fill: amber.darken(10%), phrase(w.at-mean, (p: num(p1, digits: 3))))))

  // Ninety-five percent done.
  let x95 = calc.ln(20)
  line(at(x95, 0), at(x95, 0.05), stroke: (paint: green, thickness: 0.8pt, dash: "dashed"))
  circle(at(x95, 0.05), radius: 0.09, fill: green, stroke: white + 1pt)
  content((x95 * sx + 0.1, 0.05 * sy + 0.3), anchor: "south-west",
    box(width: 3.6cm, text(size: 8pt, fill: green.darken(10%), phrase(w.p95, (x: num(x95, digits: 1))))))

  // The formula.
  content((2.35 * sx, 0.78 * sy), anchor: "west",
    box(fill: white, inset: 4pt, radius: 3pt, stroke: 0.5pt + rule,
      $P(K > x dot E[K]) approx e^(-x)$))
})
