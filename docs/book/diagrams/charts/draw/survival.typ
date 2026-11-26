// foundations.rst: the probability that a hash search is still running after x times its
// expected number of trials, in the large-work approximation P(K > x/p) ~ e^(-x).

#import "../chart.typ": *

#let draw() = context {
  let w = words("survival")
  cetz.canvas(length: 1cm, {
    import cetz.draw: *
    let (sx, sy) = (2.5, 4.2)
    let at(x, y) = (x * sx, y * sy)

    // Grid, axes and ticks.
    for y in (0.25, 0.5, 0.75, 1.0) { line(at(0, y), at(4, y), stroke: grid-stroke) }
    for x in (1, 2, 3, 4) { line(at(x, 0), at(x, 1.0), stroke: grid-stroke) }
    line(at(0, 0), at(4, 0), stroke: axis-stroke)
    line(at(0, 0), at(0, 1.0), stroke: axis-stroke)
    for x in range(0, 5) {
      line(at(x, 0), (x * sx, -0.08), stroke: axis-stroke)
      content((x * sx, -0.14), anchor: "north", tick(num(x)))
    }
    for y in (0, 0.25, 0.5, 0.75, 1.0) {
      line(at(0, y), (-0.08, y * sy), stroke: axis-stroke)
      content((-0.14, y * sy), anchor: "east", tick(num(y, digits: 2)))
    }
    content((2 * sx, -0.62), anchor: "north", annotate(w.x-axis))
    content((-1.2, 0.5 * sy), anchor: "south", angle: 90deg, annotate(w.y-axis))

    // The curve, named beside it by its formula.
    let curve = range(0, 161).map(i => at(i / 40, calc.exp(-i / 40)))
    line(..curve, stroke: bold + green)
    content(at(0.42, 0.72), anchor: "south-west",
      text(size: 8pt, fill: green-deep, $P(K > x dot E[K]) approx e^(-x)$))

    // At the mean: e^(-1).
    let p1 = calc.exp(-1)
    let guide = (paint: gold-deep, thickness: thin, dash: (2pt, 1.6pt))
    line(at(1, 0), at(1, p1), stroke: guide)
    line(at(0, p1), at(1, p1), stroke: guide)
    circle(at(1, p1), radius: 0.075, fill: gold-deep, stroke: 1pt + white)
    content((1 * sx + 0.2, p1 * sy + 0.12), anchor: "south-west", box(width: 4.6cm,
      annotate(phrase(w.at-mean, (p: num(p1, digits: 3))), kind: "wait")))

    // Ninety-five percent done.
    let x95 = calc.ln(20)
    line(at(x95, 0), at(x95, 0.05), stroke: guide)
    circle(at(x95, 0.05), radius: 0.075, fill: gold-deep, stroke: 1pt + white)
    content((x95 * sx - 0.1, 0.05 * sy + 0.25), anchor: "south", box(width: 3.4cm,
      align(center, annotate(phrase(w.p95, (x: num(x95, digits: 1))), kind: "wait"))))
  })
}
