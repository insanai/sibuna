// zero-allocation.rst: GCRA admission for a limit of 5 per second (T = 200 ms,
// tau = 800 ms). A client sends six requests at t = 0, then one request halfway between
// admissions and one exactly at every multiple of 200 ms. An arrival conforms when
// TAT <= t + tau.

#import "../chart.typ": *

#let (period, tolerance) = (200, 800)

// The arrivals, in milliseconds, with the TAT each one finds and whether it conforms.
#let arrivals = {
  let out = ()
  let tat = 0
  let times = (0, 0, 0, 0, 0, 0)
  for k in range(1, 6) { times += (k * period - period / 2, k * period) }
  for t in times {
    let found = tat
    let admitted = found <= t + tolerance
    if admitted { tat = calc.max(found, t) + period }
    out.push((t: t, seen: found, admitted: admitted, after: tat))
  }
  out
}

// A cross centred at `at`, the mark of a refused arrival.
#let cross(at, r: 0.085) = {
  import cetz.draw: *
  let (x, y) = at
  let stroke = 1.3pt + clay
  line((x - r, y - r), (x + r, y + r), stroke: stroke)
  line((x - r, y + r), (x + r, y - r), stroke: stroke)
}

#let plot(w) = cetz.canvas(length: 1cm, {
  import cetz.draw: *
  let (sx, sy) = (0.0106, 0.0022)
  let p(t, v) = (t * sx, v * sy)
  let (t-max, v-max) = (1100, 2100)

  // Where TAT > t + tau, an arrival is refused.
  line(p(0, tolerance), p(t-max, tolerance + t-max), p(t-max, v-max), p(0, v-max),
    close: true, fill: clay-soft, stroke: none)

  // Grid, axes and ticks.
  for v in range(0, 2001, step: 500) {
    line(p(0, v), p(t-max, v), stroke: grid-stroke)
    content((-0.14, v * sy), anchor: "east", tick(num(v)))
  }
  for t in range(0, 1001, step: 200) {
    line(p(t, 0), p(t, v-max), stroke: grid-stroke)
    content((t * sx, -0.14), anchor: "north", tick(num(t)))
  }
  line(p(0, 0), p(t-max, 0), stroke: axis-stroke)
  line(p(0, 0), p(0, v-max), stroke: axis-stroke)
  content((t-max * sx / 2, -0.6), anchor: "north", annotate(w.x-axis))
  content((-1.15, v-max * sy / 2), anchor: "south", angle: 90deg, annotate(w.y-axis))

  // The limit t + tau.
  line(p(0, tolerance), p(t-max, tolerance + t-max),
    stroke: (paint: clay, thickness: thin, dash: (3pt, 2pt)))
  content(p(t-max - 10, tolerance + t-max - 70), anchor: "north-east",
    annotate(w.limit, kind: "refused"))
  content(p(25, 2060), anchor: "north-west", annotate(w.refuse-zone, kind: "refused"))

  // TAT after each arrival: a staircase.
  let points = (p(0, 0),)
  let tat = 0
  for a in arrivals {
    points.push(p(a.t, tat))
    tat = a.after
    points.push(p(a.t, tat))
  }
  points.push(p(t-max, tat))
  line(..points, stroke: bold + green)
  content(p(990, 2010), anchor: "north-east", annotate(w.tat, kind: "sibuna"))

  // Each arrival at the TAT it found: a dot if admitted, a cross if refused.
  for a in arrivals {
    if a.admitted {
      circle(p(a.t, a.seen), radius: 0.075, fill: green, stroke: 1pt + white)
    } else {
      cross(p(a.t, a.seen))
    }
  }
  content(p(25, 400), anchor: "west", annotate(w.burst, kind: "sibuna"))
  content(p(30, 1480), anchor: "west", annotate(w.sixth, kind: "refused"))
  line(p(28, 1430), p(8, 1070), stroke: 0.5pt + clay)
  content(p(500, 1460), anchor: "south", annotate(w.refused, kind: "refused"))
  content(p(815, 1540), anchor: "north-west", annotate(w.admitted, kind: "sibuna"))
})

#let draw() = context {
  let w = words("gcra")
  with-notes(plot(w), phrase(w.example, (refused: num(100), admitted: num(200),
    tat: num(1000), early: num(900), limit: num(1000))))
}
