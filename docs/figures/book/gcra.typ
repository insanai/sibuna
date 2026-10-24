// Book Part V: GCRA admission for a limit of 5 per second (T = 200 ms, tau = 800 ms). A
// client sends six requests at t = 0, then one request halfway between admissions and one
// exactly at every multiple of 200 ms. An arrival conforms when TAT <= t + tau.

#import "@preview/cetz:0.5.2"
#import "../style.typ": *

#show: figure-page
#let w = words("gcra")

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

#with-notes(cetz.canvas(length: 1cm, {
  import cetz.draw: *
  let sx = 0.0115
  let sy = 0.0022
  let p(t, v) = (t * sx, v * sy)
  let (t-max, v-max) = (1100, 2100)

  // Grid and axes of the TAT panel.
  for v in range(0, 2001, step: 500) {
    line(p(0, v), p(t-max, v), stroke: 0.4pt + faint.darken(6%))
    content((-0.15, v * sy), anchor: "east", small(num(v)))
  }
  for t in range(0, 1001, step: 200) {
    line(p(t, 0), p(t, v-max), stroke: 0.4pt + faint.darken(6%))
    content((t * sx, -0.3), small(num(t)))
  }
  line(p(0, 0), p(t-max, 0), stroke: 0.7pt + muted, mark: (end: "stealth", fill: muted))
  line(p(0, 0), p(0, v-max), stroke: 0.7pt + muted, mark: (end: "stealth", fill: muted))
  content((t-max * sx / 2, -0.75), w.x-axis)
  content((-1.25, v-max * sy / 2), angle: 90deg, w.y-axis)

  // Where TAT > t + tau, an arrival is refused.
  line(p(0, tolerance), p(t-max, tolerance + t-max), p(0, tolerance + t-max), close: true,
    fill: red-light, stroke: none)
  line(p(0, tolerance), p(t-max, tolerance + t-max),
    stroke: (paint: red, thickness: 1pt, dash: "dashed"))
  content(p(t-max - 5, tolerance + t-max - 120), anchor: "north-east",
    text(size: 8pt, fill: red.darken(10%), w.limit))
  content(p(60, 1950), anchor: "north-west", text(size: 8pt, fill: red.darken(10%), w.refuse-zone))

  // TAT after each arrival: a staircase.
  let points = (p(0, 0),)
  let tat = 0
  for a in arrivals {
    points.push(p(a.t, tat))
    tat = a.after
    points.push(p(a.t, tat))
  }
  points.push(p(t-max, tat))
  line(..points, stroke: 1.6pt + blue)

  // Each arrival at the TAT it found.
  for a in arrivals {
    let at = p(a.t, a.seen)
    if a.admitted {
      circle(at, radius: 0.085, fill: green, stroke: white + 0.8pt)
    } else {
      let r = 0.09
      line((at.at(0) - r, at.at(1) - r), (at.at(0) + r, at.at(1) + r), stroke: 1.4pt + red)
      line((at.at(0) - r, at.at(1) + r), (at.at(0) + r, at.at(1) - r), stroke: 1.4pt + red)
    }
  }
  content(p(25, 400), anchor: "west", text(size: 8pt, fill: green.darken(10%), w.burst))
  content(p(20, 1080), anchor: "south-west", text(size: 8pt, fill: red.darken(10%), w.sixth))
  content(p(215, 940), anchor: "north-west",
    box(width: 4.2cm, text(size: 7.5pt, fill: ink, phrase(w.example, (refused: num(100),
      admitted: num(200), tat: num(1000), early: num(900), limit: num(1000))))))

}),
  legend(
    (swatch-dot(green), w.admitted),
    (swatch-cross(red), w.refused),
    (swatch-line(blue), w.tat),
  ),
)
