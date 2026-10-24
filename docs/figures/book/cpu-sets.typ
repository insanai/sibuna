// Book Part VIII: the CPU sets of the recorded runs on the AMD Ryzen 9 5950X. CPUs 0 to 7
// are the cores of the first CCD and 8 to 15 those of the second; CPU n + 16 is the SMT
// sibling of CPU n.

#import "@preview/cetz:0.5.2"
#import "../style.typ": *

#show: figure-page
#let w = words("cpu-sets")

// The role of each core, by core number.
#let role(n) = if n < 4 { "daemon" } else if n == 4 { "primitive" } else if n < 8 {
  "idle"
} else { "load" }

#let paints = (
  daemon: (blue-mid, blue),
  primitive: (amber-mid, amber),
  load: (green-mid, green),
  idle: (faint, muted),
)

#cetz.canvas(length: 1cm, {
  import cetz.draw: *
  let size = 1.15
  let gap = 0.2
  let step = size + gap
  let x(n) = calc.rem(n, 8) * step
  // The second CCD sits below the first.
  let y(n) = if n >= 8 { -3.75 } else { 0 }

  // The two chiplets.
  for (i, title) in (w.ccd0, w.ccd1).enumerate() {
    let (x0, y0) = (x(i * 8) - 0.22, y(i * 8))
    rect((x0, y0 - 0.22), (x0 + 8 * step - gap + 0.44, y0 + size + 0.22), radius: 0.15,
      fill: none, stroke: (paint: rule, thickness: 0.8pt))
    content((x0 + 0.05, y0 + size + 0.35), anchor: "south-west",
      text(size: 8pt, weight: "semibold", fill: muted, title))
  }

  for n in range(0, 16) {
    let (paper, edge) = paints.at(role(n))
    let (cx, cy) = (x(n), y(n))
    rect((cx, cy), (cx + size, cy + size), radius: 0.12, fill: paper, stroke: 0.8pt + edge)
    content((cx + size / 2, cy + size * 0.6),
      text(size: 10pt, weight: "bold", fill: edge.darken(15%), str(n)))
    content((cx + size / 2, cy + size * 0.22), text(size: 6.5pt, fill: muted, str(n + 16)))
  }

  // Brackets naming each set, with its option.
  let bracket(from, to, label, option, paint) = {
    let (a, b, top) = (x(from), x(to) + size, y(from) - 0.4)
    line((a, top), (a, top - 0.12), (b, top - 0.12), (b, top), stroke: 0.8pt + paint)
    content(((a + b) / 2, top - 0.28), anchor: "north", box(width: calc.max(b - a + 0.3, 2.0) * 1cm,
      align(center, text(size: 8pt, fill: paint.darken(10%), label) + linebreak()
        + text(size: 7pt, fill: paint.darken(10%), code(option)))))
  }
  bracket(0, 3, w.daemons, "--cpus 0-3", blue)
  bracket(4, 4, w.primitive, "--cpu 4", amber)
  bracket(5, 7, w.idle, "", muted)
  bracket(8, 15, w.load, "--load-cpus 8-15", green)

  content((-0.22, y(8) - 1.75), anchor: "north-west", box(width: 8 * step * 1cm, note(w.smt)))
})
