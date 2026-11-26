// benchmarks.rst: the CPU sets of the recorded runs on the AMD Ryzen 9 5950X. CPUs 0 to
// 7 are the cores of the first CCD and 8 to 15 those of the second; CPU n + 16 is the
// SMT sibling of CPU n.

#import "../chart.typ": *

// The role of each core, by core number.
#let role(n) = if n < 4 { "daemon" } else if n == 4 { "primitive" } else if n < 8 {
  "idle"
} else { "load" }

// The tone of each role: the daemons are Sibuna, the primitive suite an ordinary step,
// the load generators a party outside Sibuna, and an idle core context.
#let tone = (daemon: "accent", primitive: "step", load: "party", idle: "quiet")

#let plot(w) = cetz.canvas(length: 1cm, {
  import cetz.draw: *
  let size = 1.0
  let gap = 0.18
  let step = size + gap
  let x(n) = calc.rem(n, 8) * step
  // The second CCD sits below the first.
  let y(n) = if n >= 8 { -3.3 } else { 0 }

  // The two chiplets.
  for (i, title) in (w.ccd0, w.ccd1).enumerate() {
    let (x0, y0) = (x(i * 8) - 0.18, y(i * 8))
    rect((x0, y0 - 0.18), (x0 + 8 * step - gap + 0.36, y0 + size + 0.18), radius: 0.12,
      fill: none, stroke: thin + rule)
    content((x0 + 0.04, y0 + size + 0.26), anchor: "south-west", group-title(title))
  }

  for n in range(0, 16) {
    let (fill, edge) = tones.at(tone.at(role(n)))
    let (cx, cy) = (x(n), y(n))
    let idle = role(n) == "idle"
    rect((cx, cy), (cx + size, cy + size), radius: 0.1, fill: fill,
      stroke: if idle { (paint: line-ink, thickness: thin, dash: (2pt, 1.5pt)) }
        else { thin + edge })
    let number = if idle { quiet } else { edge.darken(25%) }
    content((cx + size / 2, cy + size * 0.6),
      text(size: 9.5pt, weight: "semibold", fill: number, str(n)))
    content((cx + size / 2, cy + size * 0.24), text(size: 7pt, fill: quiet, str(n + 16)))
  }

  // Brackets naming each set, with its option.
  let bracket(from, to, name, option, kind) = {
    let paint = if kind == "quiet" { quiet } else { tones.at(kind).at(1).darken(15%) }
    let (a, b, top) = (x(from), x(to) + size, y(from) - 0.32)
    line((a, top), (a, top - 0.1), (b, top - 0.1), (b, top), stroke: thin + paint)
    let body = text(size: 8pt, fill: paint, rich(name))
    if option != none { body += linebreak() + text(size: 8pt, fill: paint, code(option)) }
    content(((a + b) / 2, top - 0.2), anchor: "north",
      box(width: calc.max(b - a + 0.3, 2.2) * 1cm, align(center, body)))
  }
  bracket(0, 3, w.daemons, "--cpus 0-3", "accent")
  bracket(4, 4, w.primitive, "--cpu 4", "step")
  bracket(5, 7, w.idle, none, "quiet")
  bracket(8, 15, w.load, "--load-cpus 8-15", "party")
})

#let draw() = context {
  let w = words("cpu-sets")
  with-notes(plot(w), w.smt)
}
