// benchmarks.rst: one connection of the open-loop latency generator. Request k is due
// at k T. A request that falls due while the previous answer is outstanding goes out
// when that answer arrives, and its latency counts from the time it was due.

#import "../chart.typ": *

// Each request: its due time, its send time and its answer time, in units of T.
#let requests = (
  (0, 0, 0.32),
  (1, 1, 2.55),
  (2, 2.55, 2.87),
  (3, 3, 3.32),
)

#let plot(w) = cetz.canvas(length: 1cm, {
  import cetz.draw: *
  let unit = 3.0
  let row = 1.25
  let x(t) = t * unit
  let bottom = -4 * row

  // Due times.
  for k in range(0, 5) {
    line((x(k), 0.25), (x(k), bottom), stroke: grid-stroke)
    let name = if k == 0 { "0" } else if k == 1 { "T" } else { str(k) + "T" }
    content((x(k), 0.32), anchor: "south", tick(latin(name)))
  }
  content((x(0) - 0.3, 0.32), anchor: "south-east", group-title(w.due))

  let (other, other-soft) = series.other
  let (wait, _) = series.wait
  for (k, (due, sent, answered)) in requests.enumerate() {
    let y = -(k + 0.4) * row
    content((x(0) - 0.3, y), anchor: "east", tick(latin("k = " + str(k))))
    // Due, but waiting for the connection: a dotted gold line from an open dot.
    if sent > due {
      line((x(due), y), (x(sent), y), stroke: (paint: wait, thickness: bold,
        dash: "dotted"))
      circle((x(due), y), radius: 0.07, fill: white, stroke: thin + wait)
      content((x(due) - 0.15, y), anchor: "east", annotate(w.waiting, kind: "wait"))
    }
    // In flight: from the send to the answer.
    rect((x(sent), y - 0.11), (x(answered), y + 0.11), radius: 0.05, fill: other-soft,
      stroke: thin + other)
    // The latency the generator records: a green bracket below.
    let ly = y - 0.3
    line((x(due), ly + 0.07), (x(due), ly), (x(answered), ly), (x(answered), ly + 0.07),
      stroke: bold + green)
  }

  // Direct labels on the long request 1.
  let y1 = -1.4 * row
  content((x(1.78), y1 + 0.15), anchor: "south", annotate(w.in-flight, kind: "other"))
  content((x(1.6), y1 - 0.38), anchor: "north", annotate(w.recorded, kind: "sibuna"))
  // The answer to request 1 releases request 2.
  line((x(2.55), y1 - 0.12), (x(2.55), -2.4 * row + 0.13), stroke: thin + line-ink,
    mark: (end: "stealth", fill: line-ink, scale: 0.55))
  content((x(2.55) + 0.12, -1.9 * row), anchor: "west", annotate(w.released))
})

#let draw() = context {
  let w = words("open-loop")
  with-notes(plot(w), w.latency)
}
