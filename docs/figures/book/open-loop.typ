// Book Part VIII: one connection of the open-loop latency generator. Request k is due at
// k T. A request that falls due while the previous answer is outstanding goes out when
// that answer arrives, and its latency counts from the time it was due.

#import "@preview/cetz:0.5.2"
#import "../style.typ": *

#show: figure-page
#let w = words("open-loop")

// Each request: its due time, its send time and its answer time, in units of T.
#let requests = (
  (0, 0, 0.32),
  (1, 1, 2.55),
  (2, 2.55, 2.87),
  (3, 3, 3.32),
)

#with-notes(cetz.canvas(length: 1cm, {
  import cetz.draw: *
  let unit = 3.1
  let row = 0.95
  let left = 0
  let top = 0
  let x(t) = left + t * unit

  // Due times.
  for k in range(0, 5) {
    line((x(k), top + 0.35), (x(k), top - 4 * row - 0.1),
      stroke: (paint: rule, thickness: 0.6pt, dash: "dashed"))
    let label = if k == 0 { "0" } else if k == 1 { "T" } else { str(k) + "T" }
    content((x(k), top + 0.55), anchor: "south", text(size: 8pt, fill: muted, label))
  }
  content((x(0) - 0.25, top + 0.55), anchor: "south-east", note(w.due))

  for (k, (due, sent, answered)) in requests.enumerate() {
    let y = top - (k + 0.5) * row
    content((x(0) - 0.25, y), anchor: "east", text(size: 8pt, $k = #k$))
    // Waiting for the connection: due, but not yet sent.
    if sent > due {
      line((x(due), y), (x(sent), y), stroke: (paint: amber, thickness: 1.4pt, dash: "dotted"))
      circle((x(due), y), radius: 0.07, fill: white, stroke: 1pt + amber)
    }
    // In flight: from the send to the answer.
    rect((x(sent), y - 0.13), (x(answered), y + 0.13), radius: 0.06,
      fill: blue-mid, stroke: 0.7pt + blue)
    circle((x(sent), y), radius: 0.08, fill: blue, stroke: none)
    line((x(answered) - 0.02, y - 0.2), (x(answered) - 0.02, y + 0.2), stroke: 1.6pt + green)
    // The latency recorded for this request.
    let from = due
    line((x(from), y - 0.3), (x(answered), y - 0.3), stroke: 0.6pt + ink,
      mark: (start: "|", end: "|", width: 0.2, length: 0.01))
  }

  // The answer to request 1 releases request 2.
  line((x(2.55), top - 1.5 * row - 0.2), (x(2.55), top - 2.5 * row + 0.17),
    stroke: 0.6pt + muted, mark: (end: "stealth", fill: muted, scale: 0.6))

}),
  legend(
    (swatch-dot(blue), w.send),
    (box(width: 0.1cm, height: 0.32cm, fill: green, baseline: 0.05cm), w.answer),
    (swatch-line(amber, thickness: 1.4pt, dash: "dotted"), w.waiting),
  ),
  legend((box(width: 0.6cm, height: 0.2cm, baseline: 0.02cm, {
    place(horizon, line(length: 100%, stroke: 0.6pt + ink))
    place(line(start: (0pt, 0pt), end: (0pt, 100%), stroke: 0.6pt + ink))
    place(right, line(start: (0pt, 0pt), end: (0pt, 100%), stroke: 0.6pt + ink))
  }), w.latency)),
)
