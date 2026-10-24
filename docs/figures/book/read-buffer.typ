// Book Part V: the read buffer of one connection while a request is served. Every field
// of the request is a slice of the buffer; consuming the request moves the window on.

#import "@preview/cetz:0.5.2"
#import "../style.typ": *

#show: figure-page
#let w = words("read-buffer")

#cetz.canvas(length: 1cm, {
  import cetz.draw: *
  let height = 1.5
  // Segment boundaries, in centimetres from the start of the buffer.
  let (start, head, body, pending, end) = (0, 1.4, 5.7, 10.6, 13.8)
  let last = 15.8
  let segment(from, to, y, paper, edge, body-text) = {
    rect((from, y), (to, y + height), fill: paper, stroke: 0.8pt + edge)
    content(((from + to) / 2, y + height / 2), box(width: (to - from - 0.2) * 1cm,
      align(center, body-text)))
  }
  let served(from, to, y) = {
    rect((from, y), (to, y + height), fill: faint, stroke: 0.8pt + rule)
    for i in range(0, int((to - from) / 0.25)) {
      let x = from + i * 0.25
      line((x, y), (calc.min(x + height, to), y + calc.min(height, to - x)),
        stroke: 0.4pt + rule)
    }
    content(((from + to) / 2, y + height / 2), box(fill: faint, inset: 2pt, note(w.served)))
  }
  let title(body-text, words) = text(size: 8.5pt, weight: "bold", body-text) + linebreak() + note(words)

  // The buffer while the request is served.
  served(start, head, 0)
  segment(head, body, 0, blue-light, blue, title(w.head, w.head-note))
  segment(body, pending, 0, green-light, green, title(w.body, w.body-note))
  segment(pending, end, 0, amber-light, amber, title(w.pending, w.pending-note))
  rect((end, 0), (last, height), fill: white, stroke: (paint: rule, dash: "dashed"))
  content(((end + last) / 2, height / 2), note(w.free))

  // The unread window above.
  cetz.decorations.flat-brace((head, height + 0.12), (end, height + 0.12), amplitude: 0.24,
    stroke: 0.7pt + ink)
  content(((head + end) / 2, height + 0.5), anchor: "south",
    text(size: 8pt, [#code("reader.buffered()") #w.window]))
  content((start-x(0, last), height + 1.15), anchor: start-anchor("south"),
    text(weight: "bold", w.buffer))

  // Lengths below.
  let span(from, to, y, label) = {
    line((from, y), (to, y), stroke: 0.6pt + ink, mark: (start: "|", end: "|", width: 0.22,
      length: 0.01))
    content(((from + to) / 2, y - 0.08), anchor: "north", code(label))
  }
  span(head, body, -0.3, "head_len")
  span(body, pending, -0.3, "body_len")

  // What points into the buffer.
  let pointer(x, label, paint) = {
    line((x, -1.25), (x, -0.02), stroke: 0.7pt + paint,
      mark: (end: "stealth", fill: paint, scale: 0.7))
    content((x - 0.1, -1.35), anchor: "north-west", box(width: 4.0cm, text(size: 7.5pt,
      fill: paint.darken(15%), label)))
  }
  pointer(head + 0.35, w.fields, blue)
  pointer(body + 0.35, [#code("request.body")], green)
  pointer(pending + 0.35, [#code("ctx.pending") \ #w.pending-proxy], amber)

  // After the response.
  let y2 = -4.9
  content((0, y2 + height + 0.65), anchor: "south-west",
    text(size: 8.5pt, [#w.after #code("reader.consume(head_len + body_len)")]))
  served(start, pending, y2)
  segment(pending, end, y2, amber-light, amber, title(w.pending, w.next))
  rect((end, y2), (last, y2 + height), fill: white, stroke: (paint: rule, dash: "dashed"))
  content(((end + last) / 2, y2 + height / 2), note(w.free))
  line((head, y2 + height + 0.25), (pending, y2 + height + 0.25), stroke: 0.8pt + muted,
    mark: (end: "stealth", fill: muted, scale: 0.7))
  line((head, y2 + height + 0.1), (head, y2 + height + 0.4), stroke: 0.8pt + muted)
})
