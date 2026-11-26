// zero-allocation.rst: the read buffer of one connection while a request is served.
// Every field of the request is a slice of the buffer; consuming the request moves the
// window on. The request being served is the accent; the pending bytes wait (gold).

#import "../chart.typ": *

#let height = 1.95
// Segment boundaries, in centimetres from the start of the buffer.
#let (start, head, body, pending, end, last) = (0, 1.2, 5.3, 9.8, 12.7, 14.2)

// A segment of the buffer in the tone `kind`, with a title and a quiet second line.
#let segment(from, to, y, kind, title, detail) = {
  import cetz.draw: *
  let (fill, edge) = tones.at(kind)
  rect((from, y), (to, y + height), fill: fill, stroke: thin + edge)
  content(((from + to) / 2, y + height / 2), box(width: (to - from - 0.2) * 1cm,
    align(center, text(size: 9.5pt, weight: "semibold", rich(title)) + linebreak()
      + small(detail))))
}

// The bytes already served, hatched.
#let served(from, to, y, name) = {
  import cetz.draw: *
  rect((from, y), (to, y + height), fill: paper, stroke: thin + rule)
  for i in range(0, int((to - from) / 0.25)) {
    let x = from + i * 0.25
    line((x, y), (calc.min(x + height, to), y + calc.min(height, to - x)),
      stroke: 0.4pt + rule)
  }
  // The name wraps inside the segment, on a plate that hides the hatching.
  content(((from + to) / 2, y + height / 2), box(fill: paper, inset: 2pt,
    box(width: calc.min(measure(small(name)).width, (to - from - 0.2) * 1cm),
      align(center, small(name)))))
}

// The free end of the buffer.
#let free(y, name) = {
  import cetz.draw: *
  rect((end, y), (last, y + height), fill: white, stroke: (paint: rule, thickness: thin,
    dash: (3pt, 2pt)))
  content(((end + last) / 2, y + height / 2), small(name))
}

// An arrow from a label below up to the byte it points at.
#let pointer(x, body, paint) = {
  import cetz.draw: *
  line((x, -1.15), (x, -0.03), stroke: thin + paint,
    mark: (end: "stealth", fill: paint, scale: 0.55))
  content((x - 0.1, -1.22), anchor: "north-west", box(width: 3.9cm, text(size: 8pt,
    fill: paint, body)))
}

#let plot(w) = cetz.canvas(length: 1cm, {
  import cetz.draw: *
  let accent-ink = green-deep
  let wait-ink = gold-deep.darken(10%)

  // The buffer while the request is served.
  served(start, head, 0, w.served)
  segment(head, body, 0, "accent", w.head, w.head-note)
  segment(body, pending, 0, "accent", w.body, w.body-note)
  segment(pending, end, 0, "wait", w.pending, w.pending-note)
  free(0, w.free)

  // The unread window above, and the title.
  cetz.decorations.flat-brace((head, height + 0.1), (end, height + 0.1), amplitude: 0.2,
    stroke: thin + ink)
  content(((head + end) / 2, height + 0.42), anchor: "south",
    text(size: 8pt, [#code("reader.buffered()") #rich(w.window)]))
  // A title stands at the start of the line: the right end in right-to-left text.
  let (title-x, title-anchor) = if is-rtl() { (last, "south-east") } else { (0, "south-west") }
  content((title-x, height + 1.05), anchor: title-anchor,
    text(size: 9.5pt, weight: "semibold", rich(w.buffer)))

  // Lengths below.
  let span(from, to, name) = {
    line((from, -0.28), (to, -0.28), stroke: thin + ink, mark: (start: "|", end: "|",
      width: 0.2, length: 0.01))
    content(((from + to) / 2, -0.34), anchor: "north", text(size: 8pt, code(name)))
  }
  span(head, body, "head_len")
  span(body, pending, "body_len")

  // What points into the buffer.
  pointer(head + 0.3, rich(w.fields), accent-ink)
  pointer(body + 0.3, code("request.body"), accent-ink)
  pointer(pending + 0.3, code("ctx.pending") + linebreak() + rich(w.pending-proxy),
    wait-ink)

  // After the response.
  let y2 = -5.3
  content((title-x, y2 + height + 0.62), anchor: title-anchor,
    text(size: 8pt, [#rich(w.after) #code("reader.consume(head_len + body_len)")]))
  served(start, pending, y2, w.served)
  segment(pending, end, y2, "wait", w.pending, w.next)
  free(y2, w.free)
  line((head, y2 + height + 0.22), (pending, y2 + height + 0.22), stroke: thin + line-ink,
    mark: (end: "stealth", fill: line-ink, scale: 0.55))
  line((head, y2 + height + 0.1), (head, y2 + height + 0.34), stroke: thin + line-ink)
})

#let draw() = context plot(words("read-buffer"))
