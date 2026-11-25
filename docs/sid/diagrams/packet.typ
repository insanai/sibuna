// Offsets are byte positions from the start of the datagram. The body varies in length.
#let packet(fields) = {
  set text(font: "Noto Sans", size: 9pt, fill: rgb("#172033"))
  table(
    columns: (auto, auto, auto), inset: (x: 7pt, y: 3pt),
    stroke: (x: none, y: 0.45pt + rgb("#cbd5e1")),
    fill: (x, y) => if y == 0 { rgb("#dbeafe") } else if calc.odd(y) { rgb("#f8fafc") },
    table.header([*Offset*], [*Bytes*], [*Field*]),
    ..fields.flatten(),
  )
}
