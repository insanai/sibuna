// Book Part III: the byte layout of the challenge identifier and the session token.
// Field widths grow with their size in bytes; the offsets above each record are exact.

#import "@preview/cetz:0.5.2"
#import "../style.typ": *

#show: figure-page
#let w = words("wire-formats")

// A field: its name, its size in bytes and its kind (header, payload or tag).
#let challenge = (
  ("ver", 1, "header"), ("alg", 1, "header"), ("diff", 1, "header"), ("t", 1, "header"),
  ("issued_at", 8, "payload"), ("fingerprint", 8, "payload"), ("nonce", 8, "payload"),
  ("rule_hash", 8, "payload"), ("tag", 16, "tag"),
)
#let session = (
  ("ver", 1, "header"), ("alg", 1, "header"), ("bits", 1, "header"), ("res", 5, "header"),
  ("timestamp", 8, "payload"), ("expiry", 8, "payload"), ("rule_hash", 8, "payload"),
  ("fingerprint", 8, "payload"), ("tag", 16, "tag"),
)

#let colours = (
  header: (faint, muted),
  payload: (blue-light, blue),
  tag: (amber-light, amber),
)

// The drawn width of a field of `bytes` bytes, in centimetres.
#let width(bytes) = 0.72 + bytes * 0.17

#let record(y, title, fields, characters) = {
  import cetz.draw: *
  let height = 0.78
  let total = fields.map(field => width(field.at(1))).sum()
  content((start-x(0, total), y + 1.4), anchor: start-anchor("south"),
    text(weight: "bold", title))
  let x = 0
  let offset = 0
  let payload-end = 0
  for (name, bytes, kind) in fields {
    let (paper, edge) = colours.at(kind)
    let dx = width(bytes)
    rect((x, y), (x + dx, y + height), fill: paper, stroke: 0.7pt + edge)
    // The tag is named in words; the other fields by their names in the code.
    let label = if kind == "tag" { text(size: 8pt, w.tag-field) } else {
      text(size: 8pt, code(name))
    }
    content((x + dx / 2, y + height / 2), label)
    content((x, y + height + 0.16), anchor: "south", text(size: 6.5pt, fill: muted, str(offset)))
    if kind != "tag" { payload-end = x + dx }
    x += dx
    offset += bytes
  }
  content((x, y + height + 0.16), anchor: "south", text(size: 6.5pt, fill: muted, str(offset)))
  let payload-bytes = offset - 16
  // Braces under the payload and the tag.
  let brace(from, to, label, paint) = {
    cetz.decorations.flat-brace((to, y - 0.1), (from, y - 0.1), amplitude: 0.22,
      stroke: 0.7pt + paint)
    content(((from + to) / 2, y - 0.42), anchor: "north", box(width: (to - from) * 1cm,
      align(center, text(size: 8pt, fill: paint.darken(10%), label))))
  }
  brace(0, payload-end, phrase(w.payload, (n: str(payload-bytes))), blue)
  brace(payload-end, x, phrase(w.tag, (n: "16")), amber)
  content((x, y - 1.05), anchor: "north-east", note(phrase(w.total,
    (bytes: str(offset), characters: str(characters)))))
}

#cetz.canvas(length: 1cm, {
  record(0, w.challenge, challenge, 70)
  record(-3.9, w.session, session, 75)
})
