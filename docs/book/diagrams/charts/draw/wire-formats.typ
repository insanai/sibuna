// cryptography.rst: the byte layout of the challenge identifier and the session token.
// Field widths grow with their size in bytes; the offsets above each record are exact.
// The header is context, the payload ordinary data, and the keyed tag, which only
// Sibuna can make, is the accent.

#import "../chart.typ": *

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

#let tone = (header: "quiet", payload: "step", tag: "accent")

// The drawn width of a field of `bytes` bytes, in centimetres.
#let width(bytes) = 0.6 + bytes * 0.157

#let record(w, y, title, fields, characters) = {
  import cetz.draw: *
  let height = 0.72
  let total = fields.map(field => width(field.at(1))).sum()
  let (title-x, title-anchor) = if is-rtl() { (total, "south-east") } else { (0, "south-west") }
  content((title-x, y + height + 0.55), anchor: title-anchor,
    text(size: 9.5pt, weight: "semibold", rich(title)))
  let offset-label(x, n) = content((x, y + height + 0.1), anchor: "south",
    text(size: 7pt, fill: quiet, str(n)))
  let x = 0
  let offset = 0
  let payload-end = 0
  for (name, bytes, kind) in fields {
    let (fill, edge) = tones.at(tone.at(kind))
    let dx = width(bytes)
    rect((x, y), (x + dx, y + height), fill: fill, stroke: thin + line-ink)
    // The tag is named in words; the other fields by their names in the code.
    let name-text = if kind == "tag" {
      text(size: 8pt, fill: green-deep, rich(w.tag-field))
    } else { text(size: 8pt, code(name)) }
    // Equal line boxes centre every name alike, with or without descenders.
    content((x + dx / 2, y + height / 2), {
      set text(top-edge: "ascender", bottom-edge: "descender")
      name-text
    })
    offset-label(x, offset)
    if kind != "tag" { payload-end = x + dx }
    x += dx
    offset += bytes
  }
  offset-label(x, offset)
  // Braces under the payload and the tag.
  let brace(from, to, body, paint) = {
    cetz.decorations.flat-brace((to, y - 0.08), (from, y - 0.08), amplitude: 0.18,
      stroke: thin + paint)
    content(((from + to) / 2, y - 0.36), anchor: "north", box(width: (to - from) * 1cm,
      align(center, text(size: 8pt, fill: paint, body))))
  }
  brace(0, payload-end, phrase(w.payload, (n: str(offset - 16))), ink)
  brace(payload-end, x, phrase(w.tag, (n: "16")), green-deep)
  let (end-x, end-anchor) = if is-rtl() { (0, "north-west") } else { (x, "north-east") }
  content((end-x, y - 0.95), anchor: end-anchor, small(phrase(w.total,
    (bytes: str(offset), characters: str(characters)))))
}

#let draw() = context {
  let w = words("wire-formats")
  cetz.canvas(length: 1cm, {
    record(w, 0, w.challenge, challenge, 70)
    record(w, -3.4, w.session, session, 75)
  })
}
