#set page(width: auto, height: auto, margin: 6pt, fill: white)
#set text(size: 10pt, fill: rgb("#20352f"))
#table(
  columns: (auto, auto, auto),
  align: left,
  inset: (x: 10pt, y: 6pt),
  stroke: none,
  fill: (_, y) => if y == 0 { rgb("#caddce") } else if calc.odd(y) { rgb("#f0f4ee") },
  table.header([*frontend*], [*backend*], [*HTTP*]),
  [`X25519MLKEM768`], [`X25519MLKEM768`], [`200`],
  [`X25519MLKEM768`], [`X25519`], [`200`],
  [`X25519MLKEM768`], [`sni != origin.example.test`], [`502`],
)
