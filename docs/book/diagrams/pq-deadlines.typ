#import "style.typ": *
#show: figure-frame.with(lang: "en")

#let year(s) = text(weight: "bold", size: 9pt, fill: green-deep, s)
#let mark(s) = table.cell(fill: pale, text(size: 8pt, fill: green-deep, s))
#let region(s) = text(size: 8pt, weight: "semibold", s)
#table(
  columns: (24mm, 20mm, 20mm, 22mm, 24mm, 24mm),
  stroke: (x, y) => (bottom: 0.6pt + rule),
  align: left + horizon, inset: 4pt,
  [], year("2026"), year("2027"), year("2030"), year("2031"), year("2035"),
  region("US federal"), [], [], mark("Key exchange"), mark("Signatures"), [],
  region("EU roadmap"), mark("Start"), [], mark("High risk"), [], mark("Medium risk"),
  region("Singapore"), [], mark("Plans"), [], mark("CII migration"), mark("Other exposed organisations"),
)
