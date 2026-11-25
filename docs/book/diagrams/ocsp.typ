#import "style.typ": *
#show: sheet.with(lang: "en")

#let action(pos, label) = tile(pos, block(width: 39mm, align(center, label)))
#diagram(
  spacing: (13mm, 5mm),
  tile((0, 1), "OCSP response", fill: tint, stroke: blue),
  tile((1, 0), "Good"), tile((1, 1), "Revoked"), tile((1, 2), "Failure"),
  action((2, 0), "Staple and refresh at half-life"),
  action((2, 1), "Omit staple and renew certificate"),
  action((2, 2), "Serve without staple and retry"),
  ..range(3).map(i => edge((0, 1), (1, i), "->")),
  ..range(3).map(i => edge((1, i), (2, i), "->")),
)
