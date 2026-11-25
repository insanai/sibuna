#import "style.typ": *
#show: sheet.with(lang: "en")

#diagram(
  spacing: (18mm, 5mm),
  tile((0, 1), "Browser"), tile((1, 1), "Sibuna", fill: tint, stroke: blue),
  tile((2, 0), "Origin A"), tile((2, 2), "Origin B"),
  edge((0, 1), (1, 1), [HTTPS], "->"),
  edge((1, 1), (2, 0), [HTTP/1.1], "->"),
  edge((1, 1), (2, 2), [HTTP/1.1], "->"),
)
