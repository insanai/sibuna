#let configure-document() = {
  set page(margin: (x: 1.1in, y: 1in))
  set text(font: "Libertinus Serif", size: 11pt)
  set heading(numbering: "1.1")
  set par(justify: true, leading: 0.7em)
}

#let document-frontmatter(title, subtitle: none, authors: ()) = [
  #align(center)[
    #text(26pt, weight: "bold")[#title]\
    #if subtitle != none [
      #v(0.5em)
      #text(13pt, fill: rgb("4b5563"))[#subtitle]\
    ]
    #if authors.len() > 0 [
      #v(1.2em)
      #authors.join(" • ")
    ]
  ]

  #pagebreak()
  #outline()
  #pagebreak()
]
