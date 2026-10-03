// Positioned diagrams need the PDF layout engine during HTML export.
// Keep captions as semantic HTML while embedding the artwork as inline SVG.
#let preserve-figures(body) = {
  show figure: it => html.elem("figure")[
    #html.frame(it.body)
    #it.caption
  ]
  body
}
