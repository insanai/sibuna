// Typst that guidedog puts after the #show: book line (pdf_preamble in conf.toml), so
// its definitions apply to every chapter. It draws admonitions as the boxes of the
// Sibuna book: guidedog writes each admonition as gd-admonition(kind, title, body).
#import "/_templates/sibuna.typ": sibuna-box
#let gd-admonition = sibuna-box
