// Typst that guidedog puts after the #show: book line (pdf_preamble in conf.toml), so
// its definitions apply to every chapter. It draws admonitions as the boxes of the
// Sibuna book: guidedog writes each admonition as gd-admonition(kind, title, body).
#import "/_templates/sibuna.typ": sibuna-box
#let gd-admonition = sibuna-box

// Graphviz names its faces Helvetica and Courier, which Typst does not have, so the text
// of a graph's SVG falls back to the font set here. Liberation Sans (Debian package
// fonts-liberation) has the widths Graphviz measured the labels with; the book's own font
// would leave gaps and look out of place. A run that names a Noto face keeps it.
#show image: set text(font: ("Liberation Sans",))
