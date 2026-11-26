// Typst that guidedog puts after the #show: book line (pdf_preamble in conf.toml), so
// its definitions apply to every record. It draws admonitions as the callouts of the
// original SID records: guidedog writes each as gd-admonition(kind, title, body).
#import "/_templates/sibuna.typ": sid-callout
#let gd-admonition = sid-callout

// Graphviz names its faces Helvetica and Courier, which Typst does not have, so the text
// of a graph's SVG falls back to the font set here. Liberation Sans (Debian package
// fonts-liberation) has the widths Graphviz measured the labels with; the book's own font
// would leave gaps and look out of place. A run that names a Noto face keeps it.
#show image: set text(font: ("Liberation Sans",))
