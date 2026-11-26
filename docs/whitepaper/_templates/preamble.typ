// Typst that guidedog puts after the #show: book line (pdf_preamble in conf.toml), so
// its definitions apply to the whole paper. It draws admonitions as the boxes of the
// whitepaper (guidedog writes each as gd-admonition(kind, title, body)) and the abstract
// topic as the abstract panel (gd-topic(title, body)), and it makes the metric cards
// available to the paper's raw Typst blocks.
#import "/_templates/whitepaper.typ": wp-box, wp-abstract, wp-metrics
#let gd-admonition = wp-box
#let gd-topic = wp-abstract

// Graphviz names its faces Helvetica and Courier, which Typst does not have, so the text
// of a graph's SVG falls back to the font set here. Liberation Sans (Debian package
// fonts-liberation) has the widths Graphviz measured the labels with; the paper's own font
// would leave gaps and look out of place. A run that names a Noto face keeps it.
#show image: set text(font: ("Liberation Sans",))
