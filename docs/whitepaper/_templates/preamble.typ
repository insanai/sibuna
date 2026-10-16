// Typst that guidedog puts after the #show: book line (pdf_preamble in conf.toml), so
// its definitions apply to the whole paper. It draws admonitions as the boxes of the
// whitepaper (guidedog writes each as gd-admonition(kind, title, body)) and the abstract
// topic as the abstract panel (gd-topic(title, body)), and it makes the metric cards
// available to the paper's raw Typst blocks.
#import "/_templates/whitepaper.typ": wp-box, wp-abstract, wp-metrics
#let gd-admonition = wp-box
#let gd-topic = wp-abstract
