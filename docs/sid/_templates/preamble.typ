// Typst that guidedog puts after the #show: book line (pdf_preamble in conf.toml), so
// its definitions apply to every record. It draws admonitions as the callouts of the
// original SID records: guidedog writes each as gd-admonition(kind, title, body).
#import "/_templates/sibuna.typ": sid-callout
#let gd-admonition = sid-callout
