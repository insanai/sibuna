#import "../shared/shd.typ": shd-site-index
#import "registry.typ": shd-documents

#document(
  "index.html",
  title: [Shibuna Discussions],
  author: ("Sibuna Contributors",),
  description: [Index of Shibuna Discussion records.],
)[
  #shd-site-index(shd-documents)
]

#document(
  "shd/0001-shd-process.html",
  title: [SHD 0001: The Shibuna Discussion Process and Engineering Standards],
  author: ("Sibuna Contributors",),
  description: [SHD process, TigerStyle engineering standards, structural code limits, and Elm-style diagnostic reporting.],
)[
  #include "records/0001-shd-process.typ"
]

#document(
  "shd/0002-sibuna-foundation-architecture.html",
  title: [SHD 0002: Sibuna: Foundation Architecture, Delivery Plan, and Performance Contract],
  author: ("Sibuna Contributors",),
  description: [Foundation architecture, Anubis comparative analysis, zero-allocation pipeline, and delivery plan.],
)[
  #include "records/0002-sibuna-foundation-architecture.typ"
]

#document("pdf/shd-0001-shd-process.pdf")[
  #include "records/0001-shd-process.typ"
]

#document("pdf/shd-0002-sibuna-foundation-architecture.pdf")[
  #include "records/0002-sibuna-foundation-architecture.typ"
]

#document(
  "shd/0003-declarative-policy-engine.html",
  title: [SHD 0003: Title Goes Here],
  author: ("Sibuna Contributors",),
  description: [Draft discussion note],
)[
  #include "records/0003-declarative-policy-engine.typ"
]

#document("pdf/shd-0003-declarative-policy-engine.pdf")[
  #include "records/0003-declarative-policy-engine.typ"
]
