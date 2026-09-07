#import "../shared/sid.typ": sid-site-index
#import "registry.typ": sid-documents

#document(
  "index.html",
  title: [Shibuna Discussions],
  author: ("Sibuna Contributors",),
  description: [Index of Shibuna Discussion records.],
)[
  #sid-site-index(sid-documents)
]

#document(
  "sid/0001-sid-process.html",
  title: [SID 0001: The Shibuna Discussion Process and Engineering Standards],
  author: ("Sibuna Contributors",),
  description: [SID process, TigerStyle engineering standards, structural code limits, and Elm-style diagnostic reporting.],
)[
  #include "records/0001-sid-process.typ"
]

#document(
  "sid/0002-sibuna-foundation-architecture.html",
  title: [SID 0002: Sibuna: Foundation Architecture, Delivery Plan, and Performance Contract],
  author: ("Sibuna Contributors",),
  description: [Foundation architecture, Anubis comparative analysis, zero-allocation pipeline, and delivery plan.],
)[
  #include "records/0002-sibuna-foundation-architecture.typ"
]

#document("pdf/sid-0001-sid-process.pdf")[
  #include "records/0001-sid-process.typ"
]

#document("pdf/sid-0002-sibuna-foundation-architecture.pdf")[
  #include "records/0002-sibuna-foundation-architecture.typ"
]

#document(
  "sid/0003-declarative-policy-engine.html",
  title: [SID 0003: Title Goes Here],
  author: ("Sibuna Contributors",),
  description: [Draft discussion note],
)[
  #include "records/0003-declarative-policy-engine.typ"
]

#document("pdf/sid-0003-declarative-policy-engine.pdf")[
  #include "records/0003-declarative-policy-engine.typ"
]
