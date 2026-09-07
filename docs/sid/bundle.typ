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

#document(
  "sid/0004-safeline-waf-parity-semantic-inspection.html",
  title: [SID 0004: SafeLine WAF & Anubis Parity: Semantic Attack Inspection and Sliding-Window Rate Limiter],
  author: ("Sibuna Contributors",),
  description: [SafeLine WAF semantic attack inspection parity and lock-striped sliding-window rate limiting.],
)[
  #include "records/0004-safeline-waf-parity-semantic-inspection.typ"
]

#document("pdf/sid-0004-safeline-waf-parity-semantic-inspection.pdf")[
  #include "records/0004-safeline-waf-parity-semantic-inspection.typ"
]

#document(
  "sid/0005-zaxonlite-storage-architecture.html",
  title: [SID 0005: Distributed Storage Architecture: Zaxonlite Integration for Multi-Node Consensus and Cloudflare-Grade Edge Protection],
  author: ("Sibuna Contributors",),
  description: [Zaxonlite integration for multi-node consensus, dynamic policies, and distributed IP reputation.],
)[
  #include "records/0005-zaxonlite-storage-architecture.typ"
]

#document("pdf/sid-0005-zaxonlite-storage-architecture.pdf")[
  #include "records/0005-zaxonlite-storage-architecture.typ"
]

#document(
  "sid/0006-mathematical-foundations.html",
  title: [SID 0006: Mathematical Foundations of Sibuna: Sequential Work, Symmetric Authentication, Bounded State, and Linear-Time Inspection],
  author: ("Sibuna Contributors",),
  description: [Proofs, lemmas, and citations for every Sibuna hot-path primitive and their pure-Zig realisation.],
)[
  #include "records/0006-mathematical-foundations.typ"
]

#document("pdf/sid-0006-mathematical-foundations.pdf")[
  #include "records/0006-mathematical-foundations.typ"
]
