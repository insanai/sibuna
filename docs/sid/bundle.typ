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
  description: [Foundation architecture, product surfaces, zero-allocation pipeline, and delivery plan.],
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
  title: [SID 0003: Declarative Rule Policy Engine],
  author: ("Sibuna Contributors",),
  description: [Draft discussion note],
)[
  #include "records/0003-declarative-policy-engine.typ"
]

#document("pdf/sid-0003-declarative-policy-engine.pdf")[
  #include "records/0003-declarative-policy-engine.typ"
]

#document(
  "sid/0004-semantic-inspection.html",
  title: [SID 0004: Semantic Inspection and Local Flood Controls],
  author: ("Sibuna Contributors",),
  description: [Semantic attack inspection and GCRA rate limiting.],
)[
  #include "records/0004-semantic-inspection.typ"
]

#document("pdf/sid-0004-semantic-inspection.pdf")[
  #include "records/0004-semantic-inspection.typ"
]

#document(
  "sid/0005-zaxonlite-storage-architecture.html",
  title: [SID 0005: Distributed Storage Architecture],
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

#document(
  "sid/0007-console-management-interface.html",
  title: [SID 0007: The Sibuna Console: A Real-Time Management Interface for Nodes and Clusters in Pure Zig],
  author: ("Sibuna Contributors",),
  description: [The Sibuna Console, a complete management interface in pure Zig: kernel, WebSocket protocol, data model, GeoIP, cluster management, wireframes, and build pipeline.],
)[
  #include "records/0007-console-management-interface.typ"
]

#document("pdf/sid-0007-console-management-interface.pdf")[
  #include "records/0007-console-management-interface.typ"
]

#document(
  "sid/0008-ai-bot-traffic-monitoring.html",
  title: [SID 0008: AI Bot Traffic Identification, Multi-Tier Verification, and Operator Console Analytics],
  author: ("Sibuna Contributors",),
  description: [Specifies the architecture for identifying, verifying, and monitoring AI crawler and automated bot traffic in Sibuna: zero-allocation single-pass signature matching, sub-microsecond Radix CIDR verification for major providers (OpenAI, Anthropic, Google Gemini, Perplexity, Meta, Apple, ByteDance), multi-tier confidence classification, bounded telemetry extensions, and a real-time console dashboard delivering visual composition, time-series analysis, and granular tabular analytics contrasting bot traffic against actual human traffic.],
)[
  #include "records/0008-ai-bot-traffic-monitoring.typ"
]

#document("pdf/sid-0008-ai-bot-traffic-monitoring.pdf")[
  #include "records/0008-ai-bot-traffic-monitoring.typ"
]
