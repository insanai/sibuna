#import "wireframe.typ": *
#set text(font: "Noto Sans")

#detail-wire("Challenges", [Challenges · all nodes · last hour · live], [Challenge flow], [
  Issued: 8,200 → Submitted: 7,900\
  Accepted: 7,750 · Rejected: 120 · Malformed: 30

  *Accepted solve time (client reported)*\
  Algorithm: Hashcash ▾ · difficulty: 16 ▾\
  Median: 280 ms · p95 bucket: 1,024–2,048 ms\
  Timing missing: 4% · invalid: 0.1%

  Histogram: 16 logarithmic buckets\
  Show bucket counts / Open timing table

  PoSW view uses depth and opening count.\
  Untrusted device timing; no security inference.
], [Investigate and tune], [
  *Rejections by cause*\
  Double spend: 52 · Expired: 31\
  Fingerprint mismatch: 12 · Other causes: 25\
  Select a cause → per-address records

  Address / node / issued / accepted / cause\
  192.0.2.44 / 2 / 10 / 8 / expired\
  Per-address capture missing? “Not recorded”

  Adaptive difficulty: Show change timeline\
  Solver mode: Wasm / JS fallback / unknown

  Edit rule parameters → preview → save\
  Runtime limits remain node-local.
], [No data: “No challenges in this window”. Missing instrumentation: “Not available”. Late submissions may cross windows.])
