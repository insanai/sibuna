// The console: it reads the data plane, gives its SQL to the storage thread and makes
// outbound connections with verified certificates (SIDs 0007, 0012, 0013).
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (8mm, 11mm),
  party((1, 0), "Browser", "the console interface (WebAssembly)", name: <browser>),
  sibuna((1, 1), "Console server", "bounded listener", stroke: bold + green, name: <server>),
  step((0, 2), "Data plane", "counters and statistics,\nread only", width: 38mm,
    name: <plane>),
  step((1, 2), "Storage thread", "SQLite or PostgreSQL", kind: "wait", width: 38mm,
    name: <storage>),
  party((2, 2), "Outbound TLS", "peers (WSS), webhooks,\nGeoIP downloads", width: 38mm,
    name: <tls>),
  main-edge(<browser>, <server>, "<|-|>", say("HTTP and WebSocket"), label-side: left),
  edge(<server>, <plane>, "-|>", dash: "dashed", say("reads"), label-side: right),
  edge(<server>, <storage>, "-|>", say("jobs, at most 32 queued"), label-side: right,
    label-pos: 0.6),
  edge(<server>, <tls>, "-|>", say("verified certificates"), label-side: left),
)
