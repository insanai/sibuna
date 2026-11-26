// SID 0008: the streaming analytics pipeline and its decoupled minute rollup.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (10mm, 11mm),
  sibuna((0.5, 0), "HTTP ingress worker", "zero-allocation UA and CIDR trie,\nunder 45 ns of overhead",
    name: <ingress>),
  step((0, 1), "Striped atomics", "S = 16, 64-byte aligned lines,\nno bus lock, under 5 ns",
    width: 52mm, name: <atomics>),
  step((1, 1), "MPSC ring buffer", "Q = 4,096 slots (1 MiB),\nnon-blocking drop and count",
    kind: "wait", width: 52mm, name: <ring>),
  step((0.5, 2), "1 Hz collector thread", "Space-Saving sketch (m = 256),\ncategorical `[16]u64` vectors,\nfixed RAM, off the request path",
    name: <collector>),
  store((0.5, 3), "Zaxonlite storage", "`SBR3` and `SBM2` blobs, append-only,\nabout 4 KiB a minute,\n1,440 rows for 24 hours",
    name: <storage>),
  main-edge(<ingress>, <atomics>, "-|>", say("every request"), label-side: right),
  edge(<ingress>, <ring>, "-|>", say("a sample, p = 1/64"), label-side: left),
  edge(<atomics>, <collector>, "-|>"),
  edge(<ring>, <collector>, "-|>"),
  main-edge(<collector>, <storage>, "-|>", say("one write a minute"), label-side: left,
    label-pos: 0.4),
)
