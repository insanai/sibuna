// SID 0027: the two tiers of the edge. Workers and the mesh thread use the table in
// memory; only the storage thread touches the mapped file.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (10mm, 10mm),
  step((0, 0), "Workers, mesh thread", "`find`, `keep`", name: <worker>),
  sibuna((1, 0), "`SpillStore`", "the table in memory", name: <ram>),
  step((1, 1), "Bounded queue", kind: "wait", name: <queue>),
  store((0, 1), "Storage thread", "the mapped file", name: <disk>),
  outcome((2, 1), "Count shed work", kind: "stop", name: <shed>),
  main-edge(<worker>, <ram>, "<|-|>"),
  edge(<ram>, <queue>, "-|>", say("offer, ask"), label-side: left),
  edge(<queue>, <disk>, "-|>"),
  tone-edge("stop", <queue>, <shed>, "-|>", say("full"), label-side: left),
  edge(<disk>, <ram>, "-|>", say("answer"), label-side: left),
)
