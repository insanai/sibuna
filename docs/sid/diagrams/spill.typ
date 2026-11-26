// SID 0015: a worker can finish a cache miss even when the disk service stalls.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (17mm, 8mm),
  sibuna((0, 0), "Packet worker", name: <worker>),
  step((1, 0), "RAM shard", name: <ram>),
  step((2, 0), "Bounded spill queue", kind: "wait", name: <queue>),
  store((3, 0), "Storage worker", "mapped arena", name: <mmap>),
  outcome((2, 1), "Count the discarded hint", kind: "stop", name: <shed>),
  main-edge(<worker>, <ram>, "-|>", say("probe"), label-side: left),
  edge(<ram>, <queue>, "-|>", say("offer an\nevicted hint"), label-side: left),
  edge(<queue>, <mmap>, "-|>", say("service\navailable"), label-side: left),
  tone-edge("stop", <queue>, <shed>, "-|>", say("full"), label-side: left),
)
