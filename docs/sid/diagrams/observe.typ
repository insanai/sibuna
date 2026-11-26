// SID 0020: one request and the three places that observe it. The log queue is the only
// shared structure on the path.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (12mm, 7mm),
  party((0.5, 0), "Accept", name: <accept>),
  step((1.5, 1), "PROXY stage", "bounded, optional", kind: "wait", name: <stage>),
  sibuna((0.5, 2), "Request path", "worker, in-process or thread", name: <paths>),
  data((0.5, 3), "Entry", "one per request", name: <entry>),
  step((0, 4), "Counters", "per frontend, per server", name: <stats>),
  step((1, 4), "Bounded queue", "drop and count", kind: "wait", name: <queue>),
  step((1, 5), "Writer thread", "JSON lines", name: <writer>),
  main-edge(<accept>, <paths>, "-|>"),
  edge(<accept>, <stage>, "-|>", say("`proxy_protocol`"), label-side: left),
  edge(<stage>, <paths>, "-|>", say("client address"), label-side: left),
  main-edge(<paths>, <entry>, "-|>", say("dispatch"), label-side: left),
  edge(<entry>, <stats>, "-|>", say("settle"), label-side: right),
  edge(<entry>, <queue>, "-|>", say("`try_send`"), label-side: left),
  edge(<queue>, <writer>, "-|>"),
)
