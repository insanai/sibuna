// SID 0030: a connection whose chain names an agent is parked, and a judge decides it.
// Neither the edge worker nor an HTTP/3 task may wait for an agent.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (24mm, 9mm),
  sibuna((0, 0), "Edge worker\nor HTTP/3 task", "holds the socket, reads nothing", width: 36mm,
    name: <worker>),
  step((1, 0), "Bounded queue", "`hook_judges.queue`", kind: "wait", name: <queue>),
  step((1, 1), "Judges", "`hook_judges.threads`", name: <judges>),
  party((1, 2), "Agent", name: <agent>),
  outcome((0, 1.15), "Shed: run the chain here", "every agent fails with `overload`", kind: "wait",
    name: <shed>),
  edge(<worker>, <queue>, "-|>", say("a case: an owned\ncopy of the view"), label-side: left),
  edge(<queue>, <judges>, "-|>"),
  edge(<judges>, <agent>, "<|-|>", say("blocking call,\ndeadline, breaker"), label-side: right),
  main-edge(<judges>, <worker>, "-|>", say("the verdict,\na wake"), label-side: right),
  tone-edge("wait", <worker>, <shed>, "-|>", say("queue full"), label-side: right),
)
