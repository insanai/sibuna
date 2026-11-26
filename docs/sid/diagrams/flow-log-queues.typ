// SID 0020: two bounded queues carry completed flows to the access log.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (12mm, 9mm),
  step((0, 0), "Relay threads", name: <relay>),
  step((1, 0), "LB worker", name: <worker>),
  step((0.5, 1), "Flow ends", "4,096 places", kind: "wait", name: <ends>),
  step((0.5, 2), "Access log queue", kind: "wait", name: <log>),
  sibuna((0.5, 3), "Log writer", name: <writer>),
  outcome((1.8, 1.5), "Drop and count the line", kind: "stop", name: <loss>),
  edge(<relay>, <ends>, "-|>", say("`try_send`"), label-side: right),
  edge(<worker>, <ends>, "-|>", say("`try_send`"), label-side: left),
  main-edge(<ends>, <log>, "-|>", say("edge loop"), label-side: right),
  main-edge(<log>, <writer>, "-|>"),
  tone-edge("stop", <ends>, <loss>, "-|>", dash: "dashed", say("full"), label-side: left),
  tone-edge("stop", <log>, <loss>, "-|>", dash: "dashed", say("full"), label-side: right),
)
