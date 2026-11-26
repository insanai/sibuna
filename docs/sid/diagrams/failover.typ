// SID 0019: one request and its attempts. A server is tried once, and the count of
// attempts is bounded.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (16mm, 12mm),
  decision((0, 0), "Select", "not tried, eligible", name: <select>),
  step((1, 0), "Connect", name: <connect>),
  step((2, 0), "Send the request", name: <send>),
  outcome((3, 0), "Response", name: <done>),
  outcome((0, 1), "502", kind: "stop", name: <fail>),
  main-edge(<select>, <connect>, "-|>"),
  main-edge(<connect>, <send>, "-|>", say("connected"), label-side: left),
  main-edge(<send>, <done>, "-|>"),
  tone-edge("wait", <connect>, <select>, "-|>", bend: -40deg,
    say("failed, attempts left"), label-side: right),
  tone-edge("wait", <send>, <select>, "-|>", bend: -58deg,
    say("no response byte; kept, idempotent\nor refused; attempts left"), label-side: right),
  tone-edge("stop", <select>, <fail>, "-|>", say("none left"), label-side: right),
)
