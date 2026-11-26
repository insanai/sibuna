// SID 0030: the circuit breaker that one thread keeps for one agent. `limit` is
// `breaker.failures` and `open` is `breaker.open`.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (28mm, 16mm),
  start((-0.45, 0), name: <start>),
  state((0, 0), "Closed", "n failures in a row", kind: "good", name: <closed>),
  state((2, 0), "Open", "until t", kind: "stop", name: <open>),
  state((1, 1), "Half open", "one call out", kind: "wait", name: <half>),
  edge(<start>, <closed>, "-|>"),
  edge(<closed>, <closed>, "-|>", bend: 130deg, loop-angle: 90deg,
    say("success: n = 0\nfailure: n + 1 < limit")),
  tone-edge("stop", <closed>, <open>, "-|>", say("failure: n + 1 = limit,\nt = now + open"),
    label-side: left),
  edge(<open>, <open>, "-|>", bend: 130deg, loop-angle: 90deg,
    say("a call before t:\nrefused, `unavailable`")),
  edge(<open>, <half>, "-|>", say("a call at t or later"), label-side: right),
  main-edge(<half>, <closed>, "-|>", say("success"), label-side: left),
  tone-edge("stop", <half>, <open>, "-|>", bend: -30deg, say("failure:\nt = now + open"),
    label-side: right),
)
