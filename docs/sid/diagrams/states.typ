// SID 0016: the states of a connection on an HTTP worker. Each transition is taken
// inside the worker without blocking.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (12mm, 7mm),
  state((1, 0), "Idle", "no buffer", name: <idle>),
  state((1, 1), "Head", name: <head>),
  state((2, 2), "Body", "up to 64 KiB", name: <body>),
  state((1, 3), "Decide", "synchronous, no I/O", kind: "wait", name: <decide>),
  state((0, 4), "Respond", name: <respond>),
  state((2, 4), "Connect", name: <connect>),
  state((1, 5), "Exchange", kind: "accent", name: <exchange>),
  state((0, 6), "Closed", kind: "quiet", name: <closed>),
  state((2, 6), "Tunnel", kind: "good", name: <tunnel>),
  edge(<idle>, <head>, "-|>", say("bytes"), label-side: left),
  edge(<head>, <body>, "-|>"),
  edge(<head>, <decide>, "-|>"),
  edge(<body>, <decide>, "-|>"),
  edge(<decide>, <respond>, "-|>", say("deny, challenge,\ninternal route"), label-side: right),
  edge(<decide>, <connect>, "-|>", say("admit, no\npooled socket"), label-side: left),
  main-edge(<decide>, <exchange>, "-|>", say("admit"), label-side: left, label-pos: 0.3),
  edge(<connect>, <exchange>, "-|>"),
  edge(<exchange>, <tunnel>, "-|>", say("`101`"), label-side: left),
  edge(<exchange>, <closed>, "-|>"),
  edge(<respond>, <closed>, "-|>"),
  edge(<tunnel>, <closed>, "-|>"),
  edge(<respond>, (-0.75, 4), (-0.75, 0), <idle>, "-|>", say("keep-alive"),
    label-side: left, corner-radius: 5pt),
  main-edge(<exchange>, (2.85, 5), (2.85, 0), <idle>, "-|>", say("keep-alive"),
    label-side: right, corner-radius: 5pt),
)
