// SID 0021: the states of an order at the internal ACME authority. A step never moves an
// order back; valid and invalid are final.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (22mm, 9mm),
  start((-0.6, 0), name: <start>),
  state((0, 0), "`pending`", name: <pending>),
  state((1, 0), "`ready`", name: <ready>),
  state((2, 0), "`processing`", kind: "wait", name: <processing>),
  state((3, 0), "`valid`", kind: "good", name: <valid>),
  state((1, 1), "`invalid`", kind: "stop", name: <invalid>),
  edge(<start>, <pending>, "-|>"),
  edge(<pending>, <ready>, "-|>", say("every name\nvalidated"), label-side: left),
  edge(<ready>, <processing>, "-|>", say("finalize"), label-side: left),
  main-edge(<processing>, <valid>, "-|>", say("issued"), label-side: left),
  tone-edge("stop", <pending>, <invalid>, "-|>", say("a failed\nauthorization"),
    label-side: right),
  tone-edge("stop", <processing>, <invalid>, "-|>", say("issuance\nfailed"),
    label-side: left),
)
