// edge.rst: the life of a server in a pool. Only "In service" and "Ramping" take new
// flows; slow start applies when it is configured.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (30mm, 5mm),
  state((0, 1.5), "In service", kind: "good", name: <service>),
  state((1, 0), "Down", "active probe", name: <down>),
  state((1, 1), "Ejected", "passive health", name: <ejected>),
  state((1, 2), "Marked", "connect failed", name: <marked>),
  state((1, 3), "Drained", "operator", kind: "wait", name: <drained>),
  state((2, 1.5), "Ramping", "slow start", kind: "good", name: <ramp>),
  edge(<service>, <down>, "-|>", say("`fall` failures"), label-side: left),
  edge(<service>, <ejected>, "-|>", say("failures in a row"), label-side: left),
  edge(<service>, <marked>, "-|>", say("connect fails"), label-side: right),
  edge(<service>, <drained>, "-|>", say("`set state drain`"), label-side: right),
  edge(<down>, <ramp>, "-|>", say("`rise` passes"), label-side: left),
  edge(<ejected>, <ramp>, "-|>", say("ejection ends"), label-side: left),
  edge(<marked>, <ramp>, "-|>", say("2 s"), label-side: right),
  edge(<drained>, <ramp>, "-|>", say("`set state ready`"), label-side: right),
  main-edge(<ramp>, (2, 4), (0, 4), <service>, "-|>", say("ramp ends"),
    label-pos: 0.5, label-side: left, corner-radius: 6pt),
)
