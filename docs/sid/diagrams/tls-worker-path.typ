// SID 0024: where TLS ends before and after the change. A client that offers HTTP/2
// still goes to the runtime.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (18mm, 5mm),
  caption-node((0, 0), "Original path", name: <before>),
  party((0, 1), "Client", name: <c1>),
  step((1, 1), "Runtime thread", "ends TLS", name: <runtime>),
  step((2, 1), "Worker", name: <w1>),
  party((3, 1), "Server", name: <s1>),
  caption-node((0, 2.2), "TLS on the worker", name: <after>),
  party((0, 3), "Client", name: <c2>),
  sibuna((2, 3), "Worker", "ends TLS", name: <w2>),
  party((3, 3), "Server", name: <s2>),
  edge(<c1>, <runtime>, "-|>", say("TLS"), label-side: left),
  edge(<runtime>, <w1>, "-|>", say("socket pair"), label-side: left),
  edge(<w1>, <s1>, "-|>"),
  main-edge(<c2>, <w2>, "-|>", say("TLS"), label-side: left),
  main-edge(<w2>, <s2>, "-|>"),
)
