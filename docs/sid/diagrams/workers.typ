// SID 0016: ownership. One thread accepts, the HTTP workers own connections and server
// sockets, and only the admission tables are shared on the request path.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (14mm, 6mm),
  step((0, 0), "Edge worker", "accept, rate, budget", name: <accept>),
  step((0, 2), "TLS, HTTP/2, HTTP/3", "runtime", name: <tls>),
  sibuna((1, 0), "HTTP worker 1", "connections, server pool,\nbuffers, timer wheel", name: <w1>),
  caption-node((1, 1), "one per processor, up to 64"),
  sibuna((1, 2), "HTTP worker n", name: <wn>),
  party((2, 1), "Servers", name: <servers>),
  data((1, 3.4), "Shared, lock-free or striped", "policy engine, limiter, bans, routes",
    kind: "wait", name: <shared>),
  main-edge(<accept>, <w1>, "-|>", say("assign"), label-side: left),
  edge(<accept>, <wn>, "-|>"),
  edge(<tls>, <w1>, "-|>"),
  edge(<tls>, <wn>, "-|>", say("socket pair"), label-side: right),
  main-edge(<w1>, <servers>, "-|>"),
  main-edge(<wn>, <servers>, "-|>"),
  edge(<wn>, <shared>, "-", dash: "dashed", say("decide"), label-side: left),
  edge(<w1>, (1.62, 0), (1.62, 3.4), <shared>, "-", dash: "dashed", corner-radius: 5pt),
)
