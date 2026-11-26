// edge.rst: the path of a connection through a node. Each box is owned by one thread or
// one group of threads; the dashed edges are the shared, read-mostly state.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (6mm, 7mm),
  party((1.5, 0), "Client", name: <client>),
  step((1.5, 1), "Kernel listener", "`defer_accept`, backlog", name: <kernel>),
  sibuna((1.5, 2), "Edge worker", "connection rate, flow budget,\nconnection hooks", name: <edge>),
  step((0, 3), "TCP: ClientHello inspection", "five classes, fallback", width: 36mm,
    name: <inspect>),
  step((1, 3), "UDP: QUIC screen", "mapping, reply bound", name: <udp>),
  sibuna((2, 3), "HTTP worker", "TLS for HTTP/1.1", name: <worker>),
  sibuna((3.7, 3), "Protocol runtime", "HTTP/2, HTTP/3", name: <runtime>),
  step((0, 4), "Relay thread", "byte pipe", name: <relay>),
  step((2.5, 4), "Bans, limiter, traffic policy,\ngate or shield, request hooks", kind: "decision",
    name: <decide>),
  step((2.5, 5), "Choose a server", "from the snapshot", name: <choose>),
  data((0, 5.5), "Shared state", "routing snapshot, server loads,\nhealth flags", kind: "quiet",
    name: <shared>),
  party((1.5, 6.5), "Server", name: <server>),
  edge(<client>, <kernel>, "-|>"),
  edge(<kernel>, <edge>, "-|>"),
  edge(<edge>, <inspect>, "-|>", say("TCP"), label-side: right),
  edge(<edge>, <udp>, "-|>", say("UDP"), label-side: right, label-pos: 0.55),
  main-edge(<edge>, <worker>, "-|>", say("HTTP, fewest"), label-side: left),
  edge(<worker>, <runtime>, "-|>", say("offers h2"), label-side: left),
  edge(<inspect>, <relay>, "-|>", say("reserve, connect"), label-side: right),
  main-edge(<worker>, <decide>, "-|>"),
  edge(<runtime>, <decide>, "-|>", say("`Decide`"), label-side: left),
  main-edge(<decide>, <choose>, "-|>"),
  edge(<relay>, <server>, "-|>"),
  edge(<udp>, <server>, "-|>"),
  main-edge(<choose>, <server>, "-|>", say("exchange"), label-side: left),
  edge(<inspect>, (-0.75, 3), (-0.75, 5.5), <shared>, "-", dash: "dashed"),
  edge(<choose>, <shared>, "-", dash: "dashed", crossing: true),
)
