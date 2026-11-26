// operations.rst: the path of a flow through the edge. Only HTTP meets the firewall.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (8mm, 8mm),
  sibuna((1, 0), "Edge worker", "accept, admission, UDP mappings", name: <worker>),
  step((0, 1), "Relay threads", "`epoll`", name: <relay>),
  step((3, 1), "TLS termination", "TLS, HTTP/2, HTTP/3", name: <tls>),
  step((2, 2), "HTTP firewall", "gate or shield", kind: "decision", name: <firewall>),
  step((2, 3), "Route by host and path", name: <route>),
  step((3, 4), "Origin adapter", "TLS, HTTP/2, HTTP/3", name: <adapter>),
  party((0, 5), "TCP servers", name: <tcp>),
  party((1, 5), "UDP servers", name: <udp>),
  party((2, 5), "HTTP/1.1 servers", name: <h1>),
  party((3, 5), "TLS, HTTP/2 and HTTP/3 servers", width: 30mm, name: <hx>),
  edge(<worker>, <relay>, "-|>", say("TCP"), label-side: right),
  edge(<relay>, <tcp>, "-|>"),
  edge(<worker>, <udp>, "-|>", say("UDP"), label-pos: 0.78),
  edge(<worker>, <tls>, "-|>", say("HTTP with TLS"), label-side: left),
  main-edge(<worker>, <firewall>, "-|>", say("HTTP"), label-side: left),
  edge(<tls>, <firewall>, "-|>"),
  main-edge(<firewall>, <route>, "-|>", say("admitted"), label-side: left),
  edge(<worker>, <route>, "-|>", bend: -30deg, dash: "dashed",
    say("`firewall: false`"), label-pos: 0.5, label-side: left),
  main-edge(<route>, <h1>, "-|>"),
  edge(<route>, <adapter>, "-|>"),
  edge(<adapter>, <hx>, "-|>"),
)
