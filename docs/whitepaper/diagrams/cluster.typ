// A Sibuna cluster: every node gives all SQL to one storage thread; the nodes share one
// PostgreSQL database, whose replication is PostgreSQL's (SID 0011).
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#let node-of(x, title, threads, storage, ring) = (
  caption-node((x, 0.3), title),
  sibuna((x, 1), "Connection threads", threads, width: 40mm, name: label("r" + str(x))),
  step((x, 2), "Storage thread", storage, kind: "wait", width: 40mm,
    name: label("s" + str(x))),
  group(((x, 0.3), (x, 2))),
  edge(label("r" + str(x)), label("s" + str(x)), "-|>", dash: "dashed", say(ring),
    label-side: left),
)

#flow(
  spacing: (6mm, 7mm),
  party((1, -0.6), "Ingress", "TLS termination: Caddy or Nginx", name: <ingress>),
  ..node-of(0, "Node 1", "read the engine, push incidents", "batches, rebuilds", "ring of 512"),
  ..node-of(1, "Node 2", none, none, none),
  ..node-of(2, "Node 3", none, none, none),
  store((1, 3.4), "PostgreSQL primary", "policies, reputation, incidents,\nconsole tables",
    name: <pg>),
  store((1, 4.9), "Standby", "the operator's replication", kind: "quiet", name: <standby>),
  edge(<ingress>, <r0>, "-|>"),
  edge(<ingress>, <r1>, "-|>"),
  edge(<ingress>, <r2>, "-|>"),
  main-edge(<s0>, <pg>, "-|>", say("SQL, TLS `verify-full`"), label-side: right),
  main-edge(<s1>, <pg>, "-|>"),
  main-edge(<s2>, <pg>, "-|>"),
  edge(<pg>, <standby>, "-|>", dash: "dashed", say("streaming replication"), label-pos: 0.5,
    label-side: left),
)
