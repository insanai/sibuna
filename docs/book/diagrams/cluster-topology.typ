// cluster.rst: a cluster of three nodes. The router spreads the clients; the dashed edges
// are the mesh; the dotted edge is the database of SID 0028, which every node may use.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (14mm, 9mm),
  party((1, 0), "Clients", name: <clients>),
  step((1, 1), "DNS or ECMP router", name: <router>),
  sibuna((0, 2), "Node A", name: <a>),
  sibuna((1, 2), "Node B", name: <b>),
  sibuna((2, 2), "Node C", name: <c>),
  group((<a>, <b>, <c>), name: <nodes>, inset: 6pt),
  party((1, 3.2), "Servers of the pools", name: <servers>),
  store((3.2, 2), "PostgreSQL", "revisions (SID 0028)", name: <db>),
  edge(<clients>, <router>, "-|>"),
  edge(<router>, <a>, "-|>"),
  edge(<router>, <b>, "-|>"),
  edge(<router>, <c>, "-|>"),
  edge(<a>, <b>, "<|-|>", dash: "dashed", stroke: thin + gold-deep,
    say-in("wait", "mesh"), label-side: left),
  edge(<b>, <c>, "<|-|>", dash: "dashed", stroke: thin + gold-deep,
    say-in("wait", "mesh"), label-side: left),
  edge(<a>, <c>, "<|-|>", dash: "dashed", stroke: thin + gold-deep, bend: -24deg),
  main-edge(<a>, <servers>, "-|>"),
  main-edge(<b>, <servers>, "-|>"),
  main-edge(<c>, <servers>, "-|>"),
  edge(<db>, <nodes>, "-|>", dash: "dotted"),
)
