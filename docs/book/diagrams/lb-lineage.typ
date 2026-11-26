// prior-art.rst: what the edge load balancer takes from earlier systems and papers.
// Solid arrows are ideas taken directly; dashed lines are ideas shared.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#let source(at, title, detail, name) = step(at, title, detail, width: 46mm, name: name)
#let ours(at, title, detail, name) = sibuna(at, title, detail, width: 52mm, name: name)

#flow(
  spacing: (16mm, 3.5mm),
  caption-node((0, -1), "Earlier systems and papers"),
  caption-node((1, -1), "In Sibuna"),
  source((0, 0), "HAProxy", none, <haproxy>),
  source((0, 1), "nginx", none, <nginx>),
  source((0, 2), "Envoy", none, <envoy>),
  source((0, 3), "Maglev", "Eisenbud et al. 2016", <maglev>),
  source((0, 4), "Bounded loads", "Mirrokni et al. 2018", <bounded>),
  source((0, 5), "Rendezvous hashing", "Thaler-Ravishankar 1998", <hrw>),
  source((0, 6), "TinyLFU", "Einziger et al. 2017", <tinylfu>),
  ours((1, 0), "Frontends, backends,\nadmin socket", "SID 0018", <vocab>),
  ours((1, 1), "Event-driven HTTP workers", "SID 0016", <workers>),
  ours((1, 2), "Hook stages and tiers", "SID 0030", <hooks>),
  ours((1, 3.5), "`bounded_maglev`", "SID 0015", <bmaglev>),
  ours((1, 5), "Source stickiness, owner of a client", "SID 0019, SID 0026", <sticky>),
  ours((1, 6), "Spill cache admission", "SID 0027", <spill>),
  main-edge(<haproxy>, <vocab>, "-|>"),
  main-edge(<nginx>, <workers>, "-|>"),
  edge(<envoy>, <hooks>, "-", dash: "dashed"),
  main-edge(<maglev>, <bmaglev>, "-|>"),
  main-edge(<bounded>, <bmaglev>, "-|>"),
  main-edge(<hrw>, <sticky>, "-|>"),
  main-edge(<tinylfu>, <spill>, "-|>"),
  edge(<haproxy>, (-0.72, 0), (-0.72, 4), <bounded>, "-", dash: "dashed",
    corner-radius: 4pt, say("`hash-balance-factor`"), label-side: left, label-angle: auto),
)
