// SID 0015: the routing regime as a function of active peers and the sampled p95 RTT.
// With peers present, the regional and wide-area regimes keep their state between the
// thresholds.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (34mm, 22mm),
  state((0.5, 0), "Standalone or VIP", "`peers = 0`\nP2C Peak-EWMA scheduler\nlocal `sibuna-kv` mmap store\nno network gossip",
    width: 50mm, name: <r1>),
  state((0, 1), "Regional PoP mesh", "bounded-load Maglev, M = 65537\none-hop consistent peer forwarding\nbatched UDP delta-CRDT stick tables",
    kind: "accent", width: 52mm, name: <r2>),
  state((1, 1), "Geo-anycast WAN", "locality-tiered Maglev, local PoP first\nstateless AEAD flow routing tokens\nasync PostgreSQL ban and policy sync",
    kind: "wait", width: 52mm, name: <r3>),
  edge(<r1>, <r2>, "-|>", bend: -18deg, say("peer found,\nRTT up to 3.0 ms"), label-side: right),
  edge(<r2>, <r1>, "-|>", bend: -18deg, say("`peers == 0`"), label-side: right, label-pos: 0.6),
  edge(<r1>, <r3>, "-|>", bend: 18deg, say("peer found,\nRTT above 3.0 ms"), label-side: left),
  edge(<r3>, <r1>, "-|>", bend: 18deg, say("`peers == 0`"), label-side: left, label-pos: 0.6),
  edge(<r2>, <r3>, "-|>", bend: 8deg, say("p95 RTT above 3.0 ms"), label-side: left, label-pos: 0.5),
  edge(<r3>, <r2>, "-|>", bend: 30deg, say("p95 RTT below 1.5 ms"), label-side: left),
)
