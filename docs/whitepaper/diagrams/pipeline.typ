// The request pipeline, in the numbered order of its stages. Dashed arrows are early
// refusals. Times are the medians of benchmarks/results/primitives-latest.md.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#let stage(at, title, detail, name, kind: "step") = step(at, title, detail, kind: kind,
  width: 30mm, name: name)
#let refusal(..args) = edge(..args, "-|>", dash: "dashed", stroke: thin + clay)

#flow(
  spacing: (4mm, 8mm),
  data((0, 0), "Accept, read the head", "into the 64 KiB buffer", name: <accept>),
  stage((0, 1), "1. Zero-copy parse", "132.5 ns", <parse>),
  stage((1, 1), "2. Ban table", "lock-free readers", <ban>),
  stage((2, 1), "3. Internal routes", "challenge, verify", <routes>),
  stage((3, 1), "4. GCRA limiter", "6.2 ns", <gcra>),
  stage((3, 2), "5. Shield inspection", "8 KiB body: 12.8 us", <waf>, kind: "accent"),
  stage((2, 2), "6. Reputation trie", "IPv4: 32.0 ns", <trie>, kind: "accent"),
  stage((1, 2), "7. Ordered rules", "`WEIGH` scores", <rules>, kind: "accent"),
  stage((0, 2), "8. Bot automaton", "55.7 ns", <bots>, kind: "accent"),
  decision((0, 3.2), "9. Session token", "keyed BLAKE3: 155.8 ns", name: <session>),
  outcome((0, 4.4), "Challenge", "interstitial (200)\nor JSON (401)", kind: "wait",
    name: <challenge>),
  outcome((1.8, 3.2), "Admit", "proxy through the origin pool,\nor a forward-auth verdict",
    name: <admit>),
  outcome((3, 3.2), "Refuse", "403, 429 or a ban", kind: "stop", name: <refuse>),
  edge(<accept>, <parse>, "-|>"),
  edge(<parse>, <ban>, "-|>"),
  edge(<ban>, <routes>, "-|>"),
  edge(<routes>, <gcra>, "-|>"),
  edge(<gcra>, <waf>, "-|>", say("pass"), label-side: left),
  edge(<waf>, <trie>, "-|>"),
  edge(<trie>, <rules>, "-|>"),
  edge(<rules>, <bots>, "-|>"),
  edge(<bots>, <session>, "-|>", say("challenge"), label-side: right),
  main-edge(<bots>, <admit>, "-|>", say("allow"), label-side: left),
  main-edge(<session>, <admit>, "-|>", say("enough work"), label-side: right),
  edge(<session>, <challenge>, "-|>", say("none or too little"), label-side: right),
  refusal(<ban>, (1, 0.45), (3.75, 0.45), (3.75, 3.2), <refuse>),
  refusal(<waf>, <refuse>, say-in("stop", "`waf:*`"), label-side: left),
  refusal(<rules>, (1, 2.6), (2.5, 2.6), <refuse>),
)
