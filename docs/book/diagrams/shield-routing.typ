// operations.rst: how the Shield surface routes a request.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (9mm, 7mm),
  data((1, 0), "Request", name: <request>),
  step((1, 1), "Local bans and rate limit", name: <limits>),
  decision((1, 2), "Inspection\nand policy", name: <policy>),
  outcome((0, 3), "Deny", kind: "stop", name: <deny>),
  decision((2, 3), "Session MAC?", name: <session>),
  outcome((1, 4), "Origin or auth success", name: <origin>),
  outcome((3, 4), "Issue a puzzle", kind: "wait", name: <puzzle>),
  edge(<request>, <limits>, "-|>"),
  edge(<limits>, <policy>, "-|>", say("within limits"), label-side: left),
  tone-edge("stop", <policy>, <deny>, "-|>", say-in("stop", "`DENY`"), label-side: right),
  main-edge(<policy>, <origin>, "-|>", say-in("good", "`ALLOW`"), label-side: left,
    label-pos: 0.35),
  tone-edge("wait", <policy>, <session>, "-|>", say-in("wait", "`CHALLENGE`"),
    label-side: left),
  main-edge(<session>, <origin>, "-|>", say("valid"), label-side: right),
  tone-edge("wait", <session>, <puzzle>, "-|>", say("missing or invalid"), label-side: left),
)
