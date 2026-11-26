// SID 0021: the phases of an ACME client order (enum Phase in crates/acme/src/order.rs).
// A phase moves forward only; a polling phase stays while the authority is working.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (7mm, 9mm),
  state((0, 0), "`Directory`", name: <directory>),
  state((1, 0), "`Nonce`", name: <nonce>),
  state((2, 0), "`Account`", name: <account>),
  state((3, 0), "`NewOrder`", name: <order>),
  state((0, 1), "`Authorization`", name: <authz>),
  state((1, 1), "`Present`", kind: "accent", name: <present>),
  state((2, 1), "`Respond`", name: <respond>),
  state((3, 1), "`PollAuthorization`", "stays while `pending`", kind: "wait", name: <poll-authz>),
  state((0, 2), "`Finalize`", name: <finalize>),
  state((1, 2), "`PollOrder`", "stays while `processing`", kind: "wait", name: <poll-order>),
  state((2, 2), "`Download`", name: <download>),
  state((3, 2), "`Done`", kind: "good", name: <done>),
  edge(<directory>, <nonce>, "-|>"),
  edge(<nonce>, <account>, "-|>"),
  edge(<account>, <order>, "-|>"),
  edge(<order>, (3, 0.5), (0, 0.5), <authz>, "-|>", corner-radius: 5pt),
  edge(<authz>, <present>, "-|>"),
  edge(<present>, <respond>, "-|>", say("presented"), label-side: left),
  edge(<respond>, <poll-authz>, "-|>"),
  edge(<poll-authz>, (3, 1.5), (0, 1.5), <finalize>, "-|>", corner-radius: 5pt),
  edge(<authz>, (-0.75, 1), (-0.75, 2), <finalize>, "-|>", dash: "dashed",
    corner-radius: 5pt, say("already valid"), label-side: right, label-pos: 0.5),
  edge(<finalize>, <poll-order>, "-|>"),
  edge(<poll-order>, <download>, "-|>"),
  main-edge(<download>, <done>, "-|>"),
  note((1.5, 2.9), "Any phase ends in `Failed` on an unexpected answer\nor when the budget of requests is spent"),
)
