// SID 0028: how the thread edge-authority follows the head of the store. The node keeps
// the revision it serves until the worker serves a new one.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (12mm, 7mm),
  sibuna((0, 0), "Look at the head", "`store.head()`", name: <head>),
  decision((0, 1), "Reachable?", name: <reachable>),
  decision((0, 2), "A new head?", name: <new>),
  step((0, 3), "Read the revision, compose it\nwith the file, check it", name: <check>),
  decision((0, 4), "Checked?", name: <checked>),
  step((0, 5), "Leave it for the worker", name: <leave>),
  decision((0, 6), "The worker\nserves it?", name: <serves>),
  outcome((0, 7), "applied = revision", "log `DBA010`, write the cache, report", name: <applied>),
  outcome((1, 1), "Keep the revision", "log `DBA012` once, look again later", kind: "wait",
    name: <later>),
  outcome((1, 2), "Nothing to do", kind: "quiet", name: <same>),
  outcome((1, 5), "Keep the revision", "log `DBA011`, remember the refusal", kind: "stop",
    name: <refused>),
  edge(<head>, <reachable>, "-|>"),
  tone-edge("wait", <reachable>, <later>, "-|>", say("unreachable"), label-side: left),
  main-edge(<reachable>, <new>, "-|>", say("yes"), label-side: left),
  edge(<new>, <same>, "-|>", say("no"), label-side: left),
  main-edge(<new>, <check>, "-|>", say("yes"), label-side: left),
  main-edge(<check>, <checked>, "-|>"),
  tone-edge("stop", <checked>, <refused>, "-|>", say("refused"), label-side: left),
  main-edge(<checked>, <leave>, "-|>", say("yes"), label-side: left),
  main-edge(<leave>, <serves>, "-|>"),
  tone-edge("stop", <serves>, <refused>, "-|>", say("refuses"), label-side: right),
  main-edge(<serves>, <applied>, "-|>", say("yes"), label-side: left),
)
