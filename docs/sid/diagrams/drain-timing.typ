// SID 0020: a shutdown in three steps. Readiness changes before the listeners stop
// admitting flows.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (10mm, 11mm),
  party((0, 0), "SIGTERM", "readiness becomes 503", name: <signal>),
  sibuna((0, 1), "Serve new arrivals", name: <delay>),
  step((0, 2), "Close admission", "finish the established flows", kind: "wait", name: <drain>),
  step((0, 3), "Close the remaining flows and exit", name: <exit>),
  edge(<signal>, <delay>, "-|>"),
  edge(<delay>, <drain>, "-|>", say("after `global.drain_delay`, default 0 s"),
    label-side: left),
  edge(<drain>, <exit>, "-|>", say("once empty, or at `global.shutdown_timeout`,\ndefault 5 s"),
    label-side: left),
)
