// SID 0019: writers build a snapshot under the mutex and raise the generation; a reader
// compares one number and uses the snapshot its thread already has.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (16mm, 8mm),
  party((0, 0), "Reload or command", name: <writer>),
  step((1, 0), "Master table", "mutex", name: <master>),
  data((2, 0), "Snapshot", "immutable", name: <snap>),
  step((1, 1), "Generation", "atomic", kind: "wait", name: <gen>),
  sibuna((0, 2), "Request", name: <request>),
  step((2, 2), "Thread cache", "snapshot and generation", name: <cache>),
  edge(<writer>, <master>, "-|>", say("change"), label-side: left),
  edge(<master>, <snap>, "-|>", say("build"), label-side: left),
  edge(<master>, <gen>, "-|>", say("raise"), label-side: left),
  edge(<request>, <gen>, "-|>", say("compare"), label-side: left),
  main-edge(<request>, <cache>, "-|>", say("equal: use"), label-side: right),
  edge(<cache>, <snap>, "-|>", dash: "dashed", say("differs: under the\nmutex, fetch once"),
    label-side: right),
)
