// SID 0018: authority. The file decides the topology at every reload; commands lay
// changes over it, and only drains pass a reload.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (24mm, 10mm),
  data((0, 0), "`edge.jlv`", "the authority", kind: "wait", name: <file>),
  step((0, 1), "Checked revision", name: <revision>),
  sibuna((1, 1), "Serving topology", "revision and overlay", name: <serving>),
  party((1, 0), "Admin socket", "`sibuna ctl`", name: <socket>),
  outcome((2, 1), "New flows", kind: "quiet", name: <flows>),
  edge(<file>, <revision>, "-|>", say("SIGHUP, reload,\nwatch"), label-side: right),
  main-edge(<revision>, <serving>, "-|>", say("replaces topology,\nkeeps drains"),
    label-side: left),
  edge(<socket>, <serving>, "-|>", say("drain, weight,\nadd, del"), label-side: left),
  main-edge(<serving>, <flows>, "-|>"),
)
