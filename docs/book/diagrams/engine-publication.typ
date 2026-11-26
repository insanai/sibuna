// zero-allocation.rst: engine publication. After EngineSlot::publish and
// EngineCache::refresh in cmd/sibuna/src/slot.rs.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (8mm, 12mm),
  step((1, 0), "Storage thread", "builds Engine v2 off the request path", kind: "wait",
    name: <storage>),
  sibuna((1, 1), "`EngineSlot`", "`RwLock<Arc<Engine>>`\n`generation: AtomicU64`",
    stroke: bold + green, name: <slot>),
  outcome((2.6, 1), "Engine v2", "published", name: <v2>),
  step((2.2, 2.2), "Connection thread A", "`EngineCache`, generation 2", name: <a>),
  step((0.2, 2.2), "Connection thread B", "`EngineCache`, generation 1", name: <b>),
  outcome((0.2, 3.3), "Engine v1", "freed when the last cache lets go", kind: "quiet",
    name: <v1>),
  edge(<storage>, <slot>, "-|>", stroke: thin + gold-deep, label-side: left,
    say("publish: swap the `Arc` under the write lock,\n`generation += 1` (Release)")),
  main-edge(<slot>, <v2>, "-|>", say("holds"), label-side: left),
  edge(<a>, <slot>, "-|>", label-side: left, label-pos: 0.55,
    say("refresh: load the generation (Acquire);\nequal, no clone")),
  main-edge(<a>, <v2>, "-|>", say("`Arc`"), label-side: right),
  edge(<b>, <slot>, "-|>", dash: "dashed", label-side: left, label-pos: 0.5,
    say("generation moved:\nread lock, clone the `Arc`")),
  edge(<b>, <v1>, "-|>", stroke: thin + rule, say("`Arc` until the next refresh"),
    label-side: left),
)
