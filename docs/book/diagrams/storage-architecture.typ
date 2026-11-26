// operations.rst: the storage architecture of the firewall daemon. Request threads never
// wait on SQL; one storage thread owns the database.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (12mm, 8mm),
  sibuna((0.5, 0), "Request threads", "the hot path", width: 62mm, name: <workers>),
  step((0, 1), "MPSC ring", "512 incidents", kind: "wait", name: <ring>),
  step((1, 1), "`EngineSlot::publish`", "swaps the `Arc`", kind: "wait", name: <publish>),
  step((0, 2), "Storage thread", "`tokio`: drains, polls", name: <thread>),
  step((1, 2), "Rebuild the engine", "off the hot path", name: <rebuild>),
  store((0, 3), "SQLite file or PostgreSQL", "through `sqlx`", name: <db>),
  data((1, 3), "`policies`, `ip_reputation`,\n`security_incidents`,\nthe full-text index", name: <tables>),
  party((0, 4), "Other cluster nodes", kind: "quiet", name: <others>),
  edge(<workers>, <ring>, "-|>", say("push"), label-side: right),
  edge(<ring>, <thread>, "-|>", say("pop"), label-side: right),
  edge(<thread>, <db>, "-|>", say("batched SQL"), label-side: right),
  edge(<db>, <tables>, "-"),
  edge(<tables>, <rebuild>, "-|>", say("revision changed?"), label-side: right),
  edge(<rebuild>, <publish>, "-|>"),
  main-edge(<publish>, <workers>, "-|>", say("new rules"), label-side: right),
  edge(<db>, <others>, "<|-|>", dash: "dashed",
    say("shared PostgreSQL,\n`NOTIFY sibuna_policy`"), label-side: right),
)
