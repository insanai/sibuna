// SID 0007: proposed modules and their runtime interfaces. The daemon owns database
// access; console work uses its bounded mailbox; telemetry reads take no locks.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (14mm, 20mm),
  store((0, 0), "Zaxonlite", "replicated SQLite", name: <zaxonlite>),
  sibuna((1, 0), "`apps/sibuna`", "CLI, daemon, storage thread", name: <sibuna>),
  step((2, 0), "`libs/store`, `libs/policy`,\n`libs/crypto`, `libs/net`", name: <libs>),
  step((1, 1), "`libs/console`", "app: routes, auth, telemetry,\nhub, geoip, cluster", name: <console>),
  step((0.4, 2), "`libs/serve`", "kernel: listener, slots, HTTP,\nWebSocket, assets", name: <serve>),
  step((1.6, 2), "`apps/console-ui`", "wasm32 interface module", name: <ui>),
  edge(<sibuna>, <zaxonlite>, "-|>", say("SQL"), label-side: right),
  edge(<sibuna>, <libs>, "-|>"),
  main-edge(<sibuna>, <console>, "-|>", bend: -50deg, say("starts; counters"), label-side: right),
  edge(<console>, <sibuna>, "-|>", say("storage and\ncontrol mailbox"), label-side: right),
  edge(<console>, <sibuna>, "-|>", bend: -80deg, dash: "dashed", say("atomic loads"),
    label-side: right),
  edge(<console>, <serve>, "-|>"),
  edge(<console>, <ui>, "-|>", say("embeds"), label-side: left),
)
