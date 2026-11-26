// cluster.rst and operations.rst: the listener handoff of SID 0029.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#sequence(
  (
    actor("old", "Old process"),
    actor("new", "Replacement", kind: "accent"),
  ),
  (
    msg("new", "old", "`HELLO`"),
    msg("old", "new", "`LISTENERS` with `SCM_RIGHTS`"),
    msg("new", "old", "`READY`", accent: true, note: "Nobody reads UDP; the kernel holds the datagrams"),
    act("old", "Pause UDP, keep accepting TCP"),
    msg("old", "new", "`FLOWS`, then `COMMIT`"),
    act("new", "Adopt the mappings, accept TCP"),
    msg("new", "old", "`DONE`", accent: true),
    act("new", "Read UDP", accent: true),
    act("old", "Drain TCP, exit"),
  ),
  spacing: 60,
)
