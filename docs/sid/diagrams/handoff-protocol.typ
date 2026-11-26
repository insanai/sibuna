// SID 0029: the frames of the upgrade handoff and the two local cutover points. The
// replacement connects; the old process gives, the replacement takes.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#sequence(
  (
    actor("old", "Old process"),
    actor("new", "Replacement", kind: "accent"),
  ),
  (
    act("new", "Check the file, connect to the upgrade socket"),
    msg("new", "old", "`HELLO`: the range of versions",
      note: "Both ends have checked the peer with `SO_PEERCRED`"),
    msg("old", "new", "`LISTENERS`: the version, the kind and address of each listener, one descriptor each"),
    act("new", "Verify the descriptors; start HTTP, logs and counters without reading"),
    begin-frame("cutover: nobody reads UDP, at most 10 s"),
    msg("new", "old", "`READY`", accent: true),
    act("old", "Pause UDP; TCP stays open"),
    msg("old", "new", "`FLOWS`: mappings with their server sockets"),
    msg("old", "new", "`COMMIT`: the number of mappings sent"),
    act("new", "Adopt the mappings, accept TCP"),
    msg("new", "old", "`DONE`: mappings adopted and dropped", accent: true),
    end-frame(),
    act("new", "Read UDP; bind the upgrade and admin sockets; report ready", accent: true),
    act("old", "Stop accepting, forget the mappings, drain TCP, exit 0"),
  ),
  spacing: 62,
  note-width: 38,
)
