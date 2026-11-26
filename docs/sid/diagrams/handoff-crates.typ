// SID 0029: the code of the listener handoff in layers. Each layer uses the one below;
// `sibuna-upgrade` knows sockets and addresses and nothing of the edge.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#let layer(at, title, body, kind: "step", name: none) = step(at, title, body, kind: kind,
  name: name, width: 120mm)

#flow(
  spacing: (6mm, 6mm),
  layer((0, 0), "`cmd/sibuna`", "`edge/upgrade.rs`: the gate of the old process and the start of the replacement",
    kind: "accent", name: <cmd>),
  layer((0, 1), "`crates/lb`", "`bind_inherited`, `lend_listeners`, `freeze_datagrams`, `lend_flows`, `resume_datagrams`, `adopt_flows`, `arm_streams`, `arm_datagrams`, `release_listeners`, the waker",
    name: <lb>),
  layer((0, 2), "`crates/upgrade`", "the socket, the frames, the two endpoints of the protocol and the FFI: `sendmsg`, `recvmsg`, `SO_PEERCRED`, `SO_TYPE`, `kill`",
    name: <upgrade>),
  edge(<cmd>, <lb>, "-|>"),
  edge(<lb>, <upgrade>, "-|>"),
)
