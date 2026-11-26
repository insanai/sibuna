// SID 0026: a TCP or HTTP connection forwarded from the node that received it to the
// owner of its client.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#sequence(
  (
    actor("client", "Client", kind: "party"),
    actor("b", "Node B\nreceives", kind: "accent"),
    actor("a", "Node A\nthe owner", kind: "accent"),
  ),
  (
    msg("client", "b", "TCP connect"),
    act("b", "Check drain, rate and a flow slot; compute the owner"),
    msg("b", "a", "Connect to the forwarding port; the 76-byte header"),
    act("a", "Check roster, tag, epoch, frontend, drain, slot and rate"),
    msg("a", "b", "17-byte status: 1, accepted", reply: true, accent: true,
      note: "Status 2 declines: B serves the client itself. Status 3 denies: B closes."),
    msg("client", "b", "Bytes, both ways", accent: true),
    msg("b", "a", "Relayed unread, both ways", accent: true),
    act("a", "Serve with the client address of the header", accent: true),
  ),
  spacing: 48,
  note-width: 40,
)
