// SID 0025: the affinity datagram, kind 6, in wire order. It holds at most 36 entries in
// 1,200 bytes; n is the length of the datagram.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#strip((
  field("Magic `SE`,\nversion 1, kind 6", "4", offset: "0", weight: 1.6, kind: "quiet"),
  field("Sender boot nonce", "16", offset: "4", weight: 1.3, kind: "quiet"),
  field("Sequence", "8", offset: "20", weight: 1, kind: "quiet"),
  field("Count k", "1", offset: "28", weight: 0.8),
  field("k entries", "32 × k", offset: "29", weight: 1.5, kind: "accent"),
  field("Tag", "16", offset: "n - 16", weight: 1),
), width: 145mm, note: "Offsets and sizes in bytes")
#v(6pt)
#strip((
  field("Key", "16", offset: "0", kind: "accent"),
  field("Server", "8", offset: "16", kind: "accent"),
  field("End", "8", offset: "24", kind: "accent"),
), width: 80mm, title: "One entry")
