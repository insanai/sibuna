// SID 0025: the fleet-cap status datagram, kind 7, in wire order. It is addressed to one
// peer and holds at most 39 records; n is the length of the datagram.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#strip((
  field("Magic `SE`,\nversion 1, kind 7", "4", offset: "0", weight: 1.6, kind: "quiet"),
  field("Sender boot nonce", "16", offset: "4", weight: 1.3, kind: "quiet"),
  field("Sequence", "8", offset: "20", weight: 1, kind: "quiet"),
  field("Epoch", "8", offset: "28", weight: 0.8),
  field("Echo", "8", offset: "36", weight: 0.8),
  field("Count k", "1", offset: "44", weight: 0.95),
  field("k records", "29 × k", offset: "45", weight: 1.2, kind: "accent"),
  field("Tag", "16", offset: "n - 16", weight: 0.8),
), width: 150mm, note: "Offsets and sizes in bytes")
#v(6pt)
#strip((
  field("Key", "8", offset: "0", kind: "accent"),
  field("`gave`", "8", offset: "8", kind: "accent"),
  field("`got`", "8", offset: "16", kind: "accent"),
  field("`want`", "4", offset: "24", kind: "accent"),
  field("`f`", "1", offset: "28", weight: 0.6, kind: "accent"),
), width: 105mm, title: "One record")
