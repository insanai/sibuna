// SID 0022: the ban datagram, kind 3, in wire order. Offsets are bytes from the start;
// n is the length of the datagram, at most 1,200 bytes.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#strip((
  field("Magic `SE`,\nversion 1, kind 3", "4", offset: "0", weight: 1.6, kind: "quiet"),
  field("Sender boot nonce", "16", offset: "4", weight: 1.3, kind: "quiet"),
  field("Sequence", "8", offset: "20", weight: 1, kind: "quiet"),
  field("Count k", "1", offset: "28", weight: 0.8),
  field("k entries", "variable", offset: "29", weight: 1.5, kind: "accent"),
  field("Tag", "16", offset: "n - 16", weight: 1),
), width: 145mm, note: "Offsets and sizes in bytes")
#v(6pt)
#strip((
  field("End", "8", offset: "0", kind: "accent"),
  field("Key length", "1", offset: "8", kind: "accent"),
  field("Key", "at most 64", offset: "9", weight: 1.6, kind: "accent"),
), width: 80mm, title: "One entry")
