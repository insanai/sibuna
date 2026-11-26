// SID 0023: the message that carries a configuration file to a peer over TCP. n is the
// length of the message.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#strip((
  field("`SEC1`", "4", offset: "0", weight: 0.8, kind: "quiet"),
  field("Stamp", "8, Unix ms", offset: "4", weight: 1.1, kind: "quiet"),
  field("Length", "4", offset: "12", weight: 0.9, kind: "quiet"),
  field("The file", "length, at most 256 KiB", offset: "16", weight: 2.2, kind: "accent"),
  field("Tag", "32, keyed BLAKE3", offset: "n - 32", weight: 1.3),
), width: 135mm, note: "Offsets and sizes in bytes")
