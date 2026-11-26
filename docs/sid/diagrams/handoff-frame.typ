// SID 0029: a frame of the upgrade socket, a header of seven bytes and a payload.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#strip((
  field("Kind", "1", offset: "0", weight: 0.8, kind: "quiet"),
  field("Payload length", "4, little endian", offset: "1", weight: 1.4, kind: "quiet"),
  field("Descriptors", "2", offset: "5", weight: 1.1, kind: "quiet"),
  field("Payload", "at most 65,536", offset: "7", weight: 2, kind: "accent"),
), width: 125mm, note: "Offsets and sizes in bytes")
