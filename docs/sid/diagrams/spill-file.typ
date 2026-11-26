// SID 0027: the layout of the spill file, its header and a slot (crates/spill/src/format.rs).
// All numbers are little-endian.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#strip((
  field("Page 0: the header", "64 used of 4,096", offset: "0", weight: 1.2, kind: "quiet"),
  field("Page 1: a write counter of 32 bits for each shard", "4,096", offset: "4096",
    weight: 1.6, kind: "quiet"),
  field("Slots: 64 shards × B buckets × 4 slots", "64 each", offset: "8192", weight: 2.2,
    kind: "accent"),
), width: 150mm, title: "The file", note: "Offsets and sizes in bytes")
#v(8pt)
#strip((
  field("Magic `SIBSPILL`", "8", offset: "0", weight: 1.35, kind: "quiet"),
  field("Version", "4", offset: "8", weight: 1),
  field("Slot length", "4", offset: "12", weight: 1),
  field("Shards", "4", offset: "16", weight: 0.9),
  field("Ways", "4", offset: "20", weight: 0.75),
  field("Buckets\nper shard", "8", offset: "24", weight: 1.2),
  field("File length", "8", offset: "32", weight: 1),
  field("Salt", "8", offset: "40", weight: 0.75),
  field("Creation time", "8", offset: "48", weight: 1.05),
  field("Checksum", "8", offset: "56", weight: 1.35, kind: "wait"),
), width: 150mm, title: "The header")
#v(8pt)
#strip((
  field("Checksum", "8", offset: "0", weight: 1.1, kind: "wait"),
  field("Expiry", "8", offset: "8", weight: 1),
  field("Stamp", "4", offset: "16", weight: 0.9),
  field("Key length", "1", offset: "20", weight: 1),
  field("Value length", "1", offset: "21", weight: 1.05),
  field("Zero", "2", offset: "22", weight: 0.8, kind: "quiet"),
  field("Key", "24", offset: "24", weight: 1.3, kind: "accent"),
  field("Value", "16", offset: "48", weight: 1.1, kind: "accent"),
), width: 150mm, title: "A slot")
