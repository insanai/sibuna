#import "packet.typ": packet

#packet((
  ([0], [4], [Magic SE, version 1, kind 6]),
  ([4], [16], [Sender boot nonce]),
  ([20], [8], [Sequence]),
  ([28], [1], [Entry count k]),
  ([29], [32 × k], [k entries: key (16), server (8), end (8)]),
  ([n - 16], [16], [Authentication tag]),
))
