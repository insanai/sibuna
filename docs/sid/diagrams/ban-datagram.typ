#import "packet.typ": packet

#packet((
  ([0], [4], [Magic SE, version 1, kind 3]),
  ([4], [16], [Sender boot nonce]),
  ([20], [8], [Sequence]),
  ([28], [1], [Entry count k]),
  ([29], [variable], [k entries: end (8), key length (1), key]),
  ([n - 16], [16], [Authentication tag]),
))
