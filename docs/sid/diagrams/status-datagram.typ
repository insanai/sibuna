#import "packet.typ": packet

#packet((
  ([0], [4], [Magic SE, version 1, kind 7]),
  ([4], [16], [Sender boot nonce]),
  ([20], [8], [Sequence]),
  ([28], [8], [Epoch]),
  ([36], [8], [Echo]),
  ([44], [1], [Record count k]),
  ([45], [29 × k], [k records: key (8), gave (8), got (8), want (4), f (1)]),
  ([n - 16], [16], [Authentication tag]),
))
