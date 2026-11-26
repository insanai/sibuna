// SID 0021: the life of a DNS-01 TXT record, from the file that remembers it to its
// cleanup. The check asks every authoritative server, every 2 s until the timeout.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (12mm, 7mm),
  data((0, 0), "Write `certs/NAME/dns`", "the owner and the value", name: <save>),
  step((0, 1), "Publish the TXT record", "through the provider", name: <publish>),
  decision((0, 2), "Every server\nshows it?", name: <check>),
  sibuna((0, 3), "Respond to the challenge", name: <respond>),
  step((0, 4), "The order ends", "with or without a certificate", name: <ends>),
  step((0, 5), "Remove the TXT record,\nthen the file", kind: "accent", name: <cleanup>),
  outcome((1, 3), "Attempt fails", "`ACME010`", kind: "stop", name: <timeout>),
  edge(<save>, <publish>, "-|>"),
  edge(<publish>, <check>, "-|>"),
  main-edge(<check>, <respond>, "-|>", say("yes"), label-side: left),
  step((1, 2), "Wait 2 s", kind: "wait", name: <wait>),
  edge(<check>, <wait>, "-|>", say("not yet"), label-side: right),
  edge(<wait>, <check>, "-|>", bend: -45deg, say("ask again"), label-side: right),
  tone-edge("stop", <wait>, <timeout>, "-|>", say("timeout"), label-side: left),
  edge(<respond>, <ends>, "-|>"),
  edge(<timeout>, <ends>, "-|>"),
  main-edge(<ends>, <cleanup>, "-|>"),
  note((1, 5), "A file found at the start\nis cleaned up first", name: <start>),
  edge(<start>, <cleanup>, "-|>", dash: "dashed"),
)
