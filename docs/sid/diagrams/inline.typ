// SID 0017: one request on an HTTP/2 or HTTP/3 stream. The decision is a function call,
// and the server connection belongs to the runtime.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (12mm, 8mm),
  party((0, 1), "HTTP/2 or HTTP/3", "stream", name: <stream>),
  data((1, 1), "Offer", "head, start of body", name: <offer>),
  decision((2, 1), "Decide", "firewall, routes", name: <decide>),
  outcome((3, 0), "Answer", "Sibuna's response", kind: "wait", name: <answer>),
  step((3, 2), "Server", "pooled HTTP/1.1", name: <server>),
  edge(<stream>, <offer>, "-|>", say("translate,\nrender"), label-side: left),
  edge(<offer>, <decide>, "-|>", say("call"), label-side: left),
  tone-edge("wait", <decide>, <answer>, "-|>", say("refused,\nchallenged"), label-side: left),
  main-edge(<decide>, <server>, "-|>", say("`Forward`:\ntarget, head"), label-side: right),
  edge(<answer>, (0, 0), <stream>, "-|>", corner-radius: 5pt),
  main-edge(<server>, (0, 2), <stream>, "-|>", say("response"), label-side: left,
    label-pos: 0.3, corner-radius: 5pt),
)
