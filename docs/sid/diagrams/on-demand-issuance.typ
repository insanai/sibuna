// SID 0021: certificate selection on demand. The handshake applies the cheap guards and
// never talks to a network; the ACME thread applies the guards that cost time.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (13mm, 7mm),
  caption-node((0, -0.7), "TLS handshake", name: <tls-title>),
  caption-node((2, -0.7), "ACME thread", name: <acme-title>),
  step((0, 0), "Read the ClientHello\nand the name", name: <hello>),
  decision((0, 1), "Admissible,\nno certificate?", name: <admissible>),
  step((0, 2), "Queue the name and wait", kind: "wait", name: <wait>),
  sibuna((0, 4), "Continue the certificate selection", width: 40mm, name: <resume>),
  store((2, 0), "Look in the storage", name: <stored>),
  decision((2, 1), "`ask` allows,\na rate token?", name: <guards>),
  step((2, 2), "Order or issue,\nthen install", kind: "accent", name: <install>),
  step((2, 3), "Wake the waiters", name: <wake>),
  group((<tls-title>, <hello>, <resume>, <wait>), name: <tls>),
  group((<acme-title>, <stored>, <wake>), name: <acme>),
  edge(<hello>, <admissible>, "-|>"),
  edge(<admissible>, <wait>, "-|>", say("yes"), label-side: left),
  edge(<admissible>, (-0.9, 1), (-0.9, 4), <resume>, "-|>", corner-radius: 5pt,
    say("no: already\nserved, or not\nadmissible"), label-side: right, label-pos: 0.45),
  edge(<wait>, <resume>, "-|>", dash: "dashed", say("wait limit reached"), label-side: left,
    label-pos: 0.3),
  edge(<wait>, <stored>, "-|>", say("the name"), label-side: left, label-pos: 0.62),
  edge(<stored>, <guards>, "-|>", say("not there"), label-side: left),
  edge(<stored>, (2.85, 0), (2.85, 3), <wake>, "-|>", corner-radius: 5pt,
    say("loaded"), label-side: left, label-pos: 0.5),
  main-edge(<guards>, <install>, "-|>", say("yes"), label-side: left),
  edge(<guards>, (1.25, 1), (1.25, 3), <wake>, "-|>", corner-radius: 5pt, say("denied"),
    label-side: right, label-pos: 0.6),
  main-edge(<install>, <wake>, "-|>"),
  main-edge(<wake>, <resume>, "-|>", say("if still waiting"), label-side: left),
)
