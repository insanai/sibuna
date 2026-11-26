// SID 0015: a mockup of the proposed operator view of mesh links, node pressure and
// backend drain state. The figures are illustrative.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

// A small state chip in a tone.
#let chip(body, kind) = box(fill: tones.at(kind).at(0), stroke: 0.6pt + tones.at(kind).at(1),
  radius: 6pt, inset: (x: 5pt, y: 2.5pt), text(size: 7.5pt, weight: "semibold",
  fill: tones.at(kind).at(1).darken(15%), body))

// A card with a title band.
#let card(title, kind, body, width: 100%) = block(width: width, stroke: thin +
  tones.at(kind).at(1), radius: 4pt, clip: true, fill: shell, stack(
  block(width: 100%, fill: tones.at(kind).at(0), inset: (x: 7pt, y: 5pt),
    text(weight: "semibold", fill: tones.at(kind).at(1).darken(15%), title)),
  block(width: 100%, inset: (x: 7pt, y: 6pt), text(size: 8pt, body))))

#let row(..cells) = grid(columns: (auto, 1fr, auto), column-gutter: 6pt, ..cells)

#let node-card(name, state, kind, tcp, udp, memory) = card([#name #h(1fr) #chip(state, kind)],
  kind, stack(spacing: 4pt,
    [*TCP flows* #h(1fr) #tcp],
    [*UDP flows* #h(1fr) #udp],
    [*RAM and mmap* #h(1fr) #memory],
    [*Revision* #h(1fr) #code("42"), synced]))

#let server(state, kind, name, address, detail) = row(chip(state, kind),
  [*#name* #small(address)], small(detail))

#block(width: 160mm, fill: paper, stroke: thin + rule, radius: 6pt, inset: 8pt, stack(
  spacing: 8pt,
  grid(columns: (1fr, auto), align: horizon,
    text(weight: "bold", size: 9pt, fill: ink, [Console #h(4pt) / #h(4pt) Topology and
      cluster mesh]),
    chip("ATDP: LAN mesh, 3 of 3 healthy, p95 0.42 ms", "good")),
  grid(columns: (1fr, 13mm, 1fr, 13mm, 1fr), align: horizon,
    node-card("fra-edge-01", "live", "good", [142,810], [89,120], [68%, 4%]),
    align(center, small("CRDT\n0.3 ms")),
    node-card("fra-edge-02", "live", "good", [139,405], [91,004], [65%, 3%]),
    align(center, small("one-hop\nCPF")),
    node-card("fra-edge-03", "draining", "wait", [12,104 in flight], [to nodes 1 and 2],
      [21%, 0%])),
  grid(columns: (1fr, 1fr), column-gutter: 8pt,
    card([Pool #code("api_tcp_origin")],
      "accent", stack(spacing: 5pt, small("TCP, Maglev, PROXY v2 and JA4"),
        server("up", "good", "api-1", "10.20.1.11:8443", "w 100, 48,210 of 50k, 1.1 ms"),
        server("up", "good", "api-2", "10.20.1.12:8443", "w 100, 47,905 of 50k, 1.2 ms"),
        server("drain", "wait", "api-3", "10.20.1.13:8443", "w 50, 1,204 of 25k, 1.4 ms"))),
    card([Pool #code("quic_h3_fleet")],
      "party", stack(spacing: 5pt, small("UDP, tuple affinity, rate limit"),
        server("up", "good", "h3-1", "10.20.2.11:443", "w 100, 90,112 sessions, 0.6 ms"),
        server("up", "good", "h3-2", "10.20.2.12:443", "w 100, 89,992 sessions, 0.7 ms"),
        row(chip("shed", "stop"), [*UDP rate limit*],
          small("412,900 datagrams/s shed"))))),
))
