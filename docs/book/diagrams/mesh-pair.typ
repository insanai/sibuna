// cluster.rst: what flows between two nodes, by port. The kind of each datagram is in
// parentheses.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#let channel(y, title, body, kind) = edge((0, y), (2, y), "<|-|>",
  stroke: thin + tones.at(kind).at(1), label-side: left, label-sep: 2pt,
  block(width: 78mm, align(center, text(fill: tones.at(kind).at(1).darken(20%),
    weight: "semibold", size: 8.5pt, rich(title)) + linebreak() + small(body))))

#flow(
  spacing: (2mm, 15mm),
  sibuna((0, 1), "Node A", name: <a>, enclose: ((0, 0.2), (0, 3.1))),
  sibuna((2, 1), "Node B", name: <b>, enclose: ((2, 0.2), (2, 3.1))),
  node((1, 0), none, width: 80mm, height: 1pt, stroke: none),
  channel(1, "UDP, mesh port 7946 (SID 0015, 0022, 0025)",
    "probes; bans (3); commands (4); lifts (5);\nsticky entries (6); status of shares (7)", "wait"),
  channel(2, "TCP, mesh port 7946 (SID 0023)",
    "the configuration file; the digest of the file", "step"),
  channel(3, "TCP and UDP, mesh port + 1 (SID 0026)",
    "forwarded connections and datagrams", "accent"),
)
