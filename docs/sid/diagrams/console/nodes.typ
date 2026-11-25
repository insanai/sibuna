#import "wireframe.typ": *
#set text(font: "Noto Sans")

#wire(170, 100, H => {
  import cetz.draw: *
  shell(H, 170, "Nodes")
  content((29, H - 12), anchor: "west", text(size: 6.5pt, weight: "bold")[Nodes · edge-eu · leader: node 2 · last commit 4,118 · lag 0])
  for (i, n) in (("node 1 · 10.0.0.1 · follower", "healthy · v0.1.0 · up 3d 4h"), ("node 2 · 10.0.0.2 · leader", "healthy · v0.1.0 · up 3d 4h"), ("node 3 · 10.0.0.3 · follower", "storage degraded · serving last snapshot")).enumerate() {
    let x = 28 + i * 47
    panel(H, x, 16, 45, 60, none, bg: rgb("fcfcfd"))
    content((x + 2, H - 20), anchor: "west", text(size: 5.5pt, weight: "bold")[#n.at(0)])
    content((x + 2, H - 25), anchor: "west", text(size: 5pt, fill: if i == 2 { red } else { green })[#n.at(1)])
    line_chart(H, x + 2, 28, 41, 14, series: 1)
    content((x + 2, H - 46), anchor: "west", text(size: 5pt, fill: ink)[2,140 req/s · 21 MiB · 0.9 core])
    content((x + 2, H - 51), anchor: "west", text(size: 5pt, fill: ink)[bans 312 · challenges 64 k · denied 21 k])
    panel(H, x + 2, 56, 19, 6, [Drain], size: 5pt)
    panel(H, x + 23, 56, 20, 6, [Clear bans], size: 5pt)
    panel(H, x + 2, 64, 41, 6, [Open console ↗], size: 5pt)
  }
  panel(H, 28, 80, 140, 14, [Challenge verification is issuer-bound: route a solver's fetch and verify to the same node. Rate limits and spent sets are per node.], bg: amber-light, size: 5pt)
})
