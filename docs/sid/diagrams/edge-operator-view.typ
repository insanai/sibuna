#import "@preview/cetz:0.5.2"
#set text(font: "Libertinus Serif", size: 7.4pt, fill: rgb("#172033"))
#cetz.canvas(length: 1cm, {
  import cetz.draw: *

  let ink = rgb("#172033")
  let muted = rgb("#64748b")
  let blue = rgb("#1e40af")
  let blue-bg = rgb("#eff6ff")
  let green = rgb("#15803d")
  let green-bg = rgb("#f0fdf4")
  let amber = rgb("#b45309")
  let amber-bg = rgb("#fffbeb")
  let red = rgb("#b91c1c")
  let red-bg = rgb("#fef2f2")
  let violet = rgb("#6d28d9")
  let violet-bg = rgb("#f5f3ff")
  let border = rgb("#cbd5e1")

  // Outer Browser/Console Frame
  rect((0.0, 0.0), (14.4, 8.35), radius: 4pt, fill: rgb("#f8fafc"), stroke: 0.9pt + border)
  rect((0.0, 7.45), (14.4, 8.35), radius: (top: 4pt), fill: white, stroke: 0.7pt + border)
  content((0.3, 7.9), anchor: "west",
    text(weight: "bold", size: 7.4pt, fill: ink, "CONSOLE  /  TOPOLOGY & CLUSTER MESH"))
  rect((9.25, 7.62), (14.15, 8.18), radius: 9pt, fill: green-bg, stroke: 0.65pt + green)
  content((11.7, 7.9), text(weight: "bold", size: 6.5pt, fill: green,
    "ATDP: LAN PoP Mesh (3/3 Healthy / p95 0.42 ms)"))

  // Edge Node Cards Row
  let node-card(x, title, role-col, role-bg, flows, kv-txt) = {
    rect((x, 4.75), (x + 4.2, 7.05), radius: 3pt, fill: white, stroke: 0.8pt + role-col)
    rect((x, 6.45), (x + 4.2, 7.05), radius: (top: 3pt), fill: role-bg, stroke: 0.6pt + role-col)
    content((x + 2.1, 6.75), text(weight: "bold", size: 7.0pt, fill: role-col.darken(15%), title))
    content((x + 2.1, 5.6), box(width: 3.85cm, align(left, text(size: 6.4pt, [
      - *Flows:* #flows\
      - *KV RAM / Mmap:* #kv-txt\
      - *Rev:* `42` (synced) / `[Drain]`
    ]))))
  }

  node-card(0.3, "Node 1 (fra-edge-01 / LIVE)", green, green-bg, "142,810 TCP / 89,120 UDP", "68% / 4% NVMe")
  node-card(5.1, "Node 2 (fra-edge-02 / LIVE)", green, green-bg, "139,405 TCP / 91,004 UDP", "65% / 3% NVMe")
  node-card(9.9, "Node 3 (fra-edge-03 / DRAINING)", amber, amber-bg, "12,104 in-flight (CPF -> 1,2)", "21% / 0% NVMe")

  // Mesh peer links between nodes
  line((4.5, 5.9), (5.1, 5.9), stroke: 0.8pt + green, mark: (start: "stealth", end: "stealth", fill: green, scale: 0.5))
  content((4.8, 6.2), text(size: 5.8pt, fill: green, "CRDT\n0.3ms"))
  line((9.3, 5.9), (9.9, 5.9), stroke: (paint: amber, thickness: 0.8pt, dash: "dashed"),
    mark: (end: "stealth", fill: amber, scale: 0.5))
  content((9.6, 6.2), text(size: 5.8pt, fill: amber, "1-Hop\nCPF"))

  // Backend Pool Matrix (Bottom half)
  rect((0.3, 0.3), (7.05, 4.05), radius: 3pt, fill: white, stroke: 0.75pt + blue)
  content((0.5, 3.72), anchor: "west",
    text(weight: "bold", size: 6.7pt, fill: blue, "Backend: api_tcp_origin (TCP / Maglev / PROXYv2+JA4)"))
  line((0.45, 3.45), (6.9, 3.45), stroke: 0.5pt + border)
  content((3.68, 1.9), box(width: 6.35cm, align(left, text(size: 6.3pt, [
    `[UP]`    *api-1* (`10.20.1.11:8443`) w=100 flows: `48,210/50k` (`1.1ms`)\
    `[UP]`    *api-2* (`10.20.1.12:8443`) w=100 flows: `47,905/50k` (`1.2ms`)\
    `[DRAIN]` *api-3* (`10.20.1.13:8443`) w=50  flows: `1,204/25k`  (`1.4ms`)
  ]))))

  rect((7.35, 0.3), (14.1, 4.05), radius: 3pt, fill: white, stroke: 0.75pt + violet)
  content((7.55, 3.72), anchor: "west",
    text(weight: "bold", size: 6.7pt, fill: violet, "Backend: quic_h3_fleet (UDP / Tuple Affinity / Rate Limit)"))
  line((7.5, 3.45), (13.95, 3.45), stroke: 0.5pt + border)
  content((10.72, 1.9), box(width: 6.35cm, align(left, text(size: 6.4pt, [
    `[UP]`    *h3-1*  (`10.20.2.11:443`)   w=100  sessions: `90,112`   ewma: `0.6ms`\
    `[UP]`    *h3-2*  (`10.20.2.12:443`)   w=100  sessions: `89,992`   ewma: `0.7ms`\
    `[SHED]`  *UDP Rate Limit:* `412,900/s` datagrams shed (budget reached)
  ]))))

  line((2.4, 4.75), (3.4, 4.05), stroke: 0.75pt + blue, mark: (end: "stealth", fill: blue, scale: 0.55))
  line((7.2, 4.75), (3.9, 4.05), stroke: 0.75pt + blue, mark: (end: "stealth", fill: blue, scale: 0.55))
  line((2.6, 4.75), (10.3, 4.05), stroke: 0.75pt + violet, mark: (end: "stealth", fill: violet, scale: 0.55))
  line((7.4, 4.75), (10.9, 4.05), stroke: 0.75pt + violet, mark: (end: "stealth", fill: violet, scale: 0.55))
})
