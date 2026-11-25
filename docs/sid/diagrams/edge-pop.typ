#import "@preview/cetz:0.5.2"
#set text(font: "Libertinus Serif", size: 8.0pt, fill: rgb("#172033"))
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
  let slate-bg = rgb("#f8fafc")

  let card(x1, y1, x2, y2, fill-c, stroke-c, title, body) = {
    rect((x1, y1), (x2, y2), radius: 3pt, fill: fill-c, stroke: 0.75pt + stroke-c)
    content(((x1 + x2) / 2, (y1 + y2) / 2), box(width: (x2 - x1 - 0.25) * 1cm, align(center, {
      text(weight: "bold", size: 7.7pt, fill: stroke-c.darken(15%), title)
      if body != "" {
        linebreak()
        text(size: 6.7pt, fill: ink, body)
      }
    })))
  }

  let arr(p1, p2, col, lbl: none) = {
    line(p1, p2, stroke: 0.8pt + col, mark: (end: "stealth", fill: col, scale: 0.65))
    if lbl != none {
      content(((p1.at(0) + p2.at(0)) / 2, (p1.at(1) + p2.at(1)) / 2),
        box(fill: white, inset: 1.3pt, text(size: 6.6pt, fill: col.darken(10%), lbl)))
    }
  }

  // Tier 0: Clients & Attackers
  card(0.0, 11.4, 6.8, 12.6, green-bg, green, "Legitimate Clients (TCP / UDP / HTTPS / QUIC)",
    "Browsers, APIs, DNS, WireGuard, VoIP, Gaming")
  card(7.6, 11.4, 14.4, 12.6, red-bg, red, "Volumetric & State-Exhaustion Adversaries",
    "SYN/UDP Spoof Floods, Million-IP Botnets, TLS/HTTP Scrapers")

  // Tier 1: Network Perimeter
  card(1.6, 9.6, 12.8, 10.7, blue-bg, blue,
    "Edge Transit / IXP - BGP Anycast VIPs + L3/L4 ECMP Hardware Hashing",
    "Stateless 5-tuple ECMP spray across active Sibuna Edge hosts; BIRD/FRR announces /24 & /48 health")
  arr((3.4, 11.4), (4.8, 10.7), green)
  arr((11.0, 11.4), (9.6, 10.7), red)

  // Tier 2: Sibuna Edge Host Box
  rect((0.0, 2.7), (10.3, 8.85), radius: 4pt, fill: slate-bg, stroke: 1.0pt + blue)
  content((0.25, 8.52), anchor: "west",
    text(weight: "bold", size: 8.2pt, fill: blue, "Sibuna Edge Host i (Node 1..K in PoP - Zero NIC Takeover)"))

  // Inside Host: NIC + Kernel Cooperative Layer
  card(0.3, 6.85, 6.7, 8.15, blue-bg, blue,
    "NIC RSS + Kernel SO_REUSEPORT + cBPF",
    "SYN cookies, TCP_DEFER_ACCEPT, io_uring, recvmmsg, kqueue")
  card(7.0, 6.85, 10.0, 8.15, white, muted,
    "Co-Resident OS Stack",
    "BIRD/FRR BGP, SSHd,\nICMP/ARP untouched")

  // Pinned Workers
  card(0.3, 4.75, 3.35, 6.35, green-bg, green,
    "Core 0 Worker",
    "64B FlowTable + Slab\nMaglev/P2C + Plugins\nStateless UDP Gate")
  card(3.55, 4.75, 6.7, 6.35, green-bg, green,
    "Core 1..N Workers",
    "Shared-Nothing Loops\nTLS SNI + Native JA4\nGCRA + PoSW Gate")

  // Mmap KV Spill Arena
  card(0.3, 2.95, 6.7, 4.3, amber-bg, amber,
    "sibuna-kv (RAM cache + optional mmap spill service)",
    "Bounded spill queue for discardable cache entries")

  // Local Control Plane inside Host
  card(7.0, 2.95, 10.0, 6.35, violet-bg, violet,
    "Local Control Plane",
    "JLV/JSON Eval & RCU\nActive Health Prober\nSCM_RIGHTS Hot-FD\nSWIM + CRDT Gossip\nSPOE Offload Client")

  arr((5.0, 9.6), (3.5, 8.15), blue, lbl: "VIP Flows")
  arr((1.8, 6.85), (1.8, 6.35), green)
  arr((5.1, 6.85), (5.1, 6.35), green)
  arr((1.8, 4.75), (1.8, 4.3), amber)
  arr((5.1, 4.75), (5.1, 4.3), amber)
  line((7.0, 5.55), (6.7, 5.55), stroke: (paint: violet, thickness: 0.75pt, dash: "dashed"),
    mark: (end: "stealth", fill: violet, scale: 0.6))

  // Peer Cluster Mesh + Shared Control Plane (Right side)
  card(10.75, 6.15, 14.4, 8.65, green-bg, green,
    "Sibling Edge Nodes (2..K)",
    "UDP SWIM Heartbeats\nDelta-CRDT Stick-Tables\n1-Hop CPF Tunnel\n(Auto-tuned by RTT)")
  card(10.75, 2.95, 14.4, 5.75, violet-bg, violet,
    "Cluster Control Plane",
    "sibuna.jlv (GitOps) +\nPostgreSQL HA Store\nNOTIFY sibuna_policy\nWASM Operator Console")

  line((10.0, 7.4), (10.75, 7.4), stroke: 0.8pt + green,
    mark: (start: "stealth", end: "stealth", fill: green, scale: 0.6))
  line((10.0, 4.35), (10.75, 4.35), stroke: 0.8pt + violet,
    mark: (start: "stealth", end: "stealth", fill: violet, scale: 0.6))

  // Tier 3: Origin Fleets
  card(0.0, 0.3, 4.5, 1.75, blue-bg, blue,
    "TCP / TLS Origin Pool",
    "PROXYv2 + SNI + JA4 TLV\nDatabases, gRPC, TLS Ingress")
  card(4.95, 0.3, 9.45, 1.75, green-bg, green,
    "UDP / QUIC Origin Pool",
    "4-Tuple NAT / CID Affinity\nHTTP/3, DNS, Media, WireGuard")
  card(9.9, 0.3, 14.4, 1.75, amber-bg, amber,
    "HTTP/1.1 Protected Origins",
    "Sibuna Gate / Shield WAF\nStriped Keep-Alive Pools")

  arr((2.2, 2.7), (2.2, 1.75), blue, lbl: "L4 TCP")
  arr((5.1, 2.7), (7.1, 1.75), green, lbl: "L4 UDP")
  arr((6.4, 2.7), (11.8, 1.75), amber, lbl: "L7 HTTP")
})
