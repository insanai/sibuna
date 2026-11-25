#import "wireframe.typ": *
#set text(font: "Noto Sans")

#wire(170, 125, H => {
  import cetz.draw: *
  shell(H, 170, "Attack events")
  content((29, H - 12), anchor: "west", text(size: 6.5pt, weight: "bold")[Attack events])
  panel(H, 75, 9.5, 30, 5, [BY SOURCE · RAW], size: 5pt)
  panel(H, 28, 16, 140, 6, [node ▾  category ▾  rule ▾  address  country ▾  path  period ▾  ● live   export ↓], size: 5pt)
  table_rows(H, 28, 24, 140, 10, (([action], 10), ([URL], 46), ([category], 14), ([rule], 18), ([address · country], 26), ([time], 18), ([], 8)))
  // modal
  rect((40, 4), (160, H - 20), stroke: 0.5pt + ink, fill: white)
  rect((42, H - 22 - 3.5), (56, H - 22), stroke: none, fill: rgb("fef2f2"), radius: 0.8)
  content((49, H - 23.8), text(size: 4.5pt, weight: "bold", fill: red)[waf:sqli])
  content((58, H - 23.8), anchor: "west", text(size: 5pt, fill: ink)[GET /search?q=%27%20OR%201%3D1-- · node 2 · 2026-09-08 12:41:07])
  for (i, r) in (("address", "198.51.100.7 · Unknown (documentation IP) · Ban 24 h · Allow"), ("JA4 (from ingress)", "Not recorded · requires trusted-ingress capture"), ("payload", "Query excerpt: ' OR 1=1-- · matched span not recorded"), ("rule · score", "waf:sqli (terminal) · numeric score not recorded"), ("campaign", "41 · 3 incidents · nearest: 12:38:51 node 1 (0.12), 11:02:10 node 3 (0.21)"), ("id", "node 2 · seq 88,412")).enumerate() {
    let y = 28 + i * 5.2
    content((43, H - y - 2), anchor: "west", text(size: 4.5pt, fill: gray)[#r.at(0)])
    content((66, H - y - 2), anchor: "west", text(size: 4.5pt, fill: ink)[#r.at(1)])
  }
  panel(H, 42, 61, 116, 5, [REQUEST · RESPONSE                                   UTF-8 ▾], size: 4.5pt)
  panel(H, 42, 67, 116, 30, none, bg: rgb("f8fafc"))
  for (i, l) in ("GET /search?q=%27%20OR%201%3D1-- HTTP/1.1", "Host: shop.example", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) …", "Accept: text/html,application/xhtml+xml,*/*;q=0.8", "Cookie: [redacted]", "Response: local denial · no origin response").enumerate() {
    content((44, H - 70 - i * 4.2), anchor: "west", text(size: 4.3pt, font: "DejaVu Sans Mono", fill: ink)[#l])
  }
  panel(H, 42, 99, 22, 5, [Copy as cURL], size: 4.5pt)
  panel(H, 138, 99, 20, 5, [Close], bg: blue-light, weight: "bold", size: 4.5pt)
})
