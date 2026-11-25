#import "wireframe.typ": *
#set text(font: "Noto Sans")

#wire(170, 118, H => {
  import cetz.draw: *
  shell(H, 170, "Statistics")
  content((29, H - 12), anchor: "west", text(size: 6.5pt, weight: "bold")[Statistics])
  panel(H, 60, 9.5, 42, 5, [TRAFFIC · SECURITY · KIOSK ↗], size: 5pt)
  let tiles = (("21 k", "inspection denials"), ("1,204", "reputation hits"), ("3,318", "rate limited"), ("64 k", "challenges"), ("312", "bans"), ("41", "honeypot"))
  for (i, t) in tiles.enumerate() {
    tile(H, 28 + i * 16, 16, 15, 12, t.at(0), t.at(1))
  }
  for (i, m) in ("inspection trend · top addresses", "rate limiting trend · top addresses", "challenges trend · failed solvers").enumerate() {
    let y = 31 + i * 26
    panel(H, 28, y, 66, 24, [#m], size: 5pt)
    line_chart(H, 30, y + 5, 38, 17, series: 1)
    table_rows(H, 70, y + 5, 23, 4, (([address], 14), ([n], 6)))
  }
  panel(H, 97, 31, 71, 40, [real-time events], size: 5.5pt)
  for (i, e) in (("inspection", "sqli · node 2 · 198.51.100.7", "12:41:07"), ("honeypot", "ban · node 1 · 203.0.113.9", "12:41:02"), ("rate limit", "429 · node 3 · 192.0.2.44", "12:40:58"), ("challenge", "rejected · double spend", "12:40:51"), ("reputation", "deny prefix 2001:db8::/32", "12:40:40"), ("inspection", "xss · node 1 · 198.51.100.7", "12:40:33")).enumerate() {
    let y = 37 + i * 5.3
    rect((99, H - y - 3.6), (114, H - y - 0.4), stroke: 0.3pt + blue, fill: blue-light, radius: 0.8)
    content((106.5, H - y - 2), text(size: 4.3pt, fill: blue)[#e.at(0)])
    content((116, H - y - 2), anchor: "west", text(size: 4.5pt, fill: ink)[#e.at(1)])
    content((166, H - y - 2), anchor: "east", text(size: 4.3pt, fill: gray)[#e.at(2)])
  }
  panel(H, 97, 74, 34, 40, [attack categories], size: 5.5pt)
  donut(H, 101, 82, 9)
  for (i, l) in ("sqli 48%", "xss 22%", "traversal 17%", "rce 9%", "honeypot 4%").enumerate() {
    content((122, H - 82 - i * 4.5), anchor: "west", text(size: 4.5pt, fill: ink)[#l])
  }
  panel(H, 134, 74, 34, 40, [attacked paths · rule hits], size: 5.5pt)
  for (i, c) in (("/search", 22), ("/login", 12), ("/.git/config", 9), ("/wp-admin", 6), ("/api/v1", 3)).enumerate() {
    bar_row(H, 135, 82 + i * 5, c.at(1) * 0.4, c.at(0))
  }
})
