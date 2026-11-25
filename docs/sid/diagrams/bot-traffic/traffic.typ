#import "wireframe.typ": *
#set text(font: "Noto Sans")

#wire(170, 122, H => {
  import cetz.draw: *
  shell(H, 170, "Statistics")

  // Header bar & navigation tabs
  content((29, H - 11.2), anchor: "west", text(size: 6.8pt, weight: "bold", fill: ink)[Statistics · AI & Bot Traffic Overview])
  content((29, H - 14.5), anchor: "west", text(size: 4.2pt, fill: gray)[Live ingress population telemetry & 24h comparative baseline])

  // Segmented Pill Controls
  rect((98, H - 14.5), (166, H - 9.5), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"), radius: 1)
  rect((98.5, H - 14), (115, H - 10), stroke: none, fill: dark-slate, radius: 0.8)
  content((106.7, H - 12), text(size: 4.2pt, weight: "bold", fill: white)[Overview])
  content((124.5, H - 12), text(size: 4.2pt, fill: gray)[AI Providers])
  content((142.5, H - 12), text(size: 4.2pt, fill: gray)[Event Log])
  content((158.5, H - 12), text(size: 4.2pt, fill: gray)[Policy])
  content((164, H - 12), text(size: 4.2pt, fill: blue)[↗])

  // Top Proportional Ratio Card (Hero Glanceable Widget)
  rect((28, H - 26), (166, H - 16.5), stroke: 0.35pt + border-gray, fill: white, radius: 1.2)
  content((30, H - 18.6), anchor: "west", text(size: 4.6pt, weight: "bold", fill: ink)[Ingress Population Ratio (100% Monotonic Striped Counters)])
  content((164, H - 18.6), anchor: "east", text(size: 4pt, fill: gray)[2,441,000 total requests · Zero sampling error])

  // Stacked horizontal bar
  let bx = 30
  let bw = 134
  let by = H - 25.0
  let bh = 3.8
  rect((bx, by), (bx + bw * 0.582, by + bh), stroke: none, fill: green, radius: 0.6)
  content((bx + bw * 0.29, by + bh / 2), text(size: 4.4pt, weight: "bold", fill: white)[Actual Human: 58.2%])
  rect((bx + bw * 0.582, by), (bx + bw * 0.742, by + bh), stroke: none, fill: blue)
  content((bx + bw * 0.662, by + bh / 2), text(size: 4.2pt, weight: "bold", fill: white)[OpenAI 16%])
  rect((bx + bw * 0.742, by), (bx + bw * 0.832, by + bh), stroke: none, fill: purple)
  content((bx + bw * 0.787, by + bh / 2), text(size: 4.2pt, weight: "bold", fill: white)[Claude 9%])
  rect((bx + bw * 0.832, by), (bx + bw * 0.892, by + bh), stroke: none, fill: amber)
  content((bx + bw * 0.862, by + bh / 2), text(size: 4pt, weight: "bold", fill: white)[Google 6%])
  rect((bx + bw * 0.892, by), (bx + bw * 0.963, by + bh), stroke: none, fill: gray)
  content((bx + bw * 0.927, by + bh / 2), text(size: 4pt, weight: "bold", fill: white)[Search 7%])
  rect((bx + bw * 0.963, by), (bx + bw, by + bh), stroke: none, fill: red, radius: 0.6)
  content((bx + bw * 0.981, by + bh / 2), text(size: 3.8pt, weight: "bold", fill: white)[3.7%])

  // Metric tiles with deviation pills and inline sparklines
  let tiles_data = (
    ("1.42 M", "Actual Human", "+12.4%", green, green-light, (22, 25, 24, 28, 31, 30, 35, 38, 42), green),
    ("1.02 M", "Total Automated", "+18.7%", red, red-light, (18, 19, 21, 20, 24, 28, 26, 30, 33), red),
    ("766 k", "AI LLM Crawlers", "+24.1%", purple, purple-light, (10, 11, 12, 15, 18, 22, 20, 25, 28), blue),
    ("173 k", "Search Indexers", "-1.2%", gray, rgb("f1f5f9"), (15, 15, 16, 14, 15, 15, 14, 15, 15), gray),
    ("96.4%", "Verified CIDR", "48 subnets", green, green-light, (94, 95, 96, 95, 96, 96, 97, 96, 96), purple),
    ("142 k", "Challenged / Denied", "32% drop", amber, amber-light, (8, 9, 12, 15, 22, 18, 14, 16, 19), amber),
  )
  for (i, t) in tiles_data.enumerate() {
    kpi_tile(H, 28 + i * 23.3, 27.5, 21.8, 12.5, t.at(0), t.at(1), delta: t.at(2), delta-color: t.at(3), delta-bg: t.at(4), spark: t.at(5), num-color: t.at(6))
  }

  // Middle Row Left: Time-Series Composition Trend (with axes and burst callout)
  let cx = 28
  let cy = 41.5
  let cw = 68
  let ch = 36.5
  rect((cx, H - cy - ch), (cx + cw, H - cy), stroke: 0.35pt + border-gray, fill: white, radius: 1.2)
  content((cx + 2.5, H - cy - 3.2), anchor: "west", text(size: 5.2pt, weight: "bold", fill: ink)[Traffic composition])
  // Time controls
  rect((cx + cw - 28, H - cy - 5), (cx + cw - 2, H - cy - 1.8), stroke: 0.3pt + border-gray, fill: rgb("f8fafc"), radius: 0.8)
  rect((cx + cw - 28, H - cy - 5), (cx + cw - 19, H - cy - 1.8), stroke: none, fill: blue, radius: 0.8)
  content((cx + cw - 23.5, H - cy - 3.4), text(size: 3.6pt, weight: "bold", fill: white)[60s Live])
  content((cx + cw - 14, H - cy - 3.4), text(size: 3.6pt, fill: gray)[24h])
  content((cx + cw - 6, H - cy - 3.4), text(size: 3.6pt, fill: gray)[7d])

  // Plot Area
  let px = cx + 8
  let py = cy + 7.5
  let pw = cw - 10
  let ph = ch - 13.5
  for k in (0, 1, 2) {
    let gy = H - py - (k / 2) * ph
    line((px, gy), (px + pw, gy), stroke: (dash: "densely-dashed", paint: rgb("e2e8f0"), thickness: 0.3pt))
    let lbl = if k == 0 { "50k" } else if k == 1 { "25k" } else { "0" }
    content((px - 1.5, gy), anchor: "east", text(size: 3.4pt, fill: gray)[#lbl])
  }
  // Human diurnal curve
  let pts_h = ()
  for i in range(25) {
    let t = i / 24
    let v = 0.45 + 0.30 * calc.sin((t - 0.25) * 360deg) + 0.05 * calc.sin(t * 1440deg)
    pts_h.push((px + t * pw, H - py - ph + v * ph))
  }
  line(..pts_h, stroke: 0.8pt + green)
  // AI crawler curve with burst
  let pts_a = ()
  for i in range(25) {
    let t = i / 24
    let burst = 0.44 * calc.exp(-1.0 * calc.pow((t - 0.35) * 20, 2))
    let v = 0.20 + 0.06 * calc.sin(t * 720deg) + burst
    pts_a.push((px + t * pw, H - py - ph + v * ph))
  }
  line(..pts_a, stroke: 0.8pt + blue)
  // Burst callout
  let spk_x = px + 0.35 * pw
  let spk_y = H - py - ph + 0.64 * ph
  line((spk_x, spk_y), (spk_x, spk_y + 3.8), stroke: 0.3pt + blue)
  rect((spk_x - 13, spk_y + 3.8), (spk_x + 13, spk_y + 7.2), stroke: 0.3pt + blue, fill: blue-light, radius: 0.8)
  content((spk_x, spk_y + 5.5), text(size: 3.4pt, weight: "bold", fill: blue)[▲ 03:15 AM ClaudeBot (+320 rps)])
  // X-ticks
  let times = ("00:00", "04:00", "08:00", "12:00", "16:00", "20:00", "Now")
  for (i, tm) in times.enumerate() {
    let tx = px + (i / 6) * pw
    content((tx, H - py - ph - 2.2), text(size: 3.4pt, fill: gray)[#tm])
  }
  // Legend
  rect((px, H - py - ph - 4.5), (px + 2.5, H - py - ph - 3.8), stroke: none, fill: green)
  content((px + 3.5, H - py - ph - 4.1), anchor: "west", text(size: 3.6pt, fill: ink)[Human Traffic])
  rect((px + 22, H - py - ph - 4.5), (px + 24.5, H - py - ph - 3.8), stroke: none, fill: blue)
  content((px + 25.5, H - py - ph - 4.1), anchor: "west", text(size: 3.6pt, fill: ink)[AI Crawl])

  // Middle Row Right: AI Provider Market Share & Scraped Paths
  let dx = 98
  rect((dx, H - cy - ch), (dx + cw, H - cy), stroke: 0.35pt + border-gray, fill: white, radius: 1.2)
  content((dx + 2.5, H - cy - 3.2), anchor: "west", text(size: 5.2pt, weight: "bold", fill: ink)[AI Provider Distribution & Scraped Paths])

  // Segmented Donut Chart on Left Side
  let dcx = dx + 14
  let dcy = cy + 12
  segmented_donut(H, dcx, dcy, 5.2, (
    (173.5deg, blue),
    (94.0deg, purple),
    (52.2deg, amber),
    (40.3deg, gray),
  ))
  circle((dcx, H - dcy), radius: 3.4, stroke: none, fill: white)
  content((dcx, H - dcy + 0.6), text(size: 3.6pt, weight: "bold", fill: ink)[766 k])
  content((dcx, H - dcy - 1.0), text(size: 2.6pt, fill: gray)[AI Reqs])

  // Donut legend stacked below
  let dly = cy + 20.5
  content((dx + 2.5, H - dly), anchor: "west", text(size: 3.4pt, fill: blue)[• OpenAI 48% (391k)])
  content((dx + 2.5, H - dly - 3.4), anchor: "west", text(size: 3.4pt, fill: purple)[• Anthropic 26% (220k)])
  content((dx + 2.5, H - dly - 6.8), anchor: "west", text(size: 3.4pt, fill: amber)[• Google 15% (147k)])
  content((dx + 2.5, H - dly - 10.2), anchor: "west", text(size: 3.4pt, fill: gray)[• Others 11% (89k)])

  // Top Scraped Paths (Horizontal Bars on Right Side)
  content((dx + 30, H - cy - 5.5), anchor: "west", text(size: 4.2pt, weight: "bold", fill: ink)[Top Targeted URIs])
  bar_row(H, dx + 30, cy + 10.5, 12.4, "/blog (62%)", bar-color: blue)
  bar_row(H, dx + 30, cy + 16.5, 4.8, "/docs (24%)", bar-color: purple)
  bar_row(H, dx + 30, cy + 22.5, 1.8, "/api (9%)", bar-color: amber)
  bar_row(H, dx + 30, cy + 28.5, 1, "/pricing (5%)", bar-color: gray)

  // Lower Section: Real-Time AI Crawl Event Feed
  let fx = 28
  let fy = 79.5
  let fw = 138
  let fh = 40
  rect((fx, H - fy - fh), (fx + fw, H - fy), stroke: 0.35pt + border-gray, fill: white, radius: 1.2)
  content((fx + 2.5, H - fy - 3), anchor: "west", text(size: 5.2pt, weight: "bold", fill: ink)[Real-Time AI Ingress Feed (1/64 Bounded Sample Queue)])
  content((fx + fw - 2.5, H - fy - 3), anchor: "east", text(size: 4pt, fill: green)[● Ingestion: 64 samples/s · buffer: 14%])

  // Table header
  rect((fx, H - fy - 8), (fx + fw, H - fy - 4.5), stroke: none, fill: rgb("f8fafc"))
  line((fx, H - fy - 8), (fx + fw, H - fy - 8), stroke: 0.3pt + border-gray)
  content((fx + 2, H - fy - 6.2), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[TIME])
  content((fx + 16, H - fy - 6.2), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[PROVIDER])
  content((fx + 34, H - fy - 6.2), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[USER-AGENT])
  content((fx + 64, H - fy - 6.2), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[TARGET URI])
  content((fx + 104, H - fy - 6.2), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[STATUS])
  content((fx + 118, H - fy - 6.2), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[CIDR VERIFICATION])

  let events = (
    ("15:32:01", "OpenAI", blue, blue-light, "GPTBot/1.2", "/blog/deep-learning-foundations", "200 OK", green, "✔ Azure CIDR", green, green-light),
    ("15:31:58", "Anthropic", purple, purple-light, "ClaudeBot/1.0", "/docs/architecture/spec-v2", "429 Chlg", amber, "✔ AWS CIDR", green, green-light),
    ("15:31:54", "ByteDance", red, red-light, "Bytespider", "/internal/catalog-dump", "403 Deny", red, "✖ Spoofed IP", red, red-light),
    ("15:31:49", "Perplexity", cyan, cyan-light, "Perplexity-User", "/news/product-announcement", "200 OK", green, "✔ Azure CIDR", green, green-light),
    ("15:31:42", "Google", amber, amber-light, "Google-Extended", "/archive/quarterly-report", "200 OK", green, "✔ GCP CIDR", green, green-light),
    ("15:31:38", "Unknown", gray, rgb("f1f5f9"), "python-requests/2.31", "/api/v1/pricing", "429 Limit", amber, "⚡ Heuristic", amber, amber-light),
  )
  for (i, e) in events.enumerate() {
    let yy = fy + 12.5 + i * 4.8
    if calc.rem(i, 2) == 1 {
      rect((fx, H - yy - 2), (fx + fw, H - yy + 2.5), stroke: none, fill: rgb("fafafa"))
    }
    line((fx, H - yy - 2), (fx + fw, H - yy - 2), stroke: 0.2pt + border-gray)
    content((fx + 2, H - yy + 0.4), anchor: "west", text(size: 4pt, fill: gray)[#e.at(0)])
    rect((fx + 15.5, H - yy - 1.2), (fx + 31.5, H - yy + 1.8), stroke: 0.3pt + e.at(2), fill: e.at(3), radius: 0.6)
    content((fx + 23.5, H - yy + 0.3), text(size: 3.8pt, weight: "bold", fill: e.at(2))[#e.at(1)])
    content((fx + 34, H - yy + 0.3), anchor: "west", text(size: 4.1pt, weight: "bold", fill: ink)[#e.at(4)])
    content((fx + 64, H - yy + 0.3), anchor: "west", text(size: 4pt, font: "DejaVu Sans Mono", fill: ink)[#e.at(5)])
    content((fx + 104, H - yy + 0.3), anchor: "west", text(size: 4pt, weight: "bold", fill: e.at(7))[#e.at(6)])
    rect((fx + 118, H - yy - 1.2), (fx + 136, H - yy + 1.8), stroke: 0.3pt + e.at(9), fill: e.at(10), radius: 0.6)
    content((fx + 127, H - yy + 0.3), text(size: 3.6pt, weight: "bold", fill: e.at(9))[#e.at(8)])
  }
})
