#import "wireframe.typ": *
#set text(font: "Noto Sans")

#wire(170, 108, H => {
  import cetz.draw: *
  shell(H, 170, "Statistics")

  // Header and subtitle
  content((29, H - 11.2), anchor: "west", text(size: 6.8pt, weight: "bold", fill: ink)[Statistics · Major AI Service Providers & Crawlers])
  content((29, H - 14.5), anchor: "west", text(size: 4.2pt, fill: gray)[1/64 Space-Saving bounded sketch (k=256) · In-memory Radix CIDR verification (sub-50ns)])

  // Filter toolbar
  rect((28, H - 22.5), (84, H - 17), stroke: 0.35pt + border-gray, fill: white, radius: 0.8)
  content((31, H - 19.7), anchor: "west", text(size: 4.4pt, fill: gray)[🔍 Search provider, agent, or subnet...])

  rect((87, H - 22.5), (111, H - 17), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"), radius: 0.8)
  content((99, H - 19.7), text(size: 4.2pt, fill: ink)[Intent: All ▾])

  rect((114, H - 22.5), (136, H - 17), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"), radius: 0.8)
  content((125, H - 19.7), text(size: 4.2pt, fill: ink)[CIDR: All ▾])

  rect((139, H - 22.5), (155, H - 17), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"), radius: 0.8)
  content((147, H - 19.7), text(size: 4.2pt, fill: ink)[Status: All ▾])

  rect((158, H - 22.5), (166, H - 17), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"), radius: 0.8)
  content((162, H - 19.7), text(size: 4.2pt, fill: ink)[CSV ▾])

  // Table header
  rect((28, H - 29), (166, H - 24.5), stroke: none, fill: rgb("f8fafc"))
  line((28, H - 29), (166, H - 29), stroke: 0.35pt + border-gray)
  content((30, H - 26.8), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[PROVIDER])
  content((48, H - 26.8), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[ACTIVE AGENTS])
  content((76, H - 26.8), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[OPERATIONAL INTENT])
  content((102, H - 26.8), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[VOLUME & SHARE])
  content((127, H - 26.8), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[CIDR VERIFIED])
  content((145, H - 26.8), anchor: "west", text(size: 4.2pt, weight: "bold", fill: gray)[POLICY ACTION])
  content((161, H - 26.8), text(size: 4.2pt, weight: "bold", fill: gray)[CONFIG])

  let rows = (
    ("OpenAI", "GPTBot, ChatGPT-User", "Training + Live RAG", purple, purple-light, "391,200 (16.0%)", 16.0, blue, "✔ 98.2%", green, "Challenge Scraper", amber, amber-light),
    ("Anthropic", "ClaudeBot, Claude-Web", "Training + Live RAG", purple, purple-light, "220,100 ( 9.0%)", 9.0, purple, "✔ 96.4%", green, "Challenge Scraper", amber, amber-light),
    ("Google", "Google-Extended, Other", "AI Training / R&D", blue, blue-light, "146,800 ( 6.0%)", 6.0, amber, "✔ 99.5%", green, "Admitted (Allow)", green, green-light),
    ("Perplexity", "PerplexityBot, -User", "Live Search Fetch", cyan, cyan-light, " 51,300 ( 2.1%)", 2.1, cyan, "✔ 94.0%", green, "Admitted (Allow)", green, green-light),
    ("ByteDance", "Bytespider", "High-Freq Scraper", red, red-light, " 48,200 ( 2.0%)", 2.0, red, "⚠ 81.2%", red, "Denied (Block 403)", red, red-light),
    ("Meta", "Meta-ExternalAgent", "Model Training", blue, blue-light, " 22,400 ( 0.9%)", 0.9, blue, "✔ 97.1%", green, "Challenge", amber, amber-light),
    ("Apple", "Applebot-Extended", "Foundation Models", gray, rgb("f1f5f9"), " 14,800 ( 0.6%)", 0.6, gray, "✔ 98.4%", green, "Admitted (Allow)", green, green-light),
    ("Tools/Libs", "curl, python-requests", "Developer Script", gray, rgb("f1f5f9"), " 86,500 ( 3.5%)", 3.5, gray, "— 0.0%", gray, "Rate Limited", gray, rgb("f1f5f9")),
  )
  for (i, r) in rows.enumerate() {
    let yy = 34 + i * 7.6
    if calc.rem(i, 2) == 1 {
      rect((28, H - yy - 3.8), (166, H - yy + 3.8), stroke: none, fill: rgb("fafafa"))
    }
    line((28, H - yy - 3.8), (166, H - yy - 3.8), stroke: 0.2pt + border-gray)
    content((30, H - yy + 0.3), anchor: "west", text(size: 4.5pt, weight: "bold", fill: ink)[#r.at(0)])
    content((48, H - yy + 0.3), anchor: "west", text(size: 4.1pt, fill: ink)[#r.at(1)])

    // Intent pill
    rect((75, H - yy - 1.2), (99, H - yy + 1.8), stroke: 0.3pt + r.at(3), fill: r.at(4), radius: 0.6)
    content((87, H - yy + 0.3), text(size: 3.6pt, weight: "bold", fill: r.at(3))[#r.at(2)])

    // Volume text & micro progress bar
    content((102, H - yy + 0.9), anchor: "west", text(size: 4.1pt, fill: ink)[#r.at(5)])
    rect((102, H - yy - 2.8), (102 + (r.at(6) / 16.0) * 18, H - yy - 1.8), stroke: none, fill: r.at(7), radius: 0.4)

    // CIDR Verified
    content((127, H - yy + 0.3), anchor: "west", text(size: 4.3pt, weight: "bold", fill: r.at(9))[#r.at(8)])

    // Policy badge
    rect((144, H - yy - 1.4), (157, H - yy + 1.8), stroke: 0.3pt + r.at(11), fill: r.at(12), radius: 0.6)
    content((150.5, H - yy + 0.2), text(size: 3.5pt, weight: "bold", fill: r.at(11))[#r.at(10)])

    // Config button
    rect((159, H - yy - 1.8), (164, H - yy + 1.8), stroke: 0.3pt + border-gray, fill: rgb("f8fafc"), radius: 0.6)
    content((161.5, H - yy), text(size: 4pt, fill: ink)[⚙])
  }

  // Table pagination and summary footer
  rect((28, H - 104), (166, H - 97), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"), radius: 0.8)
  content((31, H - 100.5), anchor: "west", text(size: 4pt, fill: gray)[Showing 1–8 of 14 detected AI crawler organizations · Bound error under 0.2% · Memory: 42 KB])
  content((163, H - 100.5), anchor: "east", text(size: 4pt, fill: ink)[◀ Prev  #text(weight: "bold", fill: blue)[1]  2  Next ▶])
})
