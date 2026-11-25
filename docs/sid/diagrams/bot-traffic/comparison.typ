#import "wireframe.typ": *
#set text(font: "Noto Sans")

#wire(170, 108, H => {
  import cetz.draw: *
  shell(H, 170, "Statistics")

  // Header and subtitle
  content((29, H - 11.2), anchor: "west", text(size: 6.8pt, weight: "bold", fill: ink)[Statistics · Human vs. Bot Comparative Analysis])
  content((29, H - 14.5), anchor: "west", text(size: 4.2pt, fill: gray)[Side-by-side behavioral, protocol, and network telemetry analysis (100% Exact + 1/64 Samples)])

  // Left panel: Human traffic
  rect((28, H - 94), (95, H - 16), stroke: 0.35pt + border-gray, fill: white, radius: 1.2)
  rect((28, H - 23), (95, H - 16), stroke: none, fill: green, radius: 1.2)
  content((31, H - 19.5), anchor: "west", text(size: 5.6pt, weight: "bold", fill: white)[🛡 Legitimate Human Traffic Profile (58.2%)])

  // Mini KPI row
  rect((30, H - 31), (49, H - 25), stroke: 0.3pt + border-gray, fill: green-light, radius: 0.6)
  content((39.5, H - 27.2), text(size: 4.6pt, weight: "bold", fill: green)[420 rps])
  content((39.5, H - 29.8), text(size: 3.4pt, fill: gray)[peak rate])

  rect((51, H - 31), (70, H - 25), stroke: 0.3pt + border-gray, fill: rgb("f8fafc"), radius: 0.6)
  content((60.5, H - 27.2), text(size: 4.6pt, weight: "bold", fill: ink)[4.8 min])
  content((60.5, H - 29.8), text(size: 3.4pt, fill: gray)[avg session])

  rect((72, H - 31), (93, H - 25), stroke: 0.3pt + border-gray, fill: rgb("f8fafc"), radius: 0.6)
  content((82.5, H - 27.2), text(size: 4.6pt, weight: "bold", fill: ink)[78.4%])
  content((82.5, H - 29.8), text(size: 3.4pt, fill: gray)[cache hit])

  content((30, H - 34.5), anchor: "west", text(size: 4.4pt, weight: "bold", fill: ink)[HTTP Status Code Distribution])
  bar_row(H, 30, 38.5, 28, "200 OK (89.2%)", bar-color: green)
  bar_row(H, 30, 42.5, 10, "304 Cache (8.0%)", bar-color: blue)
  bar_row(H, 30, 46.5, 5, "4xx Error (2.6%)", bar-color: amber)
  bar_row(H, 30, 50.5, 2, "5xx Error (0.2%)", bar-color: red)

  content((30, H - 55), anchor: "west", text(size: 4.4pt, weight: "bold", fill: ink)[Resource Cascade & Client Engine])
  content((30, H - 59.5), anchor: "west", text(size: 3.9pt, fill: ink)[✔ 12% Document HTML / 88% Static Assets])
  content((30, H - 63.5), anchor: "west", text(size: 3.9pt, fill: ink)[✔ Full V8/WebKit/Gecko asset rendering cascade])
  content((30, H - 67.5), anchor: "west", text(size: 3.9pt, fill: ink)[✔ Median TTFB: 24 ms · Interactive clicks & scrolls])

  content((30, H - 73), anchor: "west", text(size: 4.4pt, weight: "bold", fill: ink)[Network & Origin Fingerprint])
  content((30, H - 77.5), anchor: "west", text(size: 3.9pt, fill: ink)[✔ 84% Consumer Broadband (Comcast, DT, Orange)])
  content((30, H - 81.5), anchor: "west", text(size: 3.9pt, fill: ink)[✔ Valid Session Cookies & Cryptographic PoW tokens])
  content((30, H - 85.5), anchor: "west", text(size: 3.9pt, fill: ink)[✔ Standard Browser TLS JA4 & HTTP/2 headers])

  // Right panel: Bot traffic
  rect((99, H - 94), (166, H - 16), stroke: 0.35pt + border-gray, fill: white, radius: 1.2)
  rect((99, H - 23), (166, H - 16), stroke: none, fill: red, radius: 1.2)
  content((102, H - 19.5), anchor: "west", text(size: 5.6pt, weight: "bold", fill: white)[🤖 Automated Bot & Crawler Profile (41.8%)])

  // Mini KPI row
  rect((101, H - 31), (120, H - 25), stroke: 0.3pt + border-gray, fill: red-light, radius: 0.6)
  content((110.5, H - 27.2), text(size: 4.6pt, weight: "bold", fill: red)[310 rps])
  content((110.5, H - 29.8), text(size: 3.4pt, fill: gray)[burst rate])

  rect((122, H - 31), (141, H - 25), stroke: 0.3pt + border-gray, fill: rgb("f8fafc"), radius: 0.6)
  content((131.5, H - 27.2), text(size: 4.6pt, weight: "bold", fill: ink)[Stateless])
  content((131.5, H - 29.8), text(size: 3.4pt, fill: gray)[leaf crawl])

  rect((143, H - 31), (164, H - 25), stroke: 0.3pt + border-gray, fill: rgb("f8fafc"), radius: 0.6)
  content((153.5, H - 27.2), text(size: 4.6pt, weight: "bold", fill: ink)[11.8%])
  content((153.5, H - 29.8), text(size: 3.4pt, fill: gray)[cache hit])

  content((101, H - 34.5), anchor: "west", text(size: 4.4pt, weight: "bold", fill: ink)[HTTP Status Code Distribution])
  bar_row(H, 101, 38.5, 20, "200 OK (52.1%)", bar-color: green)
  bar_row(H, 101, 42.5, 18, "403 Denied (26.3%)", bar-color: red)
  bar_row(H, 101, 46.5, 14, "429 Chlg (17.8%)", bar-color: amber)
  bar_row(H, 101, 50.5, 6, "404 Missing (3.8%)", bar-color: gray)

  content((101, H - 55), anchor: "west", text(size: 4.4pt, weight: "bold", fill: ink)[Resource Cascade & Client Engine])
  content((101, H - 59.5), anchor: "west", text(size: 3.9pt, fill: ink)[✖ 96% Document HTML / 4% Static Assets])
  content((101, H - 63.5), anchor: "west", text(size: 3.9pt, fill: ink)[✖ Zero asset cascade (headless script leaf scraper)])
  content((101, H - 67.5), anchor: "west", text(size: 3.9pt, fill: ink)[✖ Median TTFB: 18 ms · Rapid recursive crawling])

  content((101, H - 73), anchor: "west", text(size: 4.4pt, weight: "bold", fill: ink)[Network & Origin Fingerprint])
  content((101, H - 77.5), anchor: "west", text(size: 3.9pt, fill: ink)[✖ 98% Cloud Datacenter ASNs (Azure, AWS, GCP)])
  content((101, H - 81.5), anchor: "west", text(size: 3.9pt, fill: ink)[✖ Headless HTTP runtimes (Python, Go, cURL)])
  content((101, H - 85.5), anchor: "west", text(size: 3.9pt, fill: ink)[✖ Missing Sec-Fetch headers & anomalous ciphers])

  // Footer note
  rect((28, H - 104), (166, H - 97), stroke: 0.35pt + blue, fill: blue-light, radius: 0.8)
  content((31, H - 100.5), anchor: "west", text(size: 4pt, fill: blue)[Comparative telemetry derived from 100% exact atomic striped counters combined with 1/64 Space-Saving sample sketches. Zero-allocation hot path executes in sub-50 nanoseconds.])
})
