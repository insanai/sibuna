#import "wireframe.typ": *
#set text(font: "Noto Sans")

#wire(170, 114, H => {
  import cetz.draw: *
  shell(H, 170, "Statistics")
  // Dim background
  rect((26, 0), (170, H - 8), stroke: none, fill: rgb("00000033"))

  // Modal container
  rect((32, 7), (164, H - 11), stroke: 0.6pt + ink, fill: white, radius: 1.8)

  // Modal Header
  rect((32, H - 18), (164, H - 7), stroke: none, fill: rgb("f8fafc"), radius: 1.8)
  line((32, H - 18), (164, H - 18), stroke: 0.35pt + border-gray)
  rect((35, H - 15.5), (49, H - 10.5), stroke: 0.35pt + blue, fill: blue-light, radius: 0.7)
  content((42, H - 13), text(size: 4.6pt, weight: "bold", fill: blue)[OpenAI])
  content((52, H - 13), anchor: "west", text(size: 6.2pt, weight: "bold", fill: ink)[Provider Policy & Radix CIDR Enforcement])
  content((160, H - 13), text(size: 6pt, fill: gray)[✕])

  // Modal Nav Tabs
  rect((35, H - 23.5), (71, H - 19.5), stroke: none, fill: blue, radius: 0.7)
  content((53, H - 21.5), text(size: 4.2pt, weight: "bold", fill: white)[Rules & CIDR Enforcement])
  content((88, H - 21.5), text(size: 4.2pt, fill: gray)[Verified Subnets (48)])
  content((122, H - 21.5), text(size: 4.2pt, fill: gray)[Sampled Ingress Audit])

  // Left Column: Telemetry Evidence & CIDR Audit
  rect((35, H - 91), (95, H - 26), stroke: 0.35pt + border-gray, fill: rgb("fafafa"), radius: 1)
  content((38, H - 29.5), anchor: "west", text(size: 5.2pt, weight: "bold", fill: blue)[Observed Ingress Telemetry])
  content((38, H - 34.5), anchor: "west", text(size: 4.3pt, fill: ink)[• Total Volume: 391,200 reqs (16.0% site ingress)])
  content((38, H - 38.5), anchor: "west", text(size: 4.3pt, fill: ink)[• Training (GPTBot): 342,100 reqs (87.4%)])
  content((38, H - 42.5), anchor: "west", text(size: 4.3pt, fill: ink)[• Live Search (ChatGPT-User): 49,100 reqs (12.6%)])

  content((38, H - 48.5), anchor: "west", text(size: 5pt, weight: "bold", fill: ink)[Radix CIDR Verification Audit])
  // Dual-color split bar
  rect((38, H - 54), (38 + 52 * 0.982, H - 51), stroke: none, fill: green, radius: 0.5)
  rect((38 + 52 * 0.982, H - 54), (38 + 52, H - 51), stroke: none, fill: red, radius: 0.5)
  content((38, H - 57.5), anchor: "west", text(size: 4pt, fill: green)[✔ 98.2% (384,158 reqs) verified in Azure ASN 8075])
  content((38, H - 61.5), anchor: "west", text(size: 4pt, fill: red)[⚠ 1.8% (7,042 reqs) from alien residential IPs])

  content((38, H - 67.5), anchor: "west", text(size: 5pt, weight: "bold", fill: ink)[Top Target Endpoints])
  content((38, H - 72), anchor: "west", text(size: 4pt, fill: gray)[/blog (62%) · /docs (28%) · /api (10%)])
  content((38, H - 77), anchor: "west", text(size: 4pt, fill: gray)[Verified subnets: 20.15.0.0/16, 20.28.0.0/16, ...])

  // Right Column: Policy Configuration & Enforcement
  rect((99, H - 91), (161, H - 26), stroke: 0.35pt + border-gray, fill: white, radius: 1)
  content((102, H - 29.5), anchor: "west", text(size: 5.2pt, weight: "bold", fill: blue)[Policy Configuration & Enforcement])

  // Master toggle
  rect((102, H - 36), (106, H - 32), stroke: 0.4pt + blue, fill: blue-light, radius: 0.5)
  content((104, H - 34), text(size: 3.8pt, fill: blue)[✔])
  content((108, H - 34), anchor: "west", text(size: 4.4pt, weight: "bold", fill: ink)[Enforce Radix CIDR Match (sub-50ns)])

  content((102, H - 41.5), anchor: "west", text(size: 4.2pt, fill: ink)[Training Scraper (GPTBot):])
  rect((102, H - 48.5), (157, H - 43.5), stroke: 0.35pt + amber, fill: amber-light, radius: 0.7)
  content((105, H - 46), anchor: "west", text(size: 4.2pt, weight: "bold", fill: amber)[⚡ Proof-of-Work Challenge (PoW) ▾])

  content((102, H - 53.5), anchor: "west", text(size: 4.2pt, fill: ink)[Live User Search (ChatGPT-User):])
  rect((102, H - 60.5), (157, H - 55.5), stroke: 0.35pt + green, fill: green-light, radius: 0.7)
  content((105, H - 58), anchor: "west", text(size: 4.2pt, weight: "bold", fill: green)[✔ Admitted (Bypass WAF) ▾])

  content((102, H - 65.5), anchor: "west", text(size: 4.2pt, fill: ink)[Unverified / Spoofed Agents:])
  rect((102, H - 72.5), (157, H - 67.5), stroke: 0.35pt + red, fill: red-light, radius: 0.7)
  content((105, H - 70), anchor: "west", text(size: 4.2pt, weight: "bold", fill: red)[✖ Deny Immediately (Block 403) ▾])

  content((102, H - 77.5), anchor: "west", text(size: 4.2pt, fill: ink)[GCRA Rate Limiter:])
  rect((102, H - 84.5), (157, H - 79.5), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"), radius: 0.7)
  content((105, H - 82), anchor: "west", text(size: 4.2pt, fill: ink)[25 req/s · Burst capacity: 100 reqs ▾])
  content((102, H - 88), anchor: "west", text(size: 3.6pt, fill: gray)[Immutable trie updates execute via zero-downtime RCU.])

  // Modal Footer
  line((32, H - 94), (164, H - 94), stroke: 0.35pt + border-gray)
  rect((35, H - 102.5), (72, H - 97.5), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"), radius: 0.8)
  content((53.5, H - 100), text(size: 4.2pt, fill: ink)[🧪 Dry Run Simulation])

  rect((112, H - 102.5), (133, H - 97.5), stroke: 0.35pt + border-gray, fill: white, radius: 0.8)
  content((122.5, H - 100), text(size: 4.2pt, fill: gray)[Cancel])

  rect((136, H - 102.5), (161, H - 97.5), stroke: none, fill: blue, radius: 0.8)
  content((148.5, H - 100), text(size: 4.2pt, weight: "bold", fill: white)[Save & Apply Policy])
})
