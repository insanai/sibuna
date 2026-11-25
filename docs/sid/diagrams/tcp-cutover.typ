#import "@preview/cetz:0.5.2"
#set text(font: "Libertinus Serif", size: 7.8pt, fill: rgb("#172033"))
#cetz.canvas(length: 1cm, {
  import cetz.draw: *

  let ink = rgb("#172033")
  let muted = rgb("#64748b")
  let blue = rgb("#1e40af")
  let blue-bg = rgb("#eff6ff")
  let green = rgb("#15803d")
  let amber = rgb("#b45309")
  let amber-bg = rgb("#fffbeb")
  let violet = rgb("#6d28d9")

  let xs = (0.9, 3.8, 7.0, 10.3, 13.4)
  let names = (
    "Operator /\nPostgres",
    "Control Plane\n(Gen k)",
    "Pinned Workers\n(Gen k)",
    "New Process\n(Gen k+1)",
    "Live TCP/UDP\nClients",
  )
  let cols = (violet, blue, green, amber, ink)

  for i in range(5) {
    let x = xs.at(i)
    let c = cols.at(i)
    rect((x - 1.15, 9.5), (x + 1.15, 10.35), radius: 2.5pt, fill: c.lighten(88%), stroke: 0.75pt + c)
    content((x, 9.92), align(center, text(weight: "bold", size: 7.4pt, fill: c.darken(15%), names.at(i))))
    line((x, 0.3), (x, 9.5), stroke: (paint: muted.lighten(30%), thickness: 0.65pt, dash: "dashed"))
  }

  let msg(from, to, y, col, label, dashed: false) = {
    let x1 = xs.at(from)
    let x2 = xs.at(to)
    line((x1, y), (x2, y),
      stroke: (paint: col, thickness: 0.8pt, dash: if dashed { "dashed" } else { none }),
      mark: (end: "stealth", fill: col, scale: 0.6))
    content(((x1 + x2) / 2, y + 0.22), align(center,
      box(fill: white, inset: 1.2pt, text(size: 6.9pt, fill: col.darken(15%), label))))
  }

  // Band 1: Tier-1 RCU Reload
  rect((0.0, 5.65), (14.4, 9.25), radius: 3pt, fill: blue-bg.lighten(45%), stroke: 0.5pt + blue.lighten(50%))
  content((0.2, 9.02), anchor: "west",
    text(weight: "bold", size: 7.6pt, fill: blue, "Tier 1: In-Process Snapshot Reload (SIGHUP / Admin IPC / PostgreSQL NOTIFY)"))

  msg(0, 1, 8.5, violet, "1. SIGHUP / NOTIFY sibuna_policy")
  rect((2.8, 7.62), (4.8, 8.22), fill: white, stroke: 0.6pt + blue, radius: 2pt)
  content((3.8, 7.92), align(center, text(size: 6.5pt, "Eval JLV/JSON &\nBuild Maglev")))
  msg(1, 2, 7.22, blue, "2. Publish owned snapshot (gen + 1)")
  msg(4, 2, 6.62, green, "3. Existing flows keep backend; new flows use revision")
  msg(1, 0, 5.98, violet, "4. OK (applied revision & SHA-256)", dashed: true)

  // Band 2: Tier-2 Binary Upgrade
  rect((0.0, 0.5), (14.4, 5.35), radius: 3pt, fill: amber-bg.lighten(45%), stroke: 0.5pt + amber.lighten(50%))
  content((0.2, 5.12), anchor: "west",
    text(weight: "bold", size: 7.6pt, fill: amber, "Tier 2: TCP Binary / Listener Upgrade (SIGUSR2 + Unix SCM_RIGHTS)"))

  msg(0, 1, 4.6, violet, "1. SIGUSR2 (spawn upgraded binary)")
  msg(1, 3, 4.0, amber, "2. Pass TCP listener FDs (SCM_RIGHTS)")
  msg(3, 1, 3.35, green, "3. READY (new workers prepared)", dashed: true)
  msg(1, 2, 2.75, blue, "4. Detach listeners & enter draining state")
  msg(4, 3, 2.1, green, "5. New TCP connections to replacement")
  msg(4, 2, 1.45, muted, "6. Old workers drain TCP to deadline", dashed: true)
  msg(2, 1, 0.85, muted, "7. Drain complete or deadline reached", dashed: true)
})
