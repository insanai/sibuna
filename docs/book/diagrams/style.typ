// Guidedog compiles each diagram in the document that uses it.
#import "@preview/cetz:0.3.4"
#import "@preview/fletcher:0.5.8": diagram, node, edge

#let ink = rgb("#172033")
#let blue = rgb("#1e40af")
#let neutral = rgb("#475569")
#let tint = rgb("#eff6ff")
#let paper = rgb("#f1f5f9")

#let sheet(lang: "en", body) = {
  let extra = (ja: "Noto Sans CJK JP", ko: "Noto Sans CJK KR", zh: "Noto Sans CJK SC",
    ar: "Noto Sans Arabic", hi: "Noto Sans Devanagari")
  set text(font: ("Noto Sans", extra.at(lang, default: "Noto Sans")), lang: lang,
    size: 9pt, fill: ink, hyphenate: false)
  set par(leading: 0.4em)
  block(inset: 5pt, fill: white, radius: 4pt, body)
}

// Arrow labels set the row height. A longer translation wraps between its two lifelines.
#let sequence(actors, steps, notes: ()) = context {
  let gap = if actors.len() == 2 { 85 } else if actors.len() == 3 { 49 } else { 38 }
  let title-width = calc.min(35, gap - 5) * 1mm
  let title(label) = block(width: title-width, inset: 3pt, align(center, strong(label)))
  let header = actors.map(a => measure(title(a)).height / 1mm).fold(0, calc.max) + 1
  let y = -header
  let rows = ()
  for (i, step) in steps.enumerate() {
    let (from, to, label) = step
    if notes.any(n => n.first() == i) { y -= 7 }
    let span = calc.abs(to - from) * gap
    // Keep protocol tokens, wildcard names and punctuation together in RTL labels.
    let words = label.split(" · ").map(part => if part.match(regex("^[ -~]+$")) != none {
      box(text(dir: ltr, part))
    } else { part })
    let label = block(width: (span - 4) * 1mm, align(center, words.join(" · ")))
    y -= measure(label).height / 1mm + 4
    rows.push((from, to, label, y))
  }
  cetz.canvas(length: 1mm, {
    import cetz.draw: *
    for (i, actor) in actors.enumerate() {
      let x = i * gap
      let half-title = title-width / 2mm + 0.5
      rect((x - half-title, 0), (x + half-title, -header), radius: 1.4, fill: tint, stroke: 0.8pt + blue)
      content((x, -header / 2), title(actor))
      line((x, -header), (x, y - 8), stroke: (paint: neutral, thickness: 0.6pt, dash: "dashed"))
    }
    for (after, actor, label) in notes {
      let h = rows.at(after - 1).last() - 4
      content((actor * gap, h), box(fill: white, inset: 1pt, text(size: 8pt, label)))
    }
    for (from, to, label, h) in rows {
      let x = from * gap
      let dest = to * gap
      line((x, h), (dest, h), stroke: 0.9pt + blue, mark: (end: ">", scale: 0.7))
      let label-x = if calc.even(calc.abs(from - to)) { (x + dest) / 2 - gap / 3 } else { (x + dest) / 2 }
      content((label-x, h + 0.8), anchor: "south", label)
    }
  })
}

#let tile(pos, label, fill: paper, stroke: neutral) = node(pos, label,
  fill: fill, stroke: 0.8pt + stroke, corner-radius: 4pt, inset: 5pt)
