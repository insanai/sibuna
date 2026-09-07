#import "@preview/cetz:0.5.2" as cetz

#let ink = rgb("172033")
#let blue = rgb("1e40af")
#let blue_light = rgb("eff6ff")
#let green = rgb("15803d")
#let green_light = rgb("f0fdf4")
#let amber = rgb("b45309")
#let amber_light = rgb("fffbeb")
#let red = rgb("b91c1c")
#let red_light = rgb("fef2f2")
#let gray = rgb("64748b")
#let rule = rgb("cbd5e1")
#let gold = rgb("d97706")
#let paper = rgb("fdfcf9")

#let book(body) = {
  set document(
    title: "The Book of Sibuna: High-Performance Web Defense, Zero-Allocation Systems, and Native Proof-of-Work",
    author: ("Vikrant Rathore", "Ronak Rathore"),
    keywords: ("Sibuna", "Firewall", "Proof-of-Work", "WebAssembly", "Zig", "Performance", "Security"),
  )
  set page(
    paper: "a4",
    margin: (inside: 25mm, outside: 20mm, top: 22mm, bottom: 24mm),
    numbering: "1",
    number-align: center,
    header: context {
      if counter(page).get().first() > 1 {
        set text(size: 8pt, fill: gray)
        let headings = query(heading.where(level: 1).before(here()))
        let chapter = if headings.len() > 0 { headings.last().body } else { [] }
        grid(
          columns: (1fr, 1fr),
          box(width: 100%, clip: true)[The Book of Sibuna],
          box(width: 100%, clip: true, align(right, emph(chapter))),
        )
        line(length: 100%, stroke: 0.4pt + rule)
      }
    },
  )
  set text(font: "New Computer Modern", size: 10.2pt, fill: ink, lang: "en")
  set smartquote(enabled: false)
  set par(justify: true, leading: 0.74em, spacing: 0.72em)
  set heading(numbering: "1.1")
  set raw(tab-size: 4)
  show raw: set text(size: 8.3pt)
  set table(stroke: 0.45pt + rule, inset: 6pt)
  show link: set text(fill: blue)
  show heading.where(level: 1): heading => {
    pagebreak(weak: true)
    block(above: 4mm, below: 6mm)[
      #text(size: 22pt, weight: "bold", fill: ink)[#heading]
      #line(length: 42mm, stroke: 1.6pt + blue)
    ]
  }
  show heading.where(level: 2): set text(size: 15pt, fill: ink)
  show heading.where(level: 3): set text(size: 12pt, fill: blue)
  body
}

#let title_page() = {
  let cover_ink = rgb("1e293b")
  let cover_muted = rgb("64748b")
  let cover_gold = rgb("d97706")
  let cover_blue = rgb("1e40af")
  let cover_green = rgb("15803d")
  let cover_paper = rgb("f8fafc")

  set page(
    margin: (x: 23mm, top: 15mm, bottom: 18mm),
    header: none,
    numbering: none,
    background: rect(width: 100%, height: 100%, fill: cover_paper),
  )

  align(center)[
    #v(8mm)
    #text(size: 44pt, weight: "light", tracking: 8pt, fill: cover_ink)[SIBUNA]
    #v(6mm)
    #grid(
      columns: (1fr, auto, 1fr),
      column-gutter: 7pt,
      align: horizon,
      line(length: 100%, stroke: 0.65pt + cover_gold),
      circle(radius: 2.5pt, fill: cover_gold),
      line(length: 100%, stroke: 0.65pt + cover_gold),
    )
    #v(6mm)
    #text(size: 12pt, weight: "medium", tracking: 2pt, fill: cover_gold)[
      HIGH-PERFORMANCE WEB DEFENSE
    ]
    #v(4mm)
    #text(size: 9.5pt, weight: "medium", tracking: 1.8pt, fill: cover_ink)[
      ZERO-ALLOCATION SYSTEMS · NATIVE PROOF-OF-WORK · ASYMMETRIC FRICTION
    ]
    #v(7mm)

    #cetz.canvas(length: 1cm, {
      import cetz.draw: *

      // Shield boundary
      line((-2.8, 3.2), (2.8, 3.2), (2.8, 0.8), (0, -2.4), (-2.8, 0.8), (-2.8, 3.2),
        stroke: 1.4pt + cover_blue, fill: rgb("eff6ff88"))

      // Asymmetry Balance Beam
      line((-2.0, 1.8), (2.0, 1.8), stroke: 1.5pt + cover_ink)
      line((0, 1.8), (0, 0.4), stroke: 1.8pt + cover_gold)
      circle((0, 0.4), radius: 0.22, fill: cover_gold, stroke: none)

      // Left pan: Crawler work (Heavy mass)
      line((-1.8, 1.8), (-2.2, 0.6), stroke: 0.8pt + cover_muted)
      line((-1.8, 1.8), (-1.4, 0.6), stroke: 0.8pt + cover_muted)
      rect((-2.4, 0.2), (-1.2, 0.6), fill: rgb("fee2e2"), stroke: 0.8pt + red)
      content((-1.8, 0.4), text(size: 7pt, weight: "bold", fill: red)[65,536 HASHES])

      // Right pan: Server verify (Feather / Microsecond)
      line((1.8, 1.8), (1.4, 1.0), stroke: 0.8pt + cover_muted)
      line((1.8, 1.8), (2.2, 1.0), stroke: 0.8pt + cover_muted)
      rect((1.2, 0.6), (2.4, 1.0), fill: rgb("dcfce7"), stroke: 0.8pt + green)
      content((1.8, 0.8), text(size: 7pt, weight: "bold", fill: green)[62.6 ns VERIFY])

      // Bottom Crest: Silicon Chip
      rect((-0.9, -1.8), (0.9, -0.6), radius: 3pt, fill: white, stroke: 1pt + cover_ink)
      content((0, -1.2), text(size: 8pt, weight: "bold", tracking: 1pt, fill: cover_ink)[ZIG · WASM])
    })

    #v(5mm)
    #text(size: 14pt, fill: cover_ink)[
      $ "Cost"_"crawler" (N) >> "Cost"_"server" (1) quad => quad "Scraping Defeated" $
    ]
    #v(6mm)
    #line(length: 46mm, stroke: 0.55pt + cover_gold)
    #v(5mm)
    #text(size: 10.5pt, style: "italic", fill: cover_muted)[
      Anubis weighed the heart against truth. Sibuna reverses the burden of work.
    ]
    #v(32mm)
    #text(size: 10pt, weight: "medium", tracking: 2pt, fill: cover_ink)[
      VIKRANT RATHORE
    ]
    #v(2mm)
    #text(size: 7.5pt, tracking: 0.6pt, fill: cover_muted)[
      WITH ASSISTANCE FROM RONAK RATHORE
    ]
  ]
}

#let part_page(number, title, summary) = {
  set page(header: none)
  pagebreak(to: "odd")
  align(center + horizon)[
    #text(size: 11pt, tracking: 1.8pt, fill: blue)[PART #number]
    #v(5mm)
    #text(size: 26pt, weight: "bold", fill: ink)[#title]
    #v(6mm)
    #line(length: 36mm, stroke: 1.5pt + blue)
    #v(7mm)
    #box(width: 74%, text(size: 10.5pt, fill: gray)[#summary])
  ]
  pagebreak()
}

#let callout(title, body, kind: "note") = {
  let colors = if kind == "warning" {
    (red, red_light)
  } else if kind == "idea" {
    (green, green_light)
  } else {
    (blue, blue_light)
  }
  block(
    width: 100%,
    inset: 10pt,
    outset: (y: 3pt),
    radius: 3pt,
    fill: colors.at(1),
    stroke: (left: 2.2pt + colors.at(0)),
  )[
    #text(weight: "bold", fill: colors.at(0))[#title]
    #h(5pt)
    #body
  ]
}

#let definition(term, body) = callout(term, body, kind: "idea")
#let warning(title, body) = callout(title, body, kind: "warning")

#let book_quote(body, attribution) = block(
  width: 88%,
  inset: (left: 12pt, right: 8pt, y: 7pt),
  outset: (y: 4pt),
  stroke: (left: 1.4pt + blue),
)[
  #emph(body)
  #linebreak()
  #align(right, text(size: 9pt, fill: gray)[#text("- ")#attribution])
]

#let exercise(number, body, hint: none) = block(
  width: 100%,
  inset: 9pt,
  outset: (y: 3pt),
  radius: 3pt,
  fill: amber_light,
  stroke: 0.6pt + amber,
)[
  #text(weight: "bold", fill: amber)[Exercise #number.]
  #h(4pt)
  #body
  #if hint != none [
    #linebreak()
    #text(size: 9pt, fill: gray)[Hint: #hint]
  ]
]

#let objectives(body) = callout([Learning Contract], body, kind: "idea")
#let checkpoint(title, body) = callout([Checkpoint: #title], body)
#let predict(body) = callout([Predict Before Reading On], body, kind: "warning")

#let teach_back(body) = block(
  width: 100%,
  inset: 9pt,
  outset: (y: 3pt),
  radius: 3pt,
  fill: blue_light,
  stroke: 0.6pt + blue,
)[
  #text(weight: "bold", fill: blue)[Teach It Back.]
  #h(4pt)
  #body
]

#let api_anchor(symbol, purpose, source: none) = {
  let location = if source == none { [] } else { [ in #source] }
  callout([API Anchor: #symbol], [#purpose#location])
}

#let code_file(path, body) = block(
  width: 100%,
  inset: 0pt,
  outset: (y: 4pt),
  stroke: 0.6pt + rule,
  radius: 3pt,
)[
  #block(width: 100%, inset: 6pt, fill: blue_light)[
    #text(size: 8pt, weight: "bold", fill: blue)[#path]
  ]
  #block(width: 100%, inset: 8pt)[#body]
]

#let book_figure(caption, body) = figure(
  placement: none,
  body,
  caption: text(size: 9pt, fill: gray)[#caption],
)
