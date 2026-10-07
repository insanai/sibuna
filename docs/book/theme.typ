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
    title: "The Book of Sibuna: Proof of Work and Practical Web Protection",
    author: ("Vikrant Rathore", "Ronak Rathore"),
    keywords: ("Sibuna", "Firewall", "Proof-of-Work", "WebAssembly", "Zig", "Performance", "Security"),
  )
  set page(
    width: 190mm, height: 250mm,
    margin: (inside: 21mm, outside: 18mm, top: 19mm, bottom: 20mm),
    numbering: "1",
    number-align: center,
    header: context {
      if counter(page).get().first() > 1 {
        set text(size: 8pt, fill: gray)
        let page_number = here().page()
        let headings = query(heading.where(level: 1)).filter(it =>
          it.location().page() <= page_number)
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
  set text(font: "New Computer Modern", size: 10.5pt, fill: ink, lang: "en")
  set smartquote(enabled: false)
  set par(justify: true, leading: 0.60em, spacing: 1em)
  set heading(numbering: "1.1")
  set raw(tab-size: 4)
  show raw: set text(size: 8.3pt)
  // Keep short examples together. Long listings can still span a page.
  show raw.where(block: true): it => block(
    breakable: it.text.split("\n").len() > 30,
    it,
  )
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

// Mathematical artwork stays vector-sharp in both PDF and PNG exports.
#let cover_art() = cetz.canvas(length: 1cm, {
  import cetz.draw: *
  let night = rgb("142c3b")
  let copper = rgb("d7a15b")
  // Many possible request paths approach a narrow admission boundary.
  for j in range(23) {
    let points = ()
    for k in range(101) {
      let x = -6.3 + k * 0.126
      let envelope = 0.23 + 0.77 * calc.pow(calc.abs(x) / 6.3, 0.65)
      let y = (j - 11) * 0.30 * envelope + 0.20 * calc.sin(x * 35deg)
      points.push((x, y))
    }
    line(..points, stroke: (paint: if calc.rem(j, 4) == 0 { copper } else { rgb("517883") }, thickness: 0.45pt))
  }
  // A finite proof tree: dependency and authentication drawn as a constellation.
  for d in range(5) {
    let n = calc.pow(2, d)
    for i in range(n) {
      let x = (i + 0.5) * 7.2 / n - 3.6
      let y = 4.0 - d * 0.66
      if d > 0 {
        let px = (calc.quo(i, 2) + 0.5) * 7.2 / calc.pow(2, d - 1) - 3.6
        line((x,y), (px,y+0.66), stroke: 0.45pt + copper)
      }
      circle((x,y), radius: if d == 0 { 0.085 } else { 0.038 }, fill: copper, stroke: none)
    }
  }
  // Probability contours below the aperture: exp(-x), not a measured curve.
  for j in range(9) {
    let points = ()
    for k in range(80) {
      let x = k / 13.0 - 3
      points.push((x, -1.3 - j * 0.20 - 0.70 * calc.exp(-(x+3)*0.7)))
    }
    line(..points, stroke: 0.45pt + rgb("89a9a4"))
  }
  line((-0.48,-0.7),(-0.48,0.8),(0,1.1),(0.48,0.8),(0.48,-0.7), stroke: 1.7pt + copper)
  circle((0,0.15), radius: 0.12, fill: copper, stroke: none)
})

#let title_page() = {
  set page(margin: (x: 18mm, y: 17mm), header: none, numbering: none,
    background: rect(width: 100%, height: 100%, fill: rgb("142c3b")))
  set text(fill: rgb("f4ecd9"))
  align(center)[
    #v(6mm)
    #text(size: 9pt, tracking: 2.8pt, fill: rgb("d7a15b"))[THE BOOK OF]
    #v(4mm)
    #text(size: 46pt, tracking: 5pt, weight: "regular")[SIBUNA]
    #v(5mm)
    #text(size: 13pt)[The mathematics and engineering of web defense]
    #v(11mm)
    #cover_art()
    #v(9mm)
    #text(size: 10pt, tracking: 1pt, fill: rgb("d7a15b"))[WORK · TRUST · BOUNDED STATE]
    #v(1fr)
    #text(size: 10pt)[Vikrant Rathore]
    #v(2mm)
    #text(size: 8.5pt, fill: rgb("a6b9bc"))[With assistance from Ronak Rathore]
  ]
}

#let part_page(number, title, summary) = {
  // Front matter has headings too. Reset chapter numbering to the named part.
  let parts = ("I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII", "XIII")
  counter(heading).update((parts.position(part => part == number),))
  heading(level: 1, title)
  block(above: 0pt, below: 7pt)[#text(style: "italic", fill: gray)[#summary]]
}

#let callout(title, body, kind: "note") = context {
  if target() == "html" {
    return html.elem("aside", attrs: (class: "callout " + kind))[
      #html.elem("strong", title)
      #html.elem("div", body)
    ]
  }
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
  breakable: false,
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

#let objectives(body) = callout([In this chapter], body, kind: "idea")
#let checkpoint(title, body) = callout([Checkpoint: #title], body)
#let predict(body) = callout([Before continuing], body, kind: "warning")

#let teach_back(body) = block(
  width: 100%,
  inset: 9pt,
  outset: (y: 3pt),
  radius: 3pt,
  fill: blue_light,
  stroke: 0.6pt + blue,
)[
  #text(weight: "bold", fill: blue)[Explain the invariant.]
  #h(4pt)
  #body
]

#let api_anchor(symbol, purpose, source: none) = {
  let location = if source == none { [] } else { [ in #source] }
  callout([Implementation: #symbol], [#purpose#location])
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

#let book_figure(caption, body, placement: none) = figure(
  placement: placement,
  layout(size => {
    let natural = measure(body).width
    let factor = calc.min(1, size.width / natural)
    align(center, scale(x: factor * 100%, y: factor * 100%, reflow: true, body))
  }),
  caption: text(size: 9pt, fill: gray)[#caption],
)
