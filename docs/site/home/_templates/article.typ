// Sibuna's reading edition, adapted from Guidedog's standalone article layout.
// guidedog: margin-x = 30mm
#let book(title: "", author: "", version: "", date: "", lang: "en", paper: "a4",
  numbering: false, authors: (), updated: "", category: "", tags: (), summary: "", body) = {
  let code = lang.replace("_", "-").split("-").first()
  let scripts = (ar: ("Noto Naskh Arabic",), hi: ("Noto Serif Devanagari",),
    ja: ("Noto Serif CJK JP",), ko: ("Noto Serif CJK KR",), zh: ("Noto Serif CJK SC",))
  let fallback = scripts.at(code, default: ())
  let serif = ("Libertinus Serif",) + fallback
  let sans = ("Libertinus Sans",) + fallback
  let green = rgb("#176a4b")
  let quiet = rgb("#53665c")
  let rule = 0.5pt + rgb("#abbcb1")
  let names = if authors.len() > 0 { authors } else if author != "" { (author,) } else { () }
  set document(title: title, author: names, keywords: ((category,) + tags).filter(k => k != ""))
  set text(font: serif, lang: code, size: 10.5pt, fill: rgb("#20352f"), hyphenate: true)
  set par(justify: true, linebreaks: "optimized", leading: 0.65em, spacing: 0.7em)
  set block(spacing: 0.86em)
  set page(paper: paper, margin: (x: 30mm, y: 25mm),
    header: context if counter(page).get().first() > 1 {
      set text(font: sans, size: 8pt, fill: quiet)
      title
      v(3pt)
      line(length: 100%, stroke: rule)
    },
    footer: context if counter(page).get().first() > 1 {
      align(center, text(font: sans, size: 8pt, fill: quiet, counter(page).display()))
    })
  set heading(numbering: if numbering { "1.1" })
  show heading: set text(font: sans, hyphenate: false)
  show heading: set par(justify: false)
  show link: set text(fill: green)
  show link: it => {
    // A downloaded article opens the same language edition of the online book.
    if type(it.dest) == str and it.dest.starts-with("../book/") {
      let edition = (en: "", zh: "zh-hans/").at(code, default: code + "/")
      link("https://insanai.github.io/sibuna/" + edition + it.dest.slice(3), it.body)
    } else { it }
  }
  show raw: set text(font: "DejaVu Sans Mono", dir: ltr, hyphenate: false, ligatures: false)
  show raw.where(block: true): it => align(left, block(
    width: 100%, inset: 9pt, fill: rgb("#f2f5f1"), breakable: it.text.split("\n").len() > 24, it))

  text(font: sans, size: 10pt, weight: "bold", fill: green, "Sibuna")
  block(above: 8pt, below: 9pt)[
    #set par(justify: false)
    #text(size: 24pt, weight: "bold", hyphenate: false, title)
  ]
  if names.len() > 0 { block(below: 4pt, text(font: sans, names.join(", "))) }
  let dates = (date, updated).filter(d => d != "").dedup()
  if dates.len() > 0 { text(font: sans, size: 9pt, fill: quiet, dates.join(" / ")) }
  line(length: 100%, stroke: rule)
  if summary != "" { block(inset: 9pt, width: 100%, fill: rgb("#f2f5f1"), emph(summary)) }
  body
}
