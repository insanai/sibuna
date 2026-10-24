// The common look of Sibuna's figures: page, fonts, colours and the words of each
// language. `cargo xtask figures` compiles every figure once per language, passing the
// language as `--input lang=<code>`; a figure takes its words from words/<code>.toml,
// and a word that a language lacks falls back to English.

#let lang = sys.inputs.at("lang", default: "en")

// ---- Colours (the book's palette) --------------------------------------------------

#let ink = rgb("#172033")
#let muted = rgb("#64748b")
#let rule = rgb("#cbd5e1")
#let faint = rgb("#f1f5f9")
#let blue = rgb("#1e40af")
#let blue-light = rgb("#eff6ff")
#let blue-mid = rgb("#bfdbfe")
#let green = rgb("#15803d")
#let green-light = rgb("#f0fdf4")
#let green-mid = rgb("#bbf7d0")
#let amber = rgb("#b45309")
#let amber-light = rgb("#fffbeb")
#let amber-mid = rgb("#fde68a")
#let red = rgb("#b91c1c")
#let red-light = rgb("#fef2f2")
#let red-mid = rgb("#fecaca")
#let violet = rgb("#6d28d9")
#let violet-light = rgb("#f5f3ff")

// ---- Fonts ---------------------------------------------------------------------------

// Latin text is set in Noto Sans; a script that Noto Sans lacks comes from its own Noto
// font (Debian packages fonts-noto-core and fonts-noto-cjk). The renderer fails on a
// missing font, so every machine draws the same letters.
#let script-fonts = (
  zh_CN: ("Noto Sans CJK SC",),
  ja: ("Noto Sans CJK JP",),
  ko: ("Noto Sans CJK KR",),
  hi: ("Noto Sans Devanagari",),
  ar: ("Noto Sans Arabic",),
)
#let fonts = ("Noto Sans",) + script-fonts.at(lang, default: ())
#let mono-fonts = ("DejaVu Sans Mono",) + script-fonts.at(lang, default: ())

// The Typst language of a guidedog language code such as "zh_CN".
#let text-lang = lang.split("_").at(0)

// Whether text runs from right to left. The drawings keep their geometry (time and byte
// offsets grow to the right); titles move to the right edge.
#let rtl = text-lang in ("ar", "fa", "he", "ur")

// ---- Words ---------------------------------------------------------------------------

#let english = toml("words/en.toml")
#let local = if lang == "en" { english } else { toml("words/" + lang + ".toml") }

// The words of one figure: the English table with this language's entries laid over it.
#let words(figure) = {
  let base = english.at(figure)
  let over = local.at(figure, default: (:))
  let merged = (:)
  for (key, value) in base {
    if type(value) == dictionary {
      merged.insert(key, value + over.at(key, default: (:)))
    } else {
      merged.insert(key, over.at(key, default: value))
    }
  }
  merged
}

// The number conventions of this language: decimal mark and digit-group separator.
#let number-words = english.number + local.at("number", default: (:))

// `template` with every "{name}" replaced by the value of `name` in `values`, which may
// be a string or content (a formula, for instance).
#let phrase(template, values) = {
  // Splitting at the braces leaves the names at the odd positions.
  let parts = template.split(regex("[{}]"))
  parts.enumerate().map(((i, part)) => if calc.odd(i) { values.at(part) } else { part }).join()
}

// A number written with this language's decimal mark and digit groups: `digits` places
// after the mark, and groups of three in the integer part from 10,000 on.
#let num(value, digits: 0) = {
  let rounded = calc.round(value, digits: digits)
  let whole = calc.trunc(rounded)
  let int-part = str(int(calc.abs(whole)))
  if int-part.len() > 4 {
    let grouped = ""
    for (i, c) in int-part.clusters().rev().enumerate() {
      if i > 0 and calc.rem(i, 3) == 0 { grouped = number-words.group + grouped }
      grouped = c + grouped
    }
    int-part = grouped
  }
  let sign = if rounded < 0 { "-" } else { "" }
  if digits == 0 { return sign + int-part }
  let fraction = str(calc.round(calc.abs(rounded - whole) * calc.pow(10, digits)))
  while fraction.len() < digits { fraction = "0" + fraction }
  sign + int-part + number-words.decimal + fraction
}

// ---- Page ----------------------------------------------------------------------------

// A figure on a white card that fits its content, so it reads on a light page and, as
// a light panel, on a dark one.
#let figure-page(body) = {
  set page(width: auto, height: auto, margin: 0pt, fill: none)
  // Every line box spans the font's ascender and descender, so labels anchored at the
  // same point line up whatever letters they hold.
  set text(font: fonts, size: 9pt, fill: ink, lang: text-lang, hyphenate: false,
    top-edge: "ascender", bottom-edge: "descender")
  set par(leading: 0.3em)
  // Noto Sans Arabic's ascender and descender are far apart, which spaces its lines
  // twice as wide as Latin ones; fixed edges give Arabic an even, moderate line height
  // with room for its dots.
  set text(top-edge: 0.95em, bottom-edge: -0.4em) if rtl
  set par(leading: 0.45em) if rtl
  show raw: set text(font: mono-fonts, size: 1.0em)
  block(fill: white, radius: 5pt, inset: (x: 14pt, y: 12pt), body)
}

// Small helpers for labels.
#let small(body) = text(size: 7.5pt, body)
#let caps(body) = text(size: 7.5pt, weight: "semibold", body)
#let note(body) = text(size: 7.5pt, fill: muted, body)
// Code and Latin values (numbers with units, options) keep their own order inside
// right-to-left text: the box isolates them from the surrounding paragraph.
#let code(body) = box(text(font: mono-fonts, size: 0.92em, dir: ltr, body))
#let latin(body) = box(text(dir: ltr, body))

// The anchor and x position of a title at the start of a span from `left` to `right`:
// the left end, or the right end in right-to-left text.
#let start-anchor(vertical) = vertical + if rtl { "-east" } else { "-west" }
#let start-x(left, right) = if rtl { right } else { left }

// ---- Legends ---------------------------------------------------------------------------

// Swatches for a legend: a filled box, a dot, a cross and a line.
#let swatch-box(paper, edge) = box(width: 0.32cm, height: 0.24cm, radius: 1.5pt,
  fill: paper, stroke: 0.6pt + edge, baseline: 0.02cm)
#let swatch-dot(paper, edge: none) = box(baseline: 0.02cm,
  circle(radius: 0.1cm, fill: paper, stroke: if edge == none { none } else { 1.1pt + edge }))
#let swatch-cross(paint) = box(width: 0.22cm, height: 0.22cm, baseline: 0.02cm, {
  place(line(start: (0pt, 0pt), end: (100%, 100%), stroke: 1.4pt + paint))
  place(line(start: (0pt, 100%), end: (100%, 0pt), stroke: 1.4pt + paint))
})
#let swatch-line(paint, thickness: 1.6pt, dash: none) = box(width: 0.6cm, height: 0.24cm,
  baseline: 0.02cm, align(horizon, line(length: 100%,
    stroke: (paint: paint, thickness: thickness, dash: dash))))

// A legend: (swatch, label) pairs in a row that wraps when the labels are long.
#let legend(..items) = {
  set text(size: 7.5pt, fill: muted)
  items.pos().map(((swatch, label)) => box(swatch + h(0.35em) + label))
    .join(h(1.4em, weak: true))
}

// A drawing with notes below it, as wide as the drawing, so long notes wrap instead of
// widening the figure.
#let with-notes(drawing, ..notes) = context {
  let size = measure(drawing)
  stack(spacing: 7pt, drawing, ..notes.pos().map(body => block(width: size.width, body)))
}
