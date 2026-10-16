// Sibuna's Typst design for guidedog PDF books: the shared theme.
//
// This one file holds the whole design: colors, fonts, the page, headings, tables, code,
// the admonition boxes, the book cover, and the frame of a Sibuna Discussion (SID)
// record. Every Sibuna guidedog project keeps an identical copy in its _templates/
// folder; Typst cannot import a file outside the project, so we copy instead of
// linking. When we change it, we copy it to the other projects:
//
//   cp docs/book/_templates/sibuna.typ docs/sid/_templates/sibuna.typ
//
// A project uses it with two small files of its own and one setting:
//
//   _templates/book.typ      defines guidedog's `book(...)` and calls `sibuna-book`
//                            (a book or manual) or `sibuna-sid` (the SID catalog).
//   _templates/preamble.typ  replaces guidedog's admonition helper with
//                            `sibuna-box` (books) or `sid-callout` (records).
//   conf.toml                pdf_preamble = "_templates/preamble.typ"
//
// A new book, such as the manual, copies all three files from docs/book and adds the
// setting. Without the preamble the design still applies; only admonitions keep
// guidedog's default look.
//
// Only fonts built into Typst are named (Libertinus Serif, New Computer Modern, DejaVu
// Sans Mono), so an English build needs no installed fonts and reports none missing. A
// book in Chinese, Japanese, Korean, Hindi or Arabic also needs the Noto fonts that
// sibuna-script-fonts names (Debian packages fonts-noto-cjk and fonts-noto-core).

// ---- Palette -------------------------------------------------------------------------
// The book's colors, from the original docs/book/theme.typ.
#let sibuna-ink = rgb("#172033")
#let sibuna-blue = rgb("#1e40af")
#let sibuna-blue-light = rgb("#eff6ff")
#let sibuna-green = rgb("#15803d")
#let sibuna-green-light = rgb("#f0fdf4")
#let sibuna-amber = rgb("#b45309")
#let sibuna-amber-light = rgb("#fffbeb")
#let sibuna-red = rgb("#b91c1c")
#let sibuna-red-light = rgb("#fef2f2")
#let sibuna-gray = rgb("#64748b")
#let sibuna-rule = rgb("#cbd5e1")
// The cover's night sky and copper.
#let sibuna-night = rgb("#142c3b")
#let sibuna-copper = rgb("#d7a15b")
#let sibuna-cream = rgb("#f4ecd9")
#let sibuna-mist = rgb("#a6b9bc")
// The record colors, from the original docs/shared/sid.typ.
#let sid-blue = rgb("#0284c7")
#let sid-blue-light = rgb("#f0f9ff")
#let sid-amber = rgb("#d97706")
#let sid-amber-light = rgb("#fffbeb")
#let sid-slate = rgb("#475569")
#let sid-muted = rgb("#64748b")
#let sid-text = rgb("#111827")
#let sid-labels-text = rgb("#334155")
#let sid-frame = rgb("#d7dee8")
#let sid-hairline = rgb("#e2e8f0")
#let sid-code-fill = rgb("#f8fafc")
// The fill of a record's state chip; any other state is amber.
#let sid-state-fills = (
  published: rgb("#dbeafe"),
  discussion: rgb("#dcfce7"),
  committed: rgb("#ede9fe"),
  abandoned: rgb("#e5e7eb"),
)
#let sid-state-other = rgb("#fef3c7")

#let sibuna-mono = ("DejaVu Sans Mono",)

// Chinese, Japanese and Korean code needs a monospace font whose Han, kana and Hangul are
// exactly two of its Latin columns wide, so translated ASCII diagrams stay aligned; that
// font goes first, so its own Latin glyphs set the column. Other languages keep DejaVu.
#let sibuna-cjk-mono = (zh: "Noto Sans Mono CJK SC", ja: "Noto Sans Mono CJK JP",
  ko: "Noto Sans Mono CJK KR")
#let sibuna-mono-for(code) = if code in sibuna-cjk-mono {
  (sibuna-cjk-mono.at(code),) + sibuna-mono
} else { sibuna-mono }

// ---- Small helpers -------------------------------------------------------------------

// The plain text of content: what a reader would copy from it.
#let sibuna-plain(it) = {
  if it == none { return "" }
  if type(it) == str { return it }
  if type(it) != content { return str(it) }
  let f = it.func()
  // Text, raw text, and the symbols that markup escapes such as \: produce.
  if it.has("text") and type(it.text) == str { return it.text }
  if f == smartquote { return if it.double { "\"" } else { "'" } }
  if f == linebreak or f == parbreak or f == [ ].func() { return " " }
  if it.has("children") { return it.children.map(sibuna-plain).join(default: "") }
  if it.has("body") { return sibuna-plain(it.body) }
  if it.has("child") { return sibuna-plain(it.child) }
  ""
}

// Text with its runs of white space made single spaces, trimmed.
#let sibuna-clean(s) = s.replace(regex("\s+"), " ").trim()

// The Typst language and region of a guidedog language such as "pt_BR"; anything
// unusable is English, so hyphenation always has patterns.
#let sibuna-language(lang) = {
  let parts = lang.replace("_", "-").split("-")
  let code = lower(parts.at(0))
  if code.len() < 2 or code.len() > 3 or code.match(regex("^[a-z]+$")) == none {
    code = "en"
  }
  let region = if parts.len() > 1 and parts.at(1).match(regex("^[A-Za-z]{2}$")) != none {
    upper(parts.at(1))
  } else { none }
  (code, region)
}

// The fonts for the scripts that New Computer Modern lacks, by language code. Typst
// takes each character from the first font in the list that has it, so Latin text keeps
// the book's font and the other characters come from these. English needs none.
#let sibuna-script-fonts = (
  zh: ("Noto Serif CJK SC", "Noto Sans CJK SC"),
  ja: ("Noto Serif CJK JP", "Noto Sans CJK JP"),
  ko: ("Noto Serif CJK KR", "Noto Sans CJK KR"),
  hi: ("Noto Serif Devanagari", "Noto Sans Devanagari"),
  ar: ("Noto Naskh Arabic", "Noto Sans Arabic"),
)

// The languages whose letters join (Arabic) or hang from a common line (Devanagari):
// letter spacing would pull them apart, so the cover and the part labels set them
// without it.
#let sibuna-joined-scripts = ("ar", "fa", "ur", "hi", "mr", "ne")

// The heading number guidedog gave a heading, or none.
#let sibuna-heading-number(it) = if it.numbering != none {
  numbering(it.numbering, ..counter(heading).at(it.location()))
}

// The number of header rows of a table, from its table.header.
#let sibuna-header-rows(it) = {
  let head = it.children.filter(c => c.func() == table.header)
  if head.len() == 0 { return 0 }
  let columns = if type(it.columns) == int { it.columns } else { it.columns.len() }
  let spans = head.first().children.filter(c => c.func() != table.hline)
    .map(c => if c.func() == table.cell { c.at("colspan", default: 1) } else { 1 })
  calc.ceil(spans.sum(default: 0) / calc.max(columns, 1))
}

// Tells whether a table is one of guidedog's helper tables (field lists, footnotes,
// grammars): they have an auto column and draw no rules.
#let sibuna-is-helper-table(it) = type(it.columns) == array and auto in it.columns

// Code blocks: each line is its own paragraph, so a line too long for the measure
// wraps with its continuation indented instead of running into the margin.
#let sibuna-code-block(it, fill: none, stroke: none, radius: 0pt, size: 0.8em) = {
  set text(size: size)
  set par(justify: false, first-line-indent: 0em, leading: 0.5em, hanging-indent: 2em)
  show linebreak: none
  show raw.line: line => block(spacing: 0.5em, { line; if line.text == "" { sym.zws } })
  block(width: 100%, fill: fill, stroke: stroke, radius: radius, inset: 8pt,
    breakable: true, above: 1.1em, below: 1.2em, it)
}

// ---- Admonition boxes ----------------------------------------------------------------
// The preamble of a project binds guidedog's gd-admonition(kind, title, body) to one of
// these. kind is the directive ("note", "warning", or "admonition" for a titled one).

#let sibuna-loud-kinds = ("warning", "caution", "danger", "error", "attention")

// Set by a "Part" chapter heading so its first paragraph is set as the part's summary;
// any other heading or box clears it.
#let sibuna-part-intro = state("sibuna-part-intro", false)

// A book box, as the original theme drew them: Exercise boxes amber, "Explain the
// invariant" boxes blue, both framed; every other box a callout with a rule down its
// left side, green for objectives, worked examples, definitions and lemmas, red for
// warnings, and blue otherwise. The title runs into the first paragraph.
// The opening words of the translated box titles, by language: a translation starts every
// title of a kind with the same words, so its boxes get the English boxes' colours.
// exercise and explain are framed amber and blue; plain titles keep the default colour
// although they start like an idea title; idea titles are green; stop titles are red.
#let sibuna-box-words = (
  zh: (
    exercise: ("练习",),
    explain: ("解释这个不变量",),
    plain: (),
    idea: ("学习目标", "实例分析", "引理", "定理", "采用的设计约束"),
    stop: ("继续之前",),
  ),
  ko: (
    exercise: ("연습 문제",),
    explain: ("불변식 설명하기",),
    plain: ("풀이 예제: 보정 계획",),
    idea: ("학습 목표", "풀이 예제:", "보조정리", "정리"),
    stop: ("계속하기 전에",),
  ),
  ja: (
    exercise: ("演習",),
    explain: ("不変条件を説明してください",),
    plain: (),
    idea: ("この章の学習目標", "例題：", "補題", "定理", "設計上の制約"),
    stop: ("先に進む前に",),
  ),
  es: (
    exercise: ("Ejercicio",),
    explain: ("Explica el invariante",),
    plain: (),
    idea: ("Objetivos", "En este capítulo", "Ejemplo resuelto", "Definición", "Lema", "Teorema", "Corolario", "Proposición", "Restricciones de diseño"),
    stop: ("Antes de continuar",),
  ),
  de: (
    exercise: ("Übung",),
    explain: ("Die Invariante erklären",),
    plain: (),
    idea: ("Lernziele", "Durchgerechnetes Beispiel", "Definition", "Lemma", "Satz", "Übernommene Entwurfsbeschränkungen"),
    stop: ("Bevor wir weitermachen",),
  ),
  hi: (
    exercise: ("अभ्यास",),
    explain: ("अपरिवर्तनीय नियम समझाएँ",),
    plain: ("हल किया गया उदाहरण: कैलिब्रेशन योजना",),
    idea: ("उद्देश्य", "हल किया गया उदाहरण", "लेम्मा", "प्रमेय", "अपनाई गई डिज़ाइन शर्तें"),
    stop: ("आगे बढ़ने से पहले",),
  ),
  ar: (
    exercise: ("تمرين",),
    explain: ("اشرح اللامتغير",),
    plain: (),
    idea: ("الأهداف", "مثال محلول", "تمهيدية", "مبرهنة"),
    stop: ("قبل المتابعة",),
  ),
)

#let sibuna-box(kind, title, body) = context {
  sibuna-part-intro.update(false)
  let name = sibuna-clean(sibuna-plain(title))
  let words = sibuna-box-words.at(text.lang, default: (:))
  let opens(role) = words.at(role, default: ()).any(w => name.starts-with(w))
  let lead(accent) = {
    let stop = if name.ends-with(regex("[.:?!]")) { [] } else { [.] }
    text(weight: "bold", fill: accent)[#title#stop]
    h(4pt)
  }
  let framed(accent, fill) = block(width: 100%, inset: 9pt, outset: (y: 3pt),
    radius: 3pt, fill: fill, stroke: 0.6pt + accent, breakable: true,
    above: 1.3em, below: 1.3em, {
      set par(first-line-indent: 0em)
      lead(accent)
      body
    })
  if name.starts-with("Exercise") or opens("exercise") {
    return framed(sibuna-amber, sibuna-amber-light)
  }
  if name.starts-with("Explain the invariant") or opens("explain") {
    return framed(sibuna-blue, sibuna-blue-light)
  }
  let idea = ("Objectives", "In this chapter", "Worked example", "Definition", "Lemma",
    "Theorem", "Corollary", "Proposition", "Design constraints")
  let stop = kind in sibuna-loud-kinds or name.starts-with("Before continuing")
  let (accent, fill) = if stop or opens("stop") {
    (sibuna-red, sibuna-red-light)
  } else if opens("plain") {
    (sibuna-blue, sibuna-blue-light)
  } else if kind in ("tip", "hint") or idea.any(w => name.starts-with(w)) or opens("idea") {
    (sibuna-green, sibuna-green-light)
  } else {
    (sibuna-blue, sibuna-blue-light)
  }
  block(width: 100%, inset: 10pt, outset: (y: 3pt), radius: 3pt, fill: fill,
    stroke: (left: 2.2pt + accent), breakable: true, above: 1.3em, below: 1.3em, {
      set par(first-line-indent: 0em)
      text(weight: "bold", fill: accent, title)
      h(5pt)
      body
    })
}

// A record's callout, as the original SID records drew them: a rounded frame, blue for
// notes, amber for warnings, gray for implementation notes, its title on a line of its
// own.
#let sid-callout(kind, title, body) = {
  let name = sibuna-clean(sibuna-plain(title))
  let (accent, fill) = if kind in sibuna-loud-kinds or kind == "important" {
    (sid-amber, sid-amber-light)
  } else if name.starts-with("Implementation") and not name.contains("review") {
    (sid-muted, luma(97%))
  } else {
    (sid-blue, sid-blue-light)
  }
  block(width: 100%, breakable: true, inset: 10pt, radius: 6pt, fill: fill,
    stroke: 0.8pt + accent, above: 1.2em, below: 1.2em, {
      set par(first-line-indent: 0em)
      block(above: 0em, below: 0.75em, sticky: true,
        text(weight: "bold", fill: accent, title))
      body
    })
}

// ---- The book cover ------------------------------------------------------------------

// The cover art of the original book, drawn with Typst's own curves: request paths
// narrowing toward an admission aperture, a proof tree above it, and probability
// contours below. Coordinates are those of the original drawing, in units of `unit`
// with y pointing up.
#let sibuna-cover-art(unit: 1cm) = {
  let (x0, y0) = (-6.4, 4.2)
  let at(p) = ((p.at(0) - x0) * unit, (y0 - p.at(1)) * unit)
  let polyline(points, stroke) = place(top + left, curve(stroke: stroke,
    curve.move(at(points.first())), ..points.slice(1).map(p => curve.line(at(p)))))
  let dot(c, r) = {
    let (x, y) = at(c)
    place(top + left, dx: x - r * unit, dy: y - r * unit,
      circle(radius: r * unit, fill: sibuna-copper, stroke: none))
  }
  box(width: 12.8 * unit, height: 8.0 * unit, {
    // Many possible request paths approach a narrow admission boundary.
    for j in range(23) {
      let points = range(101).map(k => {
        let x = -6.3 + k * 0.126
        let envelope = 0.23 + 0.77 * calc.pow(calc.abs(x) / 6.3, 0.65)
        (x, (j - 11) * 0.30 * envelope + 0.20 * calc.sin(x * 35deg))
      })
      let paint = if calc.rem(j, 4) == 0 { sibuna-copper } else { rgb("#517883") }
      polyline(points, 0.45pt + paint)
    }
    // A finite proof tree: dependency and authentication drawn as a constellation.
    for d in range(5) {
      let n = calc.pow(2, d)
      for i in range(n) {
        let x = (i + 0.5) * 7.2 / n - 3.6
        let y = 4.0 - d * 0.66
        if d > 0 {
          let px = (calc.quo(i, 2) + 0.5) * 7.2 / calc.pow(2, d - 1) - 3.6
          polyline(((x, y), (px, y + 0.66)), 0.45pt + sibuna-copper)
        }
        dot((x, y), if d == 0 { 0.085 } else { 0.038 })
      }
    }
    // Probability contours below the aperture: exp(-x), not a measured curve.
    for j in range(9) {
      let points = range(80).map(k => {
        let x = k / 13.0 - 3
        (x, -1.3 - j * 0.20 - 0.70 * calc.exp(-(x + 3) * 0.7))
      })
      polyline(points, 0.45pt + rgb("#89a9a4"))
    }
    polyline(((-0.48, -0.7), (-0.48, 0.8), (0, 1.1), (0.48, 0.8), (0.48, -0.7)),
      1.7pt + sibuna-copper)
    dot((0, 0.15), 0.12)
  })
}

// The cover: the night page with its copper lettering and art. spaced is false for a
// script that letter spacing would break (see sibuna-joined-scripts).
#let sibuna-cover(page-size, title: "", author: "", version: "", date: "",
  version-label: "Version", kicker: none, headline: none, subtitle: none, motto: none,
  cover-note: none, logo: none, spaced: true) = {
  let spacing(amount) = if spaced { amount } else { 0pt }
  page(..page-size, margin: (x: 18mm, y: 17mm), header: none, footer: none,
    numbering: none, fill: sibuna-night, {
      set text(fill: sibuna-cream)
      set par(justify: false, first-line-indent: 0em)
      align(center, {
        v(6mm)
        if logo != none { image(logo, height: 14mm); v(4mm) }
        if kicker != none {
          text(size: 9pt, tracking: spacing(2.8pt), fill: sibuna-copper, kicker)
        }
        v(9mm)
        let big = if headline != none { headline } else { upper(title) }
        block(text(size: 46pt, tracking: 5pt, weight: "regular", hyphenate: false, big))
        if subtitle != none { v(9mm); text(size: 13pt, subtitle) }
        v(14mm)
        sibuna-cover-art()
        v(9mm)
        if motto != none {
          text(size: 10pt, tracking: spacing(1pt), fill: sibuna-copper, motto)
        }
        v(1fr)
        if author != "" { text(size: 10pt, author) }
        if cover-note != none { v(2mm); text(size: 8.5pt, fill: sibuna-mist, cover-note) }
        let edition = (if version != "" [#version-label #version], if date != "" [#date])
          .filter(x => x != none)
        if edition.len() > 0 {
          v(2mm)
          text(size: 8.5pt, fill: sibuna-mist, edition.join([ \u{00B7} ]))
        }
      })
    })
}

// ---- The book ------------------------------------------------------------------------

// How the title of a part's chapter reads in English: "Part VI: Automata" is the label
// "Part VI" and the title "Automata". A translated book gives the pattern of its own
// language (see the covers table in book.typ): a regular expression whose first group
// is the label and whose second is the title.
#let sibuna-part-pattern = regex("^(Part\s+[IVXLCDM0-9]+)\s*[:.]?\s*(.*)$")

// A chapter heading: a new page, the title set large, and a short blue rule. A chapter
// whose title matches part-pattern is a part: "Part VI: Automata" shows a letter-spaced
// PART VI above the title "Automata", and its first paragraph becomes the part's
// italic summary. spaced is false for a script that letter spacing would break.
#let sibuna-chapter-heading(it, part-pattern: sibuna-part-pattern, spaced: true) = {
  if not it.outlined {
    sibuna-part-intro.update(false)
    return block(above: 1.6em, below: 0.8em, sticky: true,
      text(size: 15pt, weight: "bold", it.body))
  }
  pagebreak(weak: true)
  let name = sibuna-clean(sibuna-plain(it.body))
  let part = name.match(part-pattern)
  let number = sibuna-heading-number(it)
  block(width: 100%, above: 4mm, below: 6mm, sticky: true, {
    set par(justify: false, first-line-indent: 0em, leading: 0.4em)
    if part != none {
      text(size: 9pt, weight: "bold", tracking: if spaced { 2.4pt } else { 0pt },
        fill: sibuna-blue, upper(part.captures.at(0)))
      v(2.5mm)
      text(size: 22pt, weight: "bold", hyphenate: false, part.captures.at(1))
    } else {
      text(size: 22pt, weight: "bold", hyphenate: false, {
        if number != none { number; h(0.5em) }
        it.body
      })
    }
    v(3mm)
    line(length: 42mm, stroke: 1.6pt + sibuna-blue)
  })
  sibuna-part-intro.update(part != none)
}

// The running head: the book's title on the left, and the chapter on the right: the
// chapter that opens on this page, or else the last one before it.
// The languages whose scripts set marks above and below the line: Devanagari's reph and
// vowel signs, the dots of Arabic letters. A clipping box cuts them off at the line, so
// the running header's boxes clip these scripts with room above and below.
#let sibuna-tall-scripts = ("hi", "ar", "fa", "he", "ur")

// fonts is the book's font list: the page header is laid out apart from the body, and
// without it a script's characters fall back to any font that has them (Devanagari
// then loses its vowel signs).
#let sibuna-running-head(title, fonts: auto) = context {
  let pg = here().page()
  if pg <= 1 { return }
  let chapters = query(heading.where(level: 1, outlined: true))
    .filter(h => h.location().page() <= pg)
  let chapter = if chapters.len() > 0 { chapters.last().body } else { [] }
  if fonts != auto { set text(font: fonts) }
  set text(size: 8pt, fill: sibuna-gray, number-type: "lining")
  set par(justify: false, first-line-indent: 0em)
  let room = if text.lang in sibuna-tall-scripts { (y: 0.5em) } else { 0pt }
  // The book's title takes its own width and the chapter's the rest, so the long
  // chapter titles of some translations still fit on one line.
  grid(columns: (auto, 1fr), column-gutter: 1em,
    box(clip: true, outset: room, title),
    box(width: 100%, clip: true, outset: room, align(end, emph(chapter))))
  v(-0.5em)
  line(length: 100%, stroke: 0.4pt + sibuna-rule)
}

// The contents, titled like a chapter; title is "Contents" in the book's language.
// The colophon, when there is one, sits at the foot of the last contents page.
#let sibuna-contents(colophon: none, title: [Contents]) = context {
  if query(heading.where(outlined: true)).len() == 0 { return }
  pagebreak(weak: true)
  block(above: 4mm, below: 8mm, {
    text(size: 22pt, weight: "bold", title)
    v(3mm)
    line(length: 42mm, stroke: 1.6pt + sibuna-blue)
  })
  set par(justify: false, first-line-indent: 0em)
  set outline.entry(fill: box(width: 1fr, repeat(text(fill: sibuna-rule)[.], gap: 0.3em)))
  show outline.entry.where(level: 1): it => {
    v(0.9em, weak: true)
    strong(it)
  }
  outline(title: none, depth: 2, indent: auto)
  if colophon != none {
    v(1fr)
    block(above: 2em, colophon)
  }
  pagebreak(weak: true)
}

// Tables, figures, code, links and quotes in the book's style: a full grid of light
// rules, bold head rows, framed code.
#let sibuna-book-blocks(body) = {
  // Guidedog sets a table in a figure; a figure does not break across pages unless
  // told to, so long tables would run off the page. Head rows repeat on every page.
  show figure: set block(breakable: true)
  show figure.caption: set text(size: 9pt, fill: sibuna-gray)
  set figure(gap: 0.8em)
  set table(stroke: 0.45pt + sibuna-rule, inset: 6pt, align: start)
  show table: set par(justify: false, first-line-indent: 0em)
  show table: it => {
    if sibuna-is-helper-table(it) { return it }
    let rows = sibuna-header-rows(it)
    show table.cell: c => if c.y < rows { strong(c) } else { c }
    it
  }
  show raw: set text(font: sibuna-mono, size: 8.3pt, hyphenate: false, ligatures: false)
  show raw.where(block: true): it => sibuna-code-block(it, stroke: 0.6pt + sibuna-rule,
    radius: 3pt, size: 1em)
  show link: set text(fill: sibuna-blue)
  set quote(block: true)
  show quote.where(block: true): it => block(width: 88%, inset: (left: 12pt, right: 8pt,
    y: 7pt), outset: (y: 4pt), stroke: (left: 1.4pt + sibuna-blue), above: 1.3em,
    below: 1.3em, {
      emph(it.body)
      if it.attribution != none {
        linebreak()
        align(end, text(size: 9pt, fill: sibuna-gray)[- #it.attribution])
      }
    })
  body
}

// The Sibuna book, with guidedog's book(...) parameters (see the Templates chapter of
// the guidedog manual) and the cover's own: kicker, headline (the big word; the title in
// capitals when none), subtitle, motto and cover-note. Two more words follow the book's
// language: contents-title, the heading of the contents, and part-pattern, how a part's
// chapter title reads (see sibuna-part-pattern). trim is the page size, the original
// 190 mm by 250 mm; none follows pdf_paper_size.
#let sibuna-book(
  title: "",
  author: "",
  version: "",
  date: "",
  lang: "en",
  paper: "a4",
  numbering: false,
  logo: none,
  copyright: "",
  version-label: "Version",
  page-ref: none,
  kicker: none,
  headline: none,
  subtitle: none,
  motto: none,
  cover-note: none,
  contents-title: [Contents],
  part-pattern: sibuna-part-pattern,
  trim: (width: 190mm, height: 250mm),
  body,
) = {
  let (code, region) = sibuna-language(lang)
  let page-size = if trim == none { (paper: paper) } else { trim }
  let spaced = code not in sibuna-joined-scripts
  set document(title: title, author: if author == "" { () } else { author })
  let fonts = ("New Computer Modern", "Libertinus Serif") + sibuna-script-fonts.at(code,
    default: ())
  set text(font: fonts, size: 10.5pt,
    fill: sibuna-ink, lang: code, region: region, hyphenate: true)
  set par(justify: true, leading: 0.60em, spacing: 0.62em)
  set list(indent: 0.4em)
  set enum(indent: 0.4em)
  state("gd-page-ref").update(_ => page-ref)

  show heading: set text(fill: sibuna-ink, hyphenate: false)
  show heading: set par(justify: false, first-line-indent: 0em)
  show heading: it => { sibuna-part-intro.update(false); it }
  show heading.where(level: 1): sibuna-chapter-heading.with(part-pattern: part-pattern,
    spaced: spaced)
  show heading.where(level: 2): set text(size: 15pt)
  show heading.where(level: 2): set block(above: 1.6em, below: 0.9em)
  show heading.where(level: 3): set text(size: 12pt, fill: sibuna-blue)
  show heading.where(level: 3): set block(above: 1.4em, below: 0.8em)
  // A part's summary: the first paragraph after a "Part" heading.
  show par: it => context {
    if sibuna-part-intro.get() {
      sibuna-part-intro.update(false)
      block(above: 0pt, below: 9pt, text(style: "italic", fill: sibuna-gray, it))
    } else { it }
  }
  show: sibuna-book-blocks
  // In a right-to-left book code still reads left to right. Inline code goes in a box,
  // so the right-to-left text around it cannot reorder its characters.
  let rtl = code in ("ar", "fa", "he", "ur")
  show raw: it => if not rtl { it } else if it.block { set text(dir: ltr); it } else {
    set text(dir: ltr)
    box(it)
  }
  show raw: set text(font: sibuna-mono-for(code))

  sibuna-cover(page-size, title: title, author: author, version: version,
    date: date, version-label: version-label, kicker: kicker, headline: headline,
    subtitle: subtitle, motto: motto, cover-note: cover-note, logo: logo,
    spaced: spaced)

  set page(..page-size,
    margin: (inside: 21mm, outside: 18mm, top: 19mm, bottom: 20mm),
    numbering: "1", number-align: center,
    header: sibuna-running-head(title, fonts: fonts))
  let colophon = if copyright != "" {
    text(size: 8pt, fill: sibuna-gray)[#emph(title)#if version != "" [,
      #version-label #version] \ \u{00A9} #copyright]
  }
  sibuna-contents(colophon: colophon, title: contents-title)
  body
}

// ---- The SID record ------------------------------------------------------------------

// A field name in a record's frame: small, bold, letter-spaced capitals.
#let sid-label(name) = text(8.7pt, weight: "bold", tracking: 0.04em, fill: sid-slate,
  upper(name))

// A field value in a record's frame.
#let sid-value(body) = text(10.2pt, fill: sid-text, body)

// A record's state chip.
#let sid-chip(state) = box(inset: (x: 0.45em, y: 0.25em), radius: 999pt,
  fill: sid-state-fills.at(state, default: sid-state-other),
  text(9pt, weight: "semibold", state))

// The fields of guidedog's gd-fields table, as a dictionary from the lowercase field
// name ("number", "title", "state", ...) to its plain text.
#let sid-fields-of(it) = {
  let fields = (:)
  for pair in it.children.chunks(2) {
    if pair.len() < 2 { continue }
    let name = lower(sibuna-clean(sibuna-plain(pair.at(0)))).trim(":").trim()
    fields.insert(name, sibuna-clean(sibuna-plain(pair.at(1))))
  }
  fields
}

// Tells whether a table is the field list that opens a record: guidedog's gd-fields
// table, whose first cell is "Number".
#let sid-is-fields(it) = {
  if not sibuna-is-helper-table(it) or it.children.len() < 2 { return false }
  sibuna-clean(sibuna-plain(it.children.first())).starts-with("Number")
}

// The frame that opens a record, made from its fields, as the original SID frame drew
// it: the group and series, the number and category, the title, then the state chip,
// intended status, dates, authors, discussion summary and labels; then the status of
// the memo and the contents.
#let sid-frontmatter(fields, title: "", prefix: "SID", group: none, series: none,
  memo: none) = {
  let field(name, default: "") = {
    let value = fields.at(name, default: "")
    if value == "" { default } else { value }
  }
  let number = field("number", default: "XXXXX")
  let state = field("state")
  let category = field("category", default: field("type"))
  let discussion = field("discussion")
  let summary = field("summary", default: discussion)
  let authors = field("authors").split(", ").join("\n")
  block(width: 100%, inset: (x: 1.05em, y: 0.95em), stroke: 0.65pt + sid-frame,
    fill: luma(99%), breakable: false, {
      set par(justify: false, first-line-indent: 0em)
      grid(columns: (1fr, auto), column-gutter: 1.4em,
        [
          #if group != none { text(12.4pt, weight: "bold", group) }
          #if series != none { linebreak(); text(9.3pt, fill: sid-muted, series) }
        ],
        align(right)[
          #text(13.5pt, weight: "bold")[#prefix #number]
          #linebreak()
          #text(9.3pt, weight: "semibold", fill: sid-muted, category)
        ])
      v(0.95em)
      block(text(21pt, weight: "bold", hyphenate: false, field("title", default: title)))
      v(0.55em)
      line(length: 100%, stroke: 0.7pt + sid-hairline)
      v(0.8em)
      grid(columns: (1fr, 1fr), column-gutter: 1.9em, row-gutter: 0.5em,
        sid-label[State], sid-label[Intended status],
        sid-chip(state), sid-value(field("status", default: state)),
        sid-label[Created], sid-label[Authors],
        sid-value(field("created")), grid.cell(rowspan: 3, sid-value(authors)),
        sid-label[Last updated],
        sid-value(field("updated")))
      v(0.65em)
      sid-label[Discussion]
      linebreak()
      sid-value(summary)
      if discussion.starts-with("http") {
        linebreak()
        text(9.3pt, link(discussion, discussion))
      }
      if field("labels") != "" {
        v(0.65em)
        sid-label[Labels]
        linebreak()
        text(10pt, fill: sid-labels-text, field("labels"))
      }
    })
  v(1em)
  if memo != none {
    block(width: 100%, inset: 0.9em, stroke: 0.7pt + rgb("#9ca3af"), fill: luma(98%), {
      set par(first-line-indent: 0em)
      strong[Status of This Memo]
      parbreak()
      memo
    })
    v(1em)
  }
  outline(title: [Contents], indent: 1.4em, depth: 3)
  v(1em)
}

// A Sibuna Discussion record, with guidedog's book(...) parameters and the frame's own:
// prefix ("SID"), group and series (the two lines at the frame's top left), and memo
// (the text of the "Status of This Memo" box; none leaves the box out).
#let sibuna-sid(
  title: "",
  author: "",
  version: "",
  date: "",
  lang: "en",
  paper: "a4",
  numbering: false,
  logo: none,
  copyright: "",
  version-label: "Version",
  page-ref: none,
  prefix: "SID",
  group: none,
  series: none,
  memo: none,
  body,
) = {
  let (code, region) = sibuna-language(lang)
  set document(title: title, author: if author == "" { () } else { author })
  set page(paper: paper, margin: (x: 1.15in, y: 1in), numbering: "1",
    number-align: center)
  set text(font: ("Libertinus Serif", "New Computer Modern"), size: 11pt, lang: code,
    region: region, hyphenate: true)
  set par(justify: true, leading: 0.7em)
  state("gd-page-ref").update(_ => page-ref)

  // Sections are numbered "1.", "1.1." as in the original records, unless guidedog
  // numbers them. A record's sections are level 2: its title is the book's.
  set heading(numbering: (..n) => {
    let parts = n.pos().slice(1)
    if parts.len() > 0 { parts.map(str).join(".") + "." }
  }) if not numbering
  show heading: set par(justify: false, first-line-indent: 0em)
  show heading: set text(hyphenate: false)
  show heading.where(level: 2): set text(size: 1.4em)
  show heading.where(level: 3): set text(size: 1.2em)
  show heading.where(level: 4): set text(size: 1.05em)

  // Long tables break across pages; head rows repeat.
  show figure: set block(breakable: true)
  show figure.caption: set text(size: 9.5pt, fill: sid-muted)
  set table(stroke: 0.8pt + black, inset: 5pt, align: start)
  show table: set par(justify: false, first-line-indent: 0em)
  show table: it => {
    if sid-is-fields(it) {
      return sid-frontmatter(sid-fields-of(it), title: title, prefix: prefix,
        group: group, series: series, memo: memo)
    }
    if sibuna-is-helper-table(it) { return it }
    let rows = sibuna-header-rows(it)
    show table.cell: c => if c.y < rows { strong(c) } else { c }
    it
  }
  show raw: set text(font: sibuna-mono, hyphenate: false, ligatures: false)
  show raw.where(block: true): it => sibuna-code-block(it, fill: sid-code-fill,
    stroke: 0.65pt + sid-hairline, radius: 4pt)
  show link: set text(fill: sid-blue)
  body
}
