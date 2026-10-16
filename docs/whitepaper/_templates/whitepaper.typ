// The Typst design of the Sibuna whitepaper for guidedog.
//
// It reproduces the design system of the first whitepaper (docs/whitepaper/whitepaper.typ
// in the Zig repository, September 2026): an A4 page with a title block instead of a
// cover, a running header and footer from the second page on, numbered sections ruled in
// sky blue, banded tables with a heavy rule under the head row, and the three "voice"
// boxes of Feynman (amber), Knuth (violet) and Lamport (sky). Guidedog's book(...) call is
// defined in book.typ, and preamble.typ binds guidedog's admonition and topic helpers to
// the boxes below:
//
//   _templates/book.typ        defines `book(...)` and calls `wp-paper`.
//   _templates/preamble.typ    binds gd-admonition to `wp-box` and gd-topic to
//                              `wp-abstract`, and exports `wp-metrics` for raw Typst.
//   conf.toml                  pdf_preamble = "_templates/preamble.typ"
//
// Only fonts built into Typst are named (New Computer Modern, Libertinus Serif, DejaVu
// Sans Mono), so a build needs no installed fonts.

// ---- Palette -------------------------------------------------------------------------
// The colors of the first whitepaper, named as it named them.
#let wp-ink = rgb("#0f172a") // Slate 900
#let wp-primary = rgb("#0369a1") // Sky 700
#let wp-primary-light = rgb("#f0f9ff") // Sky 50
#let wp-primary-text = rgb("#075985") // Sky 800, for text on the Lamport box
#let wp-purple = rgb("#6d28d9") // Violet 700
#let wp-purple-light = rgb("#f5f3ff") // Violet 50
#let wp-purple-text = rgb("#4c1d95") // Violet 900
#let wp-gold = rgb("#b45309") // Amber 700
#let wp-gold-light = rgb("#fffbeb") // Amber 50
#let wp-gold-text = rgb("#78350f") // Amber 900
#let wp-green = rgb("#047857") // Emerald 700
#let wp-green-light = rgb("#ecfdf5") // Emerald 50
#let wp-red = rgb("#b91c1c") // Red 700
#let wp-red-light = rgb("#fef2f2") // Red 50
#let wp-muted = rgb("#64748b") // Slate 500
#let wp-body-muted = rgb("#334155") // Slate 700
#let wp-border = rgb("#cbd5e1") // Slate 300
#let wp-light-border = rgb("#e2e8f0") // Slate 200
#let wp-panel = rgb("#f8fafc") // Slate 50
#let wp-head-fill = rgb("#f1f5f9") // Slate 100
#let wp-band-fill = rgb("#fafafa")

#let wp-serif = ("New Computer Modern", "Libertinus Serif")
#let wp-mono = ("DejaVu Sans Mono",)

// ---- Small helpers -------------------------------------------------------------------

// The plain text of content: what a reader would copy from it.
#let wp-plain(it) = {
  if it == none { return "" }
  if type(it) == str { return it }
  if type(it) != content { return str(it) }
  if it.has("text") and type(it.text) == str { return it.text }
  if it.func() == smartquote { return if it.double { "\"" } else { "'" } }
  if it.func() == linebreak or it.func() == parbreak or it.func() == [ ].func() {
    return " "
  }
  if it.has("children") { return it.children.map(wp-plain).join(default: "") }
  if it.has("body") { return wp-plain(it.body) }
  if it.has("child") { return wp-plain(it.child) }
  ""
}

// Text with its runs of white space made single spaces, trimmed.
#let wp-clean(s) = s.replace(regex("\s+"), " ").trim()

// The Typst language code of a guidedog language such as "en" or "pt_BR".
#let wp-language(lang) = {
  let code = lower(lang.replace("_", "-").split("-").at(0))
  if code.len() < 2 or code.len() > 3 or code.match(regex("^[a-z]+$")) == none { "en" } else {
    code
  }
}

// ---- Boxes ---------------------------------------------------------------------------
// guidedog writes each admonition as gd-admonition(kind, title, body); the preamble binds
// that name to wp-box. The title decides the box, as in the first whitepaper.

// A voice box: a colored rule down the left side, a tint, a bold title, then the body.
#let wp-voice(accent, fill, ink, italic, title, body) = block(width: 100%,
  stroke: (left: 3pt + accent), fill: fill, inset: (x: 10pt, y: 7pt),
  radius: (right: 3pt), breakable: false, above: 1.2em, below: 1.2em, {
    set par(first-line-indent: 0em, justify: true)
    text(weight: "bold", size: 8.8pt, fill: accent, title)
    v(2pt)
    text(size: 8.8pt, fill: ink, style: if italic { "italic" } else { "normal" }, body)
  })

// A theorem: a white framed box with the statement and its proof, ended by a square.
#let wp-theorem(title, body) = block(width: 100%, stroke: 0.5pt + wp-border,
  fill: white, inset: 8pt, radius: 4pt, breakable: true, above: 1.2em, below: 1.2em, {
    set par(first-line-indent: 0em)
    text(weight: "bold", fill: wp-ink, title)
    text(weight: "bold", fill: wp-ink)[.]
    h(4pt)
    body
    align(right, text(fill: wp-primary, $square$))
  })

// A callout: a rule down the left side, a tint, and the title run into the first line.
#let wp-callout(accent, fill, title, body, rule: 2.5pt, breakable: true) = block(
  width: 100%, stroke: (left: rule + accent), fill: fill, inset: 8pt, radius: 3pt,
  breakable: breakable, above: 1.2em, below: 1.2em, {
    set par(first-line-indent: 0em)
    let name = wp-clean(wp-plain(title))
    let stop = if name.ends-with(regex("[.:?!]")) { [] } else { [.] }
    text(weight: "bold", fill: accent)[#title#stop]
    h(4pt)
    body
  })

#let wp-loud-kinds = ("warning", "caution", "danger", "error", "attention", "important")

// The admonition boxes, chosen by title: "Feynman ...", "Knuth ..." and "Lamport ..."
// are the voice boxes; "Theorem ..." and "Lemma ..." the framed theorem box;
// "Invariant ..." the slate box of the first paper's invariants; "Pending ..." and
// loud kinds the amber box; every other title a sky callout.
#let wp-box(kind, title, body) = {
  let name = wp-clean(wp-plain(title))
  if name.starts-with("Feynman") {
    return wp-voice(wp-gold, wp-gold-light, wp-gold-text, true, title, body)
  }
  if name.starts-with("Knuth") {
    return wp-voice(wp-purple, wp-purple-light, wp-purple-text, false, title, body)
  }
  if name.starts-with("Lamport") {
    return wp-voice(wp-primary, wp-primary-light, wp-primary-text, false, title, body)
  }
  if name.starts-with("Theorem") or name.starts-with("Lemma") {
    return wp-theorem(title, body)
  }
  if name.starts-with("Invariant") {
    // Invariants are read as one statement, so they are kept on one page.
    return wp-callout(wp-primary, wp-panel, title, body, breakable: false)
  }
  if name.starts-with("Pending") or kind in wp-loud-kinds {
    return wp-callout(wp-gold, wp-gold-light, title, body, rule: 3pt, breakable: false)
  }
  // Callouts are short notes; kept whole, they never split around a floating table.
  wp-callout(wp-primary, wp-primary-light, title, body, rule: 2pt, breakable: false)
}

// The abstract: guidedog writes a topic as gd-topic(title, body), and the preamble binds
// that name here. A slate panel with the title centered in small bold capitals.
#let wp-abstract(title, body) = block(width: 100%, fill: wp-panel, inset: 9pt,
  radius: 5pt, stroke: 0.6pt + wp-border, above: 0.8em, below: 1em, {
    set par(first-line-indent: 0em)
    align(center, text(weight: "bold", size: 8.5pt, fill: wp-ink, upper(title)))
    v(1pt)
    text(size: 8.4pt, fill: wp-body-muted, body)
  })

// One metric card: a large figure, its label, and a line of context.
#let wp-metric-card(value, label, subtext) = block(stroke: 0.6pt + wp-border,
  fill: white, inset: (x: 6pt, top: 5pt, bottom: 6pt), radius: 4pt, width: 100%,
  align(center, {
    set par(justify: false, first-line-indent: 0em)
    text(size: 15.5pt, weight: "bold", fill: wp-primary, value)
    v(-3pt)
    text(size: 7.5pt, weight: "bold", fill: wp-ink, label)
    v(-4pt)
    text(size: 6.6pt, fill: wp-muted, subtext)
  }))

// A row of metric cards from (value, label, subtext) triples, with a source line under it.
#let wp-metrics(source: none, ..cards) = {
  let cards = cards.pos()
  block(width: 100%, above: 0.6em, below: 0.9em, {
    grid(columns: (1fr,) * cards.len(), gutter: 6pt,
      ..cards.map(((value, label, subtext)) => wp-metric-card(value, label, subtext)))
    if source != none {
      v(2pt)
      align(center, text(size: 6.8pt, fill: wp-muted, source))
    }
  })
}

// ---- The title block -----------------------------------------------------------------
// The first page has no cover: a centered block with the headline, the subtitle, a
// tagline, the authors and the affiliation, as in the first whitepaper.
#let wp-title-block(headline: none, subtitle: none, tagline: none, author: "",
  affiliation: none) = align(center, {
  set par(justify: false, first-line-indent: 0em, leading: 0.5em)
  v(2mm)
  text(size: 21pt, weight: "bold", fill: wp-ink, tracking: 0.5pt, headline)
  v(1mm)
  if subtitle != none { text(size: 12pt, weight: "medium", fill: wp-primary, subtitle) }
  if tagline != none {
    v(0.5mm)
    text(size: 8.8pt, fill: wp-muted, tagline)
  }
  v(3mm)
  if author != "" {
    let names = author.split(" and ")
    text(size: 8.8pt, weight: "bold", fill: wp-ink,
      names.join([#h(10pt) and #h(10pt)]))
  }
  if affiliation != none {
    v(0.5mm)
    text(size: 8pt, fill: wp-muted, affiliation)
  }
  v(3mm)
})

// ---- The paper -----------------------------------------------------------------------

// Tables, figures, code and footnotes in the first whitepaper's style.
#let wp-blocks(body) = {
  // Guidedog sets a table in a figure; a figure does not break across pages unless told
  // to, so long tables would run off the page. Head rows repeat on every page.
  show figure: set block(breakable: true)
  // Diagrams float to the top or bottom of a page instead of leaving a gap before them.
  set figure(gap: 0.7em, placement: auto)
  show figure: set block(above: 1.2em, below: 1.2em)
  show figure.caption: it => {
    set text(size: 8.2pt, fill: wp-muted)
    set par(justify: false, first-line-indent: 0em)
    show strong: set text(fill: wp-primary)
    block(width: 100%, it)
  }
  // A table's caption sits above it. Inside a breakable figure the caption could stay at
  // the foot of one page while the table starts on the next, so a table figure is laid
  // out as two blocks in the page flow: the caption, kept with what follows, then the
  // table, which breaks across pages and repeats its head row.
  // A short table (at most 12 rows) is kept whole with its caption and floats, because
  // a sticky caption alone does not stop a table from leaving it at the foot of a page.
  // A longer table stays in the text and breaks across pages.
  show figure.where(kind: table): it => {
    let rows = if it.body.func() == table {
      let columns = if type(it.body.columns) == int { it.body.columns } else {
        it.body.columns.len()
      }
      let cells = it.body.children.map(c => if c.func() == table.header {
        c.children.filter(x => x.func() != table.hline).len()
      } else if c.func() == table.hline { 0 } else { 1 }).sum(default: 0)
      calc.ceil(cells / calc.max(columns, 1))
    } else { 0 }
    if rows <= 12 {
      // Floats to the top or bottom of the page, so the text fills the space a table
      // that does not fit would otherwise leave empty.
      place(auto, float: true, clearance: 1.2em, block(width: 100%, breakable: false, {
        it.caption
        v(0.7em, weak: true)
        it.body
      }))
    } else {
      block(width: 100%, sticky: true, above: 1.2em, below: 0.7em, it.caption)
      block(width: 100%, above: 0.7em, below: 1.2em, breakable: true, it.body)
    }
  }

  // Tables: a slate head row over a heavy ink rule (guidedog draws it as the hline
  // after the head), hairlines between body cells, and banded rows.
  set table(
    stroke: (x, y) => if y == 0 { none } else { 0.4pt + wp-light-border },
    fill: (x, y) => if y == 0 { wp-head-fill } else if calc.even(y) { wp-band-fill } else {
      white
    },
    inset: 4.5pt,
    align: start,
  )
  set table.hline(stroke: 1.4pt + wp-ink)
  show table: set text(size: 8.2pt, number-type: "lining", number-width: "tabular")
  show table: set par(justify: false, first-line-indent: 0em, leading: 0.5em)
  show table.cell.where(y: 0): set text(weight: "bold")

  // Code and ASCII figures: a slate panel with a hairline frame.
  show raw: set text(font: wp-mono, hyphenate: false, ligatures: false)
  show raw.where(block: false): set text(size: 0.92em)
  show raw.where(block: true): it => {
    set text(size: 7.4pt)
    set par(justify: false, first-line-indent: 0em, leading: 0.45em)
    show linebreak: none
    show raw.line: line => block(spacing: 0.45em, { line; if line.text == "" { sym.zws } })
    block(width: 100%, fill: wp-panel, stroke: 0.6pt + wp-border, radius: 3pt,
      inset: 7pt, breakable: true, above: 0.9em, below: 0.9em, it)
  }

  show link: set text(fill: wp-primary)
  set footnote.entry(separator: line(length: 25%, stroke: 0.4pt + wp-border),
    clearance: 0.8em, gap: 0.4em, indent: 0em)
  show footnote.entry: set text(size: 7.4pt, fill: wp-body-muted)
  show footnote.entry: set par(justify: false, first-line-indent: 0em, leading: 0.45em)
  set list(indent: 0.4em, body-indent: 0.5em)
  set enum(indent: 0.4em, body-indent: 0.5em)
  set quote(block: true)
  show quote.where(block: true): it => block(inset: (left: 10pt, y: 4pt),
    stroke: (left: 1.2pt + wp-primary), emph(it.body))
  body
}

// Section headings. The root document's sections are level 2 (its title is the paper's
// title), so level 2 is a numbered section with the primary rule, level 3 a subsection in
// sky blue, and level 4 a bold run-in heading in ink.
#let wp-headings(numbered, body) = {
  set heading(numbering: (..n) => {
    let parts = n.pos().slice(1)
    if parts.len() > 0 { parts.map(str).join(".") }
  }) if not numbered
  show heading: set par(justify: false, first-line-indent: 0em)
  show heading: set text(hyphenate: false, number-type: "lining")
  show heading: it => block(below: 0.55em, above: 1.05em, sticky: true, {
    if it.level <= 2 {
      v(0.3em)
      text(size: 13.5pt, weight: "bold", fill: wp-ink, it)
      v(-0.25em)
      line(length: 100%, stroke: 1.2pt + wp-primary)
    } else if it.level == 3 {
      text(size: 11pt, weight: "bold", fill: wp-primary, it)
    } else {
      text(size: 9.8pt, weight: "bold", fill: wp-ink, it)
    }
  })
  body
}

// The running header and footer: blank on the first page, then the paper's short title
// and date over a hairline, and the affiliation and "n of N" under one.
#let wp-header(running-title, date-line) = context {
  if here().page() <= 1 { return }
  set par(justify: false, first-line-indent: 0em)
  grid(columns: (auto, 1fr),
    align(left, text(size: 8pt, fill: wp-muted, weight: "bold", running-title)),
    align(right, text(size: 8pt, fill: wp-muted, style: "italic", date-line)))
  v(-3pt)
  line(length: 100%, stroke: 0.4pt + wp-light-border)
}

#let wp-footer(footer-left) = context {
  if here().page() <= 1 { return }
  set par(justify: false, first-line-indent: 0em)
  line(length: 100%, stroke: 0.4pt + wp-light-border)
  v(2pt)
  grid(columns: (1fr, 1fr),
    align(left, text(size: 8pt, fill: wp-muted, footer-left)),
    align(right, text(size: 8pt, weight: "bold", fill: wp-ink, number-type: "lining",
      counter(page).display("1 of 1", both: true))))
}

// The closing rule and colophon under the last section.
#let wp-colophon(lines) = {
  v(3mm)
  line(length: 100%, stroke: 0.4pt + wp-light-border)
  v(1mm)
  align(center, text(size: 8pt, fill: wp-muted, lines))
}

// The whitepaper, with guidedog's book(...) parameters and the paper's own: headline
// (the big word), subtitle, tagline, affiliation, running-title (the header's left
// side), footer-left, keywords and colophon.
#let wp-paper(
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
  headline: none,
  subtitle: none,
  tagline: none,
  affiliation: none,
  running-title: none,
  footer-left: none,
  keywords: (),
  colophon: none,
  body,
) = {
  let authors = if author == "" { () } else { author.split(" and ") }
  set document(title: title, author: authors, keywords: keywords)
  set page(paper: paper, margin: (x: 18mm, top: 20mm, bottom: 20mm),
    header: wp-header(running-title, [Whitepaper | #date]),
    footer: wp-footer(footer-left))
  set text(font: wp-serif, size: 9.6pt, fill: wp-ink, lang: wp-language(lang),
    hyphenate: true)
  set par(justify: true, leading: 0.60em, spacing: 0.70em, first-line-indent: 0em)
  set math.equation(numbering: none)
  state("gd-page-ref").update(_ => page-ref)
  show: wp-headings.with(numbering)
  show: wp-blocks

  wp-title-block(headline: if headline != none { headline } else { upper(title) },
    subtitle: subtitle, tagline: tagline, author: author, affiliation: affiliation)
  body
  if colophon != none { wp-colophon(colophon) }
}
