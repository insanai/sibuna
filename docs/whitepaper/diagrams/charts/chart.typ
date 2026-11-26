// The common parts of Sibuna's charts: the language, the words, numbers and axes.
//
// A chart is a figure drawn from data or from a formula. It follows the figure guideline
// in ../style.typ, whose palette, type and strokes this file re-exports, and adds the
// rules of charts below.
//
// Files. Each chart has two files. charts/<name>.typ is the figure that the RST names:
//
//   #import "chart.typ": chart
//   #import "draw/<name>.typ": draw
//   #show: chart.with(lang: "en")
//   #draw()
//
// A gettext catalog translates it as one message, and a translation changes only `lang`.
// charts/draw/<name>.typ draws it, and words/<lang>.toml holds its words in every
// language, so neither drawing code nor words reach the catalogs: we can redraw a chart
// or reword a label without touching a translation.
//
// Shared files. The book's chart.typ, draw/tree.typ and words/ are the sources;
// docs/whitepaper/diagrams/charts keeps identical copies. data/ holds copies of the
// benchmark results the charts read, such as benchmarks/results/primitives-latest.json.
// We edit only the sources and run `cargo xtask figures`, which writes every copy; CI
// fails when a copy differs (`cargo xtask figures --check`).
//
// Adding a chart.
//
// 1. Write draw/<name>.typ with a function `draw()` that starts with `context` and takes
//    its words with `words("<name>")`.
// 2. Add a [<name>] table to words/en.toml and to every other word table.
// 3. Write charts/<name>.typ as above, and show it in the RST with
//    `.. typst-diagram:: diagrams/charts/<name>.typ` and the options `:caption:` and
//    `:alt:` (and `:name:` to refer to it).
// 4. Run `cargo xtask figures`, then update the catalogs: the new message is the entry
//    file, and each translation sets `lang` to its language.
//
// The rules of charts, in short.
//
// - Green, the accent, is Sibuna's own series. A comparison or a party outside Sibuna is
//   slate, a wait or a note gold, a refusal clay. A series also differs in its mark (a
//   filled or an open dot, a cross, a dashed line), so a chart reads in monochrome and
//   with any colour vision.
// - Label a series beside its marks. A legend is the last resort.
// - Axes name their quantity and unit. Grid lines are quiet; the data is the darkest ink
//   on the page.
// - A logarithmic axis shows dots, not bars: the length of a bar from an arbitrary
//   decade means nothing.
// - Words come from words/<lang>.toml by the chart's name. A word that a language lacks
//   falls back to English. A "{name}" in a word is a value the chart fills in; `num`
//   writes numbers with the language's decimal mark and digit groups.

#import "../style.typ": *

// ---- Language -----------------------------------------------------------------------

// The gettext code of the chart's language, such as "en" or "zh_CN"; `chart` sets it.
// `std.state`, because style.typ names its state-machine node `state`.
#let language = std.state("chart-language", "en")

#let _rtl-languages = ("ar", "fa", "he", "ur")

// Wraps a chart as a figure in the language `lang`.
#let chart(lang: "en", body) = figure-frame(lang: lang, {
  language.update(lang)
  // Arabic letters reach far above and below the line, and the default line box lets
  // the dots of one line touch the next; fixed edges give them room.
  set text(top-edge: 0.95em, bottom-edge: -0.4em) if lang in _rtl-languages
  body
})

// Whether the chart's language runs from right to left. Needs `context`.
#let is-rtl() = language.get().split("_").first() in _rtl-languages

// ---- Words --------------------------------------------------------------------------

#let english = toml("words/en.toml")

// This language's word table. Needs `context`.
#let _local() = {
  let lang = language.get()
  if lang == "en" { english } else { toml("words/" + lang + ".toml") }
}

// The words of chart `name`: the English table with this language's entries laid over
// it, one level of subtables deep. Needs `context`.
#let words(name) = {
  let over = _local().at(name, default: (:))
  let merged = (:)
  for (key, value) in english.at(name) {
    if type(value) == dictionary {
      merged.insert(key, value + over.at(key, default: (:)))
    } else {
      merged.insert(key, over.at(key, default: value))
    }
  }
  merged
}

// `template` with every "{name}" replaced by the value of `name` in `values`, which may
// be a string or content (a formula, for instance).
#let phrase(template, values) = {
  // Splitting at the braces leaves the names at the odd positions.
  let parts = template.split(regex("[{}]"))
  parts.enumerate().map(((i, part)) => if calc.odd(i) { values.at(part) } else { part }).join()
}

// `value` written with this language's decimal mark and digit groups: `digits` places
// after the mark, and groups of three in the integer part from 10,000 on. Needs
// `context`.
#let num(value, digits: 0) = {
  let marks = english.number + _local().at("number", default: (:))
  let rounded = calc.round(value, digits: digits)
  let whole = calc.trunc(rounded)
  let int-part = str(int(calc.abs(whole)))
  if int-part.len() > 4 {
    let grouped = ""
    for (i, c) in int-part.clusters().rev().enumerate() {
      if i > 0 and calc.rem(i, 3) == 0 { grouped = marks.group + grouped }
      grouped = c + grouped
    }
    int-part = grouped
  }
  let sign = if rounded < 0 { "-" } else { "" }
  if digits == 0 { return sign + int-part }
  let fraction = str(calc.round(calc.abs(rounded - whole) * calc.pow(10, digits)))
  while fraction.len() < digits { fraction = "0" + fraction }
  sign + int-part + marks.decimal + fraction
}

// ---- Marks and labels -----------------------------------------------------------------

// The colour of each kind of series, as an outline or line and a fill.
#let series = (
  sibuna: (green, pale),
  other: (slate, slate-soft),
  wait: (gold-deep, gold-soft),
  refused: (clay, clay-soft),
)

// Grid lines: quieter than any data.
#let grid-stroke = 0.5pt + rule.lighten(35%)
// Axes and ticks.
#let axis-stroke = thin + line-ink

// A label on the chart: 8 pt ink, or 8 pt in the darkened colour of a series.
#let annotate(s, kind: none) = {
  let fill = if kind == none { ink } else { series.at(kind).at(0).darken(12%) }
  text(size: 8pt, fill: fill, rich(s))
}
// A tick label or a quiet note.
#let tick(s) = text(size: 8pt, fill: quiet, rich(s))
// The name of an axis or a group.
#let group-title(s) = text(size: 8pt, weight: "semibold", fill: quiet, rich(s))
// A value that keeps its own order, left to right, in right-to-left text.
#let latin(s) = box(text(dir: ltr, s))

// A drawing with notes below it, as wide as the drawing, so that long notes wrap instead
// of widening the figure.
#let with-notes(drawing, ..notes) = context {
  let size = measure(drawing)
  stack(spacing: 7pt, drawing, ..notes.pos().map(body => block(width: size.width,
    text(size: 8pt, fill: quiet, body))))
}
