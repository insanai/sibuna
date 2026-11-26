// The visual vocabulary of Sibuna's figures.
//
// Every Typst figure of the book, the whitepaper and the SID records imports this file and
// starts with `#show: figure-frame.with(lang: "en")`. Guidedog compiles each figure to one
// SVG for the website and the PDF. Typst cannot import a file outside the project, so
// docs/book/diagrams, docs/whitepaper/diagrams and docs/sid/diagrams keep identical
// copies of this file. We edit the book's copy and run `cargo xtask figures`, which
// writes the other two; CI fails when a copy differs (`cargo xtask figures --check`).
// Charts, figures drawn from data, add their own rules in charts/chart.typ.
//
// Translations. A gettext catalog translates a figure as one message: its whole source.
// A translator copies the source, sets `lang` to the language and changes only the
// quoted labels. So a figure keeps its labels in plain strings, and this file turns a
// string into content (see `rich`). Text between backticks is a name from the code or
// the protocol: it is set in the monospaced face, left to right, and never translated.
//
// The guideline, in short.
//
// - One accent. Green, the colour of the website, marks Sibuna itself and the path that
//   matters. Every other colour has a meaning: gold is a decision, a wait or a note,
//   clay a refusal or a failure, leaf an outcome that counts, slate a party outside
//   Sibuna (a client, a person, an authority, a peer). Colour never decorates.
// - The shape of a node says what it is: a rounded box is a step or a component, a pill
//   a party or a state, a cylinder a store, a diamond a decision, a slanted box data in
//   flight. The tone says how it matters. A figure also reads in monochrome.
// - One face, two sizes: a title of 9.5 pt and a quiet second line of 8 pt. Edge labels
//   are small and quiet. A box holds a title and at most one short second line; a rule
//   that needs a sentence belongs in the prose.
// - Two strokes: thin (0.7 pt) for every outline and arrow, bold (1.1 pt) for the
//   accented path. A dashed line is a reply, an option or shared state; a dotted line a
//   pause in time.
// - About a dozen boxes at most. A figure fits the width of an A4 page (about 150 mm)
//   and stays readable on a phone; a larger idea becomes two figures.
// - The form follows the idea. Messages between parties over time: a sequence diagram
//   with lifelines. A lifecycle: a state machine. A path with decisions: a flow, top
//   down or left to right. Who depends on whom: layers, highest at the top. Bytes on
//   the wire: a field strip. Graphviz only where automatic layout of a real graph is the
//   point, such as the dependency graph of the crates. A Graphviz graph takes the same
//   colours and names the font Helvetica: Graphviz measures labels with its own metrics,
//   and with Noto Sans its boxes come out too small for their labels.
// - A figure keeps a margin of 6 pt inside its image, and nothing is drawn past it.
// - Light colours only. On a dark page guidedog sets the drawing on a light plate, so
//   one set of colours serves both themes and the PDF.
//
// The colours derive from the website's tokens in docs/site/site.css: paper #f7f6f1,
// ink #20352f, green #176a4b, gold #dba65c, pale #e7eee4. The type is Noto Sans, the
// face the figures have always used, with the Noto face of each script; names from the
// code are set in DejaVu Sans Mono, which Typst carries.

#import "@preview/fletcher:0.5.8" as fletcher: diagram, node, edge
#import "@preview/cetz:0.3.4"

// ---- Palette ------------------------------------------------------------------------
// Ink and lines.
#let ink = rgb("#20352f")        // --ink: text
#let quiet = rgb("#55665e")      // --muted, darkened for small text: second lines, labels
#let line-ink = rgb("#6a7c73")   // arrows and outlines
#let rule = rgb("#c3cec0")       // --line, darkened for print: lifelines, frames, guides
// Surfaces.
#let shell = rgb("#fffffc")      // an ordinary box
#let paper = rgb("#f7f6f1")      // --paper: data, context
#let pale = rgb("#e7eee4")       // --pale: the accent's ground
#let moss = rgb("#eef1e9")       // a durable store
// The one accent, for Sibuna and the path that matters.
#let green = rgb("#176a4b")      // --green
#let green-deep = rgb("#0c402c") // text on the accent
// Semantic colours, used for roles and verdicts, never as decoration.
#let gold = rgb("#dba65c")       // --gold
#let gold-soft = rgb("#fbf4e4")  // a decision, a wait, a note
#let gold-deep = rgb("#8f5512")
#let clay = rgb("#a3432b")       // a refusal or a failure
#let clay-soft = rgb("#f9e9e3")
#let leaf = rgb("#2b7a45")       // an outcome that counts
#let leaf-soft = rgb("#e2f1e4")
#let slate = rgb("#3d5d70")      // a party outside Sibuna
#let slate-soft = rgb("#e8eff2")

// ---- Type ---------------------------------------------------------------------------
#let sans = ("Noto Sans",)
#let mono = ("DejaVu Sans Mono",)
// The Noto face of each script that Noto Sans lacks (Debian fonts-noto-core and
// fonts-noto-cjk), by the Typst language of a gettext code such as "zh_CN".
#let script-fonts = (ja: "Noto Sans CJK JP", ko: "Noto Sans CJK KR",
  zh: "Noto Sans CJK SC", ar: "Noto Sans Arabic", hi: "Noto Sans Devanagari")

// ---- Roles --------------------------------------------------------------------------
// Each role is a fill and an outline.
#let tones = (
  step: (shell, line-ink),        // an ordinary step or component
  accent: (pale, green),          // Sibuna, or the path that matters
  party: (slate-soft, slate),     // a client, a person, an authority, a peer
  data: (paper, quiet),           // data in flight: a request, a datagram, a file
  store: (moss, line-ink),        // a durable store
  decision: (gold-soft, gold-deep), // a question that chooses a branch
  wait: (gold-soft, gold-deep),   // a wait, a bound, a note on the side
  good: (leaf-soft, leaf),        // an outcome that counts
  stop: (clay-soft, clay),        // a refusal, a failure, a drop
  quiet: (paper, rule),           // context that is not the point
)

// The thickness of every outline and arrow.
#let thin = 0.7pt
#let bold = 1.1pt

// ---- Text ---------------------------------------------------------------------------

// A string as content: a line break for each "\n", and the monospaced face for text
// between backticks. Code stays left to right in a right-to-left language, and its
// words stay together. Content passes unchanged.
#let rich(s) = {
  if type(s) != str { return s }
  s.split("\n").map(line => {
    line.split("`").enumerate().map(((i, part)) => if calc.odd(i) {
      box(text(font: mono, size: 0.9em, dir: ltr, part))
    } else { part }).join()
  }).join(linebreak())
}

// A quiet second line.
#let small(s) = text(size: 8pt, fill: quiet, rich(s))
// An edge label: small and quiet, so that it never competes with the boxes.
#let say(s) = text(size: 8pt, fill: quiet, rich(s))
// An edge label in a tone, such as a verdict on its branch.
#let say-in(kind, s) = text(size: 8pt, fill: tones.at(kind).at(1).darken(10%),
  weight: "medium", rich(s))
// A name from the code.
#let code(s) = box(text(font: mono, size: 0.9em, dir: ltr, s))

// A title and an optional quiet second line.
#let _label(title, detail) = if detail == none { rich(title) } else {
  rich(title) + linebreak() + small(detail)
}

// Wraps a drawing as a figure: the type is set once for the figure's language, and a
// small margin keeps the drawing off the edge of the plate that a dark page puts behind
// it. `lang` is a gettext code such as "en", "ja" or "zh_CN".
#let figure-frame(lang: "en", margin: 6pt, body) = {
  let code = lang.split("_").first()
  let extra = script-fonts.at(code, default: none)
  let faces = sans + if extra == none { () } else { (extra,) }
  set text(font: faces, lang: code, size: 9.5pt, fill: ink, hyphenate: false)
  set par(justify: false, leading: 0.45em)
  pad(margin, body)
}

// ---- Nodes of node-and-arrow diagrams ------------------------------------------------
// Every node takes its position, a title and an optional second line, as strings.

#let _parts(args) = {
  let pos = args.pos()
  (pos.at(0), pos.at(1), pos.at(2, default: none))
}

#let _content(body, width) = if width == auto { align(center, body) } else {
  block(width: width, align(center, body))
}

// A step of a process, or a component. `kind` picks the tone.
#let step(kind: "step", name: none, width: auto, ..args) = {
  let (at, title, detail) = _parts(args)
  let (fill, edge-color) = tones.at(kind)
  node(at, _content(_label(title, detail), width), fill: fill, stroke: thin + edge-color,
    shape: fletcher.shapes.rect, corner-radius: 4pt, inset: 6pt, name: name,
    ..args.named())
}

// Sibuna itself, or the component a figure is about.
#let sibuna(name: none, width: auto, ..args) = step(kind: "accent", name: name,
  width: width, ..args)

// A party outside Sibuna: a client, a person, an authority, a peer.
#let party(name: none, width: auto, kind: "party", ..args) = {
  let (at, title, detail) = _parts(args)
  let (fill, edge-color) = tones.at(kind)
  node(at, _content(_label(title, detail), width), fill: fill, stroke: thin + edge-color,
    shape: fletcher.shapes.pill, inset: 6pt, name: name, ..args.named())
}

// Data in flight: a request, a datagram, a file.
#let data(name: none, width: auto, kind: "data", ..args) = {
  let (at, title, detail) = _parts(args)
  let (fill, edge-color) = tones.at(kind)
  node(at, _content(_label(title, detail), width), fill: fill, stroke: thin + edge-color,
    shape: fletcher.shapes.parallelogram.with(angle: 12deg), inset: 6pt, name: name,
    ..args.named())
}

// A durable store, drawn as a cylinder.
#let store(name: none, width: auto, kind: "store", ..args) = {
  let (at, title, detail) = _parts(args)
  let (fill, edge-color) = tones.at(kind)
  node(at, _content(_label(title, detail), width), fill: fill, stroke: thin + edge-color,
    shape: fletcher.shapes.cylinder, inset: 7pt, name: name, ..args.named())
}

// A question with two or three answers.
#let decision(name: none, width: auto, ..args) = {
  let (at, title, detail) = _parts(args)
  let (fill, edge-color) = tones.at("decision")
  node(at, _content(_label(title, detail), width), fill: fill, stroke: thin + edge-color,
    shape: fletcher.shapes.diamond.with(fit: 0.6), inset: 4pt, name: name, ..args.named())
}

// A state of a state machine.
#let state(kind: "step", name: none, width: auto, ..args) = {
  let (at, title, detail) = _parts(args)
  let (fill, edge-color) = tones.at(kind)
  let body = if detail == none { text(weight: "semibold", rich(title)) } else {
    text(weight: "semibold", rich(title)) + linebreak() + small(detail)
  }
  node(at, _content(body, width), fill: fill, stroke: thin + edge-color,
    shape: fletcher.shapes.pill, inset: 6pt, name: name, ..args.named())
}

// The start of a state machine: a small filled dot.
#let start(at, name: none) = node(at, none, shape: circle, radius: 3pt, fill: ink,
  stroke: none, name: name)

// An outcome: where a path ends. `kind` is "good", "stop", "wait" or "quiet".
#let outcome(kind: "good", name: none, width: auto, ..args) = {
  let (at, title, detail) = _parts(args)
  let (fill, edge-color) = tones.at(kind)
  let ink-of = if kind == "quiet" { quiet } else { edge-color.darken(15%) }
  let body = if detail == none {
    text(fill: ink-of, weight: "medium", rich(title))
  } else {
    text(fill: ink-of, weight: "medium", rich(title)) + linebreak() + small(detail)
  }
  node(at, _content(body, width), fill: fill, stroke: thin + edge-color,
    shape: fletcher.shapes.rect, corner-radius: 9pt, inset: 6pt, name: name,
    ..args.named())
}

// A label with no box, such as the title of a group or the name of a column.
#let caption-node(at, body, name: none, size: 8.5pt, ..rest) = node(at,
  text(size: size, weight: "semibold", fill: quiet, rich(body)), stroke: none,
  fill: none, inset: 2pt, name: name, ..rest)

// A note on the side, in gold.
#let note(at, body, name: none, width: auto, ..rest) = node(at,
  _content(text(size: 8pt, fill: gold-deep.darken(15%), rich(body)), width),
  fill: gold-soft, stroke: 0.6pt + gold-deep, shape: fletcher.shapes.rect,
  corner-radius: 2pt, inset: 5pt, name: name, ..rest)

// A dashed group around nodes; its title is a `caption-node` placed by the figure.
#let group(cells, kind: "quiet", name: none, inset: 8pt) = {
  let (fill, edge-color) = tones.at(kind)
  node(enclose: cells, fill: fill.transparentize(25%), stroke: (paint: edge-color,
    thickness: 0.6pt, dash: "dashed"), corner-radius: 6pt, inset: inset, name: name,
    layer: -1)
}

// The house diagram: Fletcher with the figures' spacing, arrows and marks.
#let flow(..args) = diagram(
  spacing: (10mm, 7mm),
  edge-stroke: thin + line-ink,
  mark-scale: 80%,
  label-sep: 3pt,
  label-size: 8pt,
  ..args,
)

// An arrow on the path that matters.
#let main-edge(..args) = edge(..args, stroke: bold + green)
// An arrow in a tone, such as a refusal.
#let tone-edge(kind, ..args) = edge(..args, stroke: thin + tones.at(kind).at(1))

// ---- Sequence diagrams --------------------------------------------------------------
//
// `sequence` draws participants from left to right and time from top to bottom. A step
// is a message from one participant to another, an action a participant takes alone, a
// pause in time, or the start or end of a frame around steps that belong together.
// Messages are numbered so that the prose can say "in step 4". A note stands at the
// right, level with its step. A row is as tall as its label: a longer translation wraps
// between the two lifelines and the row grows.

// A participant. `kind` is "step" (a part of a system), "accent" (Sibuna), "party" (a
// client, a person, an authority) or "store".
#let actor(key, label, kind: "step") = (key: key, label: label, kind: kind)
// A message. `reply` dashes it; `accent` puts it on the path that matters.
#let msg(from, to, label, reply: false, accent: false, note: none) = (kind: "msg",
  from: from, to: to, label: label, reply: reply, accent: accent, note: note)
// An action a participant takes alone, drawn as a box on its lifeline.
#let act(at, label, accent: false, note: none) = (kind: "act", at: at, label: label,
  accent: accent, note: note)
// A pause in time across the whole diagram, such as "10 s later".
#let gap(label) = (kind: "gap", label: label)
// The start and the end of a frame, such as "if the replacement fails".
#let begin-frame(label) = (kind: "begin", label: label)
#let end-frame() = (kind: "end")

// A label on a white ground, so that a lifeline behind it never strikes through it.
#let _plate(body, width) = {
  let natural = measure(body).width + 3.5pt
  let w = if natural > width { width } else { natural }
  box(width: w, fill: white, inset: (x: 1.5pt, y: 1pt), radius: 1pt,
    align(center, body))
}

#let _head(x, a, w, head) = {
  import cetz.draw: *
  let (fill, edge-color) = tones.at(a.kind)
  let title = block(width: w * 1mm - 6pt, align(center, text(weight: "semibold",
    rich(a.label))))
  if a.kind == "store" {
    let rx = w / 2
    let ry = 1.3
    rect((x - rx, -head + ry), (x + rx, -ry), fill: fill, stroke: none)
    line((x - rx, -head + ry), (x - rx, -ry), stroke: thin + edge-color)
    line((x + rx, -head + ry), (x + rx, -ry), stroke: thin + edge-color)
    arc((x + rx, -head + ry), start: 0deg, stop: -180deg, radius: (rx, ry),
      fill: fill, stroke: thin + edge-color)
    circle((x, -ry), radius: (rx, ry), fill: fill, stroke: thin + edge-color)
    content((x, -head / 2 - 0.6), title)
  } else {
    let r = if a.kind == "party" { calc.min(head / 2, 4) } else { 1.6 }
    rect((x - w / 2, -head), (x + w / 2, 0), radius: r, fill: fill,
      stroke: thin + edge-color)
    content((x, -head / 2), title)
  }
}

#let sequence(actors, steps, spacing: 36, box-width: 0.86, note-width: 38,
  numbered: true, min-row: 8) = context {
  let mm(c) = measure(c).height / 1mm
  let xs = (:)
  for (i, a) in actors.enumerate() { xs.insert(a.key, i * spacing) }
  let box-w = spacing * box-width
  // The head is as tall as the tallest participant's name.
  let head = calc.max(8.5, ..actors.map(a => mm(block(width: box-w * 1mm - 6pt,
    align(center, text(weight: "semibold", rich(a.label))))) + 4))
  let has-notes = steps.any(s => s.at("note", default: none) != none)
  let left = -spacing / 2
  let right = (actors.len() - 1) * spacing + spacing / 2
  // A note keeps clear of a frame and of an action on the last lifeline.
  let last = actors.last().key
  let crowded = steps.any(s => s.kind == "begin" or (s.kind == "act" and s.at == last))
  let note-x = if crowded { right + 1 } else { (actors.len() - 1) * spacing + spacing * 0.3 }
  let edge-right = if has-notes { note-x + note-width } else { right }
  let n = 0
  let number(k, accent) = if numbered {
    text(fill: if accent { green } else { quiet }, weight: "bold", size: 7.4pt, str(k))
    h(0.35em)
  }
  let note-box(body) = box(fill: gold-soft, stroke: 0.6pt + gold-deep, radius: 2pt,
    inset: (x: 4pt, y: 3.6pt), width: note-width * 1mm, text(size: 7.8pt,
    fill: gold-deep.darken(20%), rich(body)))
  // First pass: the content and the height of every row.
  let rows = ()
  for s in steps {
    if s.kind == "msg" {
      n += 1
      let span = calc.abs(xs.at(s.to) - xs.at(s.from))
      let body = text(size: 8pt, [#number(n, s.accent)#rich(s.label)])
      let label = _plate(body, (span - 4) * 1mm)
      let h = calc.max(min-row, mm(label) + 4.2)
      if s.note != none { h = calc.max(h, mm(note-box(s.note)) + 2) }
      rows.push((s: s, label: label, h: h))
    } else if s.kind == "act" {
      n += 1
      let body = text(size: 8pt, [#number(n, s.accent)#rich(s.label)])
      let w = calc.min(measure(body).width / 1mm + 4, box-w + spacing * 0.1)
      let label = block(width: w * 1mm - 4pt, align(center, body))
      let h = calc.max(min-row, mm(label) + 5)
      if s.note != none { h = calc.max(h, mm(note-box(s.note)) + 2) }
      rows.push((s: s, label: label, h: h, w: w))
    } else if s.kind == "gap" {
      rows.push((s: s, h: 7))
    } else if s.kind == "begin" {
      rows.push((s: s, h: 6))
    } else {
      rows.push((s: s, h: 2.5))
    }
  }
  let total = rows.map(r => r.h).sum(default: 0)
  let bottom = -(head + total + 5)
  cetz.canvas(length: 1mm, {
    import cetz.draw: *
    // Lifelines first, so that everything else is drawn over them.
    for a in actors {
      let x = xs.at(a.key)
      line((x, -head), (x, bottom), stroke: (paint: rule, thickness: 0.7pt,
        dash: "dashed"))
    }
    for a in actors { _head(xs.at(a.key), a, box-w, head) }
    let y = -head - 1.5
    let open = ()
    for r in rows {
      let s = r.s
      y -= r.h
      if s.kind == "msg" {
        let x1 = xs.at(s.from)
        let x2 = xs.at(s.to)
        let paint = if s.accent { green } else if s.reply { line-ink } else { ink.lighten(10%) }
        let stroke = if s.reply { (paint: paint, thickness: thin, dash: (2.2pt, 1.6pt)) }
          else if s.accent { bold + paint } else { thin + paint }
        let ly = y + 1.4
        line((x1, ly), (x2, ly), stroke: stroke, mark: (end: if s.reply { ">" }
          else { "stealth" }, fill: paint, scale: 0.55))
        content(((x1 + x2) / 2, ly + 0.7), anchor: "south", r.label)
        if s.note != none {
          content((note-x, y + r.h - 0.8), anchor: "north-west", note-box(s.note))
        }
      } else if s.kind == "act" {
        let x = xs.at(s.at)
        let (fill, edge-color) = tones.at(if s.accent { "accent" } else { "step" })
        let top = y + r.h - 1.2
        let w = r.w
        rect((x - w / 2, top), (x + w / 2, y + 1), radius: 1.4, fill: fill,
          stroke: thin + edge-color)
        content((x, (top + y + 1) / 2), r.label)
        if s.note != none {
          content((note-x, top), anchor: "north-west", note-box(s.note))
        }
      } else if s.kind == "gap" {
        line((left + 1, y + 3.5), (edge-right, y + 3.5), stroke: (paint: rule,
          thickness: 0.6pt, dash: "dotted"))
        content((left + 2, y + 3.5), anchor: "west", box(fill: white,
          inset: (x: 3pt, y: 1pt), text(size: 7.8pt, style: "italic", fill: quiet,
          rich(s.label))))
      } else if s.kind == "begin" {
        open.push((s.label, y + r.h - 1))
      } else {
        let (label, top) = open.pop()
        rect((left + 1, top), (right - 1, y + 0.5), radius: 1.2, stroke: (paint: rule,
          thickness: 0.6pt))
        content((left + 1.8, top - 0.3), anchor: "north-west", box(fill: white,
          stroke: 0.6pt + rule, radius: 1pt, inset: (x: 3pt, y: 3pt),
          text(size: 7.4pt, weight: "semibold", fill: quiet, rich(label))))
      }
    }
  })
}

// ---- Field strips: bytes on the wire or in a file -----------------------------------
//
// A strip shows the fields of a message from left to right, each with its size. The
// offset of a field stands above its left edge. The widths are proportional to `weight`,
// not to the size, so that a field of one byte is still readable. A strip may have a
// title at its left and a quiet note at its right, such as "sizes in bytes"; both are
// strings of the figure, so that a translation can change them.

// A field. `size` is a string such as "4" or "32 × k", or none; `kind` picks the tone.
#let field(name, size, offset: none, weight: 1, kind: "step") = (name: name, size: size,
  offset: offset, weight: weight, kind: kind)

#let strip(fields, width: 150mm, title: none, note: none) = {
  let cells = fields.map(f => {
    let (fill, edge-color) = tones.at(f.kind)
    table.cell(fill: fill, align(center + horizon, {
      rich(f.name)
      if f.size != none { linebreak(); small(f.size) }
    }))
  })
  let offsets = fields.map(f => if f.offset == none { [] } else {
    align(left, text(font: mono, size: 7.4pt, fill: quiet, dir: ltr, f.offset))
  })
  let body = table(
    columns: fields.map(f => f.weight * 1fr),
    inset: (x: 4pt, y: 5pt),
    stroke: (x, y) => if y == 1 { thin + line-ink } else { none },
    table.header(..offsets.map(o => table.cell(inset: (x: 0pt, y: 2pt), o)),
      repeat: false),
    ..cells,
  )
  block(width: width, {
    if title != none or note != none {
      grid(columns: (1fr, auto),
        if title != none { text(size: 8.5pt, weight: "semibold", fill: quiet, rich(title)) },
        if note != none { small(note) })
      v(-1pt)
    }
    body
  })
}
