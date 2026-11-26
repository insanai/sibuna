// index.rst: parallel search against sequential work. Hashcash trials are independent,
// so M cores finish about M times sooner; the labels of the Cohen-Pietrzak tree must be
// computed in order. The two panels stand one above the other, so each has the whole
// width for its labels.

#import "../chart.typ": *
#import "tree.typ": posw-tree

#let panel-width = 14.0

// A panel: a quiet frame of `height` centimetres from `top` down, with a title.
#let panel(top, height, title) = {
  import cetz.draw: *
  rect((0, top - height), (panel-width, top), radius: 0.15, fill: paper,
    stroke: thin + rule)
  let (x, anchor) = if is-rtl() { (panel-width - 0.3, "north-east") } else {
    (0.3, "north-west")
  }
  content((x, top - 0.22), anchor: anchor, text(size: 9.5pt, weight: "semibold",
    rich(title)))
}

// Four cores search disjoint nonces at the same time; core 3 finds nonce 18 at its
// fifth trial, and every core stops.
#let hashcash(w, top) = {
  import cetz.draw: *
  let height = 4.6
  panel(top, height, w.hashcash)
  let (cell, pitch, first) = (0.62, 0.78, 1.9)
  for core in range(0, 4) {
    let y = top - 1.2 - core * 0.7
    content((first - 0.3, y), anchor: "east", annotate(phrase(w.core,
      (n: str(core + 1)))))
    for trial in range(0, 5) {
      let x = first + trial * pitch
      let found = core == 2 and trial == 4
      let (fill, edge) = tones.at(if found { "accent" } else { "step" })
      rect((x, y - 0.22), (x + cell, y + 0.22), radius: 0.06, fill: fill,
        stroke: (if found { bold } else { thin }) + edge)
      content((x + cell / 2, y), text(size: 7.5pt, fill: if found { green-deep }
        else { quiet }, str(core + 4 * trial)))
    }
    if core == 2 {
      content((first + 5 * pitch, y), anchor: "west", annotate(w.found, kind: "sibuna"))
    }
  }
  let (x, anchor) = if is-rtl() { (panel-width - 0.3, "north-east") } else {
    (0.3, "north-west")
  }
  content((x, top - 3.85), anchor: anchor, box(width: (panel-width - 0.6) * 1cm,
    small(w.time)))
}

#let draw() = context {
  let w = words("sequential-work")
  cetz.canvas(length: 1cm, {
    hashcash(w, 0)
    let top = -4.9
    panel(top, 6.0, w.posw)
    posw-tree(x: 4.9, y: top - 1.0, width: 8.2, step: 1.1, radius: 0.3,
      labels: w, label-width: 3.6)
  })
}
