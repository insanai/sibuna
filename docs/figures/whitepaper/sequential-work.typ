// Whitepaper: parallel search against sequential work. Hashcash trials are independent,
// so M cores finish about M times sooner; the labels of the Cohen-Pietrzak tree must be
// computed in order.

#import "@preview/cetz:0.5.2"
#import "../style.typ": *
#import "../posw-tree.typ": posw-tree

#show: figure-page
#let w = words("sequential-work")

#let panel(x, y, width, height, title, paint, paper) = {
  import cetz.draw: *
  rect((x, y - height), (x + width, y), radius: 0.18, fill: paper,
    stroke: 0.7pt + paint.lighten(45%))
  content((x + 0.3, y - 0.22), anchor: "north-west", text(size: 8.5pt, weight: "bold",
    fill: paint.darken(10%), title))
}

#with-notes(cetz.canvas(length: 1cm, {
  import cetz.draw: *
  let height = 6.2

  // Left: four cores search disjoint nonces at the same time.
  panel(0, 0, 6.6, height, w.hashcash, red, red-light)
  for core in range(0, 4) {
    let y = -1.25 - core * 0.85
    content((0.3, y), anchor: "west", text(size: 7.5pt, phrase(w.core, (n: str(core + 1)))))
    for trial in range(0, 6) {
      let x = 1.75 + trial * 0.62
      let found = core == 2 and trial == 4
      // The trials no core makes, because core 3 found a nonce first.
      let after = trial > 4
      rect((x, y - 0.22), (x + 0.5, y + 0.22), radius: 0.06,
        fill: if found { green-mid } else { white },
        stroke: if found { 1.2pt + green } else if after { (paint: rule, dash: "dotted") }
          else { 0.6pt + red.lighten(30%) })
      content((x + 0.25, y), text(size: 6.5pt, fill: if after { rule } else { muted },
        str(core + 4 * trial)))
    }
  }
  line((1.75, -4.75), (5.4, -4.75), stroke: 0.7pt + muted,
    mark: (end: "stealth", fill: muted, scale: 0.7))
  content((1.75, -4.9), anchor: "north-west", box(width: 4.6cm, note(w.time)))

  // Right: the tree whose labels must be computed in order.
  panel(7.0, 0, 8.4, height, w.posw, green, green-light)
  posw-tree(x: 11.2, y: -1.05, width: 7.6, step: 1.05, radius: 0.3)
}),
  legend(
    (swatch-box(green-mid, green), w.found),
    (swatch-dot(amber-light, edge: amber), w.path),
    (swatch-dot(green-light, edge: green), w.siblings),
    (swatch-line(red, thickness: 1pt, dash: "dashed"), w.left),
  ),
)
