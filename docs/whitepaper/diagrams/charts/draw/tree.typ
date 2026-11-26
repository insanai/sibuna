// The Cohen-Pietrzak tree of depth 3, shared by the book and the whitepaper. Nodes are
// named depth.index. The opening of leaf 3.5 is drawn: its root path in the accent, the
// siblings it sends in slate (they leave the prover), and the left-sibling edges hashed
// into the leaf as dashed gold arrows (the leaf waits for them).

#import "../chart.typ": *

// The path of leaf 3.5 (binary 101) and the siblings an opening of it sends.
#let path = ((0, 0), (1, 1), (2, 2), (3, 5))
#let siblings = ((1, 0), (2, 3), (3, 4))

// Draws the tree with its root at (`x`, `y`): `width` between the outer leaves and `step`
// between levels, in centimetres. `labels`, when given, holds the words `path`,
// `siblings` and `left`; they stand right of the tree, beside what they name, in boxes
// `label-width` centimetres wide.
#let posw-tree(x: 0, y: 0, width: 7, step: 1.15, radius: 0.32, labels: none,
  label-width: 3.4) = {
  import cetz.draw: *
  let position(depth, index) = {
    let span = width / calc.pow(2, depth)
    (x - width / 2 + (index + 0.5) * span, y - depth * step)
  }
  // Tree edges.
  for depth in range(0, 3) {
    for index in range(0, calc.pow(2, depth)) {
      for child in (2 * index, 2 * index + 1) {
        let on-path = (depth, index) in path and (depth + 1, child) in path
        line(position(depth, index), position(depth + 1, child),
          stroke: if on-path { bold + green } else { thin + line-ink })
      }
    }
  }
  // Left-sibling edges into leaf 3.5: from 3.4 beside it, and from 1.0 down the gap
  // between the two halves of the tree and under the leaves.
  let dashed = (paint: gold-deep, thickness: bold, dash: (3pt, 2pt))
  let arrow = (end: "stealth", fill: gold-deep, scale: 0.6)
  let (leaf, near, far) = (position(3, 5), position(3, 4), position(1, 0))
  line((near.at(0) + radius, near.at(1)), (leaf.at(0) - radius, leaf.at(1)),
    stroke: dashed, mark: arrow)
  let under = leaf.at(1) - radius - 0.35
  hobby((far.at(0) + radius * 0.75, far.at(1) - radius * 0.7),
    (x, far.at(1) - step * 0.75), (x - 0.05, leaf.at(1) + 0.2),
    (x + 0.45, under), (leaf.at(0) - 0.35, under + 0.05),
    (leaf.at(0), leaf.at(1) - radius), stroke: dashed, mark: arrow)
  // Nodes.
  for depth in range(0, 4) {
    for index in range(0, calc.pow(2, depth)) {
      let name = (depth, index)
      let (fill, edge, weight) = if name in path {
        (pale, green, bold)
      } else if name in siblings {
        (slate-soft, slate, bold)
      } else { (shell, line-ink, thin) }
      circle(position(depth, index), radius: radius, fill: fill, stroke: weight + edge)
      content(position(depth, index), text(size: 8pt, str(depth) + "." + str(index)))
    }
  }
  if labels != none {
    let beside(at, body, paint, anchor: "west", extra: 0) = content(at, anchor: anchor,
      box(width: (label-width + extra) * 1cm, text(size: 8pt, fill: paint, rich(body))))
    beside((position(1, 1).at(0) + radius + 0.3, y - step), labels.path, green-deep)
    beside((position(2, 3).at(0) + radius + 0.3, y - 2 * step), labels.siblings,
      slate.darken(10%))
    // Under the leaves the label has more room, and it grows downwards.
    beside((leaf.at(0) + 0.25, under + 0.14), labels.left, gold-deep.darken(10%),
      anchor: "north-west", extra: 0.8)
  }
}
