// The Cohen-Pietrzak tree of depth 3, shared by the book and the whitepaper. Nodes are
// named depth.index. The opening of leaf 3.5 is drawn: its root path in amber, the
// siblings it sends in green, and the left-sibling edges hashed into the leaf in red.

#import "@preview/cetz:0.5.2"
#import "style.typ": *

// The path of leaf 3.5 (binary 101) and the siblings an opening of it sends.
#let path = ((0, 0), (1, 1), (2, 2), (3, 5))
#let siblings = ((1, 0), (2, 3), (3, 4))
// The left siblings of the ancestors where the path turns right: hashed into leaf 3.5.
#let left-siblings = ((1, 0), (3, 4))

// Draws the tree with its root at (`x`, `y`): `width` between the outer leaves and `step`
// between levels, in centimetres.
#let posw-tree(x: 0, y: 0, width: 7, step: 1.15, radius: 0.33) = {
  import cetz.draw: *
  let position(depth, index) = {
    let span = width / calc.pow(2, depth)
    (x - width / 2 + (index + 0.5) * span, y - depth * step)
  }
  // Tree edges.
  for depth in range(0, 3) {
    for index in range(0, calc.pow(2, depth)) {
      for child in (2 * index, 2 * index + 1) {
        line(position(depth, index), position(depth + 1, child), stroke: 0.7pt + muted)
      }
    }
  }
  // Left-sibling edges into leaf 3.5: from 3.4 beside it, and from 1.0 down the gap
  // between the two halves of the tree and under the leaves.
  let dashed = (paint: red, thickness: 1pt, dash: "dashed")
  let arrow = (end: "stealth", fill: red, scale: 0.7)
  let (leaf, near, far) = (position(3, 5), position(3, 4), position(1, 0))
  line((near.at(0) + radius, near.at(1)), (leaf.at(0) - radius, leaf.at(1)), stroke: dashed,
    mark: arrow)
  let middle = x
  let under = leaf.at(1) - radius - 0.35
  hobby((far.at(0) + radius * 0.75, far.at(1) - radius * 0.7),
    (middle, far.at(1) - step * 0.75), (middle - 0.05, leaf.at(1) + 0.2),
    (middle + 0.45, under), (leaf.at(0) - 0.35, under + 0.05),
    (leaf.at(0), leaf.at(1) - radius), stroke: dashed, mark: arrow)
  // Nodes.
  for depth in range(0, 4) {
    for index in range(0, calc.pow(2, depth)) {
      let name = (depth, index)
      let (paper, edge, weight) = if name in path {
        (amber-light, amber, 1.3pt)
      } else if name in siblings {
        (green-light, green, 1.3pt)
      } else { (white, blue, 0.7pt) }
      circle(position(depth, index), radius: radius, fill: paper, stroke: weight + edge)
      content(position(depth, index), text(size: 7.5pt, str(depth) + "." + str(index)))
    }
  }
}
