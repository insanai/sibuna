// cryptography.rst: the depth-3 tree of the proof of sequential work and an opening of
// leaf 3.5, drawn by tree.typ.

#import "../chart.typ": *
#import "tree.typ": posw-tree

#let draw() = context {
  let w = words("posw-tree")
  cetz.canvas(length: 1cm, {
    import cetz.draw: *
    posw-tree(width: 9.2, step: 1.2, labels: w)
    // Labelling order along the leaves.
    line((-4.6, -5.25), (4.6, -5.25), stroke: thin + line-ink,
      mark: (end: "stealth", fill: line-ink, scale: 0.6))
    content((0, -5.35), anchor: "north", small(w.order))
  })
}
