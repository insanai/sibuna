// Book Part III: the depth-3 tree of the proof of sequential work and an opening of
// leaf 3.5.

#import "@preview/cetz:0.5.2"
#import "../style.typ": *
#import "../posw-tree.typ": posw-tree

#show: figure-page
#let w = words("posw-tree")

#with-notes(cetz.canvas(length: 1cm, {
  import cetz.draw: *
  posw-tree(width: 9.2, step: 1.2)
  // Labelling order along the leaves.
  line((-4.3, -4.55), (4.3, -4.55), stroke: 0.7pt + muted,
    mark: (end: "stealth", fill: muted, scale: 0.7))
  content((0, -4.7), anchor: "north", note(w.order))
}),
  legend(
    (swatch-dot(amber-light, edge: amber), w.path),
    (swatch-dot(green-light, edge: green), w.siblings),
    (swatch-line(red, thickness: 1pt, dash: "dashed"), w.left),
  ),
)
