#import "wireframe.typ": *
#set text(font: "Noto Sans")

#let sequence() = cetz.canvas(length: 1mm, {
  import cetz.draw: *
  let lanes = (("Browser", 12), ("Console", 52), ("Zaxonlite", 92), ("Storage thread (every node)", 138))
  for (name, x) in lanes {
    rect((x - 11, 0), (x + 11, 7), stroke: 0.5pt + gray, fill: blue-light)
    content((x, 3.5), text(size: 6pt, weight: "bold", fill: ink)[#name])
    line((x, 0), (x, -76), stroke: (paint: gray, thickness: 0.4pt, dash: "dashed"))
  }
  let msg(y, a, b, label, dashed: false) = {
    let xa = lanes.at(a).at(1)
    let xb = lanes.at(b).at(1)
    let pen = (paint: ink, thickness: 0.5pt, dash: if dashed { "dashed" } else { "solid" })
    if a == b {
      line((xa, -y), (xa + 6, -y), (xa + 6, -y - 3), (xa, -y - 3), mark: (end: "straight"), stroke: pen)
      content((xa - 2, -y), text(size: 5.5pt, fill: ink)[#label], anchor: "east")
    } else {
      line((xa, -y), (xb, -y), mark: (end: "straight"), stroke: pen)
      content(((xa + xb) / 2, -y + 2.2), text(size: 5.5pt, fill: ink)[#label])
    }
  }
  msg(9, 0, 1, [POST /console/api/login])
  msg(16, 1, 2, [read user; verify off-owner; store session])
  msg(23, 1, 0, [200 + session cookie + CSRF token], dashed: true)
  msg(30, 0, 1, [GET /console/ws; then sub stats])
  msg(37, 1, 0, [snapshot, then 1 Hz stats deltas], dashed: true)
  msg(44, 0, 1, [POST /console/api/policies/edit + CSRF])
  msg(51, 1, 2, [expected revision; policy + audit transaction])
  msg(58, 2, 3, [replicated commit; revision changed])
  msg(65, 3, 3, [tick: rebuild spare engine; publish], dashed: true)
  msg(72, 3, 1, [`policy` topic: rule p1 active on node n], dashed: true)
})

#sequence()
