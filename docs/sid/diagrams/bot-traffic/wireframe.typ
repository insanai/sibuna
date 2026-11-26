#import "@preview/cetz:0.5.2" as cetz

#let blue = rgb("0284c7")
#let blue-light = rgb("f0f9ff")
#let green = rgb("16a34a")
#let green-light = rgb("f0fdf4")
#let amber = rgb("d97706")
#let amber-light = rgb("fffbeb")
#let red = rgb("b91c1c")
#let red-light = rgb("fef2f2")
#let purple = rgb("7c3aed")
#let purple-light = rgb("f5f3ff")
#let gray = rgb("64748b")
#let rule = rgb("cbd5e1")
#let ink = rgb("1e293b")

#let cyan = rgb("0891b2")
#let cyan-light = rgb("ecfeff")
#let slate-light = rgb("f8fafc")
#let border-gray = rgb("e2e8f0")
#let dark-slate = rgb("0f172a")

// ---------------------------------------------------------------- wireframe primitives
// A wireframe is a canvas in millimetres with y measured from the top edge.
// The pad keeps the outer frame and its stroke inside the image.
#let wire(width, height, draw) = pad(4pt, cetz.canvas(length: 1mm, {
  import cetz.draw: *
  rect((0, 0), (width, height), stroke: 0.6pt + rule, fill: white, radius: 1.5)
  draw(height)
}))

#let sparkline_draw(H, x, y, w, h, pts, stroke-color: blue) = {
  import cetz.draw: *
  if pts.len() >= 2 {
    let min-v = calc.min(..pts)
    let max-v = calc.max(..pts)
    let range-v = if max-v == min-v { 1.0 } else { max-v - min-v }
    let coords = ()
    for (i, v) in pts.enumerate() {
      let px = x + (i / (pts.len() - 1)) * w
      let py = H - y - h + ((v - min-v) / range-v) * h
      coords.push((px, py))
    }
    line(..coords, stroke: 0.6pt + stroke-color)
  }
}

#let kpi_tile(H, x, y, w, h, number, label, delta: none, delta-color: green, delta-bg: green-light, spark: (), num-color: blue, bg: white) = {
  import cetz.draw: *
  rect((x, H - y - h), (x + w, H - y), stroke: 0.35pt + border-gray, fill: bg, radius: 1.2)
  // The metric name spans the first row. The value and change share the next.
  content((x + 1.6, H - y - 6.6), anchor: "west", text(size: 6pt, weight: "bold", fill: num-color)[#number])
  if delta != none {
    rect((x + w - 10.8, H - y - 8.1), (x + w - 1, H - y - 5), stroke: none, fill: delta-bg, radius: 0.7)
    content((x + w - 5.9, H - y - 6.55), text(size: 3.4pt, weight: "bold", fill: delta-color)[#delta])
  }
  content((x + 1.6, H - y - 2.4), anchor: "west", text(size: 4pt, fill: gray)[#label])
  // Bottom row: Sparkline running across the lower edge of the card
  if spark.len() >= 2 {
    sparkline_draw(H, x + 2, y + h - 3.2, w - 4, 2.1, spark, stroke-color: num-color)
  }
}

#let segmented_donut(H, cx, cy, r, slices) = {
  import cetz.draw: *
  let cur = 0deg
  for sl in slices {
    let span = sl.at(0)
    let col = sl.at(1)
    arc((cx, H - cy), start: cur, stop: cur + span, radius: r, anchor: "origin", stroke: 2.8pt + col)
    cur += span
  }
}

#let bar_row(H, x, y, w, label, bar-color: blue) = {
  import cetz.draw: *
  content((x, H - y), anchor: "west", text(size: 5pt, fill: ink)[#label])
  rect((x + 24, H - y - 1.2), (x + 24 + w, H - y + 1.2), stroke: none, fill: bar-color, radius: 0.6)
}

#let shell(H, W, active) = {
  import cetz.draw: *
  // top bar
  rect((0, H - 8), (W, H), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"))
  content((3, H - 4), anchor: "west", text(size: 7pt, weight: "bold", fill: blue)[SIBUNA])
  content((W - 3, H - 4), anchor: "east", text(size: 5.2pt, fill: gray)[cluster: edge-eu · 3/3 healthy  ·  admin ▾  ·  ◐])
  // sidebar
  rect((0, 0), (26, H - 8), stroke: 0.35pt + border-gray, fill: rgb("f8fafc"))
  let items = ("Statistics", "Attack events", "Challenges", "Policy", "Nodes", "GeoIP", "Settings", "Audit")
  for (i, item) in items.enumerate() {
    let yy = H - 8 - 7 - i * 6.5
    if item == active {
      rect((1.5, yy - 2.8), (24.5, yy + 2.8), stroke: none, fill: blue-light, radius: 1)
    }
    content((4, yy), anchor: "west", text(size: 5.8pt, weight: if item == active { "bold" } else { "regular" }, fill: if item == active { blue } else { ink })[#item])
  }
}
