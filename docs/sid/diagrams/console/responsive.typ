#import "wireframe.typ": *
#import "traffic-layout.typ": earth
#set text(font: "Noto Sans")

#wire(170, 114, H => {
  import cetz.draw: *
  panel(H,5,5,51,103,none)
  panel(H,7,7,47,9,[Menu · SIBUNA · admin ▾],bg:blue-light,size:7pt)
  panel(H,7,19,47,12,[Traffic · all nodes #linebreak() 24 h · Live / Pause],size:7pt)
  panel(H,7,34,22,17,[128 k #linebreak() Requests],size:7pt)
  panel(H,32,34,22,17,[128 #linebreak() Incidents],size:7pt)
  panel(H,7,54,47,27,[Globe · Traffic / Attacks],size:6pt)
  earth((22,H - 70),9)
  panel(H,34,64,18,13,[Rotate #linebreak() Flat map],size:5pt)
  panel(H,7,84,47,21,[Countries ↓ #linebreak() Timeline ↓ #linebreak() Full labels in menu],size:7pt)
  panel(H,62,5,103,23,[*Loading / empty* #linebreak() Fixed-size skeleton; no fabricated zeros. Once loaded: “No traffic in this window”. First use preserves navigation and setup links.],size:7pt)
  panel(H,62,32,103,23,[*GeoIP unavailable* #linebreak() Earth outline only; Unknown totals, provider state and admin setup link. Country controls disabled with explanation.],size:7pt)
  panel(H,62,59,103,23,[*Disconnected / partial cluster* #linebreak() Freeze last values; display age and 2/3 reporting. Retry with backoff. Resnapshot before clearing stale state.],size:7pt)
  panel(H,62,86,103,23,[*Error / permission / overflow* #linebreak() Inline diagnosis and retry; viewer actions disabled; truncated history marked. Keyboard focus persists across live patches.],size:7pt)
})
