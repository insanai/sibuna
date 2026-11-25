#import "wireframe.typ": *
#set text(font: "Noto Sans")

#wire(170, 80, H => {
  import cetz.draw: *
  panel(H, 55, 10, 60, 60, none)
  content((85, H - 16), text(size: 7pt, weight: "bold", fill: blue)[SIBUNA CONSOLE])
  panel(H, 60, 22, 50, 8, [user name])
  panel(H, 60, 33, 50, 8, [password])
  panel(H, 60, 45, 50, 8, [Sign in], bg: blue-light, weight: "bold")
  content((85, H - 60), text(size: 5pt, fill: gray)[Authentication required · no telemetry before sign-in])
  content((85, H - 74), text(size: 5pt, fill: gray)[Five attempts per minute per address · sessions expire after 30 idle minutes])
})
