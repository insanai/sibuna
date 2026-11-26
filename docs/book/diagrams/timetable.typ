// introduction.rst: one public address in front of two timetable servers.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#flow(
  spacing: (20mm, 4mm),
  party((0, 1), "Browser", name: <browser>),
  sibuna((1, 1), "Sibuna", "one public address", name: <sibuna>),
  step((2, 0), "Origin A", "timetable server", name: <a>),
  step((2, 2), "Origin B", "timetable server", name: <b>),
  main-edge(<browser>, <sibuna>, "-|>", say("HTTPS")),
  edge(<sibuna>, <a>, "-|>", say("HTTP/1.1"), label-side: left),
  edge(<sibuna>, <b>, "-|>", say("HTTP/1.1"), label-side: right),
)
