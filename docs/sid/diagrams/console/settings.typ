#import "wireframe.typ": *
#set text(font: "Noto Sans")

#wire(170, 110, H => {
  import cetz.draw: *
  shell(H, 170, "Settings")
  content((29, H - 12), anchor: "west", text(size: 6.5pt, weight: "bold")[Settings])
  panel(H, 28, 15, 140, 5.5, [USERS · API TOKENS · PAGES · RETENTION · NOTIFICATIONS · GEOIP · ABOUT], size: 5pt)
  table_rows(H, 28, 24, 90, 5, (([user], 22), ([role], 16), ([2FA], 12), ([last login], 24), ([state], 10), ([], 6)))
  panel(H, 121, 24, 47, 30, none, bg: rgb("fcfcfd"))
  content((123, H - 28), anchor: "west", text(size: 6pt, weight: "bold")[Add user])
  for (i, f) in ("name", "role: viewer ▾", "temporary password", "require two-factor ☑").enumerate() {
    panel(H, 123, 32 + i * 5.2, 43, 4.6, [#f], size: 4.8pt)
  }
  panel(H, 28, 58, 45, 24, [Pages #linebreak() challenge · denied · rate limited · banned · overloaded #linebreak() edit template · preview · reset], size: 5pt)
  panel(H, 76, 58, 45, 24, [Retention #linebreak() minutes 90 d · incidents 30 d · audit 365 d · rankings 7 d], size: 5pt)
  panel(H, 124, 58, 44, 24, [Notifications #linebreak() webhook · syslog · events: denial spike, ban, node unhealthy, leader change], size: 5pt)
  panel(H, 28, 85, 68, 22, [GeoIP #linebreak() DB-IP Lite · 2026-09 · range count from import · loaded 2026-09-08 #linebreak() Update now · attribution shown in footer], size: 5pt)
  panel(H, 99, 85, 69, 22, [About #linebreak() v0.1.0 · node 1 · cluster edge-eu · bound 127.0.0.1:9443 behind proxy #linebreak() build (example) · storage v0.6.1], size: 5pt)
})
