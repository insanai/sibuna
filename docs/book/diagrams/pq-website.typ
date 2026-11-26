#import "style.typ": *
#show: figure-frame.with(lang: "en")

#sequence(
  (actor("c", "Customer browser", kind: "party"), actor("s", "Sibuna", kind: "accent"),
   actor("w", "Website", kind: "party")),
  (
    msg("c", "s", "Offer hybrid TLS", accent: true),
    msg("s", "c", "`X25519MLKEM768`", reply: true, accent: true),
    msg("c", "s", "`GET /status`"),
    msg("s", "w", "HTTP on loopback"),
    msg("w", "s", "`200 OK`", reply: true),
    msg("s", "c", "Encrypted response", reply: true, accent: true),
  ),
  spacing: 45,
)
