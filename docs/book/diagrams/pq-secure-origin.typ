#import "style.typ": *
#show: figure-frame.with(lang: "en")

#sequence(
  (actor("c", "Customer browser", kind: "party"), actor("s", "Sibuna", kind: "accent"),
   actor("w", "Website", kind: "party")),
  (
    msg("c", "s", "Offer hybrid TLS", accent: true),
    msg("s", "c", "`X25519MLKEM768`", reply: true, accent: true),
    msg("c", "s", "`GET /status`"),
    msg("s", "w", "Offer TLS to the origin", accent: true),
    msg("w", "s", "Origin certificate and selected group", reply: true),
    act("s", "Verify the origin name and issuer"),
    msg("s", "w", "`GET /status`", accent: true),
    msg("w", "s", "`200 OK`", reply: true),
    msg("s", "c", "Encrypted response", reply: true),
  ),
  spacing: 45,
)
