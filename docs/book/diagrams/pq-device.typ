#import "style.typ": *
#show: figure-frame.with(lang: "en")

#sequence(
  (actor("c", "Older device", kind: "party"), actor("s", "Sibuna", kind: "accent"),
   actor("w", "Central service", kind: "party")),
  (
    msg("c", "s", "HTTP on loopback"),
    msg("s", "w", "Offer hybrid TLS", accent: true),
    msg("w", "s", "`X25519MLKEM768`", reply: true, accent: true),
    act("s", "Verify the service name and issuer"),
    msg("s", "w", "`GET /status`", accent: true),
    msg("w", "s", "Encrypted response", reply: true),
    msg("s", "c", "Local HTTP response", reply: true),
  ),
  spacing: 45,
)
