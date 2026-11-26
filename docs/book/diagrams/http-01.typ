// operations.rst: HTTP-01 validation of one name (RFC 8555).
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#sequence(
  (
    actor("sibuna", "Sibuna", kind: "accent"),
    actor("ca", "Certificate authority", kind: "party"),
  ),
  (
    msg("sibuna", "ca", "Order `example.org`"),
    msg("ca", "sibuna", "`TOKEN`", reply: true),
    msg("sibuna", "ca", "Ready"),
    msg("ca", "sibuna", "`GET /.well-known/acme-challenge/TOKEN` on port 80",
      note: "Answered before the firewall"),
    msg("sibuna", "ca", "`TOKEN.THUMBPRINT`", reply: true),
    msg("ca", "sibuna", "Certificate", reply: true, accent: true),
    act("sibuna", "Store it, serve it on port 443", accent: true),
  ),
  spacing: 70,
)
