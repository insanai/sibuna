// operations.rst: DNS-01 validation of a wildcard name.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#sequence(
  (
    actor("sibuna", "Sibuna", kind: "accent"),
    actor("provider", "DNS provider", kind: "party"),
    actor("dns", "Authoritative DNS", kind: "party"),
    actor("ca", "Certificate authority", kind: "party"),
  ),
  (
    msg("sibuna", "ca", "Order `*.example.org`"),
    msg("ca", "sibuna", "`TOKEN`", reply: true),
    msg("sibuna", "provider", "Publish the TXT record",
      note: "`_acme-challenge.example.org` with the text `VALUE`"),
    msg("sibuna", "dns", "Ask every server"),
    msg("dns", "sibuna", "All return `VALUE`", reply: true,
      note: "Sibuna asks again until they do"),
    msg("sibuna", "ca", "Ready", accent: true),
    msg("ca", "dns", "`TXT?`"),
    msg("dns", "ca", "`VALUE`", reply: true),
    msg("ca", "sibuna", "Certificate", reply: true, accent: true),
    msg("sibuna", "provider", "Remove the TXT record"),
  ),
  spacing: 32,
  note-width: 46,
)
