// operations.rst: the first and a later handshake for an on-demand name.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#sequence(
  (
    actor("client", "Client", kind: "party"),
    actor("sibuna", "Sibuna", kind: "accent"),
    actor("ca", "Certificate authority", kind: "party"),
  ),
  (
    msg("client", "sibuna", "ClientHello for `shop.apps.example.org`"),
    act("sibuna", "The guard permits the name"),
    msg("sibuna", "ca", "Order the name", note: "The client waits, at most for the configured limit"),
    msg("ca", "sibuna", "Validate the name"),
    msg("ca", "sibuna", "Certificate", reply: true),
    msg("sibuna", "client", "The handshake goes on with it", accent: true),
    gap("Later"),
    msg("client", "sibuna", "ClientHello for `shop.apps.example.org`"),
    msg("sibuna", "client", "The stored certificate", accent: true),
  ),
  spacing: 50,
)
