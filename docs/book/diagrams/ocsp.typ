// operations.rst: an OCSP query and its three outcomes.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#sequence(
  (
    actor("client", "Client", kind: "party"),
    actor("sibuna", "Sibuna", kind: "accent"),
    actor("responder", "OCSP responder", kind: "party"),
  ),
  (
    msg("sibuna", "responder", "Is the certificate good?"),
    msg("responder", "sibuna", "A signed answer", reply: true),
    act("sibuna", "Check the signature against the issuer"),
    begin-frame("good"),
    msg("sibuna", "client", "Staple the answer to every handshake", accent: true,
      note: "Ask again at the middle of its validity"),
    end-frame(),
    begin-frame("revoked"),
    act("sibuna", "Log it and renew the certificate at once"),
    end-frame(),
    begin-frame("the responder fails"),
    msg("sibuna", "client", "Serve without a staple", note: "Log `ACME013`, ask again after a growing delay"),
    end-frame(),
  ),
  spacing: 50,
)
