// protocol.rst: the challenge round trip. Steps on the left run in the browser, steps on
// the right in Sibuna.
#import "style.typ": *
#show: figure-frame.with(lang: "en")

#sequence(
  (
    actor("page", "Browser", kind: "party"),
    actor("worker", "Web Worker", kind: "party"),
    actor("sibuna", "Sibuna", kind: "accent"),
  ),
  (
    msg("page", "sibuna", "Navigation without a session"),
    msg("sibuna", "page", "Interstitial (HTTP 200)", reply: true),
    msg("page", "sibuna", "`GET /__sibuna/challenge.json?need=`"),
    act("sibuna", "Stateless id: payload and tag"),
    msg("sibuna", "page", "The challenge record", reply: true),
    msg("page", "worker", "Solve"),
    act("worker", "WASM or JS prover"),
    msg("worker", "page", "Nonce or proof", reply: true),
    msg("page", "sibuna", "`POST /__sibuna/verify`", accent: true),
    act("sibuna", "Verify, spent set,\nmint the MAC token", accent: true),
    msg("sibuna", "page", "`Set-Cookie`", reply: true, accent: true),
    msg("page", "sibuna", "Reload with a session", accent: true),
  ),
  spacing: 44,
)
