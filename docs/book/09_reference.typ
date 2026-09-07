#import "theme.typ": *
#import "figures.typ": *

#part_page("IX", [Desk Reference & Diagnostics], [
  We provide a complete operational desk reference: command-line parameters, internal HTTP
  routing endpoints, configuration fields, and the Elm-style diagnostic error catalog.
])

= CLI and Configuration Reference

#objectives([
  Provide quick reference documentation for all runtime CLI arguments, environment parameters,
  and internal system endpoints exposed by the Sibuna daemon.
])

== Command-Line Interface Reference

#table(
  columns: (1.4fr, 1fr, 1.6fr),
  table.header([*Flag*], [*Default*], [*Description*]),
  [`--port, -p <port>`],
  [`8080`],
  [TCP port on which the Sibuna daemon listens for incoming HTTP traffic.],

  [`--host, -h <host>`],
  [`0.0.0.0`],
  [IP interface to bind the listening socket to.],

  [`--upstream-host <host>`],
  [`127.0.0.1`],
  [Host address of the protected upstream application service.],

  [`--upstream-port, -u <port>`],
  [`3000`],
  [TCP port of the protected upstream application service.],

  [`--mode, -m <mode>`],
  [`reverse_proxy`],
  [Operating mode: `reverse_proxy` (autonomous proxy) or `forward_auth` (subrequest validator).],

  [`--difficulty, -d <diff>`],
  [`4`],
  [Proof-of-Work target difficulty, defined as number of leading hexadecimal zeros.],

  [`--verbose, -v`],
  [`false`],
  [Enables diagnostic logging for every evaluated connection and policy rule match.],
)

== Internal System Routes

When operating in Reverse Proxy mode, Sibuna reserves the `/__sibuna/*` URL namespace for
internal challenge orchestration:

#table(
  columns: (1.2fr, 0.8fr, 2fr),
  table.header([*Endpoint*], [*Method*], [*Function*]),
  [`/__sibuna/challenge`],
  [`GET`],
  [Issues a new unique challenge ID and difficulty configuration as JSON.],

  [`/__sibuna/verify`],
  [`POST`],
  [Validates submitted solution (`{"challenge_id":"...","nonce":12345}`), sets `__sibuna_token` cookie, and redirects via HTTP 302.],

  [`/__sibuna/wasm/sibuna-pow.wasm`],
  [`GET`],
  [Serves the embedded 6.9 KB freestanding WebAssembly solver (`application/wasm`).],

  [`/__sibuna/worker.js`],
  [`GET`],
  [Serves the embedded background Web Worker script (`application/javascript`).],
)

#v(4mm)

= Elm-Style Diagnostic Error Catalog

#objectives([
  Understand the design rationale of Elm-style error diagnostics, examine the complete catalog
  of Sibuna error codes, and utilize actionable remediation hints for troubleshooting.
])

== Actionable Diagnostics Philosophy

Traditional network servers emit cryptic log messages such as `Err 104: connection reset` or
`failed to verify token`. When debugging production incidents under operational stress, these
opaque errors force operators to dig through source code.

Inspired by the Elm compiler, Sibuna formats all error diagnostics with:
1. A clear textual error description.
2. A detailed explanation of why the failure occurred.
3. An actionable `Hint:` line specifying exact remediation steps.

#api_anchor([`core.explainError`], [
  Translates any native error into human-readable diagnostic messages with actionable hints.
], source: "libs/core/src/errors.zig")

== Error Code Reference Table

#table(
  columns: (1.2fr, 1.5fr, 1.8fr),
  table.header([*Error Code*], [*Cause*], [*Remediation Hint*]),
  [`DoubleSpendAttempt`],
  [A client submitted a PoW solution for a challenge that was already marked spent.],
  [Ensure clients do not replay cached responses or submit identical nonces in parallel.],

  [`ChallengeExpired`],
  [The client took longer to solve the challenge than the configured TTL (120s).],
  [Reduce difficulty or check client network latency and device CPU capabilities.],

  [`ChallengeNotFound`],
  [The submitted challenge ID was never issued or has already decayed from the cache.],
  [Ensure client requests a fresh challenge from `/__sibuna/challenge` before solving.],

  [`FingerprintMismatch`],
  [The cookie or solution originated from an IP address or User-Agent different from the issuer.],
  [Verify that client is not sharing cookies across proxy nodes or rotating IP addresses mid-session.],

  [`InvalidProofOfWork`],
  [The submitted nonce does not satisfy the target leading-zero difficulty requirement.],
  [Check that client WebAssembly solver matches the server hashing specification.],

  [`InvalidTokenSignature`],
  [The Ed25519 signature on the `__sibuna_token` cookie failed mathematical verification.],
  [Verify that all cluster nodes share the identical Ed25519 public key configuration.],

  [`StoreFull`],
  [The in-memory challenge cache has reached maximum capacity under extreme load.],
  [Increase `NUM_SHARDS` or `SHARD_CAPACITY` in `libs/store/src/challenge_store.zig`.],
)
