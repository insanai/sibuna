#import "theme.typ": *
#import "figures.typ": *

#part_page("X", [Desk Reference and Diagnostics], [
  Endpoints, metrics, error catalog, policy schema, and storage tables in one place.
])

== Endpoints

#objectives([
  Know every route under `/__sibuna/` and what each returns.
])

#table(
  columns: (1.4fr, 0.5fr, 2.2fr),
  table.header([*Endpoint*], [*Method*], [*Function*]),
  [`/__sibuna/challenge`], [GET], [The interstitial page],
  [`/__sibuna/challenge.json?path=`], [GET], [Issues a stateless challenge for the given path: `{id, algorithm, difficulty, challenges, expires_at}`],
  [`/__sibuna/verify`], [POST], [Accepts `{"challenge_id", "nonce"}` or `{"challenge_id", "proof"}`; `200` with `Set-Cookie`, or `400` with a diagnostic],
  [`/__sibuna/wasm/sibuna-pow.wasm`], [GET], [The 8,831-byte solver module, cacheable],
  [`/__sibuna/worker.js`], [GET], [The Web Worker with WASM and JavaScript provers, cacheable],
  [`/__sibuna/honeypot`], [GET], [Bans the caller for `--ban-seconds` and records an incident; `403`],
  [`/__sibuna/health`], [GET], [JSON liveness status with engine name, version, proxy mode and proof algorithm],
  [`/__sibuna/metrics`], [GET], [Prometheus text format],
)

Challenge responses carry `X-Sibuna-Status: CHALLENGE`; admitted requests carry
`X-Sibuna-Status: PASS` and `X-Sibuna-Rule` upstream (and `X-Sibuna-Rule-Hash` in forward-auth
replies).

The separate opt-in management listener serves `/console/`. Initialize its administrator
locally with `sibuna init-admin`, then replace the temporary password on first sign-in.
`/console/api/stats` and `/console/ws` require an authenticated session. The WebSocket
multiplexes statistics, events, nodes, policy, challenges and audit with bounded snapshots,
deltas and gap recovery. `/console/stream` retains the earlier statistics-only protocol. Origin error counters are not observed in
forward-auth mode. Part IX documents the console's workflows, HTTPS deployment and current
SID 0007 limits.

== Metrics

Counters exposed as `sibuna_<name>_total` in Prometheus text format:

#table(
  columns: (1.1fr, 2.4fr),
  table.header([*Counter*], [*Incremented when*]),
  [`requests`], [A request head was parsed],
  [`allowed`, `denied`, `challenged`], [A policy decision was made (admitted, refused, challenge issued or reissued)],
  [`challenges_issued`], [`/__sibuna/challenge.json` minted a challenge record],
  [`solutions_accepted`, `solutions_rejected`], [`/__sibuna/verify` accepted or rejected a proof],
  [`rate_limited`], [GCRA refused a request (`429`)],
  [`banned`], [A banned address was refused, or the honeypot banned one],
  [`proxied`, `upstream_errors`], [A request was relayed to the origin, or the origin failed (`502`)],
  [`parse_errors`], [A malformed head was refused (`400`)],
  [`overloaded`], [A connection beyond `--max-connections` was answered `503`],
  [`incidents_persisted`, `incident_batches`], [Records and transactions whose commit the storage thread confirmed],
  [`incidents_dropped`, `incident_write_failures`], [Queue pushes rejected because the ring was full, and failed commit attempts],
)

A retry can increment `incident_write_failures` without losing records, because the pending
batch is retained. Monitor increments over an interval; totals alone are not a queue depth.

== Status Codes

#table(
  columns: (0.6fr, 2.4fr),
  table.header([*Code*], [*When*]),
  [200], [Admitted (forward-auth), interstitial (HTML navigation needing a challenge), internal routes],
  [302], [Not used by the current protocol; verification answers `200` and the page reloads],
  [400], [Malformed request, or a rejected solution with an Elm-style diagnostic],
  [401], [Challenge required for a client that does not accept HTML, or in forward-auth mode],
  [403], [Policy or WAF denial, banned address, honeypot],
  [413], [Solution body larger than the 64 KB connection buffer],
  [417], [Unsupported request expectation; `100-continue` is handled locally],
  [429], [GCRA limit exceeded; `Retry-After` in seconds],
  [431], [Request head over 16 KB],
  [502], [Origin unreachable, or its response head was malformed or larger than 16 KB],
  [503], [Connection limit (`--max-connections`) reached; the socket is closed after the reply],
)

== Error Catalog

`INVALID COMMAND LINE` stops startup for any option the daemon does not recognise, any value
outside its documented range, and an invalid, missing or duplicate mode selection. The block
names the option, the value given, the range expected and the error (for example
`UnknownOption`, `InvalidValue`, `InvalidMode`, `DuplicateMode`, `TooManyPeers`). Supply
`--mode reverse_proxy` or `--mode forward_auth` once; `-m` is the equivalent short option.

#api_anchor([`core.explainError`], [
  Maps every domain error to a boundary line, an explanation, and a `Hint:`.
], source: "libs/core/src/errors.zig")

#table(
  columns: (1.3fr, 1.6fr, 1.6fr),
  table.header([*Error*], [*Cause*], [*Hint*]),
  [`MalformedChallenge`], [The identifier is not a well-formed challenge record], [Fetch a fresh challenge and submit it unchanged],
  [`InvalidChallengeTag`], [The tag does not authenticate; not issued by this cluster or edited], [Challenges cannot be forged; request a new one],
  [`ChallengeExpired`], [Older than the challenge TTL, or minted in the future], [Request a new challenge],
  [`FingerprintMismatch`], [Submitted from a different address or User-Agent], [Submit from the client that fetched it],
  [`DifficultyNotMet`], [Hashcash nonce lacks the required zero bits], [Keep searching nonces],
  [`InvalidProof`], [The sequential-work proof does not open the committed labels], [Run the prover to completion for the issued depth and openings],
  [`WrongSolutionType`], [A nonce for a PoSW challenge or a proof for Hashcash], [Match the solution field to the algorithm],
  [`DoubleSpendAttempt`], [The challenge was already spent], [Challenges are single use],
  [`StoreFull`], [Spent set shard exhausted], [Lower the challenge TTL or raise capacity],
  [`InvalidTokenSignature`], [Cookie tag or signature fails], [Re-authenticate through the interstitial],
  [`TokenExpired`], [Cookie past its expiry], [Re-authenticate],
  [`TokenBoundAddressMismatch`], [Cookie presented from a different client identity], [Cookies cannot be shared],
)

== Policy Schema

```
{
  "default_action": "ALLOW" | "DENY" | "CHALLENGE",
  "waf": true | false,
  "thresholds": { "challenge_at": int, "deny_at": int, "bits_step": int },
  "ip_rules": { "<cidr>": "ALLOW" | "DENY" | "CHALLENGE", ... },
  "rules": [
    {
      "name": "<kebab-case>",
      "path" | "path_regex": "<pattern>",
      "user_agent" | "user_agent_regex": "<pattern>",
      "headers" | "headers_regex": { "<Header>": "<pattern>" },   // up to 4
      "remote_addresses" | "cidrs": ["<cidr>", ...],             // up to 8, IPv4 or IPv6
      "action": "ALLOW" | "DENY" | "CHALLENGE" | "WEIGH",
      "weight": int,                                             // WEIGH only
      "challenge": { "difficulty": <work bits>, "algorithm": "hashcash" | "posw" }
    }
  ]
}
```

Pattern grammar: `.*` or `*` match anything; `^…$` anchors an exact path; a trailing `*`, `/*`,
or `.*` is a prefix; a pattern starting with `/` is an exact path; anything else is a
case-insensitive substring.

== Storage Tables

`policies`, `ip_reputation`, `security_incidents`, `incidents_fts` (FTS5 over path and payload),
`incidents_vec` (vec0, 64-float cosine embeddings), and `sibuna_meta`. Incident ids are
`node_id << 40 | sequence`, unique across a cluster without coordination.

== Build Targets

#table(
  columns: (1fr, 2fr),
  table.header([*Command*], [*Result*]),
  [`zig build`], [Daemon with storage, benchmark binary, browser module],
  [`zig build -Dstorage=false`], [Fully static daemon without Zaxonlite],
  [`zig build -Dcluster=true`], [Daemon with Multi-Paxos replication (needs OpenSSL 3)],
  [`zig build test`], [Unit tests, solver tests, end-to-end tests against a live daemon, storage tests],
  [`zig build fmt`], [`zig fmt --check` plus the 70-line / 99-column style gate],
  [`zig build wasm`], [The browser module only],
  [`zig build benchmark`], [`run-all.sh`: ReleaseFast benchmarks with host metadata],
  [`zig build book` / `zig build sid`], [This book / the SID records],
)

#exercise([10.1], [
  A client receives `400` with the title `CLIENT FINGERPRINT MISMATCH` after switching from
  Wi-Fi to cellular mid-solve. Explain the cause from the token and challenge formats, and
  propose the smallest change to the interstitial that recovers gracefully.
])

#teach_back([
  Without looking, list the endpoints a reverse proxy in front of Sibuna must route to the
  daemon rather than to the origin, and say why each is needed.
])
