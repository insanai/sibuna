# Sibuna

> A web firewall and anti-crawler daemon in pure Zig 0.16: zero-allocation classification,
> proof of sequential work for admission, keyed-hash sessions, a semantic WAF, and an embedded
> replicated store, in one executable.

Sibuna sits in front of an origin (as a reverse proxy) or beside an ingress (as a forward-auth
subrequest engine). Every request is parsed and classified from a single per-connection stack
buffer with no heap allocation. Unverified clients must prove work in the browser: a
Cohen–Pietrzak proof of sequential work (or bit-level Hashcash), verified natively in
microseconds and exchanged for a keyed-BLAKE3 session token bound to the client. Known
automation, forged workers, injected payloads, floods, and honeypot hits are denied before they
reach the origin.

---

## Two surfaces, one binary

| Capability | Gate (`--gate`) | Shield (`--shield`, default) |
|---|---|---|
| Proof-of-work admission and sessions | Yes | Yes |
| Declarative policy, bot signatures, CIDR reputation | Yes | Yes |
| Local GCRA limits, honeypot, bans | Yes | Yes |
| Semantic payload inspection | Disabled | SQLi, XSS, traversal, command injection |
| Reverse proxy / forward auth | Both | Both |
| Optional persistent and distributed deployment | Yes | Yes |

`--data-dir` enables storage; `--cluster-*` enables replicated policy and reputation with a
cluster build. Distributed edge deployment is an option, not a third surface. Valid sessions
still undergo policy denial checks and, in Shield, WAF inspection.

## How Sibuna compares

Facts about other products were read from their public documentation and release artefacts
in September 2026 (Anubis 1.27.0, SafeLine community edition 9.x, Cloudflare WAF developer
docs); the book's Part II carries the full table with sources.

| | Sibuna | Anubis | SafeLine CE | Cloudflare WAF |
|---|---|---|---|---|
| Runs as | One static binary, reverse proxy or forward auth | One Go binary | Seven Docker containers | Hosted network |
| Proof-of-work admission | Hashcash and Cohen–Pietrzak sequential work, WASM + JS | SHA-256 Hashcash (JS), meta-refresh, preact | JS anti-bot challenge, CAPTCHA | Managed challenge, Turnstile |
| Challenge state on server | None until solved | Store: memory, bbolt, Valkey, S3 | Managed by the stack | Managed |
| Session token | Keyed BLAKE3 tag (Ed25519 optional) | Ed25519 JWT (HS512 optional) | Cookie | `cf_clearance` |
| SQLi / XSS / RCE inspection | Shield: automaton + structural tokenizers | — | Semantic engine | Managed rulesets (Pro+) |
| Rate limiting | GCRA per client | — | Per IP, path, session | 1 / 2 / 5 / 100 rules by plan |
| Reputation, bans | Honeypot; cluster-replicated trie | DNSBL; ASN/GeoIP via paid Thoth | IP groups; threat intel (Pro) | IP lists; bot score (Enterprise) |
| Forensics | Embedded SQLite, FTS5, vector campaigns | Metrics only | PostgreSQL log + console | Security Events |
| Multi-node | Multi-Paxos replication, shared seed | Shared key + Valkey | One stack per host | Global anycast |
| Host footprint | 3.3 MB binary, ~7 MB idle | 37 MB binary, ~40 MB under load | 1 core, 1 GB RAM, 5 GB disk min. | none on premises |
| Measured here | Yes | Yes | No (Docker only) | No (hosted) |

Sibuna does not terminate ingress TLS or score bots with a model. Its opt-in console preview
includes the animated country globe, incident investigation, policy editing, users, scoped API
tokens, audit browsing and local node controls. SID 0007 remains proposed: multi-topic
subscriptions, dedicated peer transport and release acceptance
remain open. See
[loading country data from the CLI](#loading-country-data) for country data setup.

## Research foundations

Every mechanism was chosen for a published security or complexity argument, not for
popularity. The mathematics is in **SID 0006**; the engineering contracts are in SID 0002–0005.

- **Proof of Sequential Work** (Cohen–Pietrzak, EUROCRYPT 2018; quantum security by
  Blocki–Lee–Zhou, ITC 2021): non-parallelisable, deterministic solve time, `O(2^m + log N)` retained client
  memory, `t(n+1)` hashes to verify. Default tier. Hashcash (bit-level) is the second tier.
  Argon2id, HashX, and Equihash were evaluated and rejected (see SID 0002 and SID 0006).
- **Keyed BLAKE3 MAC tokens and stateless challenges**: issuer and verifier share one seed, so
  a 16-byte tag replaces a 64-byte signature; only *solved*
  challenges occupy memory (Robin Hood spent set, Celis 1986).
- **GCRA rate limiting** (ATM Forum TM 4.0): one integer per client, exact `N + L/T` bound.
- **Aho–Corasick automata** (1975) for bot and attack signatures, one pass per field, plus
  single-pass structural tokenizers instead of regular expressions.
- **Replicated SQLite** through Zaxonlite on `paxos-zig` Multi-Paxos, isolated from the hot
  path by a read-copy-update engine slot and a lock-free incident ring (Vyukov MPSC).

## Quick start

```sh
zig build -Doptimize=ReleaseFast          # daemon, benchmark, and WASM solver
zig build test                            # unit, end-to-end, and storage tests
./zig-out/bin/sibuna --port 8080 --upstream-port 3000 --secret-file /run/sibuna.seed
```

The seed file holds 64 hexadecimal characters (or 32 raw bytes); `SIBUNA_SECRET` is honoured
too, and without either the daemon draws a random seed and says so in its banner. A cluster must
share one seed.

Common flags (`--help` lists all of them):

| Flag | Default | Meaning |
|---|---|---|
| `--mode reverse_proxy\|forward_auth` | `reverse_proxy` | Proxy to `--upstream-host:--upstream-port`, or answer ingress subrequests |
| `--algorithm posw\|hashcash` | `posw` | Proof-of-work tier |
| `--difficulty <bits>` | `16` | Work bits; PoSW uses depth `bits - 3` so both tiers cost similar wall-clock |
| `--token-scheme mac\|ed25519` | `mac` | Session token construction |
| `--gate` / `--shield` | shield | Surface |
| `--rate-limit`, `--rate-window` | `100`, `10` | GCRA burst and window (seconds) |
| `--idle-timeout` | `15` | HTTP connection idle timeout in seconds |
| `--websocket-idle-timeout` | `300` | Upgraded connection idle timeout; traffic in either direction refreshes it |
| `--policy-file <json>` | none | Declarative rules (SID 0003) |
| `--workers <n>` | CPU count | Accept threads; each connection is then served on its own thread |
| `--max-connections <n>` | `1024` | Concurrent connections; further ones are answered 503 |
| `--trust-forwarded` | auto in forward-auth | Trust ingress client address, scheme and original authorization URL |
| `--data-dir <path>` | none | Enable the Zaxonlite store (Edge) |

`--mode` and `-m` select the same two modes:

Invalid, missing or repeated mode selections stop startup with `SIBUNAMODE` rather than
silently selecting a different mode.

| Mode | Application traffic | Inspection and console coverage |
|---|---|---|
| `reverse_proxy` (default) | Sibuna forwards admitted requests to the configured upstream and relays admitted WebSockets. | Request metadata, the bounded body prefix, and observed origin responses. |
| `forward_auth` | Sibuna answers ingress authorization subrequests; the ingress forwards uploads, responses and WebSockets. | Metadata supplied by the ingress; omitted bodies and origin responses are not observed. |

For forward-auth, bind Sibuna privately (`--host 127.0.0.1` for a same-host ingress) and
use the book's Caddy/Nginx recipes. A 200 means permission to continue; challenges return
401, denials 403 and limits 429. Browser challenges include the solver page; API clients
receive challenge JSON and should obtain a session before sending uploads or opening a
WebSocket. The recipes route `/__sibuna/*` directly and handle Nginx's auth-error translation.
The console, policy management and local controls remain available in either mode.

`zig build proxy-e2e` checks both CLI modes. To test the book's actual ingress recipes:

```bash
python3 tools/ingress_e2e.py zig-out/bin/sibuna --caddy /path/to/caddy --nginx /path/to/nginx
```

These optional checks use temporary loopback listeners; Nginx needs its auth-request module.

Internal routes: `/__sibuna/challenge.json`, `/__sibuna/verify`, `/__sibuna/worker.js`,
`/__sibuna/wasm/sibuna-pow.wasm` (8,831 bytes), `/__sibuna/health`, `/__sibuna/metrics`
(Prometheus), `/__sibuna/honeypot`.

For HTTPS, terminate TLS at an ingress such as Caddy or Nginx and forward HTTP/1.1 to
Sibuna on a private listener. The ingress can serve HTTP/2 to browsers; native HTTP/2 in
Sibuna is deferred to a later update. Admitted WebSocket upgrades retain their handshake, cookies,
subprotocols and extensions, then relay bytes in both directions with bounded buffers.
WebSocket applications need admission before opening their connection, just like other
protected requests. The relay does not inspect WebSocket message payloads or terminate TLS.
`zig build proxy-e2e` tests HTTP preservation, upgrades, idle expiry and shutdown; an optional
`python3 tools/proxy_e2e.py zig-out/bin/sibuna --caddy /path/to/caddy` also checks HTTPS/WSS
through a real ingress with certificate verification enabled.
Forward-auth evaluates the trusted ingress's `X-Forwarded-Uri` (Caddy) or `X-Original-URI`
(Nginx), including its query, and `X-Forwarded-Method`. Bind that listener privately so only
your ingress can supply these fields. Reverse proxy mode preserves the application Host and
reconstructs `X-Forwarded-Proto` from trusted ingress metadata, or `http` for a direct request.
It removes alternate forwarded host/port fields; applications should use the preserved Host.

Content-Length uploads stream to the backend with their MIME headers and bytes preserved,
including multipart forms and repeated file fields. WAF body inspection covers the first
8 KiB: text fields and upload metadata are inspected; file payloads and recognized binary
MIME bodies remain opaque. Fields beyond that prefix are not inspected. The backend must
validate accepted MIME types and uploaded files; Sibuna does not scan files for malware.
Chunked request bodies are currently rejected. `Expect: 100-continue` is handled locally.

## Policy file

```json
{
  "default_action": "CHALLENGE",
  "waf": true,
  "thresholds": { "challenge_at": 10, "deny_at": 40, "bits_step": 5 },
  "ip_rules": { "10.0.0.0/8": "ALLOW", "2001:db8::/32": "DENY" },
  "rules": [
    { "name": "deny-bad-worker", "headers": { "CF-Worker": ".*" }, "action": "DENY" },
    { "name": "protect-checkout", "path": "/api/checkout/*", "action": "CHALLENGE",
      "challenge": { "difficulty": 20, "algorithm": "posw" } },
    { "name": "internal", "remote_addresses": ["10.0.0.0/8", "fd00::/8"], "action": "ALLOW" },
    { "name": "headless", "user_agent": "Headless", "action": "WEIGH", "weight": 30 }
  ]
}
```

Rules match in order; `WEIGH` rules accumulate a score resolved against the thresholds; anything
unmatched is challenged. Browsers are challenged on purpose: a User-Agent is free to forge.

## Storage and clusters (Edge)

```sh
# single node: dynamic policies, reputation, forensics in ./data
sibuna --data-dir ./data --port 8080 --upstream-port 3000

# three voters (build with -Dcluster=true; production needs the TLS flags)
sibuna --data-dir ./n1 --cluster-node 1 --cluster-listen 127.0.0.1:9901 \
       --cluster-peer 2@127.0.0.1:9902 --cluster-peer 3@127.0.0.1:9903 \
       --cluster-secret-file ./psk           # loopback development PSK
```

Policies inserted into the `policies` table and bans in `ip_reputation` are picked up by every
node on its next storage tick (default 500 ms) and swapped into the workers without a restart.
Blocked payloads land in `security_incidents` with FTS5 search and are clustered into campaigns
by cosine similarity of feature-hashed trigram embeddings. Query the data directory with
`zaxon sql --data ./data`.

Build options: `-Dstorage=false` builds the pure in-memory daemon (no libc); `-Dcluster=true`
links OpenSSL 3 for Zaxonlite's mutual TLS. The dependency is the official
[`insanai/zaxonlite`](https://github.com/insanai/zaxonlite) v0.6.2 release pinned in
`build.zig.zon`.

## Measured performance

Current results: [primitive measurements](benchmarks/results/latest.json),
[whole-product comparison](benchmarks/results/tools-comparison-latest.json),
[admission comparison](benchmarks/results/admission-comparison-latest.json), and
[distributed measurements](benchmarks/results/distributed-latest.json).

```sh
sh benchmarks/run-all.sh                               # primitives
python3 benchmarks/tools.py --anubis /path/to/anubis   # whole products under wrk
python3 benchmarks/compare.py --anubis /path/to/anubis # admission operations
python3 benchmarks/cluster.py                          # 1 node vs 3 replicated nodes under wrk
python3 benchmarks/distributed.py                      # three-node checks with Python clients
```

`cluster.py` answers the cluster question directly: the same Shield configuration as one
node, one node with storage, and three replicated nodes (PSK and mutual TLS), each driven by
`wrk` alone and all at once, with idle CPU and memory per node, cross-node session and WAF
checks, issuer-bound replay rejection, ban propagation time, and service after the leader is
stopped. Results are in [`cluster-latest.json`](benchmarks/results/cluster-latest.json).

`tools.py` starts Sibuna Gate, Sibuna Shield, and Anubis as complete processes in forward-auth
and reverse-proxy modes, obtains a session by solving each product's challenge, and drives
four workloads with `wrk` (admitted, challenged, allowed static path, SQL injection with a
valid session). It records requests per second, p50/p99 latency, CPU microseconds per
request, and peak resident memory of the product process. SafeLine and Cloudflare are listed
as not measured with the published facts that stand in; the Anubis binary is supplied from its
official release and never committed.

Both harnesses run outside the daemon. Primitive operations are timed in seven batches,
with warmup and state reset outside the timer. There are no per-operation clock reads or
benchmark hooks in server code. Source/API review establishes allocation-free primitives;
the harness does not instrument allocator activity. Production metrics and concurrency
controls still cost atomics.

The distributed run uses three local daemon processes and six external load clients. It
checks successful HTTP responses, shared sessions, authenticated WAF denial, issuer-bound
challenge rejection, replicated bans, and continued service after one node stops. Results
include client and loopback costs, not WAN or client-facing TLS costs.

The engine and signature-table sizes are emitted using `@sizeOf`. Comparison with alternative
products requires actual pinned binaries and matched workloads; unsupported fixed competitor
cost models have been removed.

## Deployment limits

Cluster challenge keys are issuer-bound; route challenge fetching and solution submission
to the same node. Session tokens remain valid across members sharing a seed. Rate limits and
spent sets are local, and spent entries do not survive restarts. Shield inspects only the
first 8 KB of a body; large encoded fields, excluded structural headers and ingress-omitted
bodies remain coverage limits. This is a heuristic WAF, not a full language parser. Native
TLS termination, HTTP/2, global quotas and volumetric network mitigation are not implemented.

## Shibuna Discussions (SID)

Design records are Typst papers under `docs/sid/records/`:

- **SID 0001** The Shibuna Discussion process and engineering standards
- **SID 0002** Foundation architecture, delivery record, and performance contract
- **SID 0003** Declarative rule policy engine
- **SID 0004** Semantic attack inspection and GCRA rate limiting (the Shield surface)
- **SID 0005** Zaxonlite storage: dynamic policies, replicated reputation, forensics (Edge)
- **SID 0006** Mathematical foundations: proofs of sequential work, keyed authentication,
  rate limiting, hashing, and inspection automata
- **SID 0007** The Sibuna Console: a real-time management interface for nodes and clusters
  in pure Zig (proposed)

```sh
zig build sid                 # all SID PDFs into docs/build/
zig build sid -Dsid=6         # one record
zig build book                # docs/build/sibuna-book.pdf
zig build sid-list | sid-new -- <slug> | sid-promote -- <slug>
```

## Monorepo layout

```
sibuna/
├── build.zig / build.zig.zon    # -Dstorage (default on), -Dcluster; zaxonlite dependency
├── apps/
│   ├── sibuna/src/              # main.zig, server.zig, storage.zig, persistent.zig, e2e_test.zig
│   ├── wasm-pow/src/entry.zig   # browser solver (hashcash + PoSW), wasm32-freestanding
│   └── web/src/                 # challenge.html, worker.js (WASM + JS provers)
├── libs/
│   ├── core/                    # config, diagnostics, error explanations
│   ├── crypto/                  # keys, pow, posw, token
│   ├── net/                     # zero-copy parser, responses, streaming proxy
│   ├── policy/                  # aho_corasick, radix_trie, rule, loader, engine, waf, normalizer, embedding
│   ├── challenge/               # stateless coordinator, adaptive difficulty
│   └── store/                   # challenge_store, rate_limiter, ban_list, ring
├── benchmarks/                  # benchmark.zig, run-all.sh, results/
├── docs/                        # sid/, book/, shared/
└── tools/                       # sid.zig, check-style
```

## Building and testing

```sh
zig build                     # daemon (+ storage), benchmark, WASM
zig build test                # unit + end-to-end + storage tests
zig build fmt                 # zig fmt and structural style gates
zig build wasm                # solver only
sh benchmarks/run-all.sh      # regenerate benchmarks/results/latest.json
```

## Console preview

Bootstrap an administrator while the daemon is stopped, then start its separate loopback
management listener:

```sh
./zig-out/bin/sibuna init-admin admin --data-dir ./data
./zig-out/bin/sibuna --data-dir ./data --console 127.0.0.1:19446
```

Open `http://127.0.0.1:19446/console/` and replace the temporary password before using the
interface. Ordinary builds include committed CSS and the Zig/Wasm UI without requiring npm.
`-Dconsole=false` removes console integration; `-Dstorage=false` also defaults the console off.
The console listener starts only when `--console` is supplied.

Set `--console-location <latitude,longitude>` to place this node on the globe, for example
`--console-location 1.3521,103.8198` for a deployment in Singapore. The signed-in globe starts
at that position and animates observed country activity toward it; **Center Sibuna** returns
to the server. Coordinates are operator-declared, not inferred from private addresses.
Without them, country activity remains visible but no destination or connection arcs are invented.

The signed-in interface keeps navigation across dashboards, policy and inspection editors,
events, users, tokens, audit and node controls. Policy previews evaluate a private candidate;
saves show a field comparison and require confirmation with an expected revision. Historical
reverts compare against the current rule and create a new revision. Committed and locally
applied revisions remain separate.
Audit detail shows recorded before/after settings and marks missing historical data or redacted
selectors. The Nodes page lists every cluster member from the replicated membership table
(applied policy revision, log frontiers, draining state, a link to that member's advertised
console) together with this console's own health probes of the peer data-plane listeners
named by `--console-probe <node-id>=<http://ip:port>`; `--console-advertise <origin>` sets
the link peers show. Drain, resume and clear local bans still act only on the serving node,
require a preview and produce durable command receipts. Under `-Dcluster=true`,
`zig build console-e2e` also runs a three-node membership, failover and quorum-loss scenario,
and `zig build console-impact` measures the console's cost to the data plane (the latest
full record measured inconclusive on a busy development host; the gate needs a quiet machine).
The impact harness checks all eight streams plus each dashboard's rankings and retained
timeline queries, one configuration at a time. Full runs require
`-- --geoip-data <production.snapshot> --host-label <conditions>`; `-- --quick` checks the
harness and always reports inconclusive. Both throughput and p99 confidence intervals must pass.

A wall display signs in with a one-time kiosk code. Under Account, an operator supplies a
display label and selects **Create display code**. Paste that code into the display's sign-in
page within ten minutes to obtain read-only statistics access for up to twelve hours.
Leaving or hiding the account page erases its displayed code; this does not revoke an unused
grant. The same workflow is available through `POST /console/api/kiosk/token`. Codes never
appear in URLs.

Administrators configure notification destinations under Settings: webhooks (`https`, or
`http` to loopback) signed with `X-Sibuna-Signature: sha256=HMAC(secret, body)` when a
secret is set, and RFC 5424 syslog with an explicit UDP or framed TCP selection, for denial spikes, issued bans,
unreachable members and leader changes. Secrets are sealed under `--console-key-file`; one
cluster member delivers at a time under a fenced lease. Test delivery records intent and
completion in Audit and refreshes the destination's last outcome. If completion cannot be
recorded, the interface reports it as unconfirmed so operators can investigate before retrying.

Administrators can also edit the five browser-facing response pages (challenge, denied,
rate limited, banned, overloaded) under Settings: bounded HTML with fixed placeholders, no
scripts or external resources, previewed in a sandboxed tab and served from the next policy
snapshot. Attributes use quoted values; URLs must be literal local paths or fragments. A
restrictive Content Security Policy permits only the fixed solver on challenge pages.
Non-HTML challenges return JSON; other non-HTML refusal responses remain plain text.

Policy workflows: rules can be reordered from the managed list, a draft can be replayed
against retained inspection findings before saving, IP groups (reputation prefixes with a
note, expiry and a thirty-second undo) and country blocks computed from the active GeoIP
generation live under the applied policies, and the whole managed set can be exported and
re-imported atomically from the interface or with `sibuna console policies export` and
`sibuna console policies import --file <set.json>`.

Country actions are snapshots of the active GeoIP generation. A later import does not refresh
their reputation rows automatically. Preview the country action to compare added, retained and
removed prefixes, using **Next diff page** to inspect the complete bounded replacement. Applying
the review replaces only that country’s own rows. A changed generation or policy revision
requires another preview; independently managed prefixes are preserved and conflicts refused. Events retain WAF findings and honeypot incidents, not a complete request access log.
One authenticated WebSocket carries statistics, events, node status, policy revisions,
challenges and audit updates across navigation. Incident and audit pages keep rows in place
while you read; use **Load latest records** to include newer records. Policy updates show the
current revision without replacing an open draft. Selected non-default challenge timing
partitions remain explicit snapshots. Mutations and historical/detail queries use HTTP.
`zig build console-ui-e2e` runs the shipped Wasm against a real daemon using Node; Chrome
review separately checks the browser DOM, layout and accessibility.

For an HTTPS reverse proxy, configure `--console-origin`, `--console-behind-proxy` and explicit
`--console-trusted-proxy` CIDRs. Supply a persistent `--console-key-file` containing 64 hex
characters with owner-only permissions; it protects stored second-factor secrets. Keep this
key separate from the firewall's challenge secret. Remote management requires a valid HTTPS
origin and a trusted proxy; the browser loads globe geometry and telemetry only after login.

## Loading country data

Country lookup is provided by the first-party `libs/geoip` library (see its README). The
default provider is the public-domain `user-country` dataset from
[ip-location-db](https://github.com/sapics/ip-location-db) (PDDL 1.0, no attribution,
rebuilt daily from RIR statistics, BGP archives and geofeeds). DB-IP IP to Country Lite
(CC BY 4.0, monthly) remains selectable with `--provider dbip`.

Start Sibuna with storage and its opt-in console, then finish administrator bootstrap and
password setup. The CLI prompts for the password without putting it in shell history:

```sh
python3 tools/console_geoip.py --origin http://127.0.0.1:19446 --username admin
```

The daemon also provides a native command for scripts with an owner-only password file:

```sh
./zig-out/bin/sibuna console geoip update --version 2026-09-09 \
    --origin http://127.0.0.1:19446 --username admin \
    --password-file ./admin-password
```

Use `console geoip status` to inspect the generation and `--factor-file` when a second factor
is required. The native update requires an explicit version; the Python helper defaults to
today. Versions are `YYYY-MM-DD` for `user-country` and `YYYY-MM` for `dbip`; `--month` is
the DB-IP alias (`--month 2026-09` means `--provider dbip --version 2026-09`).

The port must match your `--console` listener. Add `--totp` to prompt for an authenticator
or recovery code. Use `--status` to inspect the active generation without importing. Remote
consoles require HTTPS with a valid certificate; HTTP is restricted to literal loopback
addresses.

The command authenticates to the running console, which downloads the provider's fixed
HTTPS files (following exactly one redirect to the publisher's asset host), verifies the
publisher's SHA-256 file for each source file, validates every row, and waits for durable
storage and local activation. It never opens the database directly. Downloads and imports
remain bounded by the daemon's existing limits. An invalid download retains the previous
generation. Interrupting the CLI or reaching `--timeout` stops polling; it does not cancel a
submitted import. The CLI signs out its own session when it exits. Repeating the command
for the active provider and version succeeds without importing it again. A supplied checksum
must match that active generation.

Use `--checksum` with an independently obtained SHA-256 of the **source bytes in provider
file order** (for `user-country`: `cat user-country-ipv4.csv user-country-ipv6.csv |
sha256sum`; for `dbip`: the compressed `.csv.gz`) to require a particular dataset. The
resulting digest is printed with the active revision, provider, version and range count.

Country mapping is approximate. Local/private addresses remain Unknown when absent from the
dataset. The globe uses sampled requests from a rolling 60-second window, so loading the
database does not invent traffic or retroactively locate old samples. Send requests through
the firewall to see live countries. When DB-IP data is active the console shows the CC BY
4.0 attribution; `user-country` requires none.

To validate a download offline or to prepare an embedded snapshot, use the library tool:

```sh
zig build geoip-snapshot -- --provider user-country --version 2026-09-09 \
    user-country-ipv4.csv user-country-ipv6.csv --snapshot-out geoip.bin
zig build -Dgeoip-data=geoip.bin
```

A build with `-Dgeoip-data` serves lookups from the embedded snapshot (about 5.6 MB for the
full dataset) at revision 0 until the first durable import replaces it. The September 9,
2026 `user-country` dataset was loaded into the development review instance with 559,667
known-country ranges and generation SHA-256
`cd52619878ee0f7592f1c9eb45b03383722a38b443408348743ba27e18a23ce0`.
Dataset files and the populated development database are not committed to Git.
