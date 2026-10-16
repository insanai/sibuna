# Sibuna

> A web firewall and anti-crawler daemon in Rust: zero-allocation classification, proof of
> sequential work for admission, keyed-hash sessions, a semantic WAF, and optional storage on
> SQLite or a shared PostgreSQL database, in one executable.

Sibuna sits in front of an origin (as a reverse proxy) or beside an ingress (as a forward-auth
subrequest engine). Every request is parsed and classified from a per-connection buffer with
no heap allocation on the warm path. Unverified clients must prove work in the browser: a
Cohen-Pietrzak proof of sequential work (or bit-level Hashcash), verified natively in
microseconds and exchanged for a keyed-BLAKE3 session token bound to the client. Known
automation, forged workers, injected payloads, floods, and honeypot hits are denied before
they reach the origin.

Sibuna is written in Rust. The data plane is built from small in-house crates with no
external dependencies; storage (sqlx), the console's outbound TLS (rustls) and the runtime
sqlx needs (tokio) are the only external libraries, each admitted by a design record and
confined to one crate ([SID 0010](docs/sid/records/0010-rust-port.rst)).

---

## Two surfaces, one binary

| Capability | Gate (`--gate`) | Shield (`--shield`, default) |
|---|---|---|
| Proof-of-work admission and sessions | Yes | Yes |
| Declarative policy, bot signatures, CIDR reputation | Yes | Yes |
| Local GCRA limits, honeypot, bans | Yes | Yes |
| Semantic payload inspection | Disabled | SQLi, XSS, traversal, command injection |
| Reverse proxy / forward auth | Both | Both |
| Optional persistent and shared storage | Yes | Yes |

`--data-dir` keeps policies, reputation and forensics in a local SQLite file; `--database-url`
with `--cluster-node` shares them between nodes through PostgreSQL. Shared storage is an
option, not a third surface. Valid sessions still undergo policy denial checks and, in
Shield, WAF inspection.

## How Sibuna compares

Facts about other products were read from their public documentation and release artefacts
(Anubis 1.27.0, SafeLine community edition 9.x, Cloudflare WAF developer docs); the book's
Part II carries the full table with sources.

| | Sibuna | Anubis | SafeLine CE | Cloudflare WAF |
|---|---|---|---|---|
| Runs as | One binary, reverse proxy or forward auth | One Go binary | Seven Docker containers | Hosted network |
| Proof-of-work admission | Hashcash and Cohen-Pietrzak sequential work, WASM + JS | SHA-256 Hashcash (JS), meta-refresh, preact | JS anti-bot challenge, CAPTCHA | Managed challenge, Turnstile |
| Challenge state on server | None until solved | Store: memory, bbolt, Valkey, S3 | Managed by the stack | Managed |
| Session token | Keyed BLAKE3 tag (Ed25519 optional) | Ed25519 JWT (HS512 optional) | Cookie | `cf_clearance` |
| SQLi / XSS / RCE inspection | Shield: automaton + structural tokenizers | None | Semantic engine | Managed rulesets (Pro+) |
| Rate limiting | GCRA per client and per rule | None | Per IP, path, session | 1 / 2 / 5 / 100 rules by plan |
| Reputation, bans | Honeypot; shared reputation trie | DNSBL; ASN/GeoIP via paid Thoth | IP groups; threat intel (Pro) | IP lists; bot score (Enterprise) |
| Forensics | SQLite or PostgreSQL, full-text search, campaign similarity | Metrics only | PostgreSQL log + console | Security Events |
| Multi-node | Shared PostgreSQL database, shared seed | Shared key + Valkey | One stack per host | Global anycast |
| Measured here | Yes | Yes | No (Docker only) | No (hosted) |

On one host under the same load, Sibuna's peak resident memory stayed at about 16 MiB, and
Anubis 1.27.0 used about 32 MiB in forward-auth mode and up to about 600 MiB in reverse-proxy
mode ([comparison-latest.md](benchmarks/results/comparison-latest.md)). SafeLine and
Cloudflare could not be run here.

Sibuna does not terminate ingress TLS or score bots with a model. Its opt-in console adds an
animated country globe, incident investigation, policy editing, users, scoped API tokens,
audit browsing, local node controls and authenticated multi-topic subscriptions.

## Research foundations

Every mechanism was chosen for a published security or complexity argument, not for
popularity. The mathematics is in **SID 0006**; the engineering contracts are in SID 0002 to
SID 0004, SID 0009 and SID 0011.

- **Proof of Sequential Work** (Cohen-Pietrzak, EUROCRYPT 2018; quantum security by
  Blocki-Lee-Zhou, ITC 2021): non-parallelisable, deterministic solve time, `O(2^m + log N)`
  retained client memory, `t(n+1)` hashes to verify. Default tier. Hashcash (bit-level) is the
  second tier. Argon2id, HashX, and Equihash were evaluated and rejected (SID 0002, SID 0006).
- **Keyed BLAKE3 MAC tokens and stateless challenges**: issuer and verifier share one seed, so
  a 16-byte tag replaces a 64-byte signature; only *solved* challenges occupy memory (Robin
  Hood spent set, Celis 1986).
- **GCRA rate limiting** (ATM Forum TM 4.0): one integer per client, exact `N + L/T` bound,
  placed by a keyed hash so a client cannot aim at a shard.
- **Aho-Corasick automata** (1975) over byte classes for bot and attack signatures, one pass
  per field, plus single-pass structural tokenizers instead of regular expressions.
- **Storage through sqlx** (SID 0011): SQLite for one node and PostgreSQL for a cluster,
  isolated from the request path by a published engine slot and a lock-free incident ring
  (Vyukov MPSC).

## Quick start

```sh
rustup target add wasm32-unknown-unknown        # the browser solver and console interface
cargo build --release -p sibuna                 # daemon with SQLite storage and the console
cargo test --workspace                          # unit, end-to-end and storage tests
./target/release/sibuna --port 8080 --upstream-port 3000 --secret-file /run/sibuna.seed
```

The seed file holds 64 hexadecimal characters (or 32 raw bytes); `SIBUNA_SECRET` is honoured
too, and without either the daemon draws a random seed and says so in its banner. A cluster
must share one seed.

Build features: the default is `sqlite` and `console`. `--no-default-features` builds the pure
in-memory daemon, which depends on no external crate. `--features postgres` adds the cluster
backend, and `--features postgres-tls` adds TLS for its database connections.

Common flags (`--help` lists all of them):

| Flag | Default | Meaning |
|---|---|---|
| `--mode reverse_proxy\|forward_auth` | `reverse_proxy` | Proxy to `--upstream-host:--upstream-port`, or answer ingress subrequests |
| `--algorithm posw\|hashcash` | `posw` | Proof-of-work tier |
| `--difficulty <bits>` | `16` | Work bits; PoSW uses depth `bits - 3` so both tiers cost similar wall-clock |
| `--token-scheme mac\|ed25519` | `mac` | Session token construction |
| `--gate` / `--shield` | shield | Surface |
| `--rate-limit`, `--rate-window` | `100`, `10` | GCRA burst and window (seconds) |
| `--challenge-rate-limit` | `30` | Challenge issuances and verifications per window per client, separate from the request budget |
| `--idle-timeout` | `15` | Longest silence in seconds; a proxied upload must deliver 16 KiB per period |
| `--websocket-idle-timeout` | `300` | Upgraded connection idle timeout |
| `--policy-file <json>` | none | Declarative rules (SID 0003) |
| `--workers <n>` | CPU count | Accept threads; each connection is served on a reused connection thread |
| `--max-connections <n>` | `1024` | Concurrent connections; further ones are answered 503 |
| `--max-connections-per-ip <n>` | `64` | Concurrent connections per client address (IPv6 per `--ipv6-prefix` network) |
| `--trust-forwarded` | auto in forward-auth | Trust the ingress client address; `--trusted-hops` picks the X-Forwarded-For entry |
| `--data-dir <path>` | none | SQLite storage for one node |
| `--database-url <url>`, `--cluster-node <id>` | none | Shared PostgreSQL storage for a cluster |

Invalid, missing or repeated options and out-of-range values stop startup with an
`INVALID COMMAND LINE` diagnostic naming the option, value and expected range rather than
silently keeping a default.

| Mode | Application traffic | Inspection and console coverage |
|---|---|---|
| `reverse_proxy` (default) | Sibuna forwards admitted requests to the configured upstream and relays admitted WebSockets. | Request metadata, the bounded body prefix, and observed origin responses. |
| `forward_auth` | Sibuna answers ingress authorization subrequests; the ingress forwards uploads, responses and WebSockets. | Metadata supplied by the ingress; omitted bodies and origin responses are not observed. |

For forward-auth, bind Sibuna privately (`--host 127.0.0.1` for a same-host ingress) and use
the book's Caddy and Nginx recipes (Part IX). A 200 means permission to continue; challenges
return 401, denials 403 and limits 429. Browser challenges include the solver page; API clients
receive challenge JSON and should obtain a session before sending uploads or opening a
WebSocket. Forward-auth evaluates the trusted ingress's `X-Forwarded-Uri` (Caddy) or
`X-Original-URI` (Nginx), including its query, and `X-Forwarded-Method`.

Internal routes: `/__sibuna/challenge`, `/__sibuna/challenge.json`, `/__sibuna/verify`,
`/__sibuna/worker.js`, `/__sibuna/wasm/sibuna-pow.wasm` (14,744 bytes), `/__sibuna/health`,
`/__sibuna/metrics` (Prometheus), `/__sibuna/honeypot`.

For HTTPS, terminate TLS at an ingress such as Caddy or Nginx and forward HTTP/1.1 to Sibuna on
a private listener. Admitted WebSocket upgrades retain their handshake, cookies, subprotocols
and extensions, then relay bytes in both directions with bounded buffers; the relay does not
inspect WebSocket messages. Reverse-proxy mode preserves the application Host, sends
`X-Forwarded-Proto`, and sends `X-Forwarded-For` as the received chain plus the socket peer
when forwarding is trusted.

Uploads stream to the backend with their MIME headers and bytes preserved. WAF body
inspection covers the first 8 KiB: text fields and upload metadata are inspected; file
payloads and bodies that are binary in fact remain opaque. Chunked request bodies are decoded
before inspection, so chunk boundaries cannot hide a payload. A body that ends within the
64 KiB connection buffer reaches the backend with a Content-Length; a longer one is re-chunked,
one chunk per read. Ambiguous chunk framing is refused with 400, and other transfer codings
with 501 (SID 0009). `Expect: 100-continue` is handled locally.

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
    { "name": "headless", "user_agent": "Headless", "action": "WEIGH", "weight": 30 },
    { "name": "api-quota", "path": "/api/*", "action": "ALLOW",
      "limits": { "rate": 30, "window_seconds": 10 } }
  ]
}
```

Rules match in order; `WEIGH` rules accumulate a score resolved against the thresholds;
`limits` gives a rule a quota of its own; anything unmatched is challenged. Browsers are
challenged on purpose: a User-Agent is free to forge. The loader fails closed: an unknown key,
a misspelled action, a malformed address or an out-of-range number rejects the whole file with
a diagnostic naming the rule and field, and the daemon does not start.

## Storage and clusters

```sh
# one node: dynamic policies, reputation and forensics in ./data/sibuna.db
sibuna --data-dir ./data --port 8080 --upstream-port 3000

# a cluster: every node shares one PostgreSQL database and the same seed
cargo build --release -p sibuna --features postgres-tls
sibuna --database-url-file /etc/sibuna/database-url --cluster-node 1 \
       --secret-file /etc/sibuna/secret
```

The URL file holds one `postgres://` URL, readable by its owner only; production clusters add
`?sslmode=verify-full&sslrootcert=/etc/sibuna/db-ca.pem`, and the daemon states at startup
whether the database connection is encrypted and verified. Policies inserted into the
`policies` table and bans in `ip_reputation` are picked up by every node on its next storage
tick (default 500 ms) or at once through `NOTIFY`, and swapped into the workers without a
restart. Blocked payloads land in `security_incidents` with full-text search and are grouped
into campaigns by cosine similarity of feature-hashed trigram embeddings. Query the data with
`sqlite3 ./data/sibuna.db` or `psql`.

Replication, failover and backups are PostgreSQL's (SID 0011): Sibuna keeps no consensus
log of its own, and a node that loses the database keeps serving its last published policy.

## Measured performance

Measured on one AMD Ryzen 9 5950X, the daemon on four CPUs and the load generator on others
([benchmarks/results](benchmarks/results/README.md), book Part VIII):

- **Whole product under `wrk`** (Shield, 64 connections): about 208,000 admitted requests per
  second in forward-auth mode at a p99 of 308 us and 12.9 us of CPU per request, and 139,000
  per second proxied to an origin; peak resident memory about 16 MiB.
- **Latency at equal offered load** (Shield, admitted requests, forward auth): p99 of 37 us at
  10,000 requests per second and 51 us at 150,000; p99.9 of 62 us at 100,000.
- **Primitives:** Hashcash verification 70 ns, PoSW verification (depth 13, 16 openings)
  22 us, a keyed-BLAKE3 session check 156 ns, request parsing with cookie 133 ns, a full
  browser-request classification 791 ns, the 40-signature Aho-Corasick scan 56 ns, a GCRA
  check 6.2 ns, and the semantic scan of an 8 KiB body 12.8 us.

**Beside Anubis.** We measured the official Anubis 1.27.0 release binary with the same
workloads, CPUs and load generator as Sibuna Gate (Hashcash work matched: 8 zero bits for
Sibuna, 2 zero hex digits for Anubis). The last column is the first Sibuna implementation,
recorded in September 2026 with an earlier harness, not measured in these runs.

| Admitted requests | Sibuna Gate | Anubis 1.27.0 | Sibuna 0.1 Gate (recorded) |
|---|---|---|---|
| Forward auth, req/s | 210,682 | 36,509 | 219,551 |
| Forward auth, p99 | 305 us | 7,477 us | 320 us |
| Forward auth, CPU per request | 12.1 us | 106.3 us | 14.7 us |
| Reverse proxy (behind `caddy respond`), req/s | 106,376 | 19,398 | 109,120 |
| Reverse proxy, p99 | 3,331 us | 11,062 us | 5,235 us |

| Admission operations per second (2 CPUs) | Sibuna (keyed BLAKE3) | Anubis (Ed25519) | Anubis (HS512) |
|---|---|---|---|
| Valid session check | 88,104 | 10,951 | 16,976 |
| Unauthenticated check | 78,997 | 28,619 | 27,785 |
| Challenge bootstrap | 42,664 | 7,893 | 7,952 |
| Proof verification | 57,924 | 12,668 | 19,261 |

These figures describe these workloads on one machine, not every deployment. Anubis is a
widely used and capable tool; several rows are not like for like (in forward-auth mode Anubis
answers some paths itself, and it does no payload inspection), and Part VIII of the book lists
each difference ([comparison-latest.md](benchmarks/results/comparison-latest.md),
[admission-latest.md](benchmarks/results/admission-latest.md)).

```sh
cargo xtask bench primitives
cargo xtask bench product
cargo xtask bench latency
cargo xtask bench help
```

The harnesses run outside the daemon. Primitive operations are timed in seven batches, with
warm-up and state reset outside the timer; there are no benchmark hooks in server code. A
test (`cmd/sibuna/tests/steady_state.rs`) asserts that a warm request makes no heap
allocation.

## Deployment limits

Challenge keys are issuer-bound; route challenge fetching and solution submission to the same
node. Session tokens remain valid across nodes sharing a seed. Rate limits and spent sets are
local, and spent entries do not survive restarts. Shield inspects only the first 8 KiB of a
body; large encoded fields, excluded structural headers and ingress-omitted bodies remain
coverage limits. This is a heuristic WAF, not a full language parser. Native TLS termination,
HTTP/2, global quotas and volumetric network mitigation are not implemented.

## Sibuna Discussions (SID)

Design records are reStructuredText under [`docs/sid/records/`](docs/sid/records), managed with
`guidedog dsc` (see [docs/sid/README.md](docs/sid/README.md)):

- **SID 0001** The Sibuna Discussion process and engineering standards
- **SID 0002** Foundation architecture, delivery plan, and performance contract
- **SID 0003** Declarative rule policy engine
- **SID 0004** Semantic attack inspection and GCRA rate limiting (the Shield surface)
- **SID 0005** Distributed storage architecture (superseded by SID 0011)
- **SID 0006** Mathematical foundations: sequential work, symmetric authentication, bounded
  state, and linear-time inspection
- **SID 0007** The Sibuna Console: a real-time management interface for nodes and clusters
- **SID 0008** AI bot traffic identification, multi-tier verification, and console analytics
  (in discussion, not implemented)
- **SID 0009** Chunked request bodies
- **SID 0010** Workspace, crates, dependency policy and performance
- **SID 0011** Storage through sqlx: SQLite for one node, PostgreSQL for clusters
- **SID 0012** Outbound TLS for the console through rustls
- **SID 0013** Console storage: a typed schema with invariants in Rust

## Workspace layout

```
sibuna2/
|-- Cargo.toml                 # workspace: one version, shared lints, every dependency once
|-- cmd/
|   |-- sibuna/                # the daemon (features: sqlite, console, postgres, postgres-tls)
|   |-- sibuna-pow-wasm/       # browser solver (Hashcash + PoSW), wasm32
|   `-- console-ui/            # console interface in Rust, compiled to WebAssembly
|-- crates/
|   |-- core/                  # configuration, diagnostics, metrics, incident types
|   |-- http/ net/ serve/      # zero-copy HTTP/1.1, streaming proxy, bounded listener
|   |-- policy/ patterns/ cidr/  # policy engine and WAF, Aho-Corasick, CIDR trie
|   |-- challenge/ pow/ crypto/  # stateless challenges, proofs of work, hashes and MACs
|   |-- store/                 # MPSC ring, spent set, GCRA limiter, ban table
|   |-- storage/               # SQLite and PostgreSQL through sqlx (SID 0011)
|   |-- console/ console-protocol/ console-storage/  # the console (SID 0007, 0013)
|   |-- tls/                   # rustls, confined to this crate (SID 0012)
|   `-- json/ encoding/ inflate/ geoip/ html/  # small reusable libraries
|-- tools/                     # xtask, bench, parity, browser (all Rust)
|-- web/                       # challenge page and worker
|-- benchmarks/results/        # committed measurement records
`-- docs/                      # book/, sid/, whitepaper/ (guidedog projects)
```

The libraries under `crates/` that do not name Sibuna in their description (`json`, `encoding`,
`inflate`, `geoip`, `html`, `http`, `patterns`, `cidr`, `crypto`, `pow`, `store`, `serve`) are
written to be reused by other projects.

## Building and testing

```sh
cargo build --workspace
cargo test --workspace                          # SQLite storage
SIBUNA_TEST_DATABASE_URL=postgres://user:pass@127.0.0.1/sibuna_test \
  cargo test -p sibuna -p sibuna-storage -p sibuna-console-storage -p sibuna-console \
  --features postgres                           # the PostgreSQL backend and cluster tests
cargo clippy --workspace --all-targets -- -D warnings
cargo xtask check                               # function, file and line size limits
cargo xtask browser console --url ... --out <dir>  # console walk-through in headless Chromium
```

The build script of `cmd/sibuna` builds both WebAssembly modules with the `wasm` profile;
`SIBUNA_POW_WASM=<path>` and `SIBUNA_CONSOLE_WASM=<path>` embed prebuilt modules instead.

## Console

Bootstrap an administrator while the daemon is stopped, then start its separate management
listener:

```sh
./target/release/sibuna init-admin admin --data-dir ./data
./target/release/sibuna --data-dir ./data --console 127.0.0.1:19446
```

Open `http://127.0.0.1:19446/console/` and replace the temporary password before using the
interface. The interface is a Rust WebAssembly module (about 720 KB, under the 768 KiB
ceiling of SID 0007) embedded in the daemon; the build never runs npm. The console listener
starts only when `--console` is supplied, and the browser loads globe geometry and telemetry
only after sign-in.

The signed-in interface covers traffic and security dashboards, events, challenges, policy
and inspection editors with previews and revision checks, GeoIP, users, API tokens, audit
history, node controls, settings and wall displays opened with one-time kiosk codes. One
authenticated WebSocket carries statistics, events, node status, policy revisions, challenges
and audit updates. Management peers (`--console-peer`, at most eight) exchange live statistics
over authenticated TLS WebSockets through rustls. Book Part IX describes every page, option
and workflow.

For an HTTPS reverse proxy, configure `--console-origin`, `--console-behind-proxy` and explicit
`--console-trusted-proxy` CIDRs, and supply a persistent `--console-key-file` (64 hex
characters, owner-only) that protects stored second-factor secrets.

## Loading country data

Country lookup is provided by the `sibuna-geoip` crate. The default provider is the
public-domain `user-country` dataset from
[ip-location-db](https://github.com/sapics/ip-location-db) (PDDL 1.0); DB-IP IP to Country
Lite (CC BY 4.0, monthly) is selectable with `--provider dbip`. The running console downloads,
verifies and activates a dataset on request:

```sh
./target/release/sibuna console geoip update --version 2026-09-09 \
    --origin http://127.0.0.1:19446 --username admin --password-file ./admin-password
./target/release/sibuna console geoip status --origin http://127.0.0.1:19446 \
    --username admin --password-file ./admin-password
```

Versions are `YYYY-MM-DD` for `user-country` and `YYYY-MM` for `dbip`. `--checksum` requires a
particular dataset, `--factor-file` supplies a second factor, and `--timeout` (default 1,200 s)
bounds the wait. The command never opens the database directly; an invalid download retains
the previous generation.

To validate a download offline or to embed a snapshot in the binary:

```sh
cargo run --release -p sibuna-geoip --bin geoip-snapshot -- --provider user-country \
    --version 2026-09-09 user-country-ipv4.csv user-country-ipv6.csv --snapshot-out geoip.bin
SIBUNA_GEOIP_DATA=geoip.bin cargo build --release -p sibuna
```

A build with an embedded snapshot serves lookups at revision 0 until the first durable import
replaces it. Country mapping is approximate; dataset files are not committed.

## Documentation

- **The Sibuna Book** ([docs/book](docs/book)): the mathematics and engineering, from the cost
  model to operations, with measurements and a quick-reference card.
- **Sibuna Discussions** ([docs/sid](docs/sid)): the design records.
- **The whitepaper** ([docs/whitepaper](docs/whitepaper)).

All three are [guidedog](https://github.com/insanai/guidedog) projects: `guidedog build html`
and `guidedog build pdf` in each directory, and `guidedog dsc build` for the SIDs.
