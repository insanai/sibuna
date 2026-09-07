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

Sibuna does not terminate TLS, ship a console, look up geography, or score bots with a model;
an ingress or a hosted edge does those.

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
| `--idle-timeout` | `15` | Seconds before an idle connection is reaped (slowloris guard) |
| `--policy-file <json>` | none | Declarative rules (SID 0003) |
| `--workers <n>` | CPU count | Accept threads; each connection is then served on its own thread |
| `--max-connections <n>` | `1024` | Concurrent connections; further ones are answered 503 |
| `--trust-forwarded` | auto in forward-auth | Honour `X-Forwarded-For` / `X-Real-IP` |
| `--data-dir <path>` | none | Enable the Zaxonlite store (Edge) |

Internal routes: `/__sibuna/challenge.json`, `/__sibuna/verify`, `/__sibuna/worker.js`,
`/__sibuna/wasm/sibuna-pow.wasm` (8,831 bytes), `/__sibuna/health`, `/__sibuna/metrics`
(Prometheus), `/__sibuna/honeypot`.

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
[`insanai/zaxonlite`](https://github.com/insanai/zaxonlite) v0.6.1 release pinned in
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
python3 benchmarks/distributed.py                      # three-node runs
```

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
