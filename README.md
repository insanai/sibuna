# Sibuna

> A web firewall and anti-crawler daemon in pure Zig 0.16: zero-allocation classification,
> proof of sequential work for admission, keyed-hash sessions, a semantic WAF, and an embedded
> replicated store, in one static binary.

Sibuna sits in front of an origin (as a reverse proxy) or beside an ingress (as a forward-auth
subrequest engine). Every request is parsed and classified from a single per-connection stack
buffer with no heap allocation. Unverified clients must prove work in the browser: a
Cohen–Pietrzak proof of sequential work (or bit-level Hashcash), verified natively in
microseconds and exchanged for a keyed-BLAKE3 session token bound to the client. Known
automation, forged workers, injected payloads, floods, and honeypot hits are denied before they
reach the origin.

---

## Three surfaces, one binary

| Surface | Flag | What runs | Full classification cost |
|---|---|---|---|
| **Gate** | `--gate` | Proof-of-work admission, declarative rules, bot signatures, reputation trie | 295 ns |
| **Shield** | `--shield` (default) | Gate + semantic WAF (SQLi, XSS, traversal, RCE), GCRA rate limiting, honeypot, ban table | 1.46 µs |
| **Edge** | `--data-dir`, `--cluster-*` | Shield + Zaxonlite store: dynamic policies, replicated IP reputation, incident forensics with full-text and vector search | off the request path |

Numbers are medians measured on an Apple M1 in `ReleaseFast` (`benchmarks/results/latest.json`).

## Research foundations

Every mechanism was chosen for a published security or complexity argument, not for
popularity. The mathematics is in **SID 0006**; the engineering contracts are in SID 0002–0005.

- **Proof of Sequential Work** (Cohen–Pietrzak, EUROCRYPT 2018; quantum security by
  Blocki–Lee–Zhou, ITC 2021): non-parallelisable, deterministic solve time, `O(log N)` client
  memory, `t(n+1)` hashes to verify. Default tier. Hashcash (bit-level) is the second tier.
  Argon2id, HashX, and Equihash were evaluated and rejected (see SID 0002 and SID 0006).
- **Keyed BLAKE3 MAC tokens and stateless challenges**: issuer and verifier share one seed, so
  a 16-byte tag replaces a 64-byte signature; verification is 134 ns, and only *solved*
  challenges occupy memory (Robin Hood spent set, Celis 1986).
- **GCRA rate limiting** (ATM Forum TM 4.0): one integer per client, exact `N + L/T` bound.
- **Aho–Corasick automata** (1975) for bot and attack signatures, one pass per field, plus
  single-pass structural tokenizers instead of regular expressions.
- **Replicated SQLite** through Zaxonlite on `paxos-zig` Multi-Paxos, isolated from the hot
  path by a read-copy-update engine slot and a lock-free incident ring (Vyukov MPSC).

## Quick start

```sh
zig build -Doptimize=ReleaseFast          # daemon, benchmark, and WASM solver
zig build test                            # 80 unit, end-to-end, and storage tests
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
| `--policy-file <json>` | none | Declarative rules (SID 0003) |
| `--workers <n>` | CPU count | Accept threads |
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
[`insanai/zaxonlite`](https://github.com/insanai/zaxonlite) v0.6.0 release pinned in
`build.zig.zon`.

## Measured performance

From `benchmarks/results/latest.json` (Apple M1, Zig 0.16.0, `ReleaseFast`, zero heap
allocation in every row). The `anubis-model` rows in that file are *reference models* of a
Go challenge proxy taken from public profiling; they were not measured on this host and the book
labels them as such.

| Workload | ns / op |
|---|---|
| Hashcash verification (16 bits) | 62.6 |
| PoSW verification (depth 13, 16 openings) | 16,920 |
| Bot automaton, 40 signatures | 85.3 |
| IPv4 / IPv6 trie lookup | 45.2 / 79.9 |
| BLAKE3 MAC token verification | 134.1 |
| Ed25519 token verification | 52,778 |
| Robin Hood spend + lookup | 22.8 |
| GCRA rate check | 4.8 |
| HTTP parse + cookie lookup | 732.5 |
| Full classification: Gate / Shield | 295 / 1,460 |
| Semantic scan of an 8 KB body | 23,702 |

Static: binary 4.25 MB, WASM solver 8,831 bytes, idle RSS 7.6 MB (12–14.5 MB with the store
open). Browser solve times under V8: PoSW depth 13 in 15 ms, depth 16 in 138 ms.

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
