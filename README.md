# Sibuna (sibuna)

> High-Performance Web AI Firewall & Anti-Crawler Daemon in Pure Zig 0.16.
> "Weighing the soul of incoming connections with zero-allocation silicon performance."

Sibuna is an open-source, ultra-fast Web AI Firewall and bot protection reverse proxy / forward-auth subrequest daemon built as a pure Zig monorepo. It imposes asymmetric computational Proof-of-Work (PoW) friction on unverified automated scrapers while providing instant, frictionless access to legitimate users and verified crawlers.

---

## Key Performance Advantages Over Anubis

- **Zero-Allocation Hot Path:** Zero dynamic heap allocations during request classification, cookie verification, and PoW validation.
- **Bare-Metal Silicon PoW Verification:** Direct native execution of SHA-256 (x86 SHA-NI / ARM NEON), HashX, and Argon2id. No in-Go WebAssembly runtime (Wazero) overhead on the server ($< 50\mu s$ vs $5\text{--}20$ms).
- **SIMD Multi-Pattern Matching:** Single-pass evaluation of hundreds of bot signatures via SIMD-accelerated Aho-Corasick automata ($100\text{--}300$ns per request).
- **Zero-Copy Radix Trie IP Filtering:** Constant-time bitwise IPv4 and IPv6 CIDR routing lookups in $\le 40$ns.
- **Ultra-Compact Tokens:** Zero-allocation Ed25519 or HMAC-BLAKE3 binary tokens cryptographically bound to client network fingerprints and policy hashes.
- **Unified Toolchain:** Zig compiles the server daemon, the native cryptographic engines, and the browser-side WebAssembly solver (`wasm32-freestanding`, $< 10$ KB).

---

## Architectural Records: Shibuna Discussions (SID)

Following the engineering practices established in `paxos-zig` (ZDS), Sibuna uses **Shibuna Discussions (SID)** as RFC/RFD-style decision records authored in Typst:

- **[SID 0001: The Shibuna Discussion Process](docs/sid/records/0001-sid-process.typ)** — Documents the SID lifecycle, numbering workflow, and review expectations.
- **[SID 0002: Sibuna Foundation Architecture, Delivery Plan, and Performance Contract](docs/sid/records/0002-sibuna-foundation-architecture.typ)** — Foundational architectural specification, comparative audit of Anubis, zero-allocation pipeline design, and delivery milestones.

### SID Commands

```sh
# List all registered SID discussions and drafts
zig build sid-list

# Create a new draft discussion record
zig build sid-new -- <slug>

# Promote a draft to an official numbered discussion
zig build sid-promote -- <slug>

# Build all SID PDF documents into docs/build/
zig build sid

# Build a single SID PDF by number or slug
zig build sid -Dshd=0002
zig build sid -Dshd=2
zig build sid -Dshd=sibuna-foundation-architecture

# Build the SID index PDF
zig build sid-index

# Build the experimental HTML bundle
zig build sid-site
```

---

## Monorepo Layout

```
sibuna/
├── build.zig                   # Root build script orchestrating libraries, apps, and docs
├── build.zig.zon               # Package manifest
├── apps/
│   ├── sibuna/                 # Main firewall daemon binary
│   ├── wasm-pow/               # Browser-side PoW solver (wasm32-freestanding)
│   └── web/                    # Client static assets, worker scripts, and templates
├── libs/
│   ├── core/                   # Arena allocators, configuration, logging, time
│   ├── crypto/                 # SHA-256 SIMD, HashX, Argon2id, Ed25519, tokens
│   ├── net/                    # Zero-copy HTTP/1.1 & HTTP/2 parser, proxy, subrequest
│   ├── policy/                 # SIMD Aho-Corasick, Radix CIDR trie, JA4H, scoring
│   ├── challenge/              # Challenge coordinator & dynamic difficulty
│   └── store/                  # Lockless sharded decay map, Valkey/Redis client
├── docs/
│   ├── shared/                 # Shared Typst templates & styling (theme.typ, sid.typ)
│   ├── sid/                    # Shibuna Discussions (records/, registry.typ, bundle.typ)
│   └── build/                  # Compiled PDF and HTML documentation artifacts
└── tools/
    └── sid.zig                 # SID management CLI tool
```

---

## Building and Testing

```sh
# Build the server daemon and libraries
zig build

# Run unit tests across all libraries
zig build test

# Compile the browser WebAssembly solver (< 10 KB)
zig build wasm

# Run the daemon
zig build run
```
