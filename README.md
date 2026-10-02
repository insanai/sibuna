<p align="center">
  <h1 align="center">sibuna</h1>
  <p align="center">
    <strong>A simple and lightweight web application firewall to protect websites and APIs without CAPTCHAs.</strong>
  </p>
  <p align="center">
    <a href="#features">Features</a> •
    <a href="#quickstart">Quickstart</a> •
    <a href="#how-it-works">How It Works</a> •
    <a href="#architecture">Architecture</a> •
    <a href="#deployment">Deployment</a> •
    <a href="#configuration">Configuration</a> •
    <a href="#philosophy">Philosophy</a> •
    <a href="#documentation">Documentation</a>
  </p>
</p>

---

**sibuna** is an open-source web application firewall (WAF) and anti-crawler daemon. It sits in front of your web application as a protective reverse proxy, or alongside your existing reverse proxy (such as Caddy, Nginx, or Traefik) as an authorization gate.

Instead of subjecting human visitors to frustrating image CAPTCHAs or privacy-invasive tracking scripts, Sibuna asks client browsers to solve a silent background computational puzzle in a fraction of a second. Instead of requiring sprawling container clusters, external databases, or heavy interpreters, Sibuna runs as a **single, self-contained executable** with predictable, bounded memory.

---

## Features

- **[x] Zero External Dependencies:** Compiles to a single static binary. No external Redis, PostgreSQL, Node, or Docker clusters required.
- **[x] Frictionless Human Verification:** Legitimate visitors solve a silent, background proof-of-work puzzle in WebAssembly ($< 1\,\text{s}$). No images to click, no tracking cookies.
- **[x] Deterministic Memory Bounds:** Fixed stack buffers for request processing. Zero dynamic heap allocation on the hot request path ensures immunity to memory fragmentation and out-of-memory crashes under flood.
- **[x] AI Crawler & Bot Governance:** Sub-45ns Radix CIDR trie matches client IPs against published ranges for OpenAI, Anthropic, Google Gemini, Perplexity, Meta, Apple, and ByteDance. Instantly catches spoofed User-Agents.
- **[x] Semantic Attack Shield:** Single-pass, linear-time Aho–Corasick automata and structural tokenizers inspect SQL injection, XSS, and path traversal without regular expression backtracking (ReDoS).
- **[x] Thermodynamic Asymmetry:** Verifying a solution costs the server under $25\,\mu\text{s}$, while mass scrapers must burn hours of dedicated CPU compute to harvest pages.
- **[x] Local Rate Limiting:** 16-shard atomic GCRA (Generic Cell Rate Algorithm) enforces strict per-client burst and sustained rate limits in $6\,\text{ns}$ with zero lock contention.
- **[x] Real-Time Management Console:** Built-in web dashboard with a live 3D country traffic globe, 24-hour comparative analytics, incident forensics with full-text search (FTS5), and granular provider toggles.
- **[x] Embedded Multi-Node Clustering:** Embedded Zaxonlite store executes Multi-Paxos consensus to synchronize dynamic policies and propagate banned IPs across nodes in milliseconds.

---

## Architecture

Following the modular design of raylib, Sibuna is divided into small, single-purpose subsystems:

```
┌────────────────────────────────────────────────────────────────────────┐
│                          SIBUNA SUBSYSTEMS                             │
├──────────────┬─────────────────────────────────────────────────────────┤
│ net          │ Zero-copy HTTP/1.1 stream parser & reverse proxy relay  │
│ crypto       │ Proof of Sequential Work (PoSW), Hashcash & BLAKE3 MAC  │
│ policy       │ Aho–Corasick signatures, Radix CIDR trie & semantic WAF │
│ challenge    │ Stateless challenge coordinator & adaptive difficulty   │
│ store        │ 16-shard GCRA rate limiter & Robin Hood spent set       │
│ edge         │ Embedded Zaxonlite store (replicated SQLite Multi-Paxos)│
│ console      │ WebAssembly operator UI, WebSocket telemetry & GeoIP    │
└──────────────┴─────────────────────────────────────────────────────────┘
```

### Two Operational Surfaces

Sibuna provides two operational surfaces within the same executable:

```
                  ┌─────────────────────────────────────────┐
                  │            Incoming Request             │
                  └────────────────────┬────────────────────┘
                                       │
                      [ Surface 1: Gate (--gate) ]
                      • Proof-of-work admission & sessions
                      • Bot signatures & Radix CIDR checks
                      • Atomic GCRA rate limiting & honeypots
                                       │
                                       ▼ Admitted
                      [ Surface 2: Shield (--shield, default) ]
                      • Inline semantic attack inspection
                      • SQL injection & XSS automata
                      • Path traversal & shell execution filters
                                       │
                                       ▼ Passed
                  ┌─────────────────────────────────────────┐
                  │             Upstream Origin             │
                  └─────────────────────────────────────────┘
```

---

## Quickstart

Getting up and running takes less than two minutes.

### 1. Build the Executable

```sh
# Clone the repository
git clone https://github.com/insanai/sibuna.git
cd sibuna

# Compile optimized release binary
zig build -Doptimize=ReleaseFast
```

The resulting standalone binary is located at `./zig-out/bin/sibuna`.

### 2. Protect Your Application

Point Sibuna to your existing web service (for example, a local server on port 3000):

```sh
./zig-out/bin/sibuna --port 8080 --upstream-port 3000 --secret-file /run/sibuna.seed
```

Open `http://localhost:8080` in your browser. Your application is now protected.

*Note on secrets:* The seed file contains 32 raw bytes (or 64 hex characters) used to sign session tokens. You can also supply the seed via the `SIBUNA_SECRET` environment variable. If omitted, Sibuna generates a secure random seed at startup and prints it to the console.

---

## How It Works

### The Revolving Door and the Wristband

Most web security today relies on **interrogation**: a security guard stops you at the doorway, holds up blurry photos, and demands that you identify every traffic light before you are allowed in. It treats every human customer like a suspected intruder, frustrates real people, and tracks their identity across the internet.

Sibuna replaces the interrogation room with a simple physical principle: **a revolving door and a wristband**.

```
  [ Real Human Visitor ]                               [ Automated Botnet / Scraper ]
            │                                                        │
            │ Walks in normally                                      │ Tries to force 50,000 requests/sec
            ▼                                                        ▼
  ┌──────────────────┐                                     ┌──────────────────┐
  │  Revolving Door  │ ◄─── Effortless push (100ms)        │  Revolving Door  │ ◄─── Impossible resistance
  │ (Proof of Work)  │      Handled silently in background │ (Proof of Work)  │      Attacker's CPU burns out
  └────────┬─────────┘                                     └────────┬─────────┘
           │                                                        │
           ▼ Receives Wristband                                     ▼ Blocked at the entrance
  ┌──────────────────┐                                     ┌──────────────────┐
  │ Keyed Wristband  │ ◄─── Checked in 28 nanoseconds      │  Origin Server   │ ◄─── Untouched & Relaxed
  │ (Session Token)  │      Free to browse any page        │                  │      Zero database strain
  └──────────────────┘                                     └──────────────────┘
```

#### 1. The Gentle Push (The Door)
When a browser first visits your website, Sibuna asks it to turn a smoothly balanced revolving door—solving a small mathematical puzzle in the background via WebAssembly in a fraction of a second.
- The human visitor **never clicks a puzzle, never solves a riddle, and sees no prompt**.
- The page simply loads.

#### 2. The Cryptographic Wristband (The Token)
Once through the door, Sibuna stamps the browser with a cryptographic **wristband** (a 16-byte keyed BLAKE3 session token).
- As the visitor browses from page to page, clicks articles, and loads images, Sibuna glances at the wristband in **28 nanoseconds**.
- No repeated challenges, no database lookups, no friction.

#### 3. The Scraper's Impasse (Thermodynamic Asymmetry)
For a human browsing a dozen pages, turning a revolving door once is completely imperceptible.
- But for an automated AI crawler or scraper attempting to harvest 100,000 pages per minute, turning that door 100,000 times requires the energy of an industrial turbine.
- The scraper’s CPU overheats and grinds to a halt under the computational debt. Meanwhile, your origin server expends virtually zero energy verifying the passes.

The burden is placed entirely on the abuser, while real people walk straight through.

---

## Deployment Recipes

### Recipe 1: Direct Reverse Proxy

The simplest topology. Sibuna receives public traffic on port 8080, validates requests, and forwards admitted traffic to your application on port 3000:

```sh
./zig-out/bin/sibuna --port 8080 --upstream-host 127.0.0.1 --upstream-port 3000
```

### Recipe 2: Forward-Authentication with Caddy

If you use Caddy for automatic TLS certificates, run Sibuna alongside Caddy as an authorization gate:

```caddy
# Caddyfile
example.com {
    # Send verification subrequests to Sibuna
    forward_auth 127.0.0.1:8080 {
        uri /__sibuna/verify
        copy_headers X-Sibuna-Session X-Sibuna-Action
    }

    # Route challenge assets directly to Sibuna
    handle /__sibuna/* {
        reverse_proxy 127.0.0.1:8080
    }

    # Proxy admitted traffic to your application
    handle {
        reverse_proxy 127.0.0.1:3000
    }
}
```

Run Sibuna on private loopback:

```sh
./zig-out/bin/sibuna --mode forward_auth --host 127.0.0.1 --port 8080
```

### Recipe 3: Forward-Authentication with Nginx

```nginx
# nginx.conf
server {
    listen 443 ssl;
    server_name example.com;

    location / {
        auth_request /__sibuna_auth;
        auth_request_set $sibuna_token $upstream_http_x_sibuna_session;
        proxy_set_header X-Sibuna-Session $sibuna_token;
        proxy_pass http://127.0.0.1:3000;
    }

    location = /__sibuna_auth {
        internal;
        proxy_pass http://127.0.0.1:8080/__sibuna/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Forwarded-Method $request_method;
    }

    location /__sibuna/ {
        proxy_pass http://127.0.0.1:8080;
    }
}
```

Validate your ingress integration with the included automated test harness:

```sh
python3 tools/ingress_e2e.py zig-out/bin/sibuna --caddy /path/to/caddy --nginx /path/to/nginx
```

---

## Configuration Cheatsheet

### Command-Line Options

| Flag | Default | Description |
|---|---|---|
| `--mode <mode>` | `reverse_proxy` | `reverse_proxy` to forward to upstream, or `forward_auth` for ingress subrequests |
| `--port <port>` | `8080` | TCP port to listen on for incoming traffic |
| `--upstream-host <host>` | `127.0.0.1` | Upstream application hostname or IP address |
| `--upstream-port <port>` | `3000` | Upstream application TCP port |
| `--algorithm <algo>` | `posw` | Proof-of-work algorithm: `posw` (sequential work) or `hashcash` |
| `--difficulty <bits>` | `16` | Difficulty bits (PoSW depth is calibrated to `bits - 3`) |
| `--token-scheme <scheme>` | `mac` | Session token format: `mac` (16-byte BLAKE3) or `ed25519` |
| `--gate` / `--shield` | `shield` | Operational surface: Gate for pure admission; Shield adds WAF inspection |
| `--rate-limit <n>` | `100` | Maximum burst requests allowed by GCRA rate limiter |
| `--rate-window <sec>` | `10` | Rate limiter refill window duration in seconds |
| `--policy-file <path>` | none | Path to declarative JSON security policy file |
| `--data-dir <path>` | none | Enables embedded Zaxonlite storage for persistence and clustering |
| `--console <host:port>` | none | Enables the web operator console on the specified address |
| `--workers <n>` | CPU count | Number of acceptor threads (each connection runs on its own bounded thread) |
| `--max-connections <n>` | `1024` | Maximum concurrent connections before returning `503 Service Unavailable` |

### Declarative Policy Rules (`policy.json`)

```json
{
  "default_action": "CHALLENGE",
  "waf": true,
  "thresholds": { "challenge_at": 10, "deny_at": 40, "bits_step": 5 },
  "ip_rules": {
    "10.0.0.0/8": "ALLOW",
    "192.168.1.0/24": "ALLOW",
    "2001:db8::/32": "DENY"
  },
  "rules": [
    {
      "name": "allow-internal-traffic",
      "remote_addresses": ["10.0.0.0/8", "fd00::/8"],
      "action": "ALLOW"
    },
    {
      "name": "protect-checkout-endpoint",
      "path": "/api/checkout/*",
      "action": "CHALLENGE",
      "challenge": { "difficulty": 20, "algorithm": "posw" }
    },
    {
      "name": "block-forged-cloudflare-workers",
      "headers": { "CF-Worker": ".*" },
      "action": "DENY"
    },
    {
      "name": "score-headless-browsers",
      "user_agent": "Headless",
      "action": "WEIGH",
      "weight": 30
    }
  ]
}
```

---

## AI Bot & Crawler Governance (SID 0008)

Modern web services face unprecedented scraping from AI training crawlers and automated LLM agents. Sibuna provides deep visibility and governance:

1. **Sub-Microsecond Subnet Matching:** Evaluates client IP addresses against verified subnet CIDRs for OpenAI, Anthropic, Google Gemini, Perplexity, Meta, Apple, and ByteDance in memory ($< 45\,\text{ns}$).
2. **Four-Tier Confidence Hierarchy:**
   - **`Verified`:** User-Agent matches provider signature *and* client IP resides within published subnets.
   - **`Declared`:** Claims a crawler User-Agent from an unverified public IP.
   - **`Suspected`:** Browser-like User-Agent exhibiting crawler heuristics (e.g. missing asset cascades).
   - **`Human`:** Verified browser session that completed background proof-of-work.
3. **Actionable Governance:** Allow AI search fetchers while rate-limiting training scrapers or blocking unverified impersonators.

---

## Operator Console & Dashboard

```sh
# 1. Bootstrap an administrator account while the daemon is stopped
./zig-out/bin/sibuna init-admin admin --data-dir ./data

# 2. Start Sibuna with storage and console listener enabled
./zig-out/bin/sibuna --data-dir ./data --console 127.0.0.1:19446
```

Open `http://127.0.0.1:19446/console/` to access:
- **Traffic Ratio Overview:** Glanceable visual breakdown of Real Human Traffic vs. AI Crawlers vs. Search Bots from 100% exact monotonic counters.
- **24-Hour Comparative Analytics:** Time-series area charts showing human diurnal traffic curves beside crawler burst spikes.
- **Live Country Activity Globe:** 3D interactive vector globe visualizing traffic flows and geographic attack origins using local GeoIP data.
- **Granular Provider Management:** View scraping volume per AI provider and toggle operational actions (Allow, Rate-Limit, Challenge, Deny).
- **Incident Investigation:** Full-text search (FTS5) over blocked payloads with campaign clustering based on feature-hashed trigram embeddings.

---

## Philosophy & Invariants

Sibuna's engineering design follows four foundational principles:

### 1. Simplicity is Prerequisite for Reliability (Edsger W. Dijkstra)
Adding moving parts increases the surface area for failure. Sibuna avoids external databases, cache servers, runtime interpreters, and container fleets. It compiles to a single, self-contained binary that does one job dependably.

### 2. Thermodynamic Asymmetry (Richard Feynman)
A defender must never spend more energy inspecting an attack than an adversary spends generating it. Like the physical inertia of a revolving door, verification requires a tiny, constant number of operations ($< 25\,\mu\text{s}$), while an unverified client must prove non-parallelizable work ($W \ge 10^3 \cdot c_s$) before entering.

### 3. Explicit Invariants and Bounded State (Leslie Lamport)
Every hot-path resource is strictly bounded:
- Request classification runs in fixed stack buffers with zero heap allocation.
- Challenge state on the server is zero until a valid solution is presented.
- Rate limits track client state in fixed 16-byte slots.
- Memory consumption is an invariant of configuration, never of traffic volume.

### 4. Literate and Honest Engineering (Donald Knuth)
A system must be honest about what it is, and what it is not.
- **What Sibuna Is:** A fast, deterministic admission gate, bot governance engine, and heuristic semantic WAF.
- **What Sibuna Is Not:** Sibuna does not terminate TLS or negotiate HTTP/2 directly (delegate this to Caddy or Nginx). It is not an antivirus scanner for uploaded files. It is not an AST language parser for SQL (write parameterized queries in your application).

---

## Comparison with Alternative Systems

Facts gathered from public documentation, release artifacts, and reproducible benchmark suites (see the Sibuna Book Part II for full citations):

| Dimension | Sibuna | Anubis (v1.27) | SafeLine CE (v9.x) | Cloudflare WAF |
|---|---|---|---|---|
| **Architecture** | Single static binary | Single Go binary | Sprawling multi-container (7 containers) | Proprietary hosted cloud |
| **Admission Puzzle** | Proof of Sequential Work & Hashcash | SHA-256 Hashcash | Proprietary challenge & image CAPTCHAs | Managed challenge & Turnstile |
| **Server Challenge State** | Zero state until solved | In-memory, bbolt, Valkey, or S3 | Managed by container stack | Managed cloud state |
| **Session Token** | Keyed BLAKE3 MAC (16 bytes) | Ed25519 JWT | Cookie-based session | `cf_clearance` cookie |
| **WAF Inspection** | Linear-time automata & tokenizers | None | Semantic inspection engine | Managed rule sets |
| **Rate Limiting** | Atomic GCRA per client | None | Per IP, path, session | Rules limited by plan tier |
| **Bot Identification** | Sub-microsecond CIDR trie & signatures | DNSBL; ASN lookup | IP groups; threat intelligence | Cloud bot management score |
| **Multi-Node Consensus** | Embedded Multi-Paxos (Zaxonlite) | Shared key + Valkey | One stack per host | Global anycast network |
| **Idle Memory Footprint** | $\sim 10\,\text{MB}$ RSS | $\sim 21\,\text{MB}$ RSS | $\ge 1\,\text{GB}$ RAM (recommended) | None on premises |
| **Open Source** | Yes | Yes | Open core / community edition | No (closed source) |

---

## Documentation

For deep technical study, the repository includes two comprehensive publications:

1. **The Sibuna Book (`docs/book/`):**
   A complete 13-chapter textbook covering the system from mathematical foundations through zero-allocation memory design, benchmarks, and production operations:
   ```sh
   zig build book                # Generates docs/build/sibuna-book.pdf
   ```
2. **Shibuna Discussions (SID) (`docs/sid/`):**
   RFC-style architectural design records:
   - **SID 0001:** The Shibuna Discussion Process and Engineering Standards
   - **SID 0002:** Foundation Architecture, Delivery Plan, and Performance Contract
   - **SID 0003:** Declarative Rule Policy Engine
   - **SID 0004:** Semantic Attack Inspection and GCRA Rate Limiting (Shield)
   - **SID 0005:** Distributed Storage Architecture: Zaxonlite Integration (Edge)
   - **SID 0006:** Mathematical Foundations: Sequential Work, Keyed Authentication, and Automata
   - **SID 0007:** The Sibuna Console: A Real-Time Management Interface for Nodes and Clusters
   - **SID 0008:** AI Bot Traffic Identification, Multi-Tier Verification, and Operator Console Analytics
   - **SID 0009:** Chunked Request Bodies and Transfer-Coding Validation

   ```sh
   zig build sid                 # Compiles all SID specification papers to PDF
   ```

---

## License

Sibuna is open-source software released under the Apache License, Version 2.0.
