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

Instead of subjecting human visitors to frustrating image CAPTCHAs or privacy-invasive tracking scripts, Sibuna asks client browsers to solve a background computational puzzle whose cost depends on the configured difficulty and client hardware. Instead of requiring sprawling container clusters, external databases, or heavy interpreters, Sibuna runs as a **single, self-contained executable** with predictable, bounded memory.

---

## Features

- **[x] Self-Contained Deployment:** The standard binary includes storage and browser assets. No external Redis, PostgreSQL, Node, or Docker is required; clustering is a separate build with OpenSSL 3.
- **[x] Browser Proof of Work:** WebAssembly solves a configurable background puzzle. No image CAPTCHA is required; successful clients receive a signed admission session.
- **[x] Bounded Request Processing:** Fixed-capacity request buffers, connection quotas and explicit overload responses. Parsing, classification and proof verification use allocation-free primitive APIs; deployment memory still depends on enabled features and concurrency.
- **[x] AI Crawler & Bot Governance:** CIDR ranges and User-Agent signatures support provider-specific policy for OpenAI, Anthropic, Google Gemini, Perplexity, Meta, Apple, and ByteDance. Operator-managed data and rules determine the decision.
- **[x] Semantic Attack Shield:** Single-pass, linear-time Aho–Corasick automata and structural tokenizers inspect SQL injection, XSS, and path traversal without regular expression backtracking (ReDoS).
- **[x] Work Asymmetry:** Clients perform configurable Hashcash or sequential work before admission; the server verifies submitted proofs with native code.
- **[x] Local Rate Limiting:** Sharded GCRA (Generic Cell Rate Algorithm) enforces per-client burst and sustained limits, with optional terminal-rule limits. Quotas remain node-local.
- **[x] Real-Time Management Console:** Opt-in dashboard with an animated country traffic globe, comparative analytics, incident investigation with full-text search (FTS5), and policy editing. GeoIP requires a separately imported dataset.
- **[x] Embedded Multi-Node Clustering:** A cluster-enabled source build uses Zaxonlite Multi-Paxos to replicate policy and reputation. Management telemetry travels separately; missing peers are shown as incomplete coverage.

---

## Architecture

Following the modular design of raylib, Sibuna is divided into small, single-purpose subsystems:

```
┌────────────────────────────────────────────────────────────────────────┐
│                          SIBUNA SUBSYSTEMS                             │
├──────────────┬─────────────────────────────────────────────────────────┤
│ socket       │ Native socket operations and interruption ownership    │
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

Download a package from [Releases](https://github.com/insanai/sibuna/releases), or build from source.
The v0.2.0 packages include the engine, embedded storage, browser solver and management console.
Clustering requires a separate `-Dcluster=true` source build with OpenSSL 3.

| Platform | Package | Requirements |
| --- | --- | --- |
| Linux x86-64 | `sibuna-linux-amd64.tar.gz` | Linux 5.10 or later; statically linked musl |
| Linux ARM64 | `sibuna-linux-arm64.tar.gz` | Linux 5.10 or later; statically linked musl |
| macOS Apple Silicon | `sibuna-macos-arm64.tar.gz` | macOS 15 or later |
| macOS Intel | `sibuna-macos-amd64.tar.gz` | macOS 15 or later |
| Windows x86-64 | `sibuna-windows-amd64.zip` | Windows 10 / Server 2019 or later; native `sibuna.exe` |

macOS builds are unsigned. Packages include license texts, corresponding-source links and a
`sibuna.build.json` manifest. Verify the archive against the release's `SHA256SUMS` before use.
On Windows, extract the ZIP and run `.\sibuna.exe --help` from PowerShell. Use Ctrl+C for
ordered shutdown and restrict seed, credential and data files with Windows ACLs.

For Linux x86-64:

```sh
curl -fLO https://github.com/insanai/sibuna/releases/download/v0.2.0/sibuna-linux-amd64.tar.gz
curl -fLO https://github.com/insanai/sibuna/releases/download/v0.2.0/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf sibuna-linux-amd64.tar.gz
(umask 077; openssl rand -hex 32 > sibuna.seed)
./sibuna --version
./sibuna --host 127.0.0.1 --port 8080 --upstream-port 3000 --secret-file ./sibuna.seed
```

Terminate public HTTPS at your ingress and keep Sibuna's listener private; see
[deployment limits](#deployment-limits) and the [operations guide](https://insanai.github.io/sibuna/book/operations.html).

### 1. Build the Executable

Use **Zig 0.17.0**, the checksum-pinned release toolchain. The storage libraries include
reviewable compatibility sources in `vendor/`; original release digests are recorded there.

```sh
# Clone the repository
git clone https://github.com/insanai/sibuna.git
cd sibuna

# Compile optimized release binary
python3 tools/prepare_build.py
zig build -Doptimize=fast
```

The resulting standalone binary is located at `./zig-out/bin/sibuna`.

### 2. Protect Your Application

Point Sibuna to your existing web service (for example, a local server on port 3000):

```sh
./zig-out/bin/sibuna --port 8080 --upstream-port 3000 --secret-file /run/sibuna.seed
```

Open `http://localhost:8080` in your browser. Your application is now protected.

*Note on secrets:* The seed file contains 32 raw bytes (or 64 hex characters) used to sign session tokens. You can also supply the seed via the `SIBUNA_SECRET` environment variable. If omitted, Sibuna generates a secure random seed at startup; sessions then expire when the process restarts.

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
Admission asks an unverified client to perform configurable work before accessing the origin, while Sibuna verifies the submitted proof natively. The cost depends on the algorithm, settings and client hardware. The benchmark records measure server operations under their stated conditions; they do not establish a universal energy or latency guarantee.

### 3. Explicit Invariants and Bounded State (Leslie Lamport)
Request-path resources have explicit bounds:

- Request classification uses caller-owned buffers and allocation-free primitive APIs.
- Sealed challenges avoid allocating a record for each outstanding puzzle; local rate and replay tables still hold client state.
- Rate limits use sharded, fixed-capacity tables.
- Deployment memory depends on enabled features and active connections within configured quotas. Exhausted capacity refuses new work.

### 4. Literate and Honest Engineering (Donald Knuth)
A system must be honest about what it is, and what it is not.
- **What Sibuna Is:** A fast, deterministic admission gate, bot governance engine, and heuristic semantic WAF.
- **What Sibuna Is Not:** Sibuna does not terminate TLS or negotiate HTTP/2 directly (delegate this to Caddy or Nginx). It is not an antivirus scanner for uploaded files. It is not an AST language parser for SQL (write parameterized queries in your application).

---

## Comparison with Alternative Systems

Sibuna combines proof-of-work admission, bounded application inspection and an opt-in
management console in one executable. Other projects cover different parts of that scope:

- [Anubis](https://github.com/TecharoHQ/anubis) uses client challenges to protect upstream resources from scraper bots.
- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity) and [Coraza](https://github.com/corazawaf/coraza) provide WAF engines for integration with web servers and applications.
- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset) provides attack-detection rules for compatible WAF engines. Sibuna's heuristic detectors do not implement that rule language.

The [book's empirical evaluation](https://insanai.github.io/sibuna/book/)
compares pinned, runnable products under documented workloads. Each result identifies its
revision, configuration and host; memory and throughput figures describe those measurements.

---

## Documentation

[Website](https://insanai.github.io/sibuna/) ·
[Book](https://insanai.github.io/sibuna/book/) ·
[Operations guide](https://insanai.github.io/sibuna/book/operations.html) ·
[Design discussions](https://insanai.github.io/sibuna/sid/)

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

The engine is licensed under **LGPL 3.0 only** and the console under **AGPL 3.0 only**,
including its WebAssembly interface. The default executable includes the console and is
distributed as a combined work under AGPL 3.0. An engine-only build uses `-Dconsole=false`.
See [LICENSE](LICENSE) for directory boundaries, [LICENSES](LICENSES) for the complete terms,
and [NOTICE](NOTICE) for dependencies. Corresponding source and build scripts are available
under each release tag; the console also provides a source-code link.

## Related open-source projects

- [Anubis](https://github.com/TecharoHQ/anubis): a proof-of-work admission proxy for reducing crawler traffic.
- [OWASP ModSecurity](https://github.com/owasp-modsecurity/ModSecurity): a web application firewall engine integrated through web-server connectors.
- [OWASP Coraza](https://github.com/corazawaf/coraza): a Go WAF library supporting ModSecurity rules and the OWASP Core Rule Set.
- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset): maintained application-attack detection rules for compatible WAF engines.

These projects overlap with different parts of Sibuna. Sibuna's bounded heuristic detectors
do not implement ModSecurity's rule language or provide drop-in Core Rule Set compatibility.
