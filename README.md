<p align="center">
  <h1 align="center">sibuna</h1>
  <p align="center">
    <strong>A simple and lightweight web application firewall to protect websites and APIs without CAPTCHAs.</strong>
  </p>
  <p align="center">
    <a href="#features">Features</a> •
    <a href="#console">Console</a> •
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

## Console

The opt-in console runs in the same executable. Add `--console` to enable it; the
[operations guide](https://insanai.github.io/sibuna/book/operations.html) covers bootstrap,
HTTPS access and GeoIP imports.

![Sibuna Console globe showing incoming sampled traffic, the request timeline and coverage](docs/readme/images/console-globe.jpg)

The globe shows sampled traffic flowing from countries to your Sibuna server. Country markers
show approximate locations, not visitors' exact positions. The arrows show activity over the
last minute. The timeline counts request outcomes, and the coverage panel explains the sampling.

<details>
<summary>Traffic overview, policy editor and incident investigation</summary>

**Traffic overview** — request outcomes, observation windows and live updates.

![Sibuna Console traffic overview with admitted, challenged and denied request counters](docs/readme/images/console-dashboard.jpg)

**Policy editor** — a sample checkout challenge rule, with explicit matchers and settings.

![Sibuna Console policy editor with a draft challenge rule for checkout](docs/readme/images/console-policy-editor.jpg)

**Incident investigation** — recorded evidence and bounded, redacted request heads.

![Sibuna Console incident evidence with redacted headers and response state](docs/readme/images/console-incident.jpg)

</details>

These are real Chrome captures of Sibuna v0.2.0 on a local review node. Traffic and GeoIP
mappings are illustrative test data; the displayed counts are not performance measurements.

---

## Architecture

Following the modular design of raylib, Sibuna is divided into small, single-purpose subsystems:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/subsystems-dark.svg">
  <img src="docs/readme/images/subsystems.svg" alt="Inside Sibuna: the jobs of its eight modules">
</picture>

`socket` opens and closes connections safely, and `net` reads HTTP requests and forwards
allowed traffic. `crypto` computes proofs and signs or verifies sessions; `challenge` creates
puzzles and adjusts their difficulty. `policy` applies access rules and looks for attacks,
while `store` tracks local request limits and used proofs. Optional `edge` storage saves
security data and shares it between nodes. `console` shows traffic and helps operators
manage protection.

### Gate and Shield

Choose Gate or Shield when you start Sibuna. Gate (`--gate`) checks access rules, proof-of-work
sessions and local request limits. Shield (`--shield`, the default) also looks for web attacks.
Your inspection settings decide whether an attack is blocked or recorded while checks continue.

Read the flow from top to bottom: rectangles show actions, diamonds show decisions, and ovals
mark the start or an outcome. Every branch has a label; color is an additional cue.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/protection-surfaces-dark.svg">
  <img src="docs/readme/images/protection-surfaces.svg" alt="How Sibuna protects a request: Gate or Shield, followed by allow, challenge or block">
</picture>

When a visitor requests a page, Shield checks for attacks; Gate skips attack inspection.
Both check access rules, sessions and request limits. A request is then forwarded to your app,
given a puzzle or stopped. A valid session does not bypass Shield's attack checks or request limits.

In reverse-proxy mode Sibuna forwards allowed requests itself. In forward-auth mode it tells
your existing proxy whether to forward them. Either deployment can use Gate or Shield.

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

Think of admission as a revolving door followed by a wristband: the client does work once,
then presents a signed session on subsequent requests. Policy determines when a challenge
is required; the proof does not establish that a client is human.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/admission-session-dark.svg">
  <img src="docs/readme/images/admission-session.svg" alt="Solve a puzzle, save a signed session cookie, and check rules on later requests">
</picture>

#### 1. Browser Work (The Door)

When a request requires a challenge, the browser solves a computational puzzle using
WebAssembly. No image CAPTCHA is needed. Work depends on configured difficulty and client
hardware, so the challenge can take time before the protected page loads. Sibuna verifies the
solution and rejects invalid proofs.

#### 2. The Signed Session (The Wristband)

A successful proof earns a session authenticated with keyed BLAKE3. The browser can reuse
it until it expires, is revoked or no longer satisfies the required work. Sibuna verifies
the session in native code; applicable inspection, policy and local rate limits still run.

#### 3. Automation and Limits

Automated clients can also solve challenges and reuse valid sessions. Proof of work adds
an admission cost; bot rules, inspection and local quotas control subsequent access.
Choose difficulty and limits for your application and visitors, rather than assuming every
request requires a new proof or that a challenge guarantees protection from overload.

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
- [BunkerWeb](https://github.com/bunkerity/bunkerweb) combines nginx, ModSecurity and OWASP CRS with bot challenges and an operator interface.
- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity) and [Coraza](https://github.com/corazawaf/coraza) provide WAF engines for integration with web servers and applications.
- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset) provides attack-detection rules for compatible WAF engines. Sibuna's heuristic detectors do not implement that rule language.

The [book's empirical evaluation](https://insanai.github.io/sibuna/book/)
compares pinned, runnable products under documented workloads. Each result identifies its
revision, configuration and host; memory and throughput figures describe those measurements.

### Measured comparison

On 4 October 2026 we compared Sibuna v0.2.0, Anubis 1.27.0 and BunkerWeb 1.6.15 with the
products on one Linux host and the request generator on another. Each product had four
allowed logical CPUs, serving the same Caddy origin over HTTP/1.1 with 64 connections.
This table uses unconditional admission, with challenges and management interfaces inactive.
The book also covers real sessions, challenge responses and native admission operations.

The table shows median request rates and the median of each run's p99 latency over five
repeated measurements. The book includes the observed ranges, CPU cost and memory use.

| Profile | Benign GET (req/s) | p99 (ms) | 8 KiB JSON POST (req/s) | p99 (ms) |
| --- | ---: | ---: | ---: | ---: |
| Origin directly | 70,759 | 4.67 | 13,719 | 9.01 |
| Sibuna Gate | 71,270 | 4.12 | 13,719 | 9.16 |
| Anubis | 28,277 | 7.50 | 13,718 | 9.20 |
| BunkerWeb, CRS off | 13,617 | 8.27 | 12,300 | 8.94 |
| Sibuna Shield | 70,909 | 4.06 | 13,719 | 9.08 |
| BunkerWeb, CRS on | 2,730 | 32.73 | 797 | 98.42 |

The JSON POST rates for Sibuna, Anubis and the direct origin are close to the same fixture
limit; use the book's ranges and configuration when interpreting the results.

BunkerWeb's CRS profile provides broader rules, structured body parsing and response
inspection; Sibuna uses bounded heuristics. These tests measure request cost, not equivalent
protection or bot-detection accuracy. Both hosts are shared containers with uncontrolled
CPU frequency and host activity. The book also reports blocked requests with BunkerWeb's
stock error page and a small custom page, so rendering cost is visible.

See the [benchmark records and replay commands](benchmarks/results/README.md#three-product-comparisons)
for the pinned artifacts, exact configuration and every sample. This comparison does not
change the separate console-impact gate's recorded verdict.

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

The engine is licensed under **LGPL 3.0** and the console under **AGPL 3.0**,
including its WebAssembly interface. The default executable includes the console and is
distributed as a combined work under AGPL 3.0. Build the engine without the console using
`-Dconsole=false`.
See [LICENSE](LICENSE) for directory boundaries, [LICENSES](LICENSES) for the complete terms,
and [NOTICE](NOTICE) for dependencies. Corresponding source and build scripts are available
under each release tag; the console also provides a source-code link.

Companies seeking a version under terms other than LGPL or AGPL can contact the authors,
Vikrant Rathore and Ronak Rathore, about alternative licensing. Libraries and other third-party
materials remain subject to their respective licenses.

## Other software to consider

- [Anubis](https://github.com/TecharoHQ/anubis): a proof-of-work admission proxy for reducing crawler traffic.
- [BunkerWeb](https://github.com/bunkerity/bunkerweb): an nginx-based security platform with ModSecurity, OWASP CRS, bot challenges and an operator interface.
- [OWASP ModSecurity](https://github.com/owasp-modsecurity/ModSecurity): a web application firewall engine integrated through web-server connectors.
- [OWASP Coraza](https://github.com/corazawaf/coraza): a Go WAF library supporting ModSecurity rules and the OWASP Core Rule Set.
- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset): maintained application-attack detection rules for compatible WAF engines.

These projects overlap with different parts of Sibuna. Sibuna's bounded heuristic detectors
do not implement ModSecurity's rule language or provide drop-in Core Rule Set compatibility.
