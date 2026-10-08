<h1 align="center">sibuna</h1>
<p align="center">Web protection with browser proof of work and an optional console.</p>
<p align="center">
  <a href="#features">Features</a> ·
  <a href="#quickstart">Quickstart</a> ·
  <a href="#console">Console</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#documentation">Documentation</a>
</p>

<!-- language-navigation -->
<p align="center">
  <a href="README.md">English</a> · <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ko.md">한국어</a> · <a href="README.ja.md">日本語</a> ·
  <a href="README.es.md">Español</a> · <a href="README.de.md">Deutsch</a> ·
  <a href="README.hi.md">हिन्दी</a> · <a href="README.ar.md">العربية</a>
</p>

**Sibuna helps protect websites and APIs from unwanted bot traffic.** It can forward requests
to your app or work alongside an existing proxy, such as Caddy, nginx or Traefik.

Sending requests is often cheap. Processing them can cost your app more work. Sibuna asks
clients to solve a puzzle before granting access. The puzzle is designed to make proof
creation cost more computation than verification. Automated clients share more of the cost
of accessing a site.

Computing also uses energy, but the amount depends on hardware and settings. Proof of work
adds an admission cost. It does not prove that a visitor is human or stop every attack.
A signed session lets admitted clients return without solving a new puzzle on every request.
Use access rules and local rate limits to control what those clients can request afterwards.

## Features

- **One executable:** engine, embedded storage, browser solver and console assets.
- **Native packages:** Linux, macOS and Windows. The browser solver uses WebAssembly.
- **Browser challenges:** configurable Hashcash or sequential work, followed by a signed session.
- **Access policies:** allow, challenge or deny requests by address, path, headers and User-Agent.
- **Application inspection:** built-in checks for SQL injection, XSS and path traversal.
- **Optional OWASP CRS:** signed rule updates, Audit and Enforce modes, private tests and rollback.
- **Local rate limits:** control bursts and sustained traffic, with optional limits per rule.
- **Operator console:** traffic, sampled country activity, recorded incidents and policy editing.
- **Cluster support:** a separate source build replicates policy and reputation through Zaxonlite.

## Quickstart

[Download a release](https://github.com/insanai/sibuna/releases/tag/v0.3.3) for your platform.
The default package includes storage and console support. The console starts with `--console`.

| Platform | Package | Requirements |
| --- | --- | --- |
| Linux x86-64 | `sibuna-linux-amd64.tar.gz` | Linux 5.10 or later; statically linked musl |
| Linux ARM64 | `sibuna-linux-arm64.tar.gz` | Linux 5.10 or later; statically linked musl |
| macOS Apple Silicon | `sibuna-macos-arm64.tar.gz` | macOS 15 or later |
| macOS Intel | `sibuna-macos-amd64.tar.gz` | macOS 15 or later |
| Windows x86-64 | `sibuna-windows-amd64.zip` | Windows 10 / Server 2019 or later; native `sibuna.exe` |

macOS builds are unsigned. Each package includes licenses, source links and a build manifest.
Verify the archive against `SHA256SUMS` before using it.

For Linux x86-64, with your app listening on port 3000:

```sh
curl -fLO https://github.com/insanai/sibuna/releases/download/v0.3.3/sibuna-linux-amd64.tar.gz
curl -fLO https://github.com/insanai/sibuna/releases/download/v0.3.3/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
tar -xzf sibuna-linux-amd64.tar.gz
(umask 077; openssl rand -hex 32 > sibuna.seed)
./sibuna --host 127.0.0.1 --port 8080 --upstream-port 3000 --secret-file ./sibuna.seed
```

Open `http://127.0.0.1:8080` to try it locally. For a public site, terminate HTTPS at a trusted
ingress and keep Sibuna's listener private. Follow the
[deployment guide](https://insanai.github.io/sibuna/book/operations.html) for Caddy or nginx.

The default mode is `reverse_proxy`. Use `--mode forward_auth` when your ingress forwards
requests and asks Sibuna for an access decision. The guide includes both configurations.
Shield's built-in inspection is enabled by default. Use `--gate` for admission without that
inspector. Choose access rules with `--policy-file <file>`, including rules for API clients
and health checks that cannot run a browser challenge.

On Windows, extract the ZIP and run `.\sibuna.exe --help` in PowerShell.
Use Ctrl+C to stop it. Restrict access to seed, credential and data files with Windows ACLs.

### Build from source

Use **Zig 0.17.0**. The pinned toolchain checksums and dependency sources are in the repository.

```sh
git clone git@github.com:insanai/sibuna.git
cd sibuna
python3 tools/prepare_build.py
zig build -Doptimize=safe -j2
```

The executable is `zig-out/bin/sibuna`. Cluster builds use `-Dcluster=true` and need OpenSSL 3.
See [CONTRIBUTING.md](CONTRIBUTING.md) for build checks.

### Enable OWASP CRS

CRS is disabled by default. Download and verify a supported signed release, then start in
Audit to review findings without applying CRS denials:

```sh
./sibuna crs check --version 4.30.0 --output ./crs-candidate
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --crs-mode audit --crs-dir ./crs-candidate
```

Use a new candidate directory. Checking a candidate does not change a running daemon.
The CLI and console can prepare updates, review changes and select a verified candidate.
Start Enforce after testing your application's normal traffic and reviewing exclusions.
See the [CRS guide](https://insanai.github.io/sibuna/book/operations.html)
for updates, rollback, body limits and incomplete inspection.
Forward-auth requires `--crs-profile headers`; it does not see full application bodies.

## Console

The console runs in the same executable. Bootstrap an administrator while the daemon is stopped:

```sh
./sibuna init-admin admin --data-dir ./data
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --data-dir ./data --console 127.0.0.1:19446
```

Open `http://127.0.0.1:19446/console/` and change the temporary password.
The [operations guide](https://insanai.github.io/sibuna/book/operations.html) explains HTTPS
access, GeoIP imports and CRS updates.
Append the CRS flags from the example above to enable inspection alongside the console.

![Sibuna Console globe, request timeline and coverage](docs/readme/images/console-globe.jpg)

The globe shows sampled country activity over the last minute. Markers give approximate
country positions. Arrows point toward the server's configured location. They do not show
individual live connections. GeoIP needs a separately imported dataset.
Set `--console-location <latitude,longitude>` to place the server on the globe.

<details>
<summary>Traffic overview, policy editor and incident investigation</summary>

**Traffic overview** — request outcomes, observation windows and live updates.

![Sibuna Console traffic overview with admitted, challenged and denied request counters](docs/readme/images/console-dashboard.jpg)

**Policy editor** — a sample checkout challenge rule, with explicit matchers and settings.

![Sibuna Console policy editor with a draft challenge rule for checkout](docs/readme/images/console-policy-editor.jpg)

**Incident investigation** — recorded evidence and bounded, redacted request heads.

![Sibuna Console incident evidence with redacted headers and response state](docs/readme/images/console-incident.jpg)

</details>

These are Chrome captures of v0.2.0 on a review node. Traffic and GeoIP mappings are test data.
The displayed counts are not benchmark results.

## How it works

A request can be admitted, challenged or denied. A visitor who solves a challenge receives
a signed session. Later requests still pass the applicable policy and rate checks.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/admission-session-dark.svg">
  <img src="docs/readme/images/admission-session.svg" alt="Solve a puzzle, receive a signed session and check rules on later requests">
</picture>

Gate checks access rules, sessions and local rate limits. Shield adds the built-in attack
inspector. Native CRS is configured separately. Start it in Audit to review findings before
enabling Enforce.

<details>
<summary>Gate, Shield and the modules inside Sibuna</summary>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/protection-surfaces-dark.svg">
  <img src="docs/readme/images/protection-surfaces.svg" alt="Gate and Shield request decisions: allow, challenge or block">
</picture>

The diagram shows the built-in Gate and Shield checks. Optional CRS adds its own inspection.
A valid session does not bypass applicable attack checks or request limits.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/subsystems-dark.svg">
  <img src="docs/readme/images/subsystems.svg" alt="The jobs of the modules inside Sibuna">
</picture>

The modules separate networking, proofs, policies, local state and management.
The [book](https://insanai.github.io/sibuna/book/) explains their responsibilities.

</details>

### Deployment limits

Sibuna uses HTTP/1.1 on its private listener. Your ingress handles public TLS and HTTP/2.
Forward-auth inspects the metadata supplied by the ingress. Full reverse-proxy CRS inspection
uses configured body and work limits. The built-in inspector covers the first 8 KiB.
Uploads stream when CRS is disabled. WebSocket messages are relayed without inspection.
Full CRS defaults to a 4 MiB request limit and a 1 MiB response limit. It buffers bodies for
inspection. Enforce refuses incomplete inspection; review limits and streaming exceptions
for your application before enabling it.

Rate limits are local to each node. Sibuna does not provide volumetric network mitigation.
The strict console performance target has not formally passed. Review the
[deployment limits and measurements](https://insanai.github.io/sibuna/book/operations.html)
before enabling the console beside a production app.

## Benchmarks

The book records the source revision, configuration and host for each run. These measurements
show request cost under one workload. They do not measure equivalent protection or bot accuracy.

### Three-product comparison

This run compared **Sibuna v0.2.0**, Anubis 1.27.0 and BunkerWeb 1.6.15 on 4 October 2026.
The server and request generator ran on separate physical hosts. Each product had four CPUs,
64 connections and the same Caddy origin. Challenges and management interfaces were inactive.
The table shows medians over five runs.

| Profile | Benign GET (req/s) | p99 (ms) | 8 KiB JSON POST (req/s) | p99 (ms) |
| --- | ---: | ---: | ---: | ---: |
| Origin directly | 70,759 | 4.67 | 13,719 | 9.01 |
| Sibuna Gate | 71,270 | 4.12 | 13,719 | 9.16 |
| Anubis | 28,277 | 7.50 | 13,718 | 9.20 |
| BunkerWeb, CRS off | 13,617 | 8.27 | 12,300 | 8.94 |
| Sibuna Shield | 70,909 | 4.06 | 13,719 | 9.08 |
| BunkerWeb, CRS on | 2,730 | 32.73 | 797 | 98.42 |

BunkerWeb's CRS profile inspects more than the v0.2.0 Shield profile in this table.
Sibuna v0.3.0 adds native CRS; this comparison predates that engine. Both hosts are shared
containers. CPU frequency and unrelated host activity were not controlled.

### Native CRS in v0.3.0

This separate run used eight dashboards, four product CPUs and 16 connections from another
host. The table shows median rates over five rounds. The built-in inspector was disabled.

| Workload | CRS disabled (req/s) | Audit, paranoia 1 (req/s) | Audit, paranoia 2 (req/s) |
| --- | ---: | ---: | ---: |
| Small GET | 47,311 | 10,787 | 7,423 |
| 8 KiB JSON POST | 13,726 | 1,151 | 799 |
| 16 KiB multipart upload | 6,704 | 4,248 | 2,887 |

At paranoia one, p99 latency was 2.34 ms, 23.43 ms and 6.34 ms for these workloads.
Peak process RSS was 133.8–140.5 MiB across the CRS profiles. No measured request hit the work
limit. The run used clean revision `d461e7f`. Its payloads and concurrency differ from the
three-product comparison, so the two tables do not form a matched comparison.

See the [benchmark records](benchmarks/results/README.md) for ranges, CPU, memory,
Enforce results and replay commands. These figures do not pass the separate console-impact gate.

## Documentation

- [Book](https://insanai.github.io/sibuna/book/): concepts, algorithms, examples and measurements.
- [Whitepaper](https://insanai.github.io/sibuna/whitepaper/): architecture, proofs and design details.
- [Operations guide](https://insanai.github.io/sibuna/book/operations.html): installation and deployment.
- [Reference](https://insanai.github.io/sibuna/book/reference.html): CLI and protocol details.
- [Design discussions](https://insanai.github.io/sibuna/sid/): decisions and engineering contracts.
- [Contributing](CONTRIBUTING.md): source builds and checks.

## Other software to consider

- [Anubis](https://github.com/TecharoHQ/anubis): browser challenges for reducing crawler traffic.
- [BunkerWeb](https://github.com/bunkerity/bunkerweb): nginx, ModSecurity, CRS and bot challenges.
- [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity): a WAF engine used through connectors.
- [Coraza](https://github.com/corazawaf/coraza): a Go WAF library supporting ModSecurity rules and CRS.
- [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset): attack-detection rules for WAF engines.

These projects cover different parts of web protection. Sibuna evaluates signed stock CRS
releases. Plugins, Lua and other ModSecurity rule sets are outside its scope.

## License

The engine is **LGPL 3.0**. The console, including its WebAssembly interface, is **AGPL 3.0**.
The default executable combines both and is distributed under AGPL 3.0.
Use `-Dconsole=false` to build the engine without the console.

[LICENSE](LICENSE) describes the scope. [LICENSES](LICENSES) contains the full terms.
[NOTICE](NOTICE) lists dependencies. Source and build scripts are available under each release tag.

Companies seeking other licensing terms can contact Vikrant Rathore and Ronak Rathore.
Third-party libraries and materials keep their respective licenses.
