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
to your app or work alongside an existing proxy, such as Caddy or nginx.

Sending requests is often cheap. Processing them can cost your app more work. Sibuna asks
clients to solve a puzzle before granting access. The puzzle is designed to make proof
creation cost more computation than verification. Automated clients share more of the cost
of accessing a site.

Computing also uses energy, but the amount depends on hardware and settings. Proof of work
adds an admission cost. It does not prove that a visitor is human or stop every attack.
A signed session lets admitted clients return without solving a new puzzle on every request.
Use access rules and local rate limits to control what those clients can request afterwards.

## Features

- **One executable:** engine, embedded SQLite storage, browser solver and console assets.
- **Native packages:** Linux, macOS, Windows, FreeBSD and OpenBSD. The browser solver uses WebAssembly.
- **Browser challenges:** proof of sequential work (default) or Hashcash, followed by a signed session.
- **Access policies:** allow, challenge, weigh or deny requests by address, path, headers and User-Agent.
- **Application inspection:** built-in checks for SQL injection, XSS, path traversal and command injection.
- **Local rate limits:** control bursts and sustained traffic, with optional limits per rule.
- **Operator console:** traffic, sampled country activity, recorded incidents and policy editing.
- **Cluster support:** a separate build shares policies and reputation through PostgreSQL.

## Quickstart

[Download a release](https://github.com/insanai/sibuna/releases/tag/v1.0.0-beta.1) for your
platform. The default package includes storage and console support. The console starts with
`--console`.

| Platform | Package | Requirements |
| --- | --- | --- |
| Linux x86-64 | `sibuna-linux-amd64.tar.gz` | Linux 5.10 or later; statically linked musl |
| Linux ARM64 | `sibuna-linux-arm64.tar.gz` | Linux 5.10 or later; statically linked musl |
| macOS Apple Silicon | `sibuna-macos-arm64.tar.gz` | macOS 15 or later |
| macOS Intel | `sibuna-macos-amd64.tar.gz` | macOS 15 or later |
| Windows x86-64 | `sibuna-windows-amd64.zip` | Windows 10 / Server 2019 or later; native `sibuna.exe` |
| FreeBSD x86-64 | `sibuna-1.0.0-beta.1-freebsd-15.1-amd64.pkg` | FreeBSD 15.1; CLI package |
| OpenBSD x86-64 | `sibuna-1.0.0-beta.1.tgz` | OpenBSD 7.9; CLI package |

This is a beta release. macOS builds are unsigned. Each package includes licenses, source
links and a build manifest. Verify the archive against `SHA256SUMS` before using it.

Debian/RPM packages cover Linux x86-64 and ARM64; Arch `sibuna-bin` covers x86-64.
FreeBSD 15.1 and OpenBSD 7.9 packages cover x86-64 and install the CLI.
Linux packages include an optional, disabled systemd service. BSD packages create no
service, account or state. These are upstream downloads; community archive acceptance
is separate. The release also includes a Helm chart and a container image,
`ghcr.io/insanai/sibuna`.
See the [package operations guide](https://insanai.github.io/sibuna/book/operations.html)
for installation, verification, private state, upgrades and Kubernetes setup.

The [Sibuna Homebrew tap](https://github.com/insanai/homebrew-sibuna) provides a CLI formula
that installs the verified release archive for macOS and Linux (Apple Silicon, ARM64 and
x86-64). The tap follows the newest published release, so it already provides this beta.
Installation does not start a service:

```sh
brew tap insanai/sibuna
brew install insanai/sibuna/sibuna
sibuna --version
```

For Linux x86-64, with your app listening on port 3000:

```sh
curl -fLO https://github.com/insanai/sibuna/releases/download/v1.0.0-beta.1/sibuna-linux-amd64.tar.gz
curl -fLO https://github.com/insanai/sibuna/releases/download/v1.0.0-beta.1/SHA256SUMS
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
and health checks that cannot run a browser challenge. `./sibuna --help` lists every option.

On Windows, extract the ZIP and run `.\sibuna.exe --help` in PowerShell.
Use Ctrl+C to stop it. Restrict access to seed, credential and data files with Windows ACLs.

### Build from source

We build and test with **Rust 1.99**. The browser solver and the console interface are Rust
compiled to WebAssembly; the build does not need Node or npm.

```sh
git clone https://github.com/insanai/sibuna.git
cd sibuna
rustup target add wasm32-unknown-unknown
cargo build --release -p sibuna
```

The executable is `target/release/sibuna`. It stores state in SQLite with `--data-dir`.
Cluster builds use `--features postgres-tls` and share one PostgreSQL database through
`--database-url-file` and `--cluster-node`.
See [CONTRIBUTING.md](CONTRIBUTING.md) for tests, lints and size checks.

## Console

The console runs in the same executable. Bootstrap an administrator while the daemon is stopped:

```sh
./sibuna init-admin admin --data-dir ./data
./sibuna --host 127.0.0.1 --upstream-port 3000 --secret-file ./sibuna.seed \
  --data-dir ./data --console 127.0.0.1:19446
```

Open `http://127.0.0.1:19446/console/` and change the temporary password.
The [operations guide](https://insanai.github.io/sibuna/book/operations.html) explains HTTPS
access, GeoIP imports, users, API tokens and wall displays.

![Sibuna Console globe, request timeline and coverage](docs/readme/images/console-globe.png)

The globe shows sampled country activity over the last minute. Markers give approximate
country positions. Arrows point toward the server's configured location. They do not show
individual live connections. GeoIP needs a separately imported dataset.
Set `--console-location <latitude,longitude>` to place the server on the globe.

<details>
<summary>Traffic overview, security overview, policies and incident investigation</summary>

**Traffic overview** - request outcomes, observation windows and live updates.

![Sibuna Console traffic overview with request, admission, challenge and denial counters](docs/readme/images/console-traffic.png)

**Security overview** - recorded findings, challenges, bans and a live event feed.

![Sibuna Console security overview with inspection, challenge, ban and honeypot findings](docs/readme/images/console-security.png)

**Policies** - the rules a node applies, in order, with their recorded hits.

![Sibuna Console policies page with the applied configuration and an allow rule](docs/readme/images/console-policies.png)

**Events** - recorded incidents, with filters by module, country, address, path and time.

![Sibuna Console events page with incident filters and recorded SQL injection findings](docs/readme/images/console-events.png)

</details>

These are headless Chromium captures of v1.0.0-beta.1 on a local test node. Traffic and
GeoIP mappings are test data. The displayed counts are not benchmark results.

## How it works

A request can be admitted, challenged or denied. A visitor who solves a challenge receives
a signed session. Later requests still pass the applicable policy and rate checks.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/admission-session-dark.svg">
  <img src="docs/readme/images/admission-session.svg" alt="Solve a puzzle, receive a signed session and check rules on later requests">
</picture>

Gate checks access rules, sessions and local rate limits. Shield adds the built-in attack
inspector. Shield is the default; `--gate` selects Gate at startup.

<details>
<summary>Gate, Shield and the crates inside Sibuna</summary>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/protection-surfaces-dark.svg">
  <img src="docs/readme/images/protection-surfaces.svg" alt="Gate and Shield request decisions: allow, challenge or block">
</picture>

The diagram shows the built-in Gate and Shield checks.
A valid session does not bypass applicable attack checks or request limits.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/readme/images/subsystems-dark.svg">
  <img src="docs/readme/images/subsystems.svg" alt="The jobs of the crates inside Sibuna">
</picture>

The crates separate networking, proofs, policies, local state, storage and management.
The [book](https://insanai.github.io/sibuna/book/) explains their responsibilities.

</details>

### Deployment limits

Sibuna uses HTTP/1.1 on its private listener. Your ingress handles public TLS and HTTP/2.
Forward-auth inspects the metadata supplied by the ingress. In reverse-proxy mode, the
built-in inspector covers the first 8 KiB of a body. Uploads stream to your app.
WebSocket messages are relayed without inspection. The inspector is a heuristic, not a full
language parser.

Rate limits are local to each node. Sibuna does not provide volumetric network mitigation.
Challenges are bound to the node that issued them; route a challenge and its solution to the
same node. The console's strict performance target has not formally passed. Review the
[deployment limits and measurements](https://insanai.github.io/sibuna/book/operations.html)
before enabling the console beside a production app.

## Benchmarks

The book records the source revision, configuration and host for each run. These measurements
show request cost under a few workloads on one machine. They do not measure equivalent
protection or bot accuracy.

### Sibuna on one host

These runs used an AMD Ryzen 9 5950X. The daemon had four CPUs and ran in memory; the load
generator and a stub origin ran on eight other CPUs. `wrk` used 64 connections over loopback.
Figures are medians of three runs.

- In forward-auth mode, every workload ran at 197,532 to 211,636 requests per second, with a
  p99 of 305 to 327 us and 11.7 to 13.8 us of CPU per request. The load generator was the limit.
- Proxied requests ran at 138,965 to 147,303 per second. Peak memory was about 16 MiB.
- At an equal offered load of 100,000 admitted requests per second, the p99.9 latency was
  62 us in forward-auth mode and 150 us in reverse-proxy mode.

### Beside Anubis

We measured the official Anubis 1.27.0 release binary with the same workloads, CPUs and load
generator. Hashcash work was matched: 8 zero bits for Sibuna, 2 zero hex digits for Anubis.
The origin was `caddy respond`. The table shows admitted requests with a session.

| Admitted requests | Sibuna Gate | Sibuna Shield | Anubis 1.27.0 |
| --- | ---: | ---: | ---: |
| Forward auth, req/s | 210,682 | 208,635 | 36,509 |
| Forward auth, p99 | 305 us | 308 us | 7,477 us |
| Forward auth, CPU per request | 12.1 us | 13.2 us | 106.3 us |
| Reverse proxy, req/s | 106,376 | 103,298 | 19,398 |
| Reverse proxy, p99 | 3,331 us | 3,321 us | 11,062 us |

The second run timed admission operations, each product on two CPUs. Anubis ran once with its
default Ed25519 tokens and once with HS512 tokens.

| Operations per second | Sibuna (keyed BLAKE3) | Anubis (Ed25519) | Anubis (HS512) |
| --- | ---: | ---: | ---: |
| Valid session check | 88,104 | 10,951 | 16,976 |
| Unauthenticated check | 78,997 | 28,619 | 27,785 |
| Challenge bootstrap | 42,664 | 7,893 | 7,952 |
| Proof verification | 57,924 | 12,668 | 19,261 |

Sibuna's peak memory stayed near 16 MiB. Anubis used about 33 MiB in forward-auth mode and up
to about 600 MiB in reverse-proxy mode. Anubis is a widely used and capable tool, and these
rows are not a ranking. Several are not like for like: in forward-auth mode Anubis answers
some paths itself, it does no payload inspection, and the challenge pages differ. The runs
used loopback without TLS, real browsers or storage.

See the [benchmark records](benchmarks/results/README.md) for the method, ranges and replay
commands: [product-latest.md](benchmarks/results/product-latest.md),
[latency-latest.md](benchmarks/results/latency-latest.md),
[comparison-latest.md](benchmarks/results/comparison-latest.md) and
[admission-latest.md](benchmarks/results/admission-latest.md).
Part VIII of the book discusses each difference.

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

These projects cover different parts of web protection. Sibuna's inspector is built in; it
does not run CRS or other ModSecurity rule sets. Pair Sibuna with a full WAF when your app
needs broader rule coverage.

## License

Sibuna is **LGPL 3.0 or later**. The license covers the engine, the libraries, the browser
solver and the console, including its WebAssembly interface.

[LICENSE](LICENSE) describes the scope. [LICENSES](LICENSES) contains the full terms.
[NOTICE](NOTICE) lists dependencies. Source and build scripts are available under each release tag.

Sibuna is written by Vikrant Rathore with assistance from Ronak Rathore and Kanak Rathore.
Companies seeking other licensing terms can contact Vikrant Rathore.
Third-party libraries and materials keep their respective licenses.
