// Feature comparison between Sibuna and the tools it is most often weighed against.
// Every cell about another product was read from that product's public documentation
// or release artefacts in September 2026; the chapter text records the sources.
#import "theme.typ": *

#let yes = text(fill: green, weight: "bold")[Yes]
#let no = text(fill: gray)[—]
#let plan(body) = text(fill: amber, size: 7.5pt)[#body]

#let feature_comparison_table() = {
  set text(size: 7.8pt)
  set par(justify: false, leading: 0.45em)
  table(
    columns: (1.05fr, 1.3fr, 1.15fr, 1.15fr, 1.15fr),
    inset: 4.5pt,
    stroke: 0.4pt + rule,
    fill: (col, row) => if row == 0 { blue_light } else if col == 1 { rgb("f8fbff") } else { none },
    table.header([*Feature*], [*Sibuna*], [*Anubis 1.27*], [*SafeLine CE 9*], [*Cloudflare WAF*]),
    [Runs as], [One static binary; reverse proxy or forward auth; optional embedded database],
      [One Go binary; reverse proxy or forward auth], [Seven Docker containers (tengine, detector, mgt, luigi, fvm, chaos, PostgreSQL)],
      [Hosted network; DNS points at Cloudflare],
    [Language, runtime], [Zig, no garbage collector, no libc when storage is off], [Go, garbage collected],
      [C/C++ proxy and detector, Go management, PostgreSQL], [Proprietary edge software],
    [Licence], [Source in the repository], [MIT], [GPL-3.0 management code; closed detector images], [Proprietary service],
    [Host footprint], [3.3 MB binary, about 7 MB resident idle; 2.4 MB without storage],
      [37 MB binary, about 40 MB resident under load], [1 CPU core, 1 GB RAM, 5 GB disk minimum, Docker 20.10+],
      [None on premises],
    [Proof-of-work admission], [Hashcash (bit-level) and Cohen–Pietrzak sequential work, chosen per rule; WebAssembly with JavaScript fallback],
      [SHA-256 Hashcash in hex nibbles (`fast`, `slow`); non-work `metarefresh` and `preact` challenges],
      [JavaScript anti-bot challenge and CAPTCHA; not work-bound], [Managed challenge, JS challenge, Turnstile; Bot Fight Mode issues a compute challenge],
    [Challenge state on the server], [None until solved; solved tags in a fixed Robin Hood table],
      [Store backend: memory, bbolt, Valkey, or S3], [Managed by the stack], [Managed by Cloudflare],
    [Session token], [Keyed BLAKE3 tag, 64-character cookie; Ed25519 optional],
      [JSON Web Token signed with Ed25519; HS512 optional], [Cookie issued by the stack], [`cf_clearance` cookie],
    [Post-quantum posture of the default token], [Symmetric: only Grover's quadratic speedup applies],
      [Ed25519: broken by Shor's algorithm], [Not documented], [Not documented],
    [Policy language], [JSON rules: path, User-Agent, headers, IPv4/IPv6 CIDR; ALLOW, DENY, CHALLENGE, WEIGH with thresholds; dynamic rules from the database],
      [YAML/JSON bots: regex on UA, path, headers; CIDR; CEL expressions; WEIGH with thresholds],
      [Console-defined custom rules, ACLs, IP groups], [Rules language expressions; #plan[5 / 20 / 100 / 1000 custom rules by plan]],
    [SQLi, XSS, RCE, traversal inspection], [Shield: tagged automaton plus structural tokenizers, first 8 KB of body],
      [#no], [Semantic analysis engine over OWASP categories, also SSRF, XXE, CRLF],
      [Managed rulesets #plan[(Pro and above)]; OWASP Core Ruleset; attack score #plan[(Business and above)]],
    [Rate limiting], [GCRA per client, local to a node], [#no (system load is exposed to CEL rules)],
      [Per IP, path, session], [#plan[1 / 2 / 5 / 100 rules by plan]; IP-only keys below Enterprise],
    [Bans and reputation], [Honeypot bans; reputation trie replicated across the cluster],
      [DNSBL; ASN and GeoIP through Thoth #plan[(paid, closed)]], [IP groups and blacklists; threat intelligence #plan[(Pro)]],
      [IP lists; managed lists and bot score #plan[(Enterprise)]],
    [Forensics], [Embedded SQLite: full-text search over incidents, vector campaign clustering],
      [Prometheus metrics only], [PostgreSQL attack log with console], [Security Events; sampled on Free],
    [Multi-node], [Multi-Paxos replication of policy and reputation; shared seed; sticky challenge verification],
      [Shared signing key; shared Valkey store], [One stack per host], [Global anycast],
    [Metrics], [Prometheus at `/__sibuna/metrics`], [Prometheus on a separate port], [Console dashboards], [Dashboard and analytics],
    [TLS termination], [#no (ingress)], [#no (ingress)], [#yes], [#yes],
    [Management console], [#no (files and SQL)], [#no], [#yes], [#yes],
    [Measured on the benchmark host], [#yes], [#yes], [#no (Docker only)], [#no (hosted)],
  )
}
