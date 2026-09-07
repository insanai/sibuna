#let sid-number = "0003"
#let sid-title = "Declarative Rule Policy Engine and Anubis Feature Parity"
#let sid-state = "published"
#let sid-created = "2026-09-07"
#let sid-discussion = "Architectural specification and design for Sibuna's zero-allocation declarative rule engine, matching and exceeding Anubis botPolicies specifications with JSON file configuration, multi-criteria matching, custom difficulty, and per-rule actions."
#let sid-labels = ("policy", "architecture", "anubis", "zero-alloc", "firewall",)
#let sid-authors = ("Sibuna Contributors <team@sibuna.local>",)
#let sid-category = "Architectural Specification"
#let sid-status = "Published"
#let sid-last-updated = "2026-09-07"

#import "../../shared/sid.typ": sid-document

#let ink = rgb("172033")
#let blue = rgb("0284c7")
#let blue-light = rgb("f0f9ff")
#let green = rgb("16a34a")
#let green-light = rgb("f0fdf4")
#let amber = rgb("d97706")
#let amber-light = rgb("fffbeb")
#let red = rgb("dc2626")
#let red-light = rgb("fef2f2")
#let gray = rgb("64748b")
#let rule = rgb("cbd5e1")

#let callout(title, body, fill: blue-light, stroke: blue) = block(
  width: 100%,
  breakable: true,
  inset: 10pt,
  radius: 6pt,
  fill: fill,
  stroke: 0.8pt + stroke,
)[
  #text(weight: "bold", fill: stroke)[#title]
  #v(0.3em)
  #body
]

#let milestone(name, outcome, exit) = block(
  width: 100%,
  breakable: true,
  inset: 10pt,
  radius: 6pt,
  stroke: 0.7pt + rule,
)[
  #text(weight: "bold", fill: blue)[#name]
  #v(0.2em)
  *Outcome:* #outcome \
  *Exit criterion:* #exit
]

#show: doc => sid-document(
  sid-number,
  sid-title,
  doc,
  authors: sid-authors,
  state: sid-state,
  created: sid-created,
  discussion: sid-discussion,
  labels: sid-labels,
  category: sid-category,
  status: sid-status,
  last-updated: sid-last-updated,
)

= Decision Summary

Implement a high-performance, declarative, file-configurable policy engine in Sibuna that
achieves complete functional parity with `TecharoHQ/anubis` policy definitions
(`docs/docs/admin/policies.mdx`), while preserving Sibuna's strict zero-allocation memory contract
on the request evaluation hot path.

Sibuna administrators can declare rules either via an external JSON configuration file
(`--policy-file <path>`) or rely on a hardened, built-in default policy set. Each rule specifies:
1. *Rule Identity:* Lowercase kebab-case identifier (`name`) exposed in metrics and logging.
2. *Multi-Criteria Matching (Conjunction):*
   - Request path pattern (`path_regex` or glob pattern)
   - User-Agent substring or regex pattern (`user_agent_regex`)
   - HTTP request header key-value patterns (`headers_regex`)
   - Remote client IP addresses or CIDR subnets (`remote_addresses`)
3. *Rule Actions:* `ALLOW`, `DENY`, `CHALLENGE`, or `WEIGH`.
4. *Challenge Parameter Overrides:* Per-rule Proof-of-Work difficulty (`challenge.difficulty`) and
   algorithm flavor (`challenge.algorithm`).

#callout([Performance Contract for Declarative Policies], [
  Regardless of the number of declared rules (up to 128 compiled rules), policy evaluation on
  incoming requests must execute in $< 200$ nanoseconds with strictly *0 bytes* of dynamic heap
  allocation. All header parsing, path inspection, and CIDR checks slice directly over stack buffers.
], fill: green-light, stroke: green)

= Analysis of Anubis Policy Architecture

In `TecharoHQ/anubis`, bot policies are defined in YAML or JSON (`data/botPolicies.yaml` or user
files) and evaluated sequentially by the Go runtime. Anubis provides four primary action types:

#table(
  columns: (1fr, 3.2fr),
  table.header([*Anubis Action*], [*Operational Effect*]),
  [`ALLOW`], [Bypasses all subsequent checks and proxies request directly to upstream backend.],
  [`DENY`], [Terminates request immediately with an error page (or 403 Forbidden).],
  [`CHALLENGE`], [Presents a client-side Proof-of-Work interstitial page; verifies issued cookie.],
  [`WEIGH`], [Dynamically scales challenge difficulty or rate weight for suspicious connections.],
)

== Limitations in Anubis Implementation

While Anubis's declarative policy model is flexible, its Go implementation introduces substantial
runtime latency and resource overhead:
1. *Regular Expression Compilation & Churn:* Each rule's `user_agent_regex` and `path_regex` executes
   via Go's `regexp` package, causing dynamic heap allocations and branch mispredictions per request.
2. *Header Map Allocations:* Inspecting `headers_regex` requires traversing Go's `http.Header` map
   (`map[string][]string`), invoking hashing and slice indexing on every evaluation.
3. *Wazero Challenge Coupling:* When `CHALLENGE` is selected with custom difficulty, Anubis enters
   its in-process Wazero WebAssembly VM to generate challenge nonces, adding 5--12 milliseconds of
   runtime delay.

= Sibuna Declarative Engine Design

Sibuna replaces runtime regex interpretation and dynamic map allocations with a pre-compiled,
flat-memory rule table evaluated via cache-line sequential scanning.

== 1. Wire & Memory Representation

```zig
pub const Action = enum(u8) {
    allow,
    deny,
    challenge,
    weigh,
};

pub const HeaderMatcher = struct {
    name: []const u8,
    pattern: []const u8,
};

pub const CidrMatcher = struct {
    network: u32,
    mask: u32,
};

pub const PolicyRule = struct {
    name: []const u8,
    path_pattern: ?[]const u8 = null,
    ua_pattern: ?[]const u8 = null,
    headers: [4]HeaderMatcher = undefined,
    header_count: u8 = 0,
    cidrs: [8]CidrMatcher = undefined,
    cidr_count: u8 = 0,
    action: Action = .allow,
    difficulty: ?u32 = null,
    algorithm: ?[]const u8 = null,
};
```

== 2. Zero-Allocation Evaluation Pipeline

When an HTTP request arrives, the `PolicyEngine` evaluates the compiled rules in declaration order:
1. *Path Matching:* Slices the zero-copy request path against `path_pattern`. Supports exact matches
   (`/favicon.ico`), prefix wildcards (`/.well-known/*`), and substring matches.
2. *Header Matching:* For each required header rule, executes zero-copy lookup in `req.getHeader(name)`
   and evaluates whether the parsed value contains or matches `pattern`.
3. *Remote CIDR Matching:* Converts `client_ip` to an integer using bitwise shifts and checks
   `(ip & mask) == network`.
4. *User-Agent Matching:* Evaluates case-insensitive substring search or branchless automaton.
5. *Conjunction Check:* A rule triggers if and only if *all* declared criteria match.
6. *First-Match-Wins:* The first rule that matches produces the terminal `Decision`. If no rule
   matches, the engine returns the default action (`.allow`).

== 3. Anubis-Equivalent Default Policy Set

When no external policy file is supplied, Sibuna initializes with an Anubis-parity rule table:

#table(
  columns: (1fr, 1.4fr, 0.8fr, 1.8fr),
  table.header([*Rule Name*], [*Match Criteria*], [*Action*], [*Purpose*]),
  [`well-known`], [Path `/.well-known/*`], [`ALLOW`], [ACME challenge & security.txt bypass],
  [`favicon`], [Path `/favicon.ico`], [`ALLOW`], [Browser static icon bypass],
  [`robots-txt`], [Path `/robots.txt`], [`ALLOW`], [Robots exclusion standard bypass],
  [`sibuna-internal`], [Path `/__sibuna/*`], [`ALLOW`], [Embedded WASM solver and health API],
  [`cloudflare-workers`], [Header `cf-worker: *`], [`DENY`], [Block unconsented serverless scrapers],
  [`amazonbot`], [UA contains `Amazonbot`], [`DENY`], [Block Amazon aggressive harvesting],
  [`ai-scrapers`], [UA in AI scraper list], [`CHALLENGE`], [Enforce PoW (default diff 4)],
  [`scraper-libs`], [UA in library list (curl, python)], [`CHALLENGE`], [Enforce PoW (elevated diff 6)],
  [`generic-browser`], [UA contains `Mozilla`], [`ALLOW`], [Standard human browser flow],
  [`default-allow`], [Catch-all], [`ALLOW`], [Default open web pass-through],
)

== 4. External Policy File Specification (JSON)

Administrators may provide a JSON policy file via `--policy-file <path>`:

```json
{
  "default_action": "ALLOW",
  "rules": [
    {
      "name": "deny-bad-worker",
      "headers": { "CF-Worker": ".*" },
      "action": "DENY"
    },
    {
      "name": "protect-checkout",
      "path": "/api/checkout/*",
      "action": "CHALLENGE",
      "challenge": {
        "difficulty": 6,
        "algorithm": "sha256"
      }
    },
    {
      "name": "internal-subnets",
      "remote_addresses": ["10.0.0.0/8", "192.168.0.0/16"],
      "action": "ALLOW"
    }
  ]
}
```

= Milestones and Delivery Plan

#milestone(
  "M1: Rule Data Structures & Zero-Alloc Pattern Matcher",
  "Implement `PolicyRule`, `Action`, zero-allocation path/header/CIDR matching in `libs/policy/`.",
  "Unit tests passing with 100% code coverage and zero heap allocations.",
)

#milestone(
  "M2: PolicyEngine JSON Loader & Default Rule Table",
  "Implement `Engine.loadFromJson` (arena startup) and `Engine.initDefault` in pure Zig.",
  "All 10 Anubis parity rules operational and verified.",
)

#milestone(
  "M3: Server & Coordinator Integration",
  "Wire `--policy-file` CLI flag, propagate rule-specific challenge difficulties to PoW coordinator.",
  "Integration test verifying per-rule custom difficulties and header-based denial.",
)

#milestone(
  "M4: SID Promotion and Book Documentation",
  "Compile SID-0003 PDF and document declarative policies in Part VIII of The Book of Sibuna.",
  "Clean compilation of `docs/build/sid-0003-declarative-policy-engine.pdf`.",
)

