#let sid-number = "0003"
#let sid-title = "Declarative Rule Policy Engine"
#let sid-state = "published"
#let sid-created = "2026-09-07"
#let sid-discussion = "Specification of Sibuna's zero-allocation declarative rule engine: JSON policy files, multi-criteria matching over path, user agent, headers, and IPv4/IPv6 CIDRs, WEIGH scoring with thresholds, per-rule challenge parameters, the evaluation order, and dynamic policies replicated through Zaxonlite."
#let sid-labels = ("policy", "architecture", "zero-alloc", "firewall",)
#let sid-authors = ("Sibuna Contributors <team@sibuna.local>",)
#let sid-category = "Architectural Specification"
#let sid-status = "Published"
#let sid-last-updated = "2026-09-07"

#import "../../shared/sid.typ": sid-document

#let blue = rgb("0284c7")
#let blue-light = rgb("f0f9ff")
#let green = rgb("16a34a")
#let green-light = rgb("f0fdf4")
#let amber = rgb("d97706")
#let amber-light = rgb("fffbeb")
#let red = rgb("dc2626")
#let red-light = rgb("fef2f2")
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
  #h(6pt)
  #box(inset: (x: 5pt, y: 2pt), radius: 3pt, fill: green-light)[#text(size: 8.5pt, weight: "bold", fill: green)[delivered]]
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

#callout([Revision note (2026-09-07)], [
  Revised after the implementation review of 2026-09-07. The original default rule table
  admitted any User-Agent containing `Mozilla` and fell through to `ALLOW`; that contradicted the
  product principle that an unverified client must pay for admission, and it meant a scraper
  with a browser User-Agent was never challenged. The implemented defaults, WEIGH semantics,
  JSON schema, IPv6 support, and evaluation order are recorded here as built.
], fill: amber-light, stroke: amber)

= Decision summary

Sibuna evaluates every request against an ordered table of declarative rules compiled at
startup (or rebuilt off the hot path from the Zaxonlite `policies` table, SID 0005). A rule is a
conjunction of optional criteria over the request path, the User-Agent, up to four headers, and
up to eight IPv4 or IPv6 CIDR blocks. Its action is `ALLOW`, `DENY`, `CHALLENGE`, or `WEIGH`,
with optional per-rule challenge difficulty (work bits) and algorithm (`hashcash` or `posw`).
Evaluation is first-terminal-match-wins; `WEIGH` rules contribute a signed score that is resolved
against thresholds when no terminal rule matched. The engine holds at most 128 rules and never
allocates during evaluation.

#callout([Performance contract], [
  Evaluation uses fixed-capacity tables and borrowed request slices with no allocator argument.
  Exact engine memory and current Gate/Shield timings are recorded by the standalone harness
  in `benchmarks/results/latest.json`. These primitive timings exclude socket I/O and do not
  establish HTTP throughput or instrumented allocation counts.
])

= Data model

```zig
pub const Action = enum(u8) { allow, deny, challenge, weigh };

pub const HeaderMatcher = struct { name: []const u8, pattern: []const u8 };
pub const CidrMatcher = struct { network: u128, mask: u128 };   // IPv4 mapped into ::ffff:0:0/96

pub const PolicyRule = struct {
    name: []const u8,
    path_pattern: ?[]const u8 = null,
    ua_pattern: ?[]const u8 = null,
    headers: [4]HeaderMatcher, header_count: u8 = 0,
    cidrs: [8]CidrMatcher, cidr_count: u8 = 0,
    action: Action = .allow,
    difficulty: ?u32 = null,        // work bits
    algorithm: ?[]const u8 = null,  // "hashcash" | "posw"
    weight: i32 = 0,                // WEIGH contribution, may be negative
};

pub const RequestView = struct {
    path: []const u8, query: []const u8 = "", client_ip: []const u8,
    user_agent: []const u8 = "", headers: []const Header = &.{}, body: []const u8 = "",
};

pub const Decision = struct {
    action: Action, rule_name: []const u8, difficulty: u32,
    algorithm: ?[]const u8 = null, score: i32 = 0,
};
```

Pattern grammar: `.*` or `*` matches anything; `^...$` anchors an exact path; a trailing `*`,
`/*`, or `.*` is a prefix match; a pattern beginning with `/` is an exact path; anything else is a
case-insensitive substring, the natural form for User-Agent rules. Header patterns use the same
grammar against the header value. CIDR matchers accept `10.0.0.0/8`, `2001:db8::/32`, bare
addresses, and IPv4-mapped IPv6 literals.

= Evaluation order

`Engine.evaluateRequest(RequestView) Decision` runs:

1. *Semantic WAF* (Shield surface only, SID 0004): any violation is a terminal `DENY` named
   `waf:<category>`.
2. *Reputation trie, terminal verdicts*: an IP matching a `deny` or `allow` prefix returns
   immediately as `ip/cidr-trie`. Bans propagated from storage therefore beat every rule,
   including the generic-browser challenge.
3. *Declarative rules in order*: the first `ALLOW`/`DENY`/`CHALLENGE` match returns; `WEIGH`
   matches add `weight` to the score and continue.
4. *Score resolution* (when the score is non-zero): negative totals `ALLOW`; totals at or above
   `deny_at` (default 40) `DENY`; totals at or above `challenge_at` (default 10) `CHALLENGE`
   with `default_difficulty + min((score - challenge_at) / bits_step, max_extra_bits)` work bits
   (`bits_step` 5, `max_extra_bits` 6).
5. *Static bypass paths*: `/favicon.ico`, `/robots.txt`, `/.well-known/*`, `/__sibuna/*`.
6. *Reputation trie, challenge verdict.*
7. *Bot-signature automaton*: a match is `CHALLENGE` named after the signature.
8. *Default action*: `CHALLENGE` unless the policy file sets `default_action`.

= Built-in policy

#table(
  columns: (1fr, 1.5fr, 0.8fr, 1.8fr),
  table.header([*Rule*], [*Criteria*], [*Action*], [*Purpose*]),
  [`well-known`], [Path `^/.well-known/.*$`], [`ALLOW`], [ACME and security.txt],
  [`favicon`], [Path `^/favicon.ico$`], [`ALLOW`], [Browser icon fetch],
  [`robots-txt`], [Path `^/robots.txt$`], [`ALLOW`], [Robots exclusion standard],
  [`sibuna-internal`], [Path `/__sibuna/*`], [`ALLOW`], [Solver assets and APIs],
  [Serverless-header denial], [Header `CF-Worker: .*`], [`DENY`], [Unconsented serverless scrapers],
  [`amazonbot`], [UA contains `Amazonbot`], [`DENY`], [Aggressive harvester],
  [`generic-browser`], [UA contains `Mozilla`], [`CHALLENGE`], [Humans clear the interstitial; scrapers pay],
  [(bot automaton)], [UA matches an AI-scraper or scraper-library signature], [`CHALLENGE`], [Known automation],
  [(default)], [Anything else], [`CHALLENGE`], [Unknown clients must prove work],
)

#callout([Why browsers are challenged], [
  A browser User-Agent is free to forge. If `Mozilla` admitted a client, every scraper would send
  it and the proof-of-work gate would be decorative. The interstitial costs a human 15–150 ms once
  per session; a harvesting fleet pays it for every session it opens. Operators who need
  unauthenticated API traffic admit it explicitly by path, header, or CIDR rule, or set
  `"default_action": "ALLOW"` to run the engine as a pure block list.
])

= Policy file

`--policy-file <path>` (or `-P`) loads a JSON document at startup. An explicit `rules` array
replaces the built-in rule table; the bypass paths, reputation trie, and bot automaton remain.

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
    { "name": "internal-subnets", "remote_addresses": ["10.0.0.0/8", "fd00::/8"], "action": "ALLOW" },
    { "name": "headless", "user_agent": "Headless", "action": "WEIGH", "weight": 30 },
    { "name": "partner-token", "headers": { "X-Partner": "v2" }, "action": "WEIGH", "weight": -20 }
  ]
}
```

Field aliases accepted for compatibility with existing policy files: `path_regex`,
`user_agent_regex`, `headers_regex`, `cidrs`. `ip_rules` feeds the reputation trie, which scales
to thousands of prefixes; per-rule `remote_addresses` is meant for a handful.

= Dynamic policies

With `--data-dir`, rows of the Zaxonlite `policies` table (name, priority, patterns, action,
difficulty, algorithm, JSON header matchers, JSON CIDR list, weight, enabled) are appended after
the file rules on every rebuild, and rebuilds are published to the workers through the
read-copy-update engine slot without a restart. Rows replicate across a cluster by Multi-Paxos.
The mechanism is specified in SID 0005.

= Verification

- Unit tests cover pattern grammar, IPv4 and IPv6 CIDR matching, rule conjunction, WEIGH
  accumulation into allow, challenge with extra bits, and deny, JSON loading including
  `waf`, `thresholds`, `ip_rules`, and `weight`, and a 100,000-request zero-allocation loop.
- End-to-end tests exercise the built-in denials (crawler and serverless-header denials), the
  static bypass on `/robots.txt` with a bot User-Agent, and the interstitial for a browser.
- The storage test inserts a policy row with header and CIDR matchers and observes the rebuilt
  engine apply it with the row's difficulty and algorithm.

= Milestones

#milestone(
  "M1: Rule data structures and zero-allocation matchers",
  "`PolicyRule`, `Action`, path/header/CIDR matching over stack slices, IPv6 support.",
  "Unit tests pass with zero heap allocation.",
)
#milestone(
  "M2: JSON loader and default table",
  "`Engine.loadFromJsonInto`, thresholds, `ip_rules`, WEIGH weights, default challenge posture.",
  "Loader test and engine tests pass.",
)
#milestone(
  "M3: Server and coordinator integration",
  "`--policy-file`, rule difficulty and algorithm carried in the challenge id, rule hash bound into the session token.",
  "End-to-end tests observe per-rule challenge parameters.",
)
#milestone(
  "M4: Dynamic policies",
  "Zaxonlite `policies` table rebuilt into the spare engine and published by RCU.",
  "Storage test observes a database rule after one tick.",
)

= Review corrections (2026-09-07)

The daemon evaluates policy before accepting a session, so a session bypasses only the
challenge verdict. Dynamic database rules are ordered before file/default rules to keep a
generic browser challenge from masking an operator's denial. Exact anchored patterns match
the complete string. Rule names must contain 1–128 bytes and no control bytes, bounding response copies and
preventing injected audit headers. The engine uses pattern-derived automaton capacity. Current timings are
recorded in `benchmarks/results/latest.json`; older figures above describe the previous build.
