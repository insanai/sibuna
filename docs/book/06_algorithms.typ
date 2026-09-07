#import "theme.typ": *
#import "figures.typ": *

#part_page("VI", [Automata, Tries, and the Semantic Firewall], [
  We examine the algorithms behind sub-microsecond classification: the tagged Aho–Corasick
  automaton, the IPv4/IPv6 radix trie, the byte-class tokenizers of the semantic WAF, and
  the declarative policy engine with WEIGH scoring.
])

= Single-Pass Multi-Pattern Matching

#objectives([
  By the end of this chapter, you should be able to derive the Aho–Corasick automaton's
  linear-time guarantee, explain the dense-table layout and comptime case folding, and argue
  why a SIMD literal engine was not adopted.
])

== Aho–Corasick as a Dense DFA

Sibuna has two literal-pattern sets: about forty bot signatures and about a hundred attack
signatures. Scanning a field against $N$ patterns one at a time is $O(N M)$; the automaton of Aho
and Corasick (1975) scans it once in $O(M)$ after building a trie with failure links. Sibuna
folds the failure links into the transition table at build time, so scanning is one table load
per input byte with no branches on the pattern set:

```zig
fn findFirstImpl(self: anytype, haystack: []const u8) ?Match {
    var state: u16 = 0;
    for (haystack) |byte| {
        state = self.transitions[state][toLower(byte)];
        const pid = self.match_id[state];
        if (pid != no_match) {
            return .{ .name = self.pattern_names[pid], .tag = self.pattern_tags[pid] };
        }
    }
    return null;
}
```

#book_figure([Trie states and failure edges for two signatures], aho_corasick_graph())

The automaton is generic over its state budget, `Automaton(1024)` for bots (512 KB) and
`Automaton(2048)` for attack signatures (1 MB), and each pattern carries an 8-bit tag so the WAF
learns the attack category from the match. Case folding goes through a 256-byte comptime table
rather than a branch. Forty signatures over a browser User-Agent cost 85 ns; the same scan by
sequential substring search costs 4.2 µs on the same host.

== Regular Expressions, SIMD Engines, and the Choice

Three families were weighed for the signature stage:

- *Backtracking regular expressions* (the ModSecurity rule-set style) run hundreds of patterns
  per request and allocate per match; they are the slowest option and the most prone to false
  positives.
- *SIMD literal engines* (Hyperscan, Vectorscan) prefilter blocks of 16–32 bytes with
  shuffle-based nibble masks (the "Teddy" algorithm) and verify candidates with automata. They
  excel on long inputs with large literal sets. The cost is a multi-megabyte C++ dependency, a
  compile-time pattern database, no WebAssembly target, and, for inputs of a hundred bytes, no
  advantage: the whole field scans in less time than one cache miss.
- *Dense Aho–Corasick plus small structural tokenizers*, the libinjection lineage, gives exact
  linear-time behaviour in a fixed table and needs nothing outside the binary.

Sibuna's fields are short, so the third family wins on both memory and speed; Part VIII records
2.9 ns per byte on an 8 KB body, the one workload where a SIMD prefilter would pay, and SID 0006
keeps that as an open item.

= The Radix Trie for IPv4 and IPv6

#objectives([
  Trace a longest-prefix lookup through the 128-bit trie, explain the IPv4 root shortcut, and
  see how the trie doubles as the reputation store fed by the cluster.
])

One binary trie over 128-bit keys serves both families: IPv6 prefixes are inserted as-is, IPv4
prefixes are mapped into `::ffff:0:0/96` so a `/24` becomes a depth-120 path. Nodes are flat
arrays indexed by `u16` with index zero as both root and "no child", so a lookup is at most 128
dependent loads with no pointer chasing.

A first implementation walked the 96 mapped-prefix levels for every IPv4 lookup and measured
257 ns; the trie now records the node at depth 96 at initialisation and starts IPv4 lookups
there:

```zig
if (address >> 32 == v4_mapped_prefix >> 32) {
    current = self.v4_root;
    i = 96;
}
```

IPv4 lookups cost 45 ns and IPv6 lookups 80 ns. The engine consults the trie twice: terminal
`allow`/`deny` verdicts before the rule table, so a cluster-wide ban beats every rule, and
`challenge` verdicts after it.

= The Semantic Firewall

#objectives([
  Understand the byte-class pre-scan, the tagged signature automaton, the SQL tokenizer with
  tautology detection, the HTML and shell structure checks, canonicalisation, and the
  false-positive discipline that a real browser request must pass untouched.
])

== A Lesson in False Positives

The first version of the WAF matched a flat substring list against every header. The list
contained `/*`, and every browser sends `Accept: text/html,…,*/*;q=0.8`. Every real browser was
classified as SQL injection and received `403`. The lesson shaped the design: a detector may fire
only on *structure*, and the test suite now passes a complete Chrome request, including a
comment body containing `select`, `--`, and an apostrophe, through the engine and asserts it
comes out clean.

== Byte Classes in One Pass

Each inspected field is scanned once to collect which byte classes occur: quotes, `=`, `<`,
shell separators, `%`, NUL, canonicalisation triggers, and double spaces. Every detector consults
the classes instead of rescanning, and the canonicalised second pass runs only when a trigger
was seen. The scan is a 256-entry table lookup per byte:

```zig
fn scanClasses(text: []const u8) Classes {
    var bits: u8 = 0;
    var prev: u8 = 0;
    var double_space = false;
    for (text) |c| {
        bits |= class_table[c];
        if (c == ' ' and prev == ' ') double_space = true;
        if (c == '*' and prev == '/') bits |= 64;
        prev = c;
    }
    // ... unpack bits into the Classes struct
}
```

== Detectors

- *Signatures.* All strong signatures of every category live in one tagged automaton; a hit
  is a terminal `deny` named `waf:sqli`, `waf:xss`, `waf:path-traversal`, or `waf:rce`.
- *SQL injection.* A single-pass word scanner looks up each alphanumeric word (at most seven
  bytes) in the keyword table and, on `or` / `and`, checks for a `literal = literal`
  tautology; `id=1 or 1=1` is terminal. Otherwise a quote byte is mandatory and the evidence
  must score at least 4 out of: quote (1), up to two keywords (2), a comment marker (1), an
  `=` (1). `admin'--` is terminal by itself. "it's a group order from the shop" scores 3 and
  passes.
- *Cross-site scripting.* Requires `<`; fires when a tag that can host script co-occurs with an
  `on<event>=` attribute in attribute position. `onboarding=1` does not count.
- *Command injection.* Requires a separator; fires when `;`, `|`, `&&`, `$(`, a backtick, or a
  newline is followed by a known command name. `status ok; done | next` passes.
- *Path traversal.* Signatures (`../`, `..%2f`, `/etc/passwd`, `id_rsa`, …) plus NUL and `%00`.

Structural headers whose grammar legitimately contains quotes and stars (`Accept*`,
`Content-Type`, `Sec-*`, `If-*`, …) are skipped; the path, query, User-Agent, other headers,
and the first 8 KB of the body are inspected, and fields with percent escapes, plus signs,
comment openers, or collapsible whitespace are canonicalised into a 2 KB stack buffer and
inspected again, so `1%27/**/UnIoN/**/SeLeCt` and `%252e%252e/` collapse onto the raw
signatures.

== Cost

A full browser request classifies in 1.46 µs on the Shield surface and 295 ns on the Gate
surface (no WAF), both without allocation. The difference, about 1.2 µs, is the semantic
firewall's price for seven header fields.

= The Declarative Policy Engine

#objectives([
  Read the rule model, the evaluation order, WEIGH scoring with thresholds, and the JSON policy
  grammar.
])

A rule is a conjunction of optional criteria (path pattern, User-Agent pattern, up to four
headers, up to eight IPv4/IPv6 CIDR blocks) with an action `ALLOW`, `DENY`, `CHALLENGE`, or
`WEIGH`, optional per-rule difficulty in work bits and algorithm, and a signed `weight`.
Evaluation order:

1. Semantic WAF (Shield only): violation is a terminal `deny`.
2. Reputation trie: `deny` or `allow` prefixes are terminal.
3. Rules in order: the first terminal match returns; `WEIGH` matches accumulate.
4. Score: negative totals `allow`; totals $>= 40$ `deny`; totals $>= 10$ `challenge` with one
   extra work bit per 5 points above the threshold, capped at six.
5. Static bypass paths, then trie `challenge` verdicts, then the bot automaton.
6. Default action, `challenge` unless the policy file says otherwise.

Built-in rules allow `/.well-known/*`, `/favicon.ico`, `/robots.txt`, and `/__sibuna/*`,
deny `CF-Worker` clients and `Amazonbot`, and challenge every `Mozilla` User-Agent: a browser
string is free to forge, so admitting it would make the gate decorative.

```json
{
  "default_action": "CHALLENGE",
  "waf": true,
  "thresholds": { "challenge_at": 10, "deny_at": 40, "bits_step": 5 },
  "ip_rules": { "10.0.0.0/8": "ALLOW", "2001:db8::/32": "DENY" },
  "rules": [
    { "name": "internal-api", "path": "/api/*", "headers": { "X-Api-Key": ".*" }, "action": "ALLOW" },
    { "name": "checkout", "path": "/checkout/*", "action": "CHALLENGE",
      "challenge": { "difficulty": 20, "algorithm": "posw" } },
    { "name": "headless", "user_agent": "Headless", "action": "WEIGH", "weight": 30 },
    { "name": "no-language", "headers": { "Accept-Language": "" }, "action": "WEIGH", "weight": -5 }
  ]
}
```

#exercise([6.1], [
  Write the byte-class table entries needed to add a detector for LDAP injection (`)(|(`
  patterns), and explain which existing class bits it can reuse.
])

#teach_back([
  Explain to a reviewer why `Accept: */*` was a false positive, what structural property the
  new SQL detector requires, and how the automaton and the tokenizer divide the work.
])
