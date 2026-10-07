#import "theme.typ": *
#import "figures.typ": *

#part_page("VI", [Automata, Tries, and the Semantic Firewall], [
  We examine the algorithms used for request classification: the tagged Aho–Corasick
  automaton, the IPv4/IPv6 radix trie, the byte-class tokenizers of the semantic WAF, and
  the declarative policy engine with WEIGH scoring.
])

== Single-Pass Multi-Pattern Matching

#objectives([
  By the end of this chapter, you should be able to derive the Aho–Corasick automaton's
  linear-time guarantee, explain the dense-table layout and compile-time case folding, and
  describe the tradeoffs considered when choosing a literal matcher.
])

=== Aho–Corasick as a Dense DFA

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

The automaton is generic over its state budget. The implementation reserves at most one
root plus the sum of all signature lengths, a safe upper bound on trie states. This avoids
historically oversized fixed tables while retaining a dense transition for every byte. Each
pattern carries an 8-bit category tag; case folding uses a 256-byte compile-time table.
Exact engine sizes and the comparison with sequential substring search are recorded in
chapter 8. The latter uses the same patterns and any-match semantics.

=== Regular Expressions, SIMD Engines, and the Choice

Three approaches were considered for the short-field signature stage:

- *Backtracking regular expressions* support rich patterns, but their evaluation cost can
  depend strongly on the expression and input. A rule engine must bound work and scratch
  memory. Sibuna's separate CRS engine uses bounded compiled matching rather than an
  unrestricted backtracking evaluator.
- *SIMD literal engines* (Hyperscan, Vectorscan) prefilter blocks of 16–32 bytes with
  shuffle-based nibble masks (the "Teddy" algorithm) and verify candidates with automata. They
  target long inputs and large literal sets. Integration also brings a C++ dependency,
  compiled pattern databases and architecture-specific code. Those costs need to be weighed
  against the benefit on the fields a deployment actually inspects.
- *Dense Aho–Corasick plus small structural tokenizers* gives a bounded linear scan in a fixed
  table. It suits the small inspector's literal sets and requires no external matching service.

Sibuna uses the third approach for its small inspector. The comparison in Part VIII records
2.9 ns per byte on an 8 KB body. That result describes the measured workload; it does not
decide the best matcher for every input. SID 0006 leaves a SIMD prefilter for longer inputs
as an option to evaluate.

== The Radix Trie for IPv4 and IPv6

#objectives([
  Trace a longest-prefix lookup through the 128-bit trie, explain the IPv4 root shortcut, and
  see how the trie doubles as the reputation store fed by the cluster.
])

One binary trie over 128-bit keys serves both families: IPv6 prefixes are inserted as-is, IPv4
prefixes are mapped into `::ffff:0:0/96` so a `/24` becomes a depth-120 path. Nodes are flat
arrays indexed by `u16`, with index zero as both root and "no child". A lookup needs at most
128 dependent array accesses. It follows indices instead of heap pointers.

A first implementation walked the 96 mapped-prefix levels for every IPv4 lookup and measured
257 ns; the trie now records the node at depth 96 at initialisation and starts IPv4 lookups
there:

```zig
if (address >> 32 == v4_mapped_prefix >> 32) {
    current = self.v4_root;
    i = 96;
}
```

The comparison measured 45 ns for IPv4 lookups and 80 ns for IPv6. The engine consults the trie twice: terminal
`allow`/`deny` verdicts before the rule table, so a cluster-wide ban beats every rule, and
`challenge` verdicts after it.

== The Semantic Firewall

#objectives([
  Understand the byte-class pre-scan, the tagged signature automaton, the SQL tokenizer with
  tautology detection, the HTML and shell structure checks, canonicalisation, and the
  false-positive discipline that a real browser request must pass untouched.
])

=== A Lesson in False Positives

The first WAF matched substrings in every header. One signature was `/*`, which also occurs
in the ordinary browser header `Accept: text/html,…,*/*;q=0.8`. The test request was wrongly
classified as SQL injection and received `403`.

That failure showed why the context of a match matters. The test suite now checks a complete
Chrome request and a benign comment containing `select`, `--` and an apostrophe. The detector
must recognise an attack pattern without treating these ordinary uses as sufficient evidence.

=== Byte Classes in One Pass

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

=== Detectors

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

The small inspector skips structural headers whose grammar permits quotes and stars,
including `Accept*`, `Content-Type`, `Sec-*` and `If-*`. It inspects the path, query,
User-Agent, other headers and the first 8 KB of the body.

Fields containing percent escapes, plus signs, comment openers or repeated whitespace are
also normalised into an 8 KB stack buffer and inspected again. This exposes encoded forms
such as `1%27/**/UnIoN/**/SeLeCt` and `%252e%252e/` to the same signatures as their decoded
forms. CRS has its own input adapters and rule-defined transformations.

=== Cost

The inspection cost depends on the fields and bytes presented to the engine, not just the
number of requests. The benchmark chapter reports separate Gate, Shield, and 8 KB body cases.
The 8 KB bound is an inspection limit, not a claim that the rest of an upload is safe. An
ingress using forward-auth must pass the relevant request information; omitted bytes cannot
be inspected by this process.

== The Declarative Policy Engine

#objectives([
  Read the rule model, the evaluation order, WEIGH scoring with thresholds, and the JSON policy
  grammar.
])

A rule matches when all its configured criteria match. Criteria can include a path pattern,
a User-Agent pattern, up to four headers and up to eight IPv4/IPv6 CIDR blocks. Its action
is `ALLOW`, `DENY`, `CHALLENGE` or `WEIGH`. A rule can also set its challenge algorithm and
work bits, or contribute a signed `weight`.

The small policy engine evaluates these stages in order:

1. Semantic WAF (Shield): an enforcing finding returns `deny`; an audit finding is recorded
   and evaluation continues.
2. Reputation trie: `deny` or `allow` prefixes are terminal.
3. Rules in order: the first terminal match returns; `WEIGH` matches accumulate. A terminal
   rule's optional rate limit applies before a session can satisfy its challenge.
4. Score: negative totals `allow`; totals $>= 40$ `deny`; totals $>= 10$ `challenge` with one
   extra work bit per 5 points above the threshold, capped at six.
5. Static bypass paths, then trie `challenge` verdicts, then the bot automaton.
6. Default action, `challenge` unless the policy file says otherwise.

Built-in rules allow `/.well-known/*`, `/favicon.ico`, `/robots.txt`, and `/__sibuna/*`,
deny `CF-Worker` clients and `Amazonbot`, and challenge every `Mozilla` User-Agent: a browser
string can be forged, so it is not sufficient evidence for admission.

```json
{
  "default_action": "CHALLENGE",
  "waf": true,
  "thresholds": { "challenge_at": 10, "deny_at": 40, "bits_step": 5 },
  "ip_rules": { "10.0.0.0/8": "ALLOW", "2001:db8::/32": "DENY" },
  "rules": [
    { "name": "internal-api", "path": "/api/*", "headers": { "X-Api-Key": ".*" },
    "action": "ALLOW" },
    { "name": "checkout", "path": "/checkout/*", "action": "CHALLENGE",
      "challenge": { "difficulty": 20, "algorithm": "posw" } },
    { "name": "headless", "user_agent": "Headless", "action": "WEIGH", "weight": 30 },
    { "name": "no-language", "headers": { "Accept-Language": "" },
    "action": "WEIGH", "weight": -5 }
  ]
}
```

=== Worked Trace: an Encoded Attack with a Valid Session

Consider `GET /search?q=%2527%2520OR%25201%253D1` from a client holding a valid session.
First the HTTP parser separates the path and query without copying their bytes. Local limits
run, then Shield inspects the request. The percent sign marks the field for canonicalization.
One decoding pass exposes `%27%20OR%201%3D1`; a second exposes `' OR 1=1`.

The tokenizer now sees a quote, the keyword `OR`, and equal literal operands. A denial is a
terminal policy result. The valid session does not turn it into an allow: the session check
only resolves a challenge decision. The storage hook copies a bounded incident record; SQL
runs later. The response path need not hold the engine snapshot while an origin connection
is idle.

#exercise("6.1", [Replace the payload with `O'Reilly` and then with `order=1`. Why should
neither alone establish SQL injection? Give an example of a false positive a substring-only
detector could produce.])

#exercise([6.2], [
  Write the byte-class table entries needed to add a detector for LDAP injection (`)(|(`
  patterns), and explain which existing class bits it can reuse.
])

#teach_back([
  Explain to a reviewer why `Accept: */*` was a false positive, what structural property the
  new SQL detector requires, and how the automaton and the tokenizer divide the work.
])

== Native Core Rule Set

OWASP Core Rule Set is a maintained SecLang policy. Its rules depend on transaction
variables, ordered transformations, chains, captures, phased input and anomaly scoring.
Sibuna's small structural inspector remains separate. The native CRS engine, daemon
integration and operator updates follow SID 0010. Operators can leave CRS Off, use Audit
to observe findings, or select Enforce after reviewing a candidate.

=== Preparing and Evaluating Rules

The compiler prepares an immutable graph from the pinned CRS 4.30.0 rules and data.
It resolves defaults, static target updates, chains and marker jumps before evaluation.
An unknown construct rejects the candidate before publication.

The executor runs rules in HTTP phases. It presents stable target collections, applies
ordered transformations, retains regex captures and updates `TX`, the transaction's local
variable map. A chain's full-match actions run from its last matched child back to its root.
Audit records a decision that would deny. Enforce keeps a denial effective as later rules run.
Evidence from a root's multi-match action can survive a failed child, but the failed chain
does not apply its full-match denial.

Each primitive shares a transaction work budget. Matching uses ordered regex simulation,
length-aware Knuth–Morris–Pratt search, sparse phrase automata and separate IPv4/IPv6
intervals. Native SQL and XSS detectors use reproducible tables from the pinned reference.

Regex compilation calculates which bytes can begin a match. An impossible start needs a
membership test rather than new matcher state. Expressions that can match an empty string
retain every possible start. Independent PCRE2 comparisons check both match results and
capture priority. Exhausting a resource budget returns an error; it cannot turn a match
into a false result. SID 0010 records corrections to the reference's phrase matching and
exclusion behaviour.

=== Reserved Memory and Publication

Transaction slots reserve entity, collection, `TX`, matcher and evidence buffers before
serving work. An exclusive lease owns one slot. If the pool is full, admission waits within
its deadline and refuses when no slot becomes available. Closing stops new leases while
admitted work retains its rule generation.

`TX` values and matched bytes remain valid until the transaction ends. Scratch reuse and
metadata replacement cannot overwrite them. The next transaction resets cursors and controls
after all borrowed values are released. Parser controls affect following rules in the same
phase. Runtime `TX` keys retain their full byte length, including decoded NULs; rule source
text rejects NULs.

Two stable cells hold rule generations and their reader counts. A transaction pins one
generation through its final phase. An update cannot reclaim that program or workspace
until its readers leave. A third update returns busy if both generations are still needed.
Shutdown joins readers before reclaiming either cell.

=== Signed Candidates and Updates

The native candidate checker uses the updater service shared with console management:

```sh
sibuna crs check --version 4.30.0
sibuna crs check                  # resolve the latest stable official release
```

It downloads the minimal archive and detached signature from fixed publisher destinations,
verifies the signature under the pinned signing key and compiles a candidate. The printed
digest, condition count and live compilation payload describe the prepared candidate.
They do not mean that protection has changed. The command works without storage or console
support. One deadline covers metadata, downloads and preparation; cancellation discards an
unfinished candidate.

Selection is a separate operator decision. The CLI and console use the same updater service
to prepare signed releases, review settings and exclusions, and select a candidate at an
expected revision. A failed preparation leaves the active generation in place. Part IX
describes these workflows and local operation without storage.

=== Request and Response Inputs

Input adapters retain duplicate URL-encoded and JSON fields, multipart filenames and part
headers, and the stock XML wildcard views. MIME parsing is shared with the small inspector.
File payloads remain in entity storage rather than becoming `ARGS`, the parsed argument
collection. JSON uses Zig's standard token scanner with fixed borrowed capacity. XML
rejects DTDs and external entities, validates scoped namespaces and separates attributes
from descendant text.

Phase-one processor controls apply before phase-two fields are published. Empty entities
and raw binary bodies remain distinct inputs. A parsing failure invalidates the transaction,
so a caller cannot evaluate a previous view or present a partial collection as complete.

The HTTP connector reads bounded entities without publishing partial bodies. It can inspect
an origin response before sending its head. Held chunked responses replay with their actual
content length. An explicit streaming decision covers indefinite responses; WebSocket
inspection ends at the validated handshake.

The bounded inflater checks gzip and zlib wrappers and checksums, handles ordered content
codings and retains the encoded entity for unchanged replay. Encoded and decoded size limits
are separate, and decoding consumes the transaction's work budget.

The daemon preserves phase order and records whether inspection completed, was excluded
for streaming or ended at a handshake. It retains request metadata across large and pipelined
uploads, checks admission limits before body acquisition, and releases inspection resources
before indefinite streaming or an accepted WebSocket tunnel. A session cannot clear a CRS
denial. Invalid acquisition or encoding remains incomplete in Audit and is refused in Enforce.

=== Verification

Library verification runs separately from enabling protection:

```sh
zig build crs-test -j2
zig build crs-update-test -j2
zig build compression-test net-test -j2
zig build crs-http-test -j2
zig build crs-audit -j2 -- vendor/crs --regex
zig build crs-regex-check -j2
zig build crs-primitive-check -j2 -- --download
zig build crs-detector-check -j2 -- --download
zig build crs-detector-data -j2 -- --check --download
zig build crs-signature-check -j2 -- --download
zig build crs-acquisition-check -j2
zig build crs-package-check -j2 -- --download
zig build crs-artifact-check -j2 -- --download
zig build crs-ftw-check -j2 -- --download
```

Native tests cover ownership, bounds, action timing and the prepared graph. Regex comparisons
check matches and captures against PCRE2. Primitive and detector checks use pinned upstream
vectors; data checks reproduce committed assets. Signature checks compare native RSA receipts
with isolated GnuPG verification. Independent JSON, form, MIME, XML, URI and cookie decoders
check input acquisition. These reference implementations are test tools, not runtime dependencies.

The engine FTW probe retains upstream rule-ID assertions. It reports malformed-input refusals,
work exhaustion and omitted wire or response contracts separately. ModSecurity reports
annotate independently reproduced differences without changing expectations. An Albedo
origin can supply real response bytes, but this probe does not test proxy holdback or delivery.
Reports state the work used and the configured ceiling.

The actual-daemon FTW harness sends the full pinned corpus through Sibuna and reads saved
console findings. It distinguishes complete contracts from acquisition refusals, work
exhaustion, malformed representations and response tests preempted by a request denial.
It checks that a request-phase refusal sends no bytes to the origin. Unknown incomplete
inspection fails qualification. Part VIII and SID 0010 retain the measurements, exact
reference evidence and compatibility limits.

Signed-package preparation verifies the archive before bounded gzip/tar decoding. Private
compilation uses an allocator that caps live payload and frees temporary storage. The
resulting program retains no borrowed staging bytes. Package tests check this ownership
against the signed release; generation publication checks compatibility separately.

At restart, the updater reads a bounded manifest and exact regular-file sizes from the
operator-owned directory. It rechecks the signature, recompiles the source and verifies the
archive and configuration identities. Invalid profiles are refused before source loading.
Restart tests cover disk round trips, rejected reloads and retention of a previously prepared
candidate. Management tests separately check saved intent, publication, receipts and recovery.
