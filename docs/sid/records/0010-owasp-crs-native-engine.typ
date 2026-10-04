#let sid-number = "0010"
#let sid-title = "Native OWASP Core Rule Set Evaluation and Verified Rule Updates"
#let sid-state = "discussion"
#let sid-created = "2026-10-04"
#let sid-discussion = "Native SecLang compilation and bounded CRS evaluation, complete input contracts, anomaly scoring, immutable rule generations, authenticated operator updates, and compatibility gates."
#let sid-labels = ("security", "policy", "performance",)
#let sid-authors = ("Sibuna Contributors <team@sibuna.local>",)
#let sid-category = "Architectural Specification"
#let sid-status = "Open for Discussion"
#let sid-last-updated = "2026-10-04"

#import "../../shared/sid.typ": sid-document

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

= Abstract

Sibuna supplies proof-of-work admission and a small structural inspection engine. OWASP
Core Rule Set (CRS) supplies a maintained application-attack policy written in SecLang;
it does not supply an HTTP proxy or a matching engine. Importing its regular expressions
as isolated signatures would discard scoring, exclusions, transformations and control flow.
This discussion specifies a separate, opt-in native Zig implementation with explicit resource
bounds and a verified update service shared by the CLI and console.

Compatibility is a release-specific, tested property. A syntactically readable rule is not
necessarily executable. An update must compile every selected directive and pass the
compatibility checks before publication. Unsupported syntax, unavailable required input,
resource exhaustion and failed verification are distinct outcomes; none means “no attack.”
The present Sibuna inspector remains available without CRS. This SID extends the optional
Shield surface of SID 0004; it does not change Gate admission or the proof protocol.

= Context and scope

CRS 4.30.0, released on 2 October 2026, is the initial compatibility target. The minimal
release archive was downloaded from the official release and checked against its GitHub
asset digest, SHA-256
`3d678a41fd5aade34760127fef5dd64fd7a77848913fc0f70dde0cf467c94427`.
The detached signature was also independently verified with GPG against the pinned CRS
fingerprint below. This audit verification does not implement the proposed native update
verifier. Unmodified fixtures and their file digests are in `vendor/crs/provenance.json`.
The active directives in the distributed rule files and example setup are the design input.
Commented examples and optional plugins do not establish support requirements silently.

#table(
  columns: (2fr, 1fr, 3fr),
  table.header([Construct], [Count], [Required meaning]),
  [`SecRule`], [693], [Selectors, operator, ordered actions and chain membership],
  [`SecAction`], [8], [Unconditional transaction actions],
  [`SecMarker`], [31], [Ordered control-flow destinations],
  [`SecDefaultAction`], [5], [Defaults specific to each evaluation phase],
  [`SecRuleUpdateTargetById`], [55], [Persistent target exclusions applied after rule load],
  [`SecComponentSignature`], [1], [Release identity],
  [Distinct operators], [19], [Numeric, string, phrase, address, validation and injection operators],
  [Distinct transforms], [20], [Ordered, per-rule input transformations],
  [`chain` actions], [73], [Dependent rule conditions; not independent detections],
)

These counts are reproducible by the native inventory tool. They describe source constructs,
not the number of independently blocking rules. Repeated metadata, inherited defaults and
chain continuations must not be counted as independent protections.

The scope includes stock CRS rules and data files, local exclusions, request and response
phases, anomaly scoring, rule diagnostics, bounded matching, CLI and console updates,
rollback, restart recovery and cluster publication. Arbitrary ModSecurity plugins, Lua scripts,
external programs, remote data lookup during a request and historical CRS 3 compatibility
are outside this initial compatibility target. Their presence rejects a candidate; it does not
silently weaken it. Supporting a later release requires passing the same gate.

= Design review

== Alternatives

*Extract signatures into the existing automaton.* This loses `TX` state, chain semantics,
argument names, captures, phase ordering, exclusions and transformation order. A signature
importer is not a CRS implementation. Reject this alternative.

*Embed ModSecurity.* This provides a mature reference implementation but brings a broad
C++ runtime and connector-dependent body and allocation semantics. It remains a useful
independent test oracle. It does not meet the intended first-party native Zig architecture.

*Build a general extension or query engine.* CRS needs a finite collection of operators,
transaction variables and ordered actions. It does not require a general-purpose scripting
language or a database on the request path. Use typed compiled instructions and explicit
budgets rather than an unrestricted interpreter or user callbacks.

*Compile SecLang into a native immutable program.* This retains the upstream policy,
places allocations and parsing outside the request path, and exposes compatibility and
resource limits. Adopt this design. The engineering cost is substantial: regex matching,
transforms and structured inputs require independent conformance testing. The design does
not treat those costs as solved by mathematical notation.

== Critical findings and dispositions

- SID 0004’s inspection heuristics are not the `libinjection` algorithm. Reusing them under
  `@detectSQLi` or `@detectXSS` would make a false compatibility claim. Preserve operator
  semantics against pinned upstream vectors and an independent engine.
- One global canonicalization pass cannot replace SecLang’s ordered `t:` actions. Preserve
  `t:none`, duplicate transforms, captures and `multiMatch` at their specified stages.
- A linear-time Boolean regex matcher alone does not prove capture equivalence. Preserve
  ordered alternatives and greedy/lazy priorities; test captured bytes against PCRE2.
- The existing 8 KiB body prefix cannot represent complete `ARGS`, JSON, XML or multipart
  collections. An enforcing body profile must obtain its complete bounded input before
  forwarding it. A streamed prefix must never be labelled complete.
- Blocking a response after sending its head is too late. Response enforcement requires
  holdback before publication to the client. Streaming exclusions must be explicit.
- A successful database commit cannot atomically publish a runtime generation on every node.
  Show committed and per-node applied revisions separately, as SID 0007 already requires.
- CRS updates can introduce false positives. Automatic retrieval does not authorize automatic
  changes to thresholds, exclusions or enforcement mode. Preserve operator configuration and
  require validation of the resulting complete candidate.

= Architecture and ownership

#table(
  columns: (2fr, 4fr),
  [Module], [Responsibility],
  [`libs/crs`], [SecLang reader, typed compiler, operators, transforms, transaction state and diagnostics. No networking, database or daemon imports.],
  [`libs/policy`], [Compose CRS with existing inspection and policy; preserve denial precedence.],
  [`libs/net`], [Generic bounded body acquisition and response holdback contracts; no rule knowledge.],
  [Daemon], [Preallocate transaction slots, pin immutable programs, run updates and compose storage and control services.],
  [Console service], [Authorize updates, provide job status, revisions, compatibility findings and audit.],
  [Console UI], [Render the operator controls and coverage; never evaluate security decisions in Wasm.],
)

A generation owns all source bytes, typed instructions, regex programs, phrase automata,
data tables and provenance. A transaction borrows one generation until its final phase has
completed. Every reference into that generation remains valid through the response and
logging phases. Generations are reference-counted under the existing publication discipline;
publication must not reuse a slot while a transaction still owns it.

Each request obtains a preallocated transaction slot. Slot state contains bounded collections,
`TX` values, captures, transformation scratch and work counters. `init` resets it, and `deinit`
returns it after all phases and evidence copying. No request evaluation allocates, loads a file,
executes SQL, downloads a rule or formats an unbounded message. Engine rebuilds remain
private until all validations pass. The console libraries do not import daemon implementation.

= Source language and compiled representation

The reader tracks file, physical line and byte offsets. It recognizes comments, quoted
arguments, escaped quotes and continued lines before separating action lists. Backslashes
belonging to a regex are not globally decoded as string escapes. Commas inside quoted
messages are not action separators. NUL, malformed quoting, dangling continuations and
capacity overflow produce stable diagnostics with a source location and recovery hint.

The compiler constructs concrete structs and tagged unions for directives, selectors,
operators, transformations and actions. It resolves IDs, phases, defaults, marker targets,
chain links and static exclusions before publication. Duplicate IDs, dangling chains, backward
or unresolved `skipAfter` destinations and unknown constructs reject the entire candidate.
Supported directives are compiled; inventory-only recognition is not execution support.

Selectors retain collection identity, exact keys, regex keys, exclusions and count selectors.
Names and values are separate entries. Duplicate headers and arguments retain their original
order. Cookie parsing, JSON paths and XML selectors follow the tested reference semantics.
Absent data, an empty value and unobservable data are different states. Macro expansion uses
bounded scratch; missing values and numeric conversion obey the reference contract.

Actions are ordered. A chain retains its conditions and the reference engine’s action timing,
including capture and transaction-variable visibility. Defaults are phase-local. `pass` does
not bypass other rules. `block` resolves through the configured disruptive default action;
CRS anomaly mode accumulates detections before its blocking evaluation. `deny` remains an
explicit disruptive action. `skipAfter` is compiled to a forward instruction index, never a
runtime text search. Logging and audit controls affect evidence, not detection truth.
Within the one configuration context, a phase accepts one `SecDefaultAction`; repeated
declarations reject the candidate instead of replacing it. Defaults without an explicit
phase select request headers, as the pinned parser does. Each declaration must contain
`pass` or `deny`, and must not contain `t:none` or configuration-only actions such as IDs
and chain markers. The complete phase default binds to every rule when compilation
finishes, including rules read before that declaration. Capturing defaults lexically at
each rule's source position would differ from the reference's final ruleset lookup.

#table(
  columns: (2fr, 4fr),
  [Operator family], [CRS 4.30.0 names],
  [Comparison], [`eq`, `ge`, `gt`, `lt`, `streq`, `within`],
  [Text], [`beginsWith`, `contains`, `endsWith`, `rx`],
  [Tables], [`pm`, `pmFromFile`, `ipMatch`],
  [Validation], [`validateByteRange`, `validateUrlEncoding`, `validateUtf8Encoding`],
  [Structure], [`detectSQLi`, `detectXSS`],
  [Unconditional], [`unconditionalMatch`],
)

Phrase files compile into a shared Aho–Corasick representation with per-rule output lists.
Case and boundary semantics must agree with the operator rather than an unrelated policy
matcher. Boolean address lists compile into sorted disjoint intervals, preserving IPv4 and
IPv6 as distinct families. The policy trie carries actions and maps IPv4 into IPv6 space;
reusing it would change `ipMatch` semantics. Numeric comparisons use checked conversion and
explicit signed arithmetic.
The pinned implementation’s `eq` converts a decimal prefix to a 32-bit signed integer and
treats conversion exceptions as zero, whereas `ge`, `gt` and `lt` use 64-bit `atoll`.
Preserve those distinct domains. Because overflowing `atoll` is not portable, the native
profile reports an explicit numeric-limit outcome outside its signed 64-bit domain. This
difference must be covered by the compatibility report rather than labelled a negative match.
Literal `contains` and `within` use length-aware KMP search. Static needles prepare their
prefix tables off-path; macro-expanded needles prepare in bounded transaction scratch.
Capture-producing operators write transaction-owned slices or offsets, never temporary stack
references. Detector parity is checked against upstream libinjection, including fingerprints
and error outcomes. Third-party data and code retain their own license notices.

== Transaction views and macro expansion

A shared variable view contains typed collection entries, borrowed name/value bytes and
per-collection coverage for the current phase. Empty, absent, unavailable and incomplete
collections are distinct. Fixed ASCII key comparison preserves the pinned reference's
case-insensitive dictionaries without its locale-dependent conversion of signed bytes.
Transaction entries retain their input order; selectors may evaluate every duplicate.
Macro expansion cannot reproduce an unspecified C hash-table iteration order reliably.
If a macro reference selects more than one value, return an explicit ambiguous-variable
outcome rather than pick an undocumented value. The stock macro profile uses exact keys
or scalar variables; a bare keyed collection and nested macro references reject compilation.
These constraints appear in the compatibility report and do not erase duplicate inputs.

Compile each runtime string into literal and typed-reference parts off-path, bounded by
64 KiB of source and 1,024 parts. `%{TX.name}` and `%{TX:name}` select the same key; a key
retains dots after its first collection separator. Unknown collections, malformed braces,
empty keys and NUL source are diagnostics. Missing keys in a complete collection expand
to an empty string, matching the pinned runtime-string evaluator. An unavailable or
incomplete collection is an error even if a conveniently matching entry is present.
Expanded values are bytes and are not recursively parsed as additional macros.

Expansion borrows caller-owned piece scratch and a disjoint output buffer. Resolve all
parts, validate coverage and unique selection, add lengths with checked arithmetic and
reserve the output-copy work before writing output. Every entry scan, key comparison,
part and copied byte debits the transaction budget. Source and entry lifetimes cover the
whole expansion. The view has no callbacks, SQL, network operations or allocation.

*Lemma (atomic bounded expansion).* For $P$ parts, $E$ entries and maximum key length $K$,
resolution costs at most $O(P E K)$, charged to the shared budget; copying costs $O(L)$
for the checked expanded length $L$. Each resolved part occupies one caller-owned slice.
No output write occurs until every lookup, capacity check and copy-work reservation has
succeeded, so a rejected expansion leaves output unchanged. Copies then cannot fail under
the disjoint-buffer and lifetime invariants. No partial argument can be mistaken for a
completed expansion, and injected `%{...}` bytes in values cannot add lookup work.

Transforms required by this release are `base64Decode`, `cmdLine`, `compressWhitespace`,
`cssDecode`, `escapeSeqDecode`, `hexEncode`, `htmlEntityDecode`, `jsDecode`, `length`,
`lowercase`, `none`, `normalizePath`, `normalizePathWin`, `removeCommentsChar`,
`removeNulls`, `removeWhitespace`, `replaceComments`, `sha1`, `urlDecodeUni` and
`utf8toUnicode`. There are 20 names including the reset action `none`. Output expansion is
checked before writing. Invalid encoding is interpreted as specified by the transform and
validation operators; truncation is an error, not a transformed field.

The byte profile fixes ASCII case conversion and C-locale whitespace. In particular, the
reference `removeWhitespace` also removes isolated `0xc2` and `0xa0` bytes, while
`compressWhitespace` preserves them. A Unicode-aware replacement would change rule
semantics and is not interchangeable. Numeric `length` counts bytes, not code points.
Each primitive receives disjoint caller-owned input/output buffers and the shared work
budget. It checks a conservative output bound before writes: identity, lowercase and
filtering need at most $N$ bytes, hex encoding needs $2 N$, and length needs the decimal
digit count of $N$. Capacity multiplication is checked. These primitives perform a bounded
number of visits per input byte, so their time is $O(N)$; composing $T$ stages costs the
sum of stage lengths, including expansion. The last local `t:none` suppresses inherited
transforms and all local transforms through that reset. A `t:none` in default actions
rejects the candidate even if a local reset suppresses those inherited transforms.
Ordered duplicates remain.

Ordinary matching consumes the final value. `multiMatch` consumes the original and each
stage whose reference transform reports a change. This flag is not byte inequality:
`compressWhitespace` can replace a lone tab with a space while reporting no change, and
`length` always reports a change, including `"1"` becoming `"1"`. There is no additional
final value when the last stage reports no change. The native iterator borrows two reserved
buffers and terminates permanently on any resource error. Consumers must finish each match
and preserve required captures before advancing. Transform iteration is not a transaction
executor: no rule effects may be published from a resource-limited partial evaluation.
The reference materializes all stage values before matching; the executor must demonstrate
equivalent ordering of repeated match effects rather than stop after the first match.

Escape, command-line and comment transforms use monotone bounded scans. Escape decoding
consumes one literal byte or one escape of at most four bytes; unknown escapes discard
the backslash, incomplete hexadecimal escapes retain their following bytes, and octal
escapes retain the low eight bits. Command-line normalization removes quotes, backslashes
and carets, compresses its specified separators and removes a preceding space before
`/` or `(`. Its change flag compares lengths, even when case conversion changes bytes.
Comment-marker removal preserves comment contents; comment replacement consumes a complete
or unterminated `/*` comment and emits one space. These are distinct operations.

*Lemma (scan bound).* Every scan iteration advances the input cursor by at least one, with
at most four escape probes and one output byte. Marker removal checks six fixed strings
of at most four bytes. Command-line space removal only decreases
the output cursor. Hence output capacity $N$ suffices and time is $O(N)$, with no recursion
or rescanning. Reserve $8 N + 1$ work units before writing, or $32 N + 1$ for marker
removal; arithmetic overflow is a work
limit error. SHA-1 emits its 20 binary digest bytes, rather than hexadecimal text. Its
charged work is $N + 80 ceil((N + 9) / 64) + 1$, covering the input and all compression
rounds including padding. SHA-1 here is a compatibility transform, not an authentication
or artifact-verification primitive.

The pinned primitive corpus is a compatibility subset. The test adapter reproduces its
length-aware binary escapes and C-string JSON boundary. One escape-decoder fixture embeds
`\xga`, which the reference harness matches as a hexadecimal token but cannot parse: its
unchecked `sscanf` result is uninitialized. The digest manifest identifies this fixture
explicitly; it cannot provide deterministic conformance evidence. Native tests cover invalid
escapes directly, and the checker fails if the recorded exception stops being undefined.
Three byte-range fixtures exercise an operator after failed initialization, which the
reference unit runner ignores. The checker first requires native compilation to reject
each fixture, then checks the historical empty-table result through a test adapter.
That adapter is not linked into the daemon and does not permit invalid candidate activation.

CSS decoding consumes up to six hexadecimal digits and one following C-locale whitespace
byte; an escaped newline and trailing backslash disappear. An unrecognized CSS escape
removes the backslash without setting the reference change flag. JavaScript decoding uses
four-digit `\u`, two-digit `\x`, C escapes and octal escapes bounded to one byte; a
three-digit octal escape above `377` consumes two digits instead. URL decoding recognizes
`%xx`, `%uHHHH` and `+`. These three transforms retain the low byte and fold full-width
ASCII `ff01` through `ff5e` by adding `20` to it. No Unicode map table is configured in
the initial compatibility profile; a candidate requiring such a table is unsupported.
All decode lookahead is bounded by seven bytes, each step consumes input, and output is
at most $N$. Reserve $16 N + 1$ work units before writes, including the unchanged stages.
This byte profile must not be substituted with a Unicode string decoder.

HTML entity decoding recognizes the reference's five case-insensitive name prefixes
(`quot`, `amp`, `lt`, `gt`, `nbsp`) and decimal/hexadecimal numeric entities with optional
semicolons. It scans an entire alphanumeric name, including a suffix after a recognized
prefix. Numeric entities use a fixed signed 64-bit positive `strtol` profile with saturation
at its maximum, then retain the low byte; the result is independent of the host C ABI.
Unknown entities retain their bytes. Scanning and copying consume each input range a
bounded number of times, with $N$ output capacity and $32 N + 1$ reserved work.

The base64 profile pins Mbed TLS commit `2ca6c285a0dd3f33982dd57299012dacab1ff206`,
the submodule selected by ModSecurity 3.0.14, including its alphabet/padding and whitespace validation:
LF and CRLF are permitted, spaces are permitted before a line ending or at the end,
and embedded spaces or tabs are invalid. At most two trailing `=` are allowed. It emits
complete four-character groups and discards an incomplete final group; a newer decoder
that rejects the entire value would erase a valid prefix and change detection. Nonempty
invalid input becomes empty, as in
ModSecurity's wrapper. The wrapper's C-string boundary means the first input NUL ends
base64 input; the outer transform's change flag still uses the original byte length.
Validation precedes decoding, each is $O(N)$, capacity $N$ suffices, and $8 N + 1$ work
is reserved. This versioned profile is explicit; a finite vector pass does not establish
equivalence with arbitrary builds using another version of Mbed TLS.

= Algorithms and mathematical contracts

`utf8toUnicode` is a permissive compatibility transform, not the validation operator.
It emits lowercase `%u` hexadecimal with at least four digits for structurally complete
two-to-four-byte sequences. Overlong encodings and surrogates append their original leading
byte after the escape; both conditions can apply. Leading `f5` through `f7` are also copied
before that escape. Invalid or incomplete sequences in the `c0` through `f7` classes consume
their first byte, while isolated continuation bytes and bytes at least `f8` remain literal.
Nonfinal NUL bytes disappear; a final NUL remains. These quirks follow the pinned source,
whose sentinel-backed lookahead is replaced with explicit slice-length checks.

Each iteration consumes a literal byte, an invalid leading byte, or a complete sequence.
The largest output for a two-byte sequence is seven bytes, for a three-byte sequence seven,
and for a four-byte sequence nine. Thus $4 N$ output capacity suffices, checked before
writes, and $32 N + 1$ work covers bounded probes and hex output. The reference change flag
is set for complete multibyte conversion, not for every dropped or copied invalid byte.
Neither the original path nor protocol input validation may be replaced with this transform.

Path normalization preserves the reference's byte-cursor semantics, including relative
backreferences, repeated separators, trailing separators and the Windows variant's
backslash conversion. It is not filesystem resolution, URL decoding or symlink traversal.
The reference recognizes a backreference from the final two emitted dots at a segment
boundary; replacing it with an operating-system path API would change rule behavior.
Native indices saturate at the root where the reference temporarily forms a pointer before
the buffer; no pointer arithmetic outside an allocation is performed. The reference's
change flag is retained, including a final backreference that changes bytes without setting it.
For example, `/..` becomes empty in this profile; this transform must never be reused to
authorize filesystem paths or alter the path forwarded to the origin.

*Lemma (normalization amortization).* The input cursor only advances. Each output byte is
written once and can be removed by at most one backwards scan. Charging removals against
their preceding writes bounds all backwards scans by $N$. Hence normalization costs $O(N)$,
requires $N$ output bytes, and reserves $16 N + 1$ work; it needs no segment-stack allocation.

== Definitions and axioms

Let a program contain $R$ rule conditions, at most $S$ regex states per expression and a
transaction contain at most $F$ selected fields of maximum length $N$. Let $B$ be the
transaction work budget and $C$ its total owned byte capacity. A primitive consumes work
before performing it. Source limits and multiplication are checked before allocation.

*Axiom A1 (input identity).* The proxy and inspector agree on the validated request framing
and on the bytes forwarded to the origin. This is an integration assumption tested with
Content-Length, chunked bodies, duplicate headers and malformed framing; it is not a proof
that arbitrary upstream proxies parse the same way.

*Axiom A2 (generation lifetime).* A pinned generation is immutable and cannot be reclaimed
until every borrower releases it. The lifetime proof below depends on this ownership rule.

*Axiom A3 (reference semantics).* The pinned SecLang reference and its tests define the
selected compatibility profile. Passing a finite test corpus is evidence of compatibility, not
proof of detection of every possible attack.

The initial regex reference is ModSecurity 3.0.14’s implementation, with the LF byte
profile and `DOTALL | MULTILINE` compilation defaults. An empty expression becomes `.*`;
collection-key regexes additionally use case-insensitive matching. Scoped pattern options
can override those defaults. The reference manual’s older dot/end-anchor description does
not match this implementation, so differential checks pin the source behavior explicitly.
Generic PCRE-default tests alone are insufficient to establish SecLang compatibility.

*Axiom A4 (finite capacity).* Inputs and intermediate representations fit the published limits,
or evaluation returns an explicit limit outcome. The engine must never silently truncate a
field, collection, transform, macro expansion, capture or instruction sequence.

== Lemma 1: linear source reading

A reader advances its source cursor monotonically and visits each source byte a constant
number of times for newline, quote and escape handling. Therefore reading $L$ source bytes
costs $O(L)$ time and $O(K)$ caller-owned scratch for maximum logical-line length $K$.

*Proof.* Each state transition consumes a byte or returns a token. Continuation recognition
uses bounded lookahead and never searches backwards. Quoting changes state without
revisiting earlier input. Capacity rejection terminates the read. Summing the bounded work
per consumed byte gives the stated time bound. Action-list splitting has the same argument.

== Lemma 2: bounded regular-expression simulation

For the regular subset supported by the compiler, a Thompson program with an ordered Pike
simulation visits each active state at most once per input position. Its Boolean matching
cost is $O(S N)$ and scratch is bounded by the program and capture-slot counts.

*Proof.* The epsilon closure marks a state before following its outgoing edges. Each state
has bounded out-degree, so closure work is $O(S)$. Processing one byte advances those
states once. Ordered thread insertion selects the highest-priority equivalent thread. There
are at most $N + 1$ positions. Capture priority and greedy/lazy behavior require a separate
conformance check; the Boolean bound does not prove PCRE capture equivalence.

Backreferences, recursive patterns and unsupported PCRE extensions reject compilation.
They are not approximated by a regular language. Unbounded repetitions of nullable
capture-producing expressions are also rejected: ordinary first-arrival state deduplication
does not reproduce PCRE’s final empty capture. Supporting that form requires a separately
verified lowering. The initial stock release does not require it. Possessive quantifiers and atomic behavior
require explicit compatible handling or rejection. The release audit must analyze parsed
regex syntax, not infer features by searching for punctuation substrings. Unanchored matching
adds start threads at each position in the same simulation; restarting a matcher for every
suffix would introduce an avoidable quadratic bound.

== Lemma 3: linear literal search

For a literal needle of length $M$ and input of length $N$, KMP preparation and matching
cost $O(M + N)$ time and $O(M)$ caller-owned prefix storage. On a mismatch, the matched
prefix length strictly decreases; it can increase at most once per consumed byte. Thus
the total fallback steps are bounded by the total advances. Charge each comparison before
performing it. Empty needles match at offset zero, byte equality retains embedded NUL, and
work exhaustion returns a limit outcome rather than a negative match.

== Byte and encoding validation bounds

Byte-range validation compiles inclusive decimal ranges into a 256-bit membership table.
It rejects empty, reversed and out-of-byte ranges before activation. The reference's
decimal-prefix parsing is retained, including leading whitespace and `+`; trailing suffixes
do not change a parsed number. Inspecting a field counts every out-of-range byte and records
the first and last offset without allocating. Construction is $O(L + 256 K)$ for $K$
ranges and source length $L$; matching is $O(N)$ with 32 immutable bytes of table storage.
Reserve $4 N + 1$ work before matching. Set union is idempotent, so duplicate and overlapping
ranges cannot change membership or double-count a byte.

UTF-8 validation separately pins ModSecurity 3.0.14's byte behavior. It rejects incomplete
sequences, bad continuations, overlong encodings, surrogates and leading bytes at least
`f5`. Its `f4` branch accepts some values above `10ffff`; this is a documented reference
quirk, not RFC 3629 validation. The CRS primitive must remain distinct from strict Unicode
validation used by protocol and structured-input parsers. Each successful step advances
one to four bytes; lookahead checks remaining length before reads. Reserve $8 N + 1$
work before validation. An invalid encoding is a positive validation-operator match;
resource exhaustion is a separate error, never a negative match.

== Phrase automata and reference profiles

Phrase programs own their dictionary and use sparse sorted byte edges, breadth-first
failure construction and caller-free matching. ASCII case folding is fixed. At most 256
edges leave a node, so binary lookup takes at most nine comparisons. Construction bounds
dictionary bytes, phrase count, node count and charged work; it has no recursive tree walk.
Empty dictionaries match nothing. Empty phrases and NUL-bearing phrases reject compilation:
the pinned reference's phrase allocation uses `strlen` even when it receives a longer
explicit length, so binary NUL phrases do not provide a safe compatibility target.
The reference profile also rejects non-ASCII dictionary bytes: its signed-character
conversion passes negative values to locale case folding. Binary input fields remain valid;
the general native profile has unsigned byte edges.

The general Aho–Corasick profile follows failure links to the longest suffix with a
transition. The ModSecurity 3.0.14 profile instead preserves two source quirks: construction
checks only the parent's immediate failure node, and a suffix match captures the current
node's original prefix text rather than the matched suffix. Dictionary insertion order fixes
that text, including case. The compatibility profile must be named explicitly; improved
general matching must not silently change `TX.0` or which rules add anomaly scores.

Sibuna's security execution adopts the complete unsigned-byte profile, with the original
matched dictionary phrase as capture. The legacy profile is a diagnostic comparison tool,
not a console setting that can weaken protection. This is an explicit semantic correction:
`aabcx` and `bc` against `aabc` must detect `bc`, and `abcd` and `bc` against `ABC` must
capture `bc`, rather than the reference's missed match and `abc` capture respectively.
Stock CRS contains non-ASCII phrases, including SSRF addresses and web-shell markers, which
remain executable. The artifact ABI identifies this native phrase profile and its conformance
report lists these known reference differences. It must not claim byte-for-byte ModSecurity
equivalence. All other unexplained detection or capture mismatches still fail the gate.

*Lemma (phrase search bound).* A successful transition increases depth by one and every
failure strictly decreases it. Summed over $N$ input bytes, there are at most $N$ depth
increases and $N$ failure steps. Binary edge searches cost $O(log 256)$ each, hence matching
is $O(N log 256)$ with constant transaction state. Every lookup and consumed byte is charged
before execution. For the general profile, the failure invariant establishes complete
dictionary matching; that correctness statement does not apply to the reference's shortened
construction. Both profiles require independent result and capture tests.

Inline phrase arguments retain the pinned quoting, escape and binary-pair parser, followed
by C-locale whitespace splitting. Invalid escape/binary syntax falls back to the original
literal argument as the reference does; a decoded NUL still rejects compilation. Phrase-file
input is supplied from the verified artifact, never a request-time path or URL. LF separates
lines, empty lines and whitespace-prefixed `#` comments are skipped, and all other bytes
remain literal, including a CR and whitespace-only lines. Both paths enforce byte and
phrase bounds before constructing the owned automaton, and release temporary input storage
on every failure. Dictionary formatting is part of the operator semantics.

== Address sets and family isolation

An address set owns sorted inclusive intervals, ordered by family and unsigned network
value. IPv4 uses 32 bits and IPv6 uses 128 bits. An IPv4-mapped IPv6 literal remains IPv6,
matching the reference's separate trees. Private and reserved addresses remain eligible:
this is a security predicate, not a GeoIP public-address classifier.
The pure length-aware parser follows RFC 4291 section 2.2, including exactly one `::`
that elides at least one group and a dotted decimal tail on any IPv6 prefix. It writes
at most eight 16-bit groups, rejects excess or empty groups before indexing, and never
uses the socket library's special-case IPv4-mapping parser. Accepted address text is
at most 45 bytes. Eight charged byte visits per input byte cover family selection,
delimiter scans and digit parsing; the fixed group array is transaction-local.

For an address $a$, family width $w$ and prefix length $p$, let
$s = floor(a / 2^(w-p)) 2^(w-p)$. The interval is $[s, s + 2^(w-p) - 1]$.
Host prefixes use a zero host mask and `/0`
uses the whole family; the implementation handles these boundaries without shifting by
the integer width. Overlapping or adjacent intervals of the same family merge. Compilation
uses bounded iterative merge sort with charged copies and comparisons, then one merge scan.
It limits source bytes and prefix count before allocation, owns the resulting intervals,
and frees intermediate storage on every failure. Matching has no allocation or recursion.

*Lemma (address-set equivalence).* Each CIDR describes exactly its inclusive interval.
Merging overlapping or adjacent intervals preserves their union and cannot cross a family
boundary. After merging, membership is determined by the last interval whose start is no
greater than the address: any earlier interval ends before that interval begins. Binary
search therefore gives the same Boolean result as testing every original prefix.
Compilation costs $O(B + P log P)$ for $B$ source bytes and $P$ prefixes; lookup costs
$O(log P)$ after bounded literal parsing. Every comparison and copy is charged before
execution. A work-limit error is not a negative predicate result.

LF-delimited source supports comma lists and `#` comments, without network or file access
on the request path. Empty comma elements are skipped as in the reference. CIDR suffixes
are strictly decimal and within the family width; whitespace, zones, NULs, trailing junk
and malformed addresses reject compilation. Invalid input fields match nothing, rather
than resolving names. The native profile intentionally accepts valid `/0` and IPv6 `/128`
prefixes: the pinned reference rejects `/0` and mishandles an explicit IPv6 `/128` suffix.
Its permissive `atoi` suffix parsing and C-string truncation are not safe native contracts.
These declared differences belong to the artifact compatibility report; valid stock CRS
lists and the defined upstream membership vectors must otherwise agree.

== Structural detector tables

The SQL detector ports the libinjection commit selected by ModSecurity 3.0.14,
`b9fcaaf9e50e9492807b23ffcc6af46ee1f203b9`. Its 9,352 keyword and fingerprint entries
are a versioned immutable byte asset, not source strings searched by a general rule
interpreter. Reproducible extraction validates the pinned source digest, exact entry count,
strict ASCII ordering, unique keys, type codes and maximum 29-byte key length. The asset
contains a little-endian offset/length index and concatenated keys; compilation validates
every index and the format before exposing any lookup. Both source and generated-data
digests are retained with the upstream BSD license. No C library or runtime compiler is
required to use this table.

*Lemma (dictionary lookup bound).* ASCII case folding preserves each byte's fixed ordering.
Binary search halves the remaining key interval on each comparison, so a lookup compares
at most $ceil(log_2(K + 1))$ keys for $K$ entries, each of length at most 29. Every compared
byte and search iteration is charged before reading it. Empty, longer, NUL-bearing and
non-ASCII queries cannot equal a table key. They must never trigger locale conversion or
read outside their supplied length. The table lookup is not a SQLi decision: the detector
still requires its pinned tokenization, folding, context passes, fingerprint and whitelist.
CRS capture stores the resulting fingerprint in transaction-owned memory.

SQL tokenization uses one bounded context shared by its lexical routines: borrowed input,
caller-owned prefix scratch, cursor, dialect/quote selection, counters and the transaction
budget. Tokens own a 32-byte value array and retain the reference's maximum 31-byte value,
source position, variable prefix count and opening/closing quote markers. This is detector
state, not truncation of forwarded application data. Nonempty tokens consume input; skipped
control bytes also advance the cursor. A resource failure permanently terminates that
tokenization context, preventing callers from treating a later empty result as success.

The port retains the pinned comment, operator, number, bracket-word, variable and quoted
string grammars, including C-string membership quirks for embedded NUL. Oracle alternative
quotes retain the reference's signed-byte delimiter restriction explicitly. Quoted strings
scan forward; checking a preceding backslash run is charged to that disjoint input run.
PostgreSQL dollar-string delimiters can be long. Use the already proved length-aware KMP
matcher with caller-owned prefix scratch instead of the reference's potentially quadratic
substring scan; insufficient scratch is an explicit capacity error. Token copying is bounded
by 31 bytes and every input visit, dictionary comparison and copy is charged. Token parity
must compare kind, position, bytes, prefix counts and quote markers, not just the final
attack Boolean. Tokenization and dictionary lookup alone are not an executable detector.

SQL folding keeps the pinned eight-token array and at most five final fingerprint tokens.
The extra token supplies lookahead for the fifth token. Ordered pair and triple rewrites,
compound-word merging, trailing-comment handling and the five-token reductions must retain
their reference order, counters and source metadata. Fixed-array copies debit their bound
before writing. Rewrites that keep the window size change a token kind; reductions decrease
the window size, and reading advances the source cursor. Independently of any amortized
argument, every loop iteration debits work, so an unexpected rewrite cycle terminates with
an explicit work-limit error. No unproved linear-time claim is made for the whole detector.
The lexical routines, table and finite token window bound per-step work and memory.
Fingerprint parity is checked with the exact pin before using the blacklist and whitelist;
a fingerprint by itself is not an attack decision.

`detectSQLi` performs the reference's at-most-five ANSI/MySQL and simulated-quote passes.
The keyword-table fingerprint blacklist is followed by its small-pattern whitelist, with
the original token counts, quote boundaries, trailing comments and case-sensitive
`sp_password` exception. Capture is the positive fingerprint, not the original field.
Whitelist checks retain the pin's clipped-length source indexing and signed-byte whitespace
predicate, with explicit length checks before reading. An undefined reference read is an
incomplete detector error, never an invented safe result. Every pass uses the same shared
budget and scratch. A negative result does not erase exhaustion or publish a stale capture.

XSS tokenization uses the same libinjection pin. A finite tagged state replaces its recursive
state callbacks: each step either yields a token, terminates or changes state in one iterative
driver. Data, tag names, attribute names/values, declarations, comments and CDATA keep their
distinct token kinds. Token slices borrow the immutable input and remain within its length.
Five initial contexts represent data and unquoted, single-, double- and back-quoted values.
This is a detector grammar, not an HTML sanitizer or a general browser parser.
The pin's signed-byte attribute-whitespace routine returns `0xff` as its EOF sentinel;
preserve that declared byte-profile behavior explicitly on every native and Wasm target.

*Lemma (HTML tokenizer storage and progress).* State, cursor and one offset/length token
require constant auxiliary storage. Every state dispatch and byte read debits the shared
budget before execution. Attribute slash runs, malformed tag transitions and comment scans
return through the iterative driver, so their length cannot increase call-stack depth.
State-only transitions have bounded fixed work; scanning loops advance a cursor. Exhaustion
poisons the context and cannot be mistaken for end of input. Even a future erroneous state
cycle ends at the work bound. Tests compare every token kind, offset and byte range with the
pin in all five contexts, including empty and binary inputs, before detector use.

`detectXSS` runs those five contexts over one input and one shared budget. Its positive
predicates are the pin's tag and attribute classifications, URL prefixes, declarations and
legacy comment forms. Static event, attribute and tag tables are reproducibly extracted
from the same digest-pinned source; they are detector data with the upstream BSD notice.
The tables contain 298 distinct event names (one duplicate is removed), 20 attribute
classifications and 20 complete tag names. A positive `detectXSS` capture is the evaluated
field, whereas `detectSQLi` captures its fingerprint; the executor must own the captured
bytes before its transformation scratch is reused.
ASCII comparison skips embedded NUL, and numeric HTML references preserve the pinned
decoder's consumed-length and low-byte comparison semantics. Short or malformed references
return their literal ampersand without reading beyond the supplied length. Event-name prefix
comparisons are bounded by the attribute token, even where the C routine reads a fixed
event-name length without checking that token's length. Such undefined reference reads are
excluded from a parity claim. Style values and banned attributes are detected when a value
token occurs, retaining the reference's attribute-state reset ordering. This algorithm is
not evidence that arbitrary HTML is safe, nor a replacement for application output encoding.

*Lemma (XSS decision bound).* There are five passes and finite static classification tables.
Each token, table comparison, numeric-reference byte and comment search is charged to the
same budget. Numeric accumulation checks the fixed maximum before its next multiplication;
indices and consumed lengths remain within the field. The detector allocates no scratch
proportional to the input. Consequently its auxiliary storage is constant and its charged
work cannot exceed the transaction budget. A work error poisons the detector context; a
later context pass cannot convert that error into a negative result.

== Lemma 4: sound prefiltering

A candidate regex may be skipped by a literal prefilter only when the compiler has proven
that every match implies the prefilter predicate.

*Proof.* If matching implies predicate $P$, then absence of $P$ implies absence of a match
by contraposition. A literal found in one alternative does not establish this implication for
other alternatives. Unknown analysis results disable the optimization. Transformed inputs
require predicates over the same transformation stage.

== Theorem 1: bounded evaluation work

Provided every primitive debits the shared transaction budget before executing, total charged
work is at most $B$. Exhaustion returns `work_limit`; it cannot return a successful negative
match. All loops, including transform decoding, macro expansion, selector scans and epsilon
closures, must be covered by the accounting contract.

*Proof.* The budget begins at $B$ and each permitted debit reduces its nonnegative balance.
A debit exceeding the balance terminates evaluation before its work occurs. The sum of
permitted debits cannot exceed the initial balance. This is a work bound, not a wall-clock
latency guarantee: scheduling, memory stalls and body acquisition require separate deadlines.

Without prefiltering, a coarse matching bound is $O(R F S N)$, limited by $B$. This bound
explains why CRS has a distinct performance envelope from Sibuna’s small default inspector.
No claim that hundreds of independent patterns cost one scan is made.

== Theorem 2: score isolation and conditional monotonicity

For a detection rule that adds a nonnegative severity $w$ to a paranoia-level score $a_p$,
checked arithmetic gives $a'_p = a_p + w >= a_p$. The blocking score is
$A = sum_(p=1)^P a_p$ for blocking paranoia level $P$; threshold $T$ blocks when $A >= T$.
Detection paranoia level may be higher and must be reported separately.

*Proof.* Addition of a nonnegative integer preserves order when no overflow is permitted.
Summation preserves that relation. Arbitrary `setvar` actions can reset or subtract scores,
so monotonicity is conditional on the stated action, not a property of every SecLang program.
CRS scores never overwrite policy WEIGH scores, paid challenge work or a pre-existing denial.

== Theorem 3: coherent publication

Under A2, a transaction pinned to generation $g$ observes rules, data tables, exclusions and
configuration from $g$ for all its phases, even if $g + 1$ is published concurrently.

*Proof.* Pinning yields a reference to immutable owned storage. Publication changes the
pointer used by later acquisitions and does not mutate that storage. Reference ownership
prevents reclamation before release. A response cannot acquire a fresh generation halfway
through a transaction. Restart publication uses the last completely validated manifest.

== Theorem 4: no partial activation

A rejected candidate cannot change the active generation when all validation precedes the
single publication operation and durable state names complete immutable artifacts.

*Proof.* Parsing, verification and compilation operate on privately owned candidate storage.
Failure destroys that storage and leaves the active pointer unchanged. Successful publication
references the completed artifact. Database intent and runtime completion remain separate;
a node that cannot apply the committed revision reports failure and retains its prior generation.

These proofs concern execution and ownership. They do not prove that CRS eliminates bot
traffic, that a payload is safe, or that all applications tolerate a given blocking threshold.

= Input acquisition and HTTP phases

#table(
  columns: (1fr, 2fr, 3fr),
  [Phase], [Input], [Publication boundary],
  [1], [Request line and headers], [Before acquiring or forwarding a protected body],
  [2], [Complete decoded body and parsed fields], [Before origin receives protected request bytes],
  [3], [Validated response status and headers], [Before client receives the response head],
  [4], [Complete selected response body], [Before client receives a protected response body],
  [5], [Final transaction state], [Logging; cannot undo bytes already sent],
)

Request acquisition decodes HTTP transfer framing once and supplies the same entity bytes
for inspection and replay. Chunk extensions and trailers are validated by the transport.
URL-encoded fields retain duplicates; JSON has bounded depth and stable flattened paths;
XML forbids external entities and network access; multipart parsing separates field values,
file names, part headers and file payloads. Binary file contents remain file data unless a rule
selects raw body bytes. MIME metadata is not trusted as proof that a payload is harmless.
Parsing errors populate the corresponding collection/error semantics and cannot masquerade
as an empty valid document. Ambiguous framing is rejected before CRS evaluation.

The enforcing reverse-proxy profile holds the bounded request before sending it to the origin.
Response-body enforcement holds eligible MIME types before sending the response head.
Content encoding requires bounded decoding with an expansion limit; inspection of compressed
wire bytes is not inspection of the decoded representation. Oversize and timeout outcomes
have explicit policies. The safe enforcing default refuses an uninspectable protected body;
operators can configure a documented streaming exclusion for a route or MIME type.

WebSocket upgrades inspect the HTTP handshake and then become a tunnel. CRS does not
inspect WebSocket frames. Server-sent events and other indefinite responses use an explicit
streaming profile without phase-4 body enforcement. The UI reports the missing coverage.
A completed body must never be required for a tunnel or an intentionally streaming response.

Forward-auth observes the authenticating proxy’s forwarded request metadata, not the origin
body or response. It offers a named headers profile and reports phases 2–4 as unavailable.
A full-body enforcing profile is rejected in forward-auth mode. Console status and audit
records distinguish full reverse-proxy coverage from metadata admission.

= Resource limits and failure policy

The compiler stores configurable bounds in the generation manifest. Initial hard ceilings are
8 MiB downloaded archive, 32 MiB extracted source, 256 files, 64 KiB logical line, 4,096 rule
conditions, 256 conditions per chain, 16,384 states per regex and 64 MiB compiled program.
All capacities are checked with overflow-safe arithmetic. A supported stock release that
exceeds them is rejected and diagnosed; ceilings are reviewed from measured requirements.

Initial transaction defaults are 4 MiB of request entity data, 1 MiB of eligible response data,
1,024 collection entries, depth 64, 256 KiB aggregate collection/macro storage and 16 million
charged work units. Byte scratch and capture storage are sized off-path from the candidate.
These values are proposal defaults, not measured guarantees or an application-upload limit
when CRS is disabled. Larger configured bounds require a displayed memory reservation and
benchmark acceptance before use. Eight simultaneous acquisition slots reserve at least
40 MiB for request and response entity bytes, before metadata and matcher scratch.

Pool exhaustion returns a recoverable service-unavailable response. Body size limits return
an explicit refusal before origin delivery. Work exhaustion in enforcement refuses the
transaction; audit mode records an incomplete evaluation and continues according to its
explicit audit policy. Invalid compiler input cannot enable audit or enforcement implicitly.
Capture and incident queues retain bounded loss counters; logging loss must not reverse a
decision. Error responses disclose neither payload secrets nor internal traces.

= Operator configuration and updates

Proposed startup controls are `--crs` (enable enforcement), `--no-crs` (disable),
`--crs-mode off|audit|enforce` and `--crs-dir`,
`--crs-paranoia`, `--crs-detection-paranoia`, `--crs-request-limit`,
`--crs-response-limit`, `--crs-work-budget` and `--crs-slots`. Thresholds and exclusions
are explicit configuration with revisions. CRS starts disabled. Conflicting enable/disable/mode options are rejected rather than
resolved by argument order. The console provides the same Off, Audit and Enforce controls;
a mode change is an authorized revision, not a browser-local toggle. Off skips CRS
evaluation, input holdback and telemetry production while retaining the verified artifact
for a later reviewed activation. CRS enforcement and Gate admission are independent
choices; enabling CRS does not silently switch Gate to Shield. Begin application tuning in
audit mode, inspect findings, add narrow exclusions and then select enforcement.
A broad rule exclusion must state the lost protection in the console.

The native command `sibuna crs update` submits an authenticated management job, using the
same service as the console’s *Security → Core Rule Set* page. `--version` selects a tagged
release; omission checks the latest stable official release. `check`, `status` and `rollback`
share bounded typed request/response contracts. Offline `validate` accepts an extracted
candidate without starting the daemon and reports syntax, feature and capacity diagnostics.
There is no unauthenticated network endpoint or shell command invocation in the service.

Engine deployments without the console retain a file-based update path. The native updater
verifies and compiles the artifact off-path, then replaces a versioned manifest in the
operator-owned `--crs-dir`. The daemon’s bounded reload task validates that manifest and
publishes a complete generation. Expected manifest revisions, atomic replacement, durable
intent/completion and the previous verified artifact provide conflict and recovery semantics.
Filesystem permissions authorize this local path; it does not open an unauthenticated
management listener or require the AGPL console for the LGPL engine’s rule updates.
Clustered deployments use the storage owner’s revision discipline rather than independent
file writers. Both paths share verification, compilation and publication code.

Update stages are retrieve metadata, download, verify signature and digest, safely unpack,
read, compile, run candidate checks, persist intent, publish and record completion. The
console shows a release diff, excluded rules, memory/work bounds, selected profile, committed
revision and node application status. Activation requires an expected revision and a fresh
administrator authorization; CLI authentication is not an implicit privilege bypass. Downloads
run off the request path with bounded concurrency, connection/read deadlines and cancellation.

The trust root is the pinned CRS signing fingerprint
`36006F0E0BA167832158821138EEACA1AB8A6E72`, with explicit operator-reviewed key rotation.
Upstream detached OpenPGP signature verification must be implemented or supplied by an
audited portable verifier before online activation ships. TLS and an asset digest alone do
not establish independent upstream signature authenticity. The public key is not fetched
and trusted afresh from the same download during every update.

Repository scope is fixed to `coreruleset/coreruleset`. Release tag and asset names are parsed
strictly; prereleases and floating branches are not selected automatically. HTTPS redirects
are limited to the official asset hosts. The downloader limits compressed and expanded bytes,
rejects absolute paths, parent traversal, duplicate names, devices, symbolic/hard links and
unexpected archive members, and does not execute repository tooling. Phrase-file references
resolve within the verified generation directory. Local overrides remain separate from upstream
files and are reapplied, validated and hashed into the effective candidate.

Persisted manifest fields include upstream tag, archive digest, signing fingerprint, compiler
ABI, compatibility profile, effective configuration digest, rule and byte counts, revision,
previous revision and artifact state. Intent and redacted audit are committed together.
Publication completion records its actual outcome. Restart selects a complete validated
artifact; orphan staging artifacts are reclaimed within a quota. Retain the current and previous
generations plus bounded staging space. Rollback is a new reviewed revision, not pointer
mutation without history. An incompatible binary refuses the artifact and explains recovery.

Cluster nodes validate the same content-addressed artifact and report applied revisions.
Large rule archives do not travel in telemetry WebSockets. Artifact transfer uses the
bounded authenticated management channel or independent verified retrieval. Nodes with an
unapplied security revision are visibly unhealthy; policy enforcement must not report them
as converged. Concurrent updates use existing storage-owner compare-and-swap discipline.

= Console and evidence

The page presents current release, mode, coverage, thresholds, paranoia levels, last verified
update, effective exclusions and node convergence. The update form separates checking a
release from activating it and shows concrete incompatibility diagnostics. Operators can
switch to audit, add a narrow target exclusion, test a captured redacted candidate, activate a
validated update and roll back. The live feed uses existing bounded subscription contracts.

Incidents retain generation digest, CRS rule ID, message, tags, phase, severity, paranoia level,
score contribution, final threshold decision and coverage/limit outcomes. Matched values,
headers and bodies follow SID 0007’s redaction and capture policy. No credentials or full file
payloads are logged implicitly. Missing matches caused by incomplete inputs are labelled
incomplete rather than zero. Existing engine incidents and CRS findings remain distinguishable.

= Verification and acceptance

1. Reader and compiler tests cover comments, quoting, continuations, duplicate IDs, inherited
   phases/defaults, chained rules, marker resolution, exclusions and every selected release file.
   The native inventory must agree with independently checked source counts.
2. Operator and transform tests use upstream vectors and differential results from pinned
   ModSecurity/PCRE2/libinjection. Include embedded NUL, non-ASCII bytes, invalid UTF-8,
   every capture, duplicate fields, macro expansion, negative arithmetic and overflow.
3. Regex tests verify Boolean matches and captures, alternate priorities, anchors, character
   classes, scoped flags, greedy/lazy behavior, counted repeats and adversarial work limits.
   Fuzz the parser and matcher against PCRE2 within the supported syntax profile.
4. Run the selected CRS release’s FTW corpus against a real daemon. Record expected rule
   IDs, scores and disruption behavior. Document reference differences rather than rewriting
   tests to accept a weaker detector. Every selected stock directive must compile.
5. Live proxy tests cover full Content-Length and chunked uploads, multipart files, JSON/XML,
   compressed responses, long streams, origin failure, redirects, WebSocket upgrades,
   challenge admission and forward-auth headers. Uninspectable bodies must not reach the
   origin under the full enforcing profile. Preserve existing regressions from SID 0009.
6. Update tests exercise bad signatures, truncated downloads, traversal archives, missing data,
   incompatible syntax, compilation capacity, canceled callers, saturated queues, stale revisions,
   failed publication, restart, rollback and three-node convergence. Every failure retains the
   prior effective generation and records an honest completion outcome.
7. Chrome tests cover the update, incompatibility, mode, exclusions, testing and rollback flows,
   accessibility, aligned forms, responsive layouts and stale/reconnected subscriptions.
8. Run `zig build fmt test sid -j2`, native CRS tests and all console/cluster gates. Compile
   Linux, macOS and native Windows. Check that disabled CRS has no telemetry or evaluation
   work and that offline validation needs neither storage nor console.
9. Regenerate measured request-path benchmarks on separate load/service hosts. Compare
   CRS disabled, audit and enforce at paranoia levels 1 and 2, small requests, JSON bodies,
   multipart uploads and eight dashboards. Report CPU, peak reservation, work-limit rates,
   throughput, latency distributions and host/container scheduling limits. CRS performance
   is reported separately from the existing lightweight inspector. An inconclusive result
   cannot be described as a passed performance gate.

= Delivery and status

Deliver independently reviewable chunks: source contracts and diagnostics; full candidate
compiler; regex/operators/transforms; structured acquisition and phased transactions;
immutable policy integration; verified artifact/update service; CLI; console; compatibility and
performance evidence. Foundation commits must not expose a production “CRS enabled” flag
until the executable compatibility gate is satisfied. Documentation distinguishes implemented
capabilities from this design throughout delivery.

Promotion assigns a permanent discussion number under SID 0001. It is not acceptance of a
finished implementation. The record advances to Committed after the gates above pass;
Published requires a normative implementation and reproducible compatibility evidence.
This document records design decisions and contracts, not a chronological progress log.

= Licensing

The engine is LGPL 3.0 and the console is AGPL 3.0. CRS is Apache 2.0; its downloaded
rules, data and derivative generated tables retain upstream attribution and notices. Other
libraries retain their respective licenses. Companies seeking terms without LGPL or AGPL
may contact the authors. Adding rules does not replace the existing component license policy.

= References

- #link("https://github.com/coreruleset/coreruleset")[OWASP Core Rule Set source and license].
- #link("https://github.com/coreruleset/coreruleset/releases/tag/v4.30.0")[CRS 4.30.0 release].
- #link("https://www.rfc-editor.org/rfc/rfc4291.html#section-2.2")[RFC 4291 address text grammar].
- #link("https://coreruleset.org/docs/1-getting-started/1-1-crs-installation/")[CRS installation and signed releases].
- #link("https://coreruleset.org/docs/2-how-crs-works/2-1-anomaly_scoring/")[CRS anomaly scoring].
- #link("https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)")[ModSecurity SecLang reference].
- #link("https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.14/src/utils/regex.cc")[ModSecurity 3.0.14 regex implementation and compilation defaults].
- #link("https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.14/test/unit/unit_test.cc")[Pinned primitive corpus binary decoding].
- #link("https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.14/src/rule_with_actions.cc")[Reference transform ordering and change flags].
- #link("https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.14/src/rule_with_operator.cc")[Reference per-match effects and chain evaluation].
- #link("https://github.com/owasp-modsecurity/ModSecurity/tree/v3.0.14/src/actions/transformations")[Reference byte transforms].
- #link("https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.14/src/utils/acmp.cc")[Reference phrase failure construction and capture behavior].
- #link("https://github.com/Mbed-TLS/mbedtls/blob/2ca6c285a0dd3f33982dd57299012dacab1ff206/library/base64.c")[Pinned base64 decoding profile].
- #link("https://github.com/owasp-modsecurity/secrules-language-tests/tree/a3d4405e5a2c90488c387e589c5534974575e35b")[SecLang corpus pinned by ModSecurity 3.0.14].
- #link("https://www.pcre.org/current/doc/html/pcre2pattern.html")[PCRE2 pattern semantics].
- #link("https://swtch.com/~rsc/regexp/regexp1.html")[Russ Cox: Regular Expression Matching Can Be Simple And Fast].
- #link("https://swtch.com/~rsc/regexp/regexp2.html")[Russ Cox: Regular Expression Matching: the Virtual Machine Approach].
- #link("https://github.com/libinjection/libinjection/tree/b9fcaaf9e50e9492807b23ffcc6af46ee1f203b9")[Pinned libinjection source, vectors and BSD license].
- SID 0001 (discussion process), SID 0003 (policy), SID 0004 (inspection), SID 0005
  (storage), SID 0006 (mathematics), SID 0007 (console) and SID 0009 (request framing).
