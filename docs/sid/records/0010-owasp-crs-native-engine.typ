#let sid-number = "0010"
#let sid-title = "Native OWASP Core Rule Set Evaluation and Verified Rule Updates"
#let sid-state = "discussion"
#let sid-created = "2026-10-04"
#let sid-discussion = "Native SecLang compilation and bounded CRS evaluation, complete input contracts, anomaly scoring, immutable rule generations, authenticated operator updates, and compatibility gates."
#let sid-labels = ("security", "policy", "performance",)
#let sid-authors = ("Sibuna Contributors <team@sibuna.local>",)
#let sid-category = "Architectural Specification"
#let sid-status = "Open for Discussion"
#let sid-last-updated = "2026-10-06"

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
fingerprint below. Runtime update candidates must also pass the native pinned-key verifier
specified below. Unmodified fixtures and their file digests are in `vendor/crs/provenance.json`.
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
  [`libs/crs-update`], [Off-path, bounded publisher retrieval and authenticated candidate preparation; shared by CLI and console jobs. No daemon or database imports.],
  [`libs/policy`], [Compose CRS with existing inspection and policy; preserve denial precedence.],
  [`libs/net`], [Generic bounded body acquisition and response holdback contracts; no rule knowledge.],
  [`libs/compression`], [Pure bounded gzip/zlib expansion shared by HTTP representation decoding and signed-archive preparation. No allocation or application imports.],
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

== Condition effects and transaction views

A prepared condition composes selection, validated transform replay, the predicate and
local `capture` and `setvar` effects. It is not an executable generation: post-match
controls, disruption, phase scheduling and entity coverage require separate validation.
Evaluate every field and every reported transform stage, rather than returning after
the first match. Apply operator captures, update matched variables, then execute local
transaction writes in source order. Negation reverses predicate truth but does not
invent captures for a failed operator. A successful capture-producing operator writes
captures even when negation subsequently makes that candidate false; unmatched capture
groups do not delete older TX keys. A condition with no matching candidate clears
all four matched-variable collections; it does not undo earlier transaction writes.
Chain traversal evaluates its child once after all parent candidates have run. A failed
child cannot roll back the parent's already executed local writes.

The transaction context borrows immutable acquired entries and owns reserved TX metadata,
matched metadata, monotonic matched bytes and a separate merged-view array. Rebuild the
merged view before each target, predicate and action, so earlier TX writes are visible
without exposing metadata that a write can compact. A target snapshot remains separate
from this merged view. Match values and their qualified names are copied before advancing
transform scratch. Matched lists retain occurrence order and duplicates; their scalar
views refer to the last occurrence. Native input order is deterministic, whereas the
reference's unordered collection traversal does not specify a portable order. Do not
admit externally supplied TX or matched entries into this context.

*Lemma (effect lifetime).* Acquired bytes and generation constants remain immutable,
TX replacements preserve old bytes, matched bytes are monotonic, and target metadata is
copied before mutation. Consequently a target snapshot's byte references remain valid
through its condition's later writes. Rebuilding the separate merged view cannot invalidate
that snapshot. This does not establish equivalence for undefined reference ordering.

*Failure rule.* Any selection, transform, predicate, capture, view-capacity or action
failure poisons the context and TX store. Prior writes remain available only as failure
evidence; replenishing a work budget cannot resume evaluation as a completed rule. The
caller must apply its configured resource failure disposition and return the reserved
slot. Bound metadata copies and matched-byte copies against the same work ledger.

Compile contiguous chain topology separately from condition programs. Validate every
root, continuation ID/phase, forward child link, maximum depth and marker destination
before accepting that topology. The evaluator checks the supplied condition count and
reserves the complete unwind index buffer before the first local effect. Evaluate links
once from root to leaf. On the first false link, return no post-match indices, retaining
the already executed TX writes. Only after every link is true return the indices from
leaf to root for the later post-match executor. Topology preparation and chain truth do
not authorize activation or execute disruption and controls.

*Lemma (bounded chain traversal).* Every child is the adjacent next row, all rows in a
chain share a root/ID/phase, and each chain has at most $C$ rows. Traversal therefore
visits at most $C$ distinct conditions without recursion. The returned reversal is the
same order as reference recursive unwinding. Local effects run before the next link and
remain when a later link is false. This establishes chain traversal and effect visibility,
conditional on each condition's semantics; it does not prove post-match action handling.

The phase cursor visits roots in source order for one selected phase, skipping entire
continuation ranges. It requires completion of a pending root before advancing. Apply
its forward `skipAfter` destination only when the complete chain matched and post-match
actions succeeded. Beginning a later phase resets the scan; phases may be omitted by
an explicitly configured observation profile but may not repeat or run backwards. A
phase is complete only after a scan reports exhaustion with no pending root. Budget
failure poisons the cursor instead of masquerading as normal end-of-phase.

*Lemma (phase termination).* Ordinary advancement moves from a root to its chain end;
a compiled marker destination is a forward root boundary or the terminal boundary.
Both strictly increase the source position. Therefore a phase visits at most the
number of source roots. Five ordered phases perform at most five such scans, excluding
the separately charged condition and action work.

== Transaction controls

Prepare `ctl` into typed body-processor, forced-body, audit and exclusion operations.
The initial profile accepts JSON, XML and URLENCODED processor overrides; On/Off forced
body selection; On/Off/RelevantOnly audit selection; rule removal by ID or tag; and target
removal by ID or tag. Other controls reject the generation. IDs are positive signed-32-bit
decimal values; whole-rule removals accept space-separated IDs and inclusive ranges.
Target-by-ID accepts one ID, matching the pinned v3 action. Reject malformed ranges,
empty targets, extra delimiters and numeric suffixes rather than adopting permissive
`stoi` parsing. Normalize collection identifiers into the native collection enum; tag
and target-key comparisons remain byte-exact. Tags are expanded from the candidate
rule against the current transaction view before selection.

Whole-rule controls are checked before any condition effects. Target-wide controls are
checked before requiring the collection. Value targets retain their immutable snapshots,
but refresh the transaction view and expanded tags before filtering each candidate; an
earlier candidate's TX write can therefore affect a later tag exclusion. Count selectors
filter entries before aggregation, consistently with the native static-exclusion profile.
Tag expansion uses the shared bounded macro scratch and work ledger. Unavailable tag inputs
are resource/coverage failures, never a silently non-matching exclusion.

Reserve transaction exclusion entries before evaluation. A prepared control owns its
constant strings and exclusion descriptors. Applying it checks the complete required
entry count and work charge before copying descriptors into the transaction array.
These descriptors borrow the generation, which must remain pinned across phases.
Processor and audit overrides similarly debit before publishing one value. Audit settings
affect evidence, never rule truth or denial. Capacity, work or selection failure poisons
the control state; later phases cannot resume it after replenishing a budget.

*Lemma (bounded control publication).* For $K$ prepared exclusion entries and $N$ reserved
slots, the capacity check proves $u + K <= N$ before mutation. Charging $K$ units before
the copy makes publication indivisible with respect to recoverable errors. Selection
visits at most $N$ entries and the supplied rule tags, charging every compared byte.
A target-qualified entry requires both rule selection and matching collection/key;
therefore it cannot suppress another collection or an entire rule when no field is given.
Generation pinning preserves borrowed exclusion bytes until transaction release.

== Full-match actions and evidence

Prepare full-match actions independently of the condition's local captures and TX writes.
The executable order is the phase's non-disruptive defaults, local tags, the last local
severity/logdata/message, local non-disruptive runtime actions, then the last explicit
disruptive action. A local `block` invokes the phase's disruptive default. Default TX
writes execute here; local TX writes have already executed for matching candidates and
must not run again. Status is a validated HTTP value from 100 through 599. Severity is a
named Emergency-through-Debug value or an integer from 0 through 7; permissive numeric
suffixes and out-of-domain reference values reject preparation.

Execute a successful chain's prepared programs from leaf to root with one shared evidence
event. Tags append in that order; later metadata overwrites earlier metadata. A failed chain
has no post-match event. Reserve the event slot before its first effect, and publish the
completed event after all actions succeed. Macro results and namespace bindings are copied
into monotonic reserved storage before reusing expansion scratch. `initcol` binds an IP,
global or resource key, as the pinned action does; it does not access a database or authorize
unimplemented external collection selectors or mutations.

`deny` records a would-deny decision in Audit and denies in Enforce. Status 200 becomes 403
when a denial has no alternate status. The HTTP enforcing profile accepts terminal
intervention statuses 400–599. Before publication it refuses observed, non-logging status
actions outside that range except the default 200, including passing actions whose status
could survive to a later denial. Audit retains the pure executor's status semantics. HEAD
refusals preserve the selected error code and send no payload.

*Lemma (terminal HTTP intervention).* Initially the status is 200. Every status action in an
observed enforcing phase writes either 200 or an error status; all other actions preserve it.
Induction on the prepared action sequence preserves this set. A denial converts 200 to 403,
so every emitted intervention has one terminal error code. Logging cannot retroactively
intervene after publication. $square$

`pass` never clears transaction denial. Evidence
logging flags and audit-engine overrides remain separate from that decision. Evidence
capacity or action failure poisons the action and evaluation states; no partial event is
published as complete. Earlier TX writes remain failure evidence, not resumable execution.

*Lemma (post-match lifetime and order).* A validated unwind contains adjacent decreasing
indices belonging to one rule ID and phase. Iterating it is bounded by chain depth and has
the same leaf-to-root order as recursive reference unwinding. Copying expanded strings
before the next expansion preserves earlier event fields and tag occurrences. Publication
after the last successful action prevents a failed suffix from becoming a completed event.
These statements do not establish HTTP entity acquisition or authorization to activate a
complete generation.

Root `multiMatch` findings are a separate pre-chain evidence contract. After captures,
matched-variable publication and local writes, expand that root's severity, logdata,
message and tags for each positive reported stage. Publish a reserved candidate event
before advancing transform scratch. These findings survive a false child, while controls
and disruption still require full chain truth. Do not emit a duplicate final full-match
event for a `multiMatch` root; its full-match actions still execute. The selected stock
release uses root `multiMatch`; continuation `multiMatch` is rejected in this initial
profile because its inherited rule-message logging semantics require separate conformance.
Candidate metadata failure poisons evaluation just like other evidence failures.

*Lemma (candidate evidence).* Every candidate event copies its expanded strings before
the next predicate or transformation can reuse scratch. Each event corresponds to one
reported positive stage after that stage's TX writes, and no full-chain truth is assumed.
Thus later mutation cannot rewrite an earlier finding, and failed chains cannot erase
already observed candidates or acquire their unexecuted post-match controls.

== Immutable rule programs and phased execution

Compose the owned conditions, full-match actions and validated topology into one rule
program. Resolve `pmFromFile` names relative to their source file within the supplied
artifact's canonical path table. Reject absolute paths, traversal, ambiguous duplicates
and missing files. Copy phrase data during preparation; no filesystem handle or borrowed
artifact buffer reaches evaluation. Apply every bound static target update to its root's
selector list before preparation, preserving additions and exclusions in declaration order.
Validate updates to existing predicate roots and bound the combined target list, rather
than checking each directive in isolation. Preparation failure destroys the whole candidate.

The program owns its rule signature and all runtime constants independently of the source
plan. Reserve scratch from the maximum prepared regex state count and maximum transform
expansion for the selected field bound. Preparing this program establishes rule execution
contracts, not complete entity acquisition or permission to activate the daemon.

One phased executor borrows that program, the evaluation frame, action state and bounded
unwind indices. It schedules roots, evaluates conditions, unwinds full-match actions and
only then completes the pending root's `skipAfter` decision. Controls feed the same
transaction's following conditions. An enforcing intervention halts the current phase
after its completed root and returns Denied, distinguished from normal exhaustion; later
protection phases cannot run, but logging may run. Audit records would-deny and continues.
Any phase-order, predicate, action or resource error poisons all three states.

*Lemma (composed lifetime).* Every prepared component owns its runtime text and tables,
and the executor borrows one immutable program through transaction release. Therefore
destroying the source plan or download buffer cannot change subsequent rule evaluation.
Composition introduces no backwards control edge: root cursor advancement and chain
evaluation remain bounded by their earlier lemmas. This is conditional on complete phase
inputs; it does not prove an HTTP connector has supplied them or held back its response.

== Reserved transaction slots

Initialize slots in place before serving protected work. A slot owns its arena, acquired
entity buffers, TX and matched pools, independent merged/snapshot metadata, evidence pools,
macro buffers, transform buffers, unwind indices and one matcher workspace sized from the
largest prepared regex. The arena's allocator points at the stable slot owner, not a moved
temporary. Destroy partial reservations on failure; report retained arena capacity separately
from compiled program storage and process RSS.

Size transform scratch using each prepared target's collection bound. Raw request and
response entities have different bounds from parsed fields, while count values fit the
reserved decimal buffer. Taking the maximum actual target expansion is conservative without
applying every field transform to the largest unrelated entity. Check all requested payload
sizes before allocation and retained capacity after allocation against the configured slot
ceiling. Per-slot ceilings and slot count bound startup reservation; exceeding either cannot
silently reduce inspection coverage or turn into request-path allocation.

Wire request and response entities have independent reservations from their decoded bodies.
The decoder always returns primary decoded storage, including an even number of coding
layers; only intermediate layers borrow the alternate buffer. Therefore response decoding
may reuse the alternate buffer and inflater history without invalidating REQUEST_BODY for
later response or logging rules. Identity bodies borrow their retained wire reservation.
The complete origin head has its own 16 KiB reservation. Every one of these allocations is
charged to both the per-slot payload bound and retained arena capacity at startup.

Beginning a transaction resets TX, matched/evidence cursors, controls and work, retaining the
reserved buffers. A second begin while active is refused. Between phases, replace only the
acquired view after validating its ownership and charged metadata bound; preserve existing TX
and copied matched values. Finish ends every transaction borrow before reuse or destruction.
The connector remains responsible for acquiring complete immutable input and ensuring that
only one worker owns a slot.

*Lemma (slot separation).* Each arena reservation returns disjoint typed regions, and frame
assertions exclude overlap with acquired and generation storage. A matcher may swap its
private lists without changing ownership. Resetting cursors before the next transaction and
ending all prior borrows prevents old TX or evidence from becoming that transaction's view.
Replacing acquired metadata cannot alter the monotonic copies retained by TX and matches.

#block(breakable: false, table(
  columns: (2fr, 4fr),
  [Operator family], [CRS 4.30.0 names],
  [Comparison], [`eq`, `ge`, `gt`, `lt`, `streq`, `within`],
  [Text], [`beginsWith`, `contains`, `endsWith`, `rx`],
  [Tables], [`pm`, `pmFromFile`, `ipMatch`],
  [Validation], [`validateByteRange`, `validateUrlEncoding`, `validateUtf8Encoding`],
  [Structure], [`detectSQLi`, `detectXSS`],
  [Unconditional], [`unconditionalMatch`],
))

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

=== Prepared variable selection

Compile positive targets and exclusions into separate, ordered arrays with owned keys and
case-insensitive key-regex programs. Before evaluating one positive target, materialize its
complete selected entries into caller-owned metadata scratch. Preserve duplicate entries and
input order; repeated positive selectors remain separate evaluations. Do not retain indices
into a mutable `TX` table. Each copied entry still borrows immutable input or transaction-owned
bytes, so later action writes must preserve those byte lifetimes. Snapshot each target when it
is reached, allowing actions on earlier targets to affect later target evaluation as in the
reference. A capacity or work failure invalidates the snapshot; a partial slice never escapes.

Count targets yield one decimal count, including zero, in dedicated caller scratch. Exclusions
apply before counting. An excluded whole target produces no synthetic count. Empty complete
collections, unavailable collections and incomplete collections remain distinct. The two XML
selectors require explicit element/attribute metadata; absent classification is an error rather
than broad selection. Structured acquisition must establish that metadata and coverage.

The native profile consistently scopes exclusions to their collection and applies them to
values and counts, including exact-key targets. Keys compare with fixed ASCII case folding;
patterns use the pinned case-insensitive selector flags. The pinned parser attaches exclusions
to dictionary variables, but its exact-key resolution path bypasses that filter unless the
selector is eliminated by identical source text. That inconsistency is a declared compatibility
difference, not an equivalence claim. Compatibility and operator-exclusion tests must cover
it before activation. Exclusions are operator intent and can reduce protection.

*Lemma (bounded target snapshot).* With $E$ entries, $X$ exclusions and bounded regex state
counts, each positive target visits at most $E$ entries, and each retained candidate checks at
most $X$ exclusions. Every scan, comparison and regex transition consumes the shared budget.
At most $E$ copied metadata records and one decimal count are needed for a target. All borrowed
bytes survive its evaluation, and no request allocation or callback is required. The lemma
does not establish acquisition coverage or equivalence for unsupported selectors.

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

=== Transaction-owned variables

`TX` is a caller-owned metadata table and monotonic byte pool reserved with the transaction
slot. Keys use fixed ASCII case-insensitive equality and are unique; updates preserve the
original key spelling and entry order. A missing key differs from a present empty value.
Runtime keys remain length-aware, including NULs in decoded argument names expanded by
rules. A binary key never aliases its prefix. Empty runtime keys and NULs in source text
remain errors; these contracts concern different boundaries.
Each successful write copies its new value to unused pool space. Old value bytes remain
valid until the transaction ends, so target snapshots and macro parts cannot dangle after
an action updates or deletes their source key. Deletion compacts metadata without reclaiming
bytes. Entry and byte capacity are explicit bounds, not a hidden allocation fallback.

Reserve the complete write capacity and copy work before touching stored metadata or bytes.
Arithmetic uses the pinned `setvar` profile: each operand is a decimal prefix converted to
a signed 32-bit integer, with invalid or out-of-range conversion yielding zero. Addition
and subtraction are checked in that domain; overflowing signed C arithmetic is undefined
and becomes an explicit native numeric-limit outcome. Arithmetic never wraps a high anomaly
score into a permissive value. Missing previous values convert to zero.
Counts and arithmetic values use one fixed-capacity decimal writer rather than general
formatting. The maximum integer width is 64 bits: at most 20 digits, including a sign for
the signed domain. Widen before negating the minimum signed value. Reserve the fixed
capacity's work before writing; the loop then performs at most one division per digit.

A resource, invalid-key or arithmetic failure poisons the transaction store. Refilling a
budget cannot resume partial action execution as a completed transaction. Previously written
private state may remain for diagnostics but cannot support an admission decision or a
completed finding. Reinitialization starts a new transaction and invalidates all old borrows.
The later executor must handle this failure as the configured limit outcome, not a negative
match. Multiple action writes are not claimed to be one atomic batch.

*Lemma (stable atomic variable write).* A lookup visits at most the bounded entry count;
the copied key and value length is bounded by remaining pool space. Capacity and work
reservation precede both writes, so failure leaves existing entries and pool usage unchanged.
After reservation, disjoint copies cannot fail and the metadata update publishes the completed
value. Monotonic pool usage ensures every earlier value slice stays valid for the transaction
lifetime. The poison flag prevents further use after a failed mutation. This proof assumes
the caller respects buffer disjointness and the slot lifetime.

Compile transaction-variable actions into a typed operation and two owned macro programs:
target key and optional operand. Support assignment, addition, subtraction, unset and bare
key assignment to `1` in the transaction namespace. Expand the operand before the key, as
the pinned action does, using separate caller buffers and one shared view/budget. Resolve
both programs before any store mutation. An expansion failure poisons the store even though
stored bytes have not changed. This primitive does not decide when an action runs in a chain
or whether a match is disruptive. Persistent namespaces require their own bounded lifecycle
and cannot be routed into `TX` silently.

== Prepared operator interface

One typed compiled-operator interface owns the prepared regex, phrase, address or byte-range
program, or a literal/numeric argument template. It dispatches every one of the stock
operator kinds through existing bounded primitives. Static `contains` needles prepare
their KMP prefix tables off-path; variable needles and `within` use caller-owned prefix
scratch. Runtime argument templates apply to the reference's comparison and text operators,
not to regex patterns or static phrase/address data. Phrase-file bytes are resolved from
the validated artifact and supplied during compilation; evaluation has no file interface.
Multiple phrase files retain line boundaries and their input order. Their total bytes,
file count, phrase count and automaton nodes are bounded before publication.

The evaluation frame centralizes the input, shared budget, regex workspace, prefix scratch
and macro buffers. Results separate predicate truth from operator capture. Regex captures
are input offsets, phrase captures borrow the generation dictionary, XSS captures borrow
the evaluated input, and SQL fingerprints own their small byte array. Comparison, encoding,
address and byte-range predicates do not invent `TX` captures from incidental match spans.
The result's capture access requires that the result, input and pinned generation remain
alive; the transaction copies any persistent capture before scratch is reused. Negation,
selection, transformations, chains and actions belong to the executor. A work, scratch or
macro error remains an error and cannot be converted into truth by negation.

*Lemma (prepared ownership).* Compilation owns or copies every argument and static table
before returning a program. A failed compilation releases all its private allocations.
Evaluation borrows only that immutable program and the frame; it creates no dynamic storage
or new owner. Every successful capture either consists of bounded offsets, a generation-
owned dictionary slice, an input slice or owned fingerprint bytes. Therefore retaining the
generation and copying ephemeral captures suffices for lifetime safety. This lemma assumes
the caller enforces frame disjointness and does not prove rule-action semantics.

== Ordered transformation profiles

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

=== Validated constant-space transform replay

The native executor may replace per-stage value copies with a validated replay for one
snapshotted field. Its input bytes, generation and transformation configuration are immutable
through both passes. First run the complete pipeline without predicates or rule effects,
using two dedicated scratch buffers and the transaction budget. Any transform failure stops
before that field's effects. Measure the exact charged transform work $D$ and reserve another
$D$ from the transaction budget before exposing a matching value. The replay receives that
separate reserved budget; predicates and effects continue to use the remaining shared budget.
Interleaved actions therefore cannot consume the replay's already reserved transform work.
The outer ledger counts the reservation once; inner debits spend those transferred units,
so work reporting does not sum both the reservation and its later consumption.

Run the same pure pipeline again and expose values in the reference order, copying captures
or persistent values before advancing scratch. No request allocation or per-stage value pool
is required. The replay object stays at a stable caller-owned address because its iterator
borrows its reserved budget. Failure invalidates it permanently. This method doubles the
transform work and counts both passes; performance reporting must include that cost. It
does not reserve predicate work or make multiple rule effects atomic. An exhausted predicate
or effect still stops the transaction with an explicit limit outcome.

*Lemma (replay equivalence).* Under immutable input/configuration and deterministic pure
transforms, induction on stage index gives the same bytes and change flag in both passes.
Their sequence of visible values is consequently the same as materialization before matching.
The first pass establishes capacity and the cost $D$; reserving $D$ gives the second pass enough
transform work independently of intervening actions. Two scratch buffers require space bounded
by the largest intermediate value, while total transform work is twice the sum of stage costs.
The lemma does not permit retaining scratch slices after the next value, mutating input bytes,
or substituting transforms that depend on evolving transaction state. Those would invalidate
the proof and must use a separately specified execution method.

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

= Algorithms and mathematical contracts

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
profile and `DOTALL | MULTILINE` compilation defaults. Its regex constructor substitutes
`.*` for an empty expression; collection-key regexes additionally use case-insensitive
matching. The `@rx` operator has a preceding empty-argument fast path: it succeeds without
running that regex or producing captures. Preserve that distinction in the prepared
operator. Runtime macro patterns need their own bounded compilation contract; until that
exists, reject them explicitly rather than interpreting macro source as a static regex.
Scoped pattern options
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

=== Conservative first-byte filtering

Prepare a 256-bit first-byte set and a nullable flag for each syntax node. A byte class
contributes its members; alternatives union their sets; concatenation takes the left set
and adds the right set when the left side is nullable. Captures and repetitions inherit
their child's set. Treat assertions as nullable without a byte contribution, even when
their position-dependent condition may fail. A zero-count repetition may conservatively
retain extra members. This computation costs constant work per node and runs off path.

*Lemma (safe start omission).* If an expression is nonnullable and the next byte is outside
its prepared set, no match can start at that input position. Induction on the syntax tree
establishes that every accepting nonempty path consumes a first byte in the set. Ignoring
assertion conditions only adds possible paths. Omitting such a start thread therefore
removes no accepting path and preserves the priority of surviving captures. Nullable
expressions always add a start thread, including at end of input. $square$

The matcher charges each membership probe and retains its ordered simulation for all
remaining threads. This improves common nonmatching prefixes without changing the worst-case
$O(S N)$ bound or permitting an exhausted budget to be reported as a negative match.
Long-prefix capture fixtures and independent PCRE2 comparisons verify the optimization.

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

Two stable pin cells bound generation lifetime. A serialized publisher replaces only the
inactive cell when its reader count is zero and its transaction pool has drained. Acquisitions
increment the selected cell's count and validate the active index again before accessing
its payload. Both index operations and reader-count operations use sequential consistency;
acquire/release ordering on separate atomics does not establish that validation proof.
The cells and their counters are never relocated or reset while workers exist. Reader
acquisition permits three attempts and at most 4,096 pins; exhaustion returns unavailable.

*Lemma (stable-cell reclamation).* In the sequentially consistent order, a reader whose
validation precedes replacement has already incremented the cell's count, preventing
reclamation until release. A late reader whose increment follows the publisher's zero check
cannot access the retired payload: validation observes another active cell, or observes that
the same cell has been published again after its new payload is complete. Stable counters
preserve late increments across that reuse. Releasing the exclusive transaction slot before
the cell pin ensures both mutable workspace and immutable program borrows have ended.
Publication may refuse a third outstanding generation rather than wait or reclaim live work.

Closing first stops publication and pins, then retires the pools. The owner cancels or finishes
and joins every potential reader before freeing the cells, including a worker stalled before
incrementing a counter. Observing zero counters alone is insufficient to establish shutdown.
An unpublished candidate can be destroyed directly: destruction closes its empty pool before
reclamation. Failed publication leaves candidate ownership and the active generation unchanged.

The immutable generation owns blocking and detection paranoia levels and the inbound/outbound
anomaly thresholds. Configured startup seeds those four TX values before metadata acquisition
and phase-one evaluation. CRS fallback initialization therefore preserves operator tuning.
Levels must be in 1–4 with detection no lower than blocking; thresholds are nonzero 16-bit
integers. Invalid tuning rejects startup before a slot becomes active. A pinned lease supplies
both execution mode and tuning, so a later publication cannot change either during a transaction.
Decimal conversion and TX ownership use the transaction's charged, caller-owned buffers.

== Theorem 4: no partial activation

A rejected candidate cannot change the active generation when all validation precedes the
single publication operation and durable state names complete immutable artifacts.

*Proof.* Parsing, verification and compilation operate on privately owned candidate storage.
Failure destroys that storage and leaves the active pointer unchanged. Successful publication
references the completed artifact. Database intent and runtime completion remain separate;
a node that cannot apply the committed revision reports failure and retains its prior generation.

These proofs concern execution and ownership. They do not prove that CRS eliminates bot
traffic, that a payload is safe, or that all applications tolerate a given blocking threshold.

== Exclusive pool leases and shutdown

A generation owns at most 31 stable transaction slots. One atomic 32-bit word records
leased slots and a separate closed bit. Admission examines a free bit and claims it with
strong compare-and-swap; at most the slot count attempts are permitted. Contention can
return service unavailable even when some capacity remains, rather than spin without a
bound. No request allocates, grows the pool or waits for another request's workspace.

Closing atomically sets the closed bit in the same occupancy word. It stops new leases;
it neither cancels existing work nor invalidates a generation. The owner joins workers
and observes closed with all lease bits clear before freeing slots. Release publishes all
workspace writes before clearing its bit. A lease is an exclusive ownership token that
must not be copied or reused after release. Entity, Executor and View borrows end first.

*Lemma (exclusive reservation).* Two successful claim operations cannot return the same
occupied bit without an intervening release: compare-and-swap accepts only the observed
word with that bit clear. The closed bit shares this word, so admission cannot succeed
using a word observed before close once close has linearized. Acquire/release ordering
makes prior writes visible to the next successful owner. The immutable generation outlives
the pool, and the pool outlives every lease; shutdown alone does not establish reclamation.
Pool startup checks aggregate retained arena capacity plus slot objects, independently of
the per-slot reservation ceiling, and unwinds every completed slot on failure.

== Acquired collection ownership

The collection builder reserves one monotonic byte pool and separate entry metadata per
slot. Named headers, cookies and arguments share one immutable copy with their name
aliases; duplicate occurrences remain separate and ordered. Query and URL-encoded fields
populate ARGS and their GET/POST views. The pinned JSON processor populates ARGS without
claiming URL-encoded POST coverage. Combined size counts decoded keys and values once,
retaining the reference's six-decimal scalar representation.

A field reserves all aliases, copied bytes and work before publishing any entry. Failure
poisons the builder and refuses access to partial views. A collection becomes complete
only after its parser succeeds; empty complete and unavailable are distinct. Raw bodies
borrow the separately reserved immutable entity buffers instead of using the smaller field
pool. TX and matched-variable collections belong to evaluation state and cannot be supplied
by acquisition. Begin an empty transaction before acquisition so decoding and inspection
share one ledger; replacing acquired views preserves TX and copied matches between phases.

*Lemma (atomic field publication).* Capacity and work checks precede every copy and entry
write. After reservation, the bounded disjoint copies cannot fail. Alias entries point to the
same saved key/value without multiplying their byte charge. Monotonic storage preserves
prior value borrows when scalar metadata changes. Parser failure leaves no accessible
complete view, even when earlier fields were published internally.

== URL-encoded and URI decoding

Use one length-aware percent decoder for URI metadata and form fields, with an explicit
plus-as-space option. Scan, validate and size the output before writing; preserve decoded
NULs and every other byte without C-string truncation. Form parsing splits only on `&`
and the first `=`, retains duplicate order, accepts empty keys and values, and retains empty
interior separator segments. A final separator does not add another field. Semicolons remain data. Parsed fields are copied before scratch reuse.
GET or POST coverage is completed only after the entire input succeeds; the connector
completes combined ARGS after all contributing processors finish.

The native acquisition profile refuses malformed percent escapes explicitly. This differs
from the pinned reference's non-strict decoder, which retains them and sets an error flag.
The initial collection profile does not expose that reference error flag. Refusal avoids
pretending that malformed input was fully decoded; enforcement refuses the request and
audit applies its explicit incomplete-input policy. This difference requires independent
fixtures and an operator-visible compatibility report. It must not be a silent negative match.

*Lemma (decode bound).* Each input byte is visited at most twice and emits at most one
output byte; a valid escape consumes three bytes and emits one. Reserving four charged units
per input byte plus one covers validation, hex conversion and copying. Validation and output
capacity precede writes, so malformed input and exhausted capacity leave scratch unchanged.
The additional form scans reserve two visits per input byte. All costs share the transaction
ledger and all loops advance monotonically, independent of argument count.

== Bounded JSON tokenization and paths

Use Zig 0.17's standard JSON scanner for strict UTF-8, escape, number and grammar validation.
It emits duplicate object keys in source order and number spellings without numeric rounding.
Supply its bit stack with fixed borrowed storage and refuse a new container at the configured
depth before its push. The scanner's allocator has no storage to offer; valid and depth-refused
inputs never invoke it. Neither standard scanner deinitialization nor owning JSON parsing
may free or replace the borrowed bit array. Assemble partial escaped strings in fixed output,
copying them into acquisition storage before reading the next token. Reject invalid UTF-8,
unpaired surrogates, trailing tokens, malformed grammar and excessive values explicitly.

The CRS adapter uses an iterative caller-owned frame stack. Root scalars use `json`; root
objects use `json.` and arrays append `.array_0`, `.array_1`, and so on. Each container retains
its prefix length; closing restores the parent prefix and advances the parent array ordinal.
Empty containers still advance their array position. An empty object key becomes `empty-key`,
as the pinned processor's `getCurrentKey` does. Nested paths and repeated keys remain distinct
occurrences, including path collisions inherent in the reference's flattened representation.
JSON populates ARGS and ARGS_NAMES; it does not add values to the URL-encoded POST view.

*Lemma (JSON scratch bound).* The borrowed bit array has at least $ceil(D/8)$ bytes for depth
$D$. Peek checks depth before every push and does not push itself; therefore the standard
bit stack cannot grow. The adapter stack has exactly $D$ frames and checks before adding one.
Decoded strings and paths refuse overflow before copying. Prefix restoration changes only
scratch cursors; previously published fields have monotonic owned copies. No recursion,
heap allocation, number coercion or duplicate-key map is needed on the request path.
Reserve 32 units per source byte for standard scanner state visits and charge each emitted
token, assembled byte, path copy and field publication separately. This conservative ledger
can refuse an entity below its byte ceiling; byte limits do not promise a given work budget.
The compiler version and JSON qualification fixtures must change together if scanner storage
or tokenization contracts change.

== Complete multipart acquisition

Share MIME token and parameter syntax in the pure text library, retaining the policy library's
compatibility facade. The complete processor scans delimiters using the existing charged KMP
primitive with at most 74 pattern bytes. A matching prefix is a delimiter only with valid
closing/line-ending syntax; lookalike prefixes inside binary files remain payload. Preamble,
epilogue and transport padding are bounded by the entity reservation. Require a closing
delimiter; partial bodies cannot publish complete coverage.

Each part has at most 8 KiB of headers by default and the entity has at most 256 parts.
Header names use MIME tokens; reject control bytes, folded lines, duplicate Content-Disposition,
duplicate Content-Type, duplicate transfer encodings and conflicting disposition parameters.
Field values populate POST arguments, preserving duplicates. File fields publish their original
name and filename, file-name aliases, aggregate file byte size and every raw part-header line.
The file payload remains in entity storage and is neither copied into ARGS nor scanned as text
unless a rule selects the raw body. An empty filename follows the pinned reference's field
classification. Names, filenames and field values are copied before parameter scratch reuse.

Ordinary quoted filename parameters decode quote/backslash pairs and preserve other
backslashes as the pinned processor does. UTF-8 `filename*` is accepted with an ordinary
filename only when its strictly decoded bytes equal that filename. The reference retains the
ordinary name; some backends prefer the extended one. Refusing differing names prevents an
inspection/backend disagreement. Unsupported charsets and transfer encodings are explicit
uninspectable-input outcomes. The native profile refuses LF-only, folded or ambiguous headers
rather than exposing the reference's permissive error-flag semantics as complete input.
Multipart field sizes contribute to native ARGS_COMBINED_SIZE as query and form fields do;
this is a conservative complete-field total, not the pinned processor's legacy query-only
scalar update. These declared differences require fixtures and compatibility reporting.

*Lemma (multipart scan bound).* Boundary bytes contain no CR or LF, so a rejected delimiter
candidate cannot contain an overlapping full delimiter. Resuming after the candidate and
charging each KMP comparison yields linear scanning over the entity. Suffix padding advances
monotonically and is charged before each visit. Part/header ceilings, entry limits and owned
byte limits independently bound metadata. Complete coverage is published only after closing
and all fields succeed; any error poisons the builder. No file handle, temporary upload,
network fetch or request-path heap allocation is needed.

== Restricted XML acquisition and namespace ownership

The UTF-8 XML 1.0 profile supports the stock `/*` and `//@*` selectors. Root selection returns
one concatenation of descendant text and CDATA; attribute selection returns ordinary
attributes in document order, excluding namespace declarations. Entry keys retain the actual
XPath expression so matched-variable labels do not substitute invented node paths. Bare XML
selects an opaque document-tree value in the reference, rather than these values, and is
explicitly unsupported. Other XPath expressions reject compilation before activation.

Follow the #link("https://www.w3.org/TR/xml/")[XML 1.0 fifth-edition] character and name
ranges. Validate UTF-8 throughout the document, including comments and instructions. Normalize
literal CR/CRLF to LF and attribute whitespace to spaces; character references retain their
referenced whitespace. Decode the five predefined entities and checked decimal/hex scalar
references. Unknown entities, invalid characters, unpaired markup, repeated roots, malformed
comments and invalid declarations poison acquisition. XML declarations accept version 1.0
and UTF-8; other encodings are explicit unsupported-input outcomes. Refuse every DTD or entity
declaration. No external URI, entity loader, file, network or recursive expansion is available.

A caller-owned stack tracks element names and scoped namespace cursors. Decode namespace
URIs into the acquired monotonic byte pool; names borrow the immutable entity. Resolve prefixes
after reading all start-tag attributes, including declarations placed after their use. Bindings
are exact, scoped identifiers, never fetched locations. Apply the reserved xml/xmlns rules,
reject unbound prefixes and duplicate expanded attribute names, and restore namespace cursors
at each end tag. Borrow saved attribute values when publishing metadata instead of copying
them twice. Namespace declarations consume the same byte bound even though they are not
selected attributes. Root text is copied before its decoder scratch can be reused.

*Lemma (bounded XML ownership).* Each lexical scan advances within the reserved entity.
An element pushes at most one frame and must pop with the same qualified name. All stacks,
attributes and namespace bindings check capacity before publication. Restoring a scope cursor
does not reclaim saved URI/value bytes; monotonic ownership preserves existing metadata.
Root text and attributes become a complete XML view only after the whole document succeeds.
Namespace and duplicate comparisons debit their byte visits, bounding the quadratic attribute
comparison term by the shared ledger. UTF-8 lexical validation reserves 16 source visits per
byte; character-data decoding reserves eight and every copy is separately charged. These
bounds and refusal of general entities prevent recursive expansion or request-time allocation.
Independent XML parsing fixtures qualify this profile; they do not establish arbitrary XPath
support or whole-engine detection equivalence.

= Input acquisition and HTTP phases

The metadata adapter consumes pure shared HTTP field types, never a socket or daemon
object. The transport supplies the validated request line, raw target, method, protocol,
resolved client address and transaction identity. Copy these into the acquired monotonic
pool before transport buffers can be refilled. Retain duplicate header, query and cookie
occurrences in arrival order. A repeated Content-Type is an ambiguity error, not a last-wins
processor choice.

Split the raw target on the first literal query delimiter before percent decoding. A raw
fragment remains in REQUEST_URI_RAW and the request line, but does not contribute query
fields or decoded filename/URI metadata. URI plus signs remain plus signs; form plus signs
become spaces. REQUEST_FILENAME retains the decoded path and REQUEST_BASENAME follows
the final slash or backslash. Absolute URI metadata removes the authority from REQUEST_URI,
without changing the filename or the raw transport target. Strict malformed-percent refusal
is the native profile's declared difference from the reference's permissive URI decoder.

Cookies follow the pinned connector's byte semantics: trim final string whitespace and
leading key whitespace, split each occurrence at its first equals sign, preserve interior
whitespace and values, retain bare keys and duplicates, and skip empty keys. Do not unquote,
percent-decode or treat these acquired fields as authenticated session cookies. Before phase
one, the reference media prefixes select MULTIPART or URLENCODED; phase-one controls can
subsequently override processor selection. Strict MIME/body validation belongs to the entity
boundary, before phase-two publication.

*Lemma (metadata separation).* Query parsing cannot reinterpret an encoded path
delimiter as a transport delimiter, and scratch reuse cannot change already acquired URI
metadata.

*Proof.* The shared target splitter runs on raw bytes. Percent decoding receives its path
and query slices separately. Every scalar is copied into the monotonic pool before form
parsing reuses its disjoint scratch. Header/cookie aliases refer only to completed immutable
copies. Checked scan reservations plus copy charges bound the work, and every refusal
poisons the builder, making a partial view inaccessible. $square$

#block(breakable: false, table(
  columns: (1fr, 2fr, 3fr),
  [Phase], [Input], [Publication boundary],
  [1], [Request line and headers], [Before acquiring or forwarding a protected body],
  [2], [Complete decoded body and parsed fields], [Before origin receives protected request bytes],
  [3], [Validated response status and headers], [Before client receives the response head],
  [4], [Complete selected response body], [Before client receives a protected response body],
  [5], [Final transaction state], [Logging; cannot undo bytes already sent],
))

Request acquisition decodes HTTP transfer framing once and supplies the same entity bytes
for inspection and replay. Chunk extensions and trailers are validated by the transport.
URL-encoded fields retain duplicates; JSON has bounded depth and stable flattened paths;
XML forbids external entities and network access; multipart parsing separates field values,
file names, part headers and file payloads. Binary file contents remain file data unless a rule
selects raw body bytes. MIME metadata is not trusted as proof that a payload is harmless.
Parsing errors populate the corresponding collection/error semantics and cannot masquerade
as an empty valid document. Ambiguous framing is rejected before CRS evaluation.

The transport's reserved entity reader removes transfer framing into caller-owned storage.
Content-Length, chunked and close-delimited reads have an independent entity ceiling;
chunked control bytes also have a separate ceiling, defaulting to 64 KiB. Each decoding
window is at most 16 KiB. An incomplete chunk-size or trailer line is scanned incrementally,
bounded by the existing 4 KiB line limit. Eight consecutive reads without progress refuse
acquisition. Upload activity is credited per 16 KiB consumed, while response activity follows
each origin read. These policies retain slow-upload protection without cutting an active
slow response. The reader owns no writer and never publishes a partial entity.

The HTTP service's consumed-head pin lends only the connection buffer tail to subsequent
reads. It preserves borrowed request metadata without copying it, whether admission has
already consumed a buffered body prefix or CRS is about to acquire the complete entity.
Prefetched body and pipeline bytes remain in that tail. Restore the full buffer after final
evidence and telemetry consumption, before the next request can compact it. The daemon's
ordinary relay and complete entity acquisition share this ownership primitive.

*Lemma (bounded transport acquisition).* For entity ceiling $E$, framing ceiling $F$ and
line ceiling $L$, successful acquisition visits $O(E + F)$ bytes with $O(L)$ reader storage
in addition to the caller's entity reservation. It consumes no following pipelined message.

*Proof.* Length and close-delimited paths advance over each consumed byte once. Chunked
decoding advances over complete control units and payload runs; incremental scanning visits
only newly arrived bytes of a pending line before one complete validation. Consumed control
bytes are charged independently of copied payload. Both ceilings are checked before copying
or advancing the accepted result. The decoder stops at the terminal trailer delimiter, and
length framing stops at its declared count. No writer is reachable during these operations.
This argument does not cover content decompression, socket deadlines or later publication,
which remain separate connector obligations. $square$

The enforcing reverse-proxy profile holds the bounded request before sending it to the origin.
After phase-one controls run, select the effective entity processor from the strict MIME
descriptor and its explicit override. The automatic descriptor selects URLENCODED or
MULTIPART only; JSON and XML selection comes from phase-one policy controls. Reject
duplicate boundary/charset parameters and unsupported JSON/XML charsets. This native
profile validates the complete media type instead of accepting a misleading media prefix.
An empty HTTP entity establishes empty complete body collections without invoking a
nonempty-document parser or inventing a REQUEST_BODY occurrence. Raw binary entities
remain immutable borrowed bytes and never become form fields merely because they contain
an equals sign. Parsed body fields extend the already acquired query fields. Update body
length, processor and aggregate sizes before acquiring the phase-two view.

Any entity acquisition error poisons the builder, evaluation context and intervention state.
The caller cannot run the previous phase's merged view after a failed parser. Publish a
complete view only after every contribution succeeds; repeated body acquisition is an
ordering error. Entity and work limits remain independent: a body fitting its byte ceiling
may exhaust the shared parser/matcher budget.

*Lemma (entity failure isolation).* A failed entity acquisition cannot produce a valid
negative phase-two result or overwrite a retained raw entity with parser scratch.

*Proof.* Each parser writes only reserved scratch and monotonic owned fields, while raw
entities are immutable borrows into separate reserved buffers. Every error poisons all three
transaction owners. The executor refuses a poisoned context or state before running a rule,
and the builder refuses its partial view. No body data reaches phase two until the successful
view is acquired. $square$

Response-body enforcement holds eligible MIME types before sending the response head.
Content encoding requires bounded decoding with an expansion limit; inspection of compressed
wire bytes is not inspection of the decoded representation. Oversize and timeout outcomes
have explicit policies. The safe enforcing default refuses an uninspectable protected body;
operators can configure a documented streaming exclusion for a route or MIME type.

The shared inflater preserves compressed input and writes into disjoint reserved output and
history storage. It validates gzip reserved flags, optional header CRC, payload CRC and
terminal size; zlib validates FCHECK, compression/window fields and Adler-32 and refuses
external dictionaries. HTTP accepts gzip, its x-gzip alias and zlib-wrapped deflate as specified
by #link("https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4.1")[RFC 9110 §8.4.1].
It combines ordered Content-Encoding fields and decodes at most four layers in reverse
order. Every layer has an independent decoded ceiling and uses the transaction work ledger.
Charge compressed input before decoding and reserve work for each output allowance before
the native decoder runs. Empty stored DEFLATE blocks may consume framing without
producing output; progress is measured in both consumed input and produced bytes. A stalled
decoder is refused, while valid flush boundaries retain the exact expansion ceiling.
Direct streaming limits each allowance to 8 KiB; an indirect
reader must not expand ahead of that charge. Unused allowances are not refunded. Preserve
the most recent 32 KiB of history when compacting its caller-owned 64 KiB buffer, and start
each member with empty history. A one-byte overflow probe distinguishes an exact fit from
an oversized entity without copying past the decoded ceiling.
The compressed wire ceiling is independent of the decoded ceiling. Unsupported codings,
invalid wrappers, expansion overflow and exhausted work are refusals, never identity data.
Identity data remains an immutable borrow and obeys the decoded ceiling.

HTTP gzip permits at most 64 concatenated members, as defined by
#link("https://www.rfc-editor.org/rfc/rfc1952.html#section-2.2")[RFC 1952 §2.2]; each member
validates its own checksum and terminal size against the same aggregate output ceiling.
Signed rule archives require exactly one member and reject trailing data. A failed decode
cannot publish partial scratch as an accepted representation. The HTTP connector retains
the original encoded entity and metadata for replay rather than substituting decoded bytes
under their original Content-Encoding.

*Lemma (bounded representation expansion).* For $K <= 4$ coding layers, compressed
lengths $C_i$ and decoded lengths $D_i <= D$, expansion takes $O(sum_i (C_i + D_i))$ visits
and two buffers of size $D$, one 64 KiB history buffer and bounded local decoder state.

*Proof.* Each wrapper scan advances monotonically. The native DEFLATE decoder consumes
bounded Huffman symbols and length/distance runs, while checksum and copy passes advance
over decoded bytes. Every output contribution checks the aggregate ceiling before copying;
all members of a layer share that count. Alternating two disjoint buffers suffices because
each layer consumes only its preceding immutable result. Precharging input and bounded
output allowances prevents expansion after the ledger is exhausted; preserving the DEFLATE
history keeps backward references valid across those steps. Checksums authenticate format
integrity, not publisher identity or payload safety. This argument assumes the pinned native
DEFLATE implementation and does not establish a wall-clock latency guarantee. $square$

WebSocket upgrades inspect the HTTP handshake and then become a tunnel. CRS does not
inspect WebSocket frames. Server-sent events and other indefinite responses use an explicit
streaming profile without phase-4 body enforcement. The UI reports the missing coverage.
A completed body must never be required for a tunnel or an intentionally streaming response.

The transport accepts an optional exchange-owned response inspector. Its header callback
chooses holdback or explicit streaming before final response publication. An inspection
refusal or acquisition failure sends no response bytes; informational origin responses are
suppressed while an inspector is present. Holdback copies the validated head into a separate
reservation before the origin reader can refill, removes chunk framing and invokes the body
callback on the complete reserved entity. Replay drops transfer framing and trailer declarations
and emits its actual content length. HEAD and other bodyless replies preserve representation
metadata. A fully held close-delimited response can keep the client connection open but cannot
return the origin socket to the pool. An accepted WebSocket handshake runs header inspection
and refuses a holdback decision before any 101 bytes are sent.

These generic hooks import no rule engine. They refuse additional transfer codings on held
bodies; content encoding is preserved for wire replay and must be decoded and validated by
the application inspection callback before it claims decoded-body coverage. Neither the
presence of these hooks nor a library fixture establishes live CRS activation.

The daemon's entity adapter composes the shared decoder with the phase coordinator.
Request decoding checks phase-one completion before acquiring the phase-two view. Response
headers are copied into acquired metadata before the reader can refill; header denial takes
precedence over every streaming or handshake exclusion. A held body is decoded into its
primary reservation, evaluated in phase four and retained through logging. Audit preserves
would-deny findings while accepting a completed evaluation; Enforce returns an inspection
denial before transport publication. Both replay the original encoded entity if admitted.
Transport, wrapper or decoding failures poison all transaction owners and retain a bounded
internal cause; they cannot finalize as inspected. Unsupported body coverage uses the named
streaming or handshake ending rather than empty body collections. These adapter contracts
are qualified separately from listener startup, generation selection and operator updates.

The listener rebases a consumed pipeline prefix before borrowing a protected request head.
It retains that head while acquiring the entire transfer-decoded request into the slot's wire
reservation. Existing admission limits run before body acquisition and before `100 Continue`;
subsequent dispatch does not spend their budget or count the request twice. The decoded
entity is a separate inspection view for CRS and the existing inspector; the origin receives
the original content-coded representation. Request-phase refusal precedes origin delivery.
Origin response-phase refusal precedes final client publication. Existing admission counters
retain their meanings; external outcome telemetry selects a response refusal once, rather
than counting both admission and denial. Boot-local CRS counters distinguish complete,
headers, handshake and excluded-stream coverage, incomplete evaluations and would-deny
findings. They are exposed on the existing internal metrics endpoint when CRS is configured.
Admission owns the external outcome when response inspection is absent. A held response
owns it after inspection; an excluded stream owns it at early slot release. Relay completion
must not count an outcome already selected by either path. Console-enabled listener tests
exercise this ownership; compiling out telemetry cannot qualify exact outcome accounting.
After response-header enforcement, trusted operator rules may set
`tx.sibuna_stream_response=1` for a route or MIME type (`0` retains holdback; other values
are invalid). Such an exception declares omitted response-body coverage and cannot bypass
a phase-three denial. Before a stream or accepted handshake begins its indefinite relay,
finish logging and coverage, clear the inspection deadline and release the slot and generation
pin. Later transport completion or failure cannot touch storage already leased to another
request. Explicit exclusions do not retain scarce inspection resources for connection life.

The pure HTTP transaction coordinator couples successful acquisition to exactly one phase
execution. Its state advances from request headers through request body, response headers
and response body; repeated or out-of-order transitions poison the transaction. Response
metadata keeps duplicate occurrences and the validated three-digit status. A response entity
uses its independent byte ceiling and the same retained work ledger and generation.

Finalization names its coverage: inspected, headers profile, local response, origin unavailable,
handshake only or streaming excluded. Inspected completion requires the response-body phase;
handshake/streaming endings require completed response-header evaluation. The headers
profile cannot acquire a body. Omitted body coverage remains unavailable instead of being
fabricated as a complete empty response. Logging executes once with retained TX and matched
state, including after an enforcing request denial. A phase-five deny records would-deny
intent, never a new delivery denial; an earlier denial remains retained.

*Lemma (publication order).* A successful full transaction cannot skip an acquisition
boundary without declaring an explicit partial-coverage ending.

*Proof.* Each transition requires the preceding coordinator phase, complete acquisition and
view publication before execution. Failure poisons its builder, context and state. Full inspected
completion requires phase four. Every other permitted completion has a named coverage
reason; none supplies absent body bytes to selectors. Logging runs only after a permitted
ending and records completion without undoing publication. The lease owner retains the slot
until final evidence consumption ends. $square$

Forward-auth observes the authenticating proxy’s forwarded request metadata, not the origin
body or response. It offers a named headers profile and reports phases 2–4 as unavailable.
A full-body enforcing profile is rejected in forward-auth mode. Console status and audit
records distinguish full reverse-proxy coverage from metadata admission.

The daemon composition layer strips and validates CRS options independently of data-plane
and console parsing. Off returns before opening artifact files or reserving a pool. For an
enabled process, startup authenticates and compiles the artifact again, applies explicit
startup configuration and validates it against the listener's actual observation contract.
The manifest revision identifies its signed sources; startup overrides are process
configuration, not persisted management edits. One stable runtime owns publication and
generation leases. Its source read buffers are released after compilation, and its
generations remain alive until every listener and management reader has joined.

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
112.6 MiB for retained wire and decoded entities, alternate decoding, inflater and response
head storage, before metadata, allocator overhead and matcher scratch.

Inspection slots have an absolute deadline independent of socket activity. The connection
reaper interrupts both client and attached origin I/O at expiry; the owning worker keeps
its slot until it unwinds. Progress may renew idle expiry but cannot extend this deadline.
Registration clears any prior deadline before reusing a connection entry. Clearing the
inspection deadline after a declared streaming ending preserves the independent HTTP or
WebSocket idle policy.

Pool exhaustion returns a recoverable service-unavailable response. Body size limits return
an explicit refusal before origin delivery. Work exhaustion in enforcement refuses the
transaction; audit mode records an incomplete evaluation and continues according to its
explicit audit policy. The response adapter's audit default permits replay of a completely
acquired, transport-valid original entity after a semantic decode or work failure. A failed
header evaluation permits ordinary streaming without inventing body coverage. Both retain
the first bounded failure code, poison the transaction and refuse an inspected completion;
an operator can select refusal instead. This policy does not turn malformed transfer framing,
incomplete acquisition or a violated transport bound into a deliverable response. Enforcement
always refuses a semantic inspection failure. Invalid compiler input cannot enable audit or
enforcement implicitly.
Capture and incident queues retain bounded loss counters; logging loss must not reverse a
decision. Error responses disclose neither payload secrets nor internal traces.

= Operator configuration and updates

Proposed startup controls are `--crs` (enable enforcement), `--no-crs` (disable),
`--crs-mode off|audit|enforce` and `--crs-dir`,
`--crs-paranoia`, `--crs-detection-paranoia`, `--crs-request-limit`,
`--crs-response-limit`, `--crs-work-budget`, `--crs-timeout` and `--crs-slots`.
The absolute inspection deadline defaults to 30 seconds and accepts 1–300 seconds;
configured CRS requires a working connection reaper even when both idle timers are disabled. Thresholds and exclusions
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
share bounded typed request/response contracts. Running commands require `--origin`,
`--username` and a private `--password-file`; `--factor-file` supplies a required second
factor. An insecure remote HTTP origin is refused. Every change supplies `--revision`,
including zero for an initial selection. Preparation owns a temporary session until it
finishes, reports an unchanged selection and closes the session; activation remains a
separate `select --id <reviewed-id> --revision <expected-revision>` command. Status reports
saved intent and local boot-fenced application separately. Unknown outcomes require a
fresh status query. Mode clones current settings; rollback takes the exact previous settings
and refuses overrides. A bounded `--settings` file rejects unknown names. Offline
`validate --directory <saved-candidate>` authenticates and compiles the restart files
without starting the daemon or opening application storage.
The independent `test --directory <saved-candidate> --case <json-file>
[--mode off|audit|enforce]` command re-authenticates signed source and runs the private phased
evaluator. It inherits the manifest's profile, paranoia levels, thresholds and slot limits;
a mode override affects this test alone. Its JSON report binds source and operator digests
and the saved candidate revision, and states that active protection is unchanged and no
origin was contacted. Invalid inputs are refused without printing their contents. An
incomplete engine report remains incomplete rather than becoming a successful inspection.
There is no unauthenticated network endpoint or shell command invocation in the service.

Candidate preparation also runs independently as `sibuna crs check [--version <x.y.z>]
[--timeout <seconds>] [--configuration <file>] [--output <new-directory>]`. Operator
configuration is a bounded regular file, read without following its final symbolic link.
An output directory is created exclusively inside an operator-owned parent; it is never
reused or replaced. The saved artifact records Off at revision one and can be authenticated
again by explicit startup configuration. This candidate is not a selected, durable management
revision and does not change a running process. A failed save can leave a private partial
directory, which cannot be mistaken for active protection. Its report identifies a verified candidate rather than active
protection. The native `libs/crs-update` service owns bounded download buffers and a private
package, exposing no daemon or database types. CLI and console jobs share this service.
Latest-release metadata is limited to 128 KiB and accepts a canonical stable tag; asset
destinations are reconstructed from that tag, never taken from metadata links. Signature
and archive bounds are 16 KiB and 8 MiB. One monotonic deadline, at most five minutes,
covers discovery, both transfers and preparation. Each transfer receives the remaining
budget, and cancellation or expiration after compilation destroys the unpublished package.

Engine deployments without the console retain a file-based update path. The native updater
verifies and compiles the artifact off-path, then replaces a versioned manifest in the
operator-owned `--crs-dir`. The daemon’s bounded reload task validates that manifest and
publishes a complete generation. Expected manifest revisions, atomic replacement, durable
intent/completion and the previous verified artifact provide conflict and recovery semantics.
Filesystem permissions authorize this local path; it does not open an unauthenticated
management listener or require the AGPL console for the LGPL engine’s rule updates.
Clustered deployments use the storage owner’s revision discipline rather than independent
file writers. Both paths share verification, compilation and publication code.

== Local filesystem selection

A local store uses immutable generation directories, a versioned `selection.bin` and a
separate boot-fenced `applied.bin`. The selection names the current and previous source
directories and binds each manifest digest. Operators prepare and review signed candidates
before `crs update --directory <store> --from <candidate> --revision <expected>`. Mode and
rollback changes also create a new immutable generation. Every mutation holds the same
nonblocking exclusive file lock and rechecks the expected revision under that lock.
The lock file is never replaced or removed; operating-system ownership releases the lock
after a crash. A busy lock is a recoverable error, not a reason to wait indefinitely.

Sources and their manifest are synchronized before the atomic selector replacement; the
namespace transition is then synchronized on supported local filesystems. The selector
is durable intent, not proof of a running effect. A joined, bounded daemon task enabled
explicitly by `--crs-reload --crs-dir <store>` authenticates the named source, compiles it
privately, reserves its complete generation and rechecks selection before publication.
It records a separate boot-fenced receipt. Startup applies the saved selection before
opening listeners. Failed updates preserve the last usable running generation and report
failure; a restart refuses a corrupt selected generation rather than guessing an older one.
Console management and local reload cannot own the same publisher, and clustered processes
reject local reload. File ownership authorizes this path; no management listener is opened.

*Lemma: immutable local selection.* Assume cooperative writers use the stable lock inode,
atomic replacement provides a complete old or new selector, and synchronization succeeds
on the operator's local filesystem. A selector references complete, synchronized sources,
because its installation follows source preparation. A reader holds a shared lock while
loading and publishing; collection cannot remove its source and a writer cannot change its
selection during publication. Exclusive writers compare revisions before installation, so
two changes with one expected revision cannot both commit. A failure before installation
leaves the previous selector intact; an uncertain failure after installation requires a
status query. A receipt acknowledges an observed boot and revision, never process liveness.

The store retains current and previous generations and bounds private staging. Reclamation
runs under the same lock and targets the store's generated names, never unrelated operator
files. Atomic namespace semantics, lock contention, stale edits, interrupted staging,
restart, retained rollback and an unknown completion outcome require executable tests.

Update stages are retrieve metadata, download, verify signature and digest, safely unpack,
read, compile, run candidate checks, persist intent, publish and record completion. The
console shows a release diff, excluded rules, memory/work bounds, selected profile, committed
revision and node application status. Activation requires an expected revision and a fresh
administrator authorization; CLI authentication is not an implicit privilege bypass. Downloads
run off the request path with bounded concurrency, connection/read deadlines and cancellation.

The trust root is the pinned CRS signing fingerprint
`36006F0E0BA167832158821138EEACA1AB8A6E72`, with explicit operator-reviewed key rotation.
TLS and an asset digest alone do not establish independent upstream signature authenticity.
The public key is not fetched and trusted afresh from the same download during every update.

== Owned preparation diagnostics

A failed source parse, reference resolution or executable compilation copies its source
location before releasing the compiler arena. The diagnostic owns a UTF-8 path of at most
256 bytes, a path-truncation flag, optional 32-bit line and resolved rule ID, and a bounded
engine error identifier. Stable categories distinguish syntax, unsupported constructs,
references, capacity and other compilation failures, each with an explanation and recovery
hint. Locations not established before failure stay absent. No rule text, patterns, matched
values, request data, SQL or internal traces enter this envelope.

The native offline, filesystem-authorized and authenticated commands share the same
contract. Schema 43 adds an optional 2 KiB diagnostic column to the bounded candidate
ledger. Failure state, owned diagnostic and existing redacted audit record commit together;
a failed audit leaves the candidate Preparing without a partial diagnostic. Historical rows
without diagnostics remain absent. Authorized views validate and copy the complete record;
HTML escapes its text. A failed candidate cannot be selected or change active protection.

*Lemma (diagnostic lifetime).* A reported source location cannot borrow a released compiler
arena or operator input buffer.

*Proof.* The source compiler captures its site before its owning arena is released; the
executable compiler captures a condition's site while the borrowed plan is still alive.
Both copy bounded metadata into an inline owned record. Native reporting, storage messages
and UI decoding retain that value, never its original slices. Teardown and input erasure
therefore do not affect the reported location. $square$

== Durable management ledger

The storage owner alone handles the candidate ledger. A candidate has a random 128-bit
identifier, the authenticated actor, an expected selection revision, a bounded lifetime and
one of Preparing, Verified, Selected, Failed, Canceled or Retired. A check prepares a candidate;
selecting it is a separate, freshly authorized action. Off, Audit, Enforce and rollback share
that selection operation. Rollback copies retained signed source into a new candidate and
advances the revision; it never decreases an applied revision.

Source crosses the bounded mailbox in owned 2 KiB chunks. The maximum archive, detached
signature and private operator configuration are 8 MiB, 16 KiB and 64 KiB. Sequential ordinals,
full preceding chunks and exact retry bytes prevent holes, append-after-final-chunk and
replacement of queued work. The native preparation service submits the verification witness
after pinned signature verification and complete compilation. HTTP cannot submit a witness
or read raw source. Storage checks manifest compatibility and complete source lengths;
those structural checks do not replace cryptographic verification.

Four live source sets bound staging: the current selection, its previous selection and up to
two candidates. Each source set is at most 8 MiB + 80 KiB; hex storage has a factor of two
before database/index overhead. An atomic count predicate prevents concurrent writers from
exceeding that bound. Expired and discarded candidates release chunks, and a new selection
retires older source outside the retained pair. At most 128 ledger rows are retained, with
24-hour identifier tombstones and bounded pruning. A preparing command expires within five
minutes, preventing its reuse after a tombstone has been removed.

Prepared mutations recheck the administrator cookie, account revision, CSRF, expiry and
required factor in the same statement as the edit. Authorization is checked again for reads
and lost-reply retries. Selecting uses expected-revision compare-and-swap; its redacted audit
trigger commits with the selected pointer. A failed audit rolls back both pointer and candidate
state. Database selection and runtime publication remain separate operations. Node receipts
record the boot, attempted revision, actual application result and bounded failure reason.
A successful receipt requires that revision to be currently published by the reporting node;
repeated receipts do not duplicate audit. A new boot must establish its own application result.
Missing or failed receipts are pending or failed coverage, never successful protection.

The daemon composes one stable publisher and one joined management worker. A console with
no selected rules allocates neither a generation nor a transaction pool. Off checks an atomic
activation flag once per request, before framing and dispatch, and follows the ordinary
buffered path. Publication can change between requests without allocating on that path.
The management worker has a 1 MiB stack, owns preparation inputs, and releases or transfers
each compiled package explicitly. Its shutdown joins before storage and publisher destruction.
Source transfers and bounded TLS downloads observe cancellation; borrowed caller memory never
outlives a disconnected caller. A failed preparation leaves the existing generation usable.

On the first console startup, a generation authenticated from the operator's filesystem may
be adopted into an empty ledger before listeners open. The native service verifies its signed
source again and binds the manifest to the actual published identity and configuration.
Adoption records filesystem authority as actor zero; it cannot replace an existing selection.
Later starts restore the saved source without relying on the original directory. Explicit
startup mode, profile, paranoia, threshold and resource options must agree with that selection;
conflicting process input is refused rather than silently overriding reviewed desired state.

Each node checks desired state once per second and re-authenticates retained source before
compilation and publication. It checks the desired revision again before publishing. A busy
publisher, exhausted reservation or unavailable storage retains the prior generation and
retries with exponential delays bounded at sixty seconds. Receipts compare signed identity,
operator digest, activation and resource settings with the local publication. A lost database
reply after publication retries a successful receipt; it does not report a failed runtime
effect. Candidate expiry and bounded tombstone pruning run once per minute off the request path.

Administrator session routes expose a bounded status view, candidate preparation, reviewed
selection, discard and the current operator configuration. They do not accept native witnesses,
source paths or signing keys. Bearer credentials and kiosk sessions cannot reach these routes.
Preparation accepts a caller-retained 128-bit identifier and expected revision. A mode change
clones the current source; rollback clones the retained previous source. An update that omits
operator text preserves the current configuration rather than silently removing exclusions.
Rollback rejects setting overrides and restores the previous configuration and settings.
Each clone re-verifies the signed archive and compiler compatibility before it becomes Verified.
The operator reviews release/configuration digests and effective settings before selection.

Operator text is at most 64 KiB. The HTTP body accommodates its worst-case JSON escaping;
body, parser workspace and transferred editor storage together remain below 1 MiB. These
buffers have explicit heap owners and are wiped on release. Large editor values fill their
destination directly, avoiding by-value temporaries on the bounded HTTP thread stack. A
configuration read verifies its digest and administrator authority before responding. This
editor read is the exception to the raw-source boundary; archive and signature chunks remain
internal. A selection reply reports commit and does not claim application. Operators inspect
the serving node and boot-fenced receipts after an unknown reply or a pending runtime effect.

The console's retained editor and JSON transfer buffers require 4,632,128 bytes of static
Wasm memory with the pinned Zig 0.17 build, including its 256 KiB stack. Set initial and maximum
memory to 6 MiB (96 WebAssembly pages), leaving bounded layout headroom without runtime growth.
The asset-byte ceiling remains 768 KiB and is independent of linear memory. The browser bridge
and native renderer use the same owned model; leaving the CRS page or ending a session wipes
operator text. Responses carry generation tickets, so late requests cannot repopulate a new
page or session. The daemon's capacity estimate adds the joined 1 MiB worker stack, bounded
source, private compiler and queued editor; selected transaction pools remain separately
reported runtime reservations.

== Native detached signature profile

The initial portable verifier accepts one definite-length OpenPGP version-4 binary-document
signature under the pinned RSA-4096 primary key, with SHA-256 or SHA-512. It verifies the
key artifact's SHA-256 pin before decoding its primary key, checks its canonical MPI lengths,
exponent 65537 and version-4 fingerprint, and copies the standard library's public-key state.
The pinned key has no expiry and its subkey is encryption-only. Signing subkeys, key rotation,
revocation material or new signature algorithms require a reviewed trust-profile change;
they cannot select an untrusted key by an issuer string. Learned revocation must disable
that trust root through the same reviewed software/configuration process.

Decode bounded ASCII armor into caller buffers and reject partial/indeterminate packet
lengths, ambiguous packet sequences, noncanonical MPIs and unsupported signature kinds.
CRC24 is not authenticity: ignore missing, malformed or disagreeing CRC footers as
#link("https://www.rfc-editor.org/rfc/rfc9580.html#section-6.1")[RFC 9580 §6.1] requires.
Require one hashed issuer fingerprint and creation time; check any issuer key ID against
that fingerprint. Creation time must follow the trusted key and may exceed the operator's
clock by at most 300 seconds. Honor hashed signature expiration. Reject duplicate protected
metadata, security metadata in the unhashed area and unknown critical subpackets. Noncritical
notation and signer-display fields carry no authority and are not exposed as signer identity.

Hash the exact compressed archive bytes, the v4 signature header through its hashed
subpackets, and the six-byte v4 trailer described by
#link("https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.4")[RFC 9580 §5.2.4]. Check the
two-byte digest prefix, then use Zig's `std.crypto.Certificate.rsa.PKCS1v1_5Signature` to
verify the complete DigestInfo and padding. Left-pad a short canonical signature MPI to
512 bytes; do not use a helper that appends zeros to its right. Return a SHA-256 receipt
for the verified archive and its protected creation time. Verification uses no subprocess,
filesystem lookup, downloaded key, C dependency or request-path allocation.

*Security assumption.* Authentication depends on the reviewed key pin, the private key's
security, RSA-4096 signature security and the supported hashes' collision resistance.
SHA-1 is used for the prescribed legacy fingerprint, not archive authentication or accepting
a newly downloaded public key. RSA PKCS1 signatures are a compatibility verification
profile for upstream artifacts; the application does not generate them.

*Lemma (signed-byte binding).* The v4 preimage includes every supplied archive byte and
the complete protected metadata prefix. Full standard-library signature verification
therefore authenticates that exact preimage under the trusted public key, conditional on
the security assumptions. A digest-prefix match or CRC match alone is insufficient.
Definite lengths and checked reader advances bound parsing by the armor/packet capacities;
archive hashing is linear in its 8 MiB ceiling and runs outside request processing.

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

The native restart manifest has an exact 251-byte version-one encoding within a
512-byte input ceiling. Fixed big-endian integer widths and explicit field order avoid
host padding, pointer width and enum-layout dependencies. It carries the schema marker,
compiler ABI, pinned signing fingerprint, revision/previous revision, upstream version,
archive and operator digests, signed creation time, file sizes, condition count, compilation
high-water mark, activation/profile, thresholds, transaction limits, slot count and total
reservation. Refuse truncated records, trailing bytes, unknown modes, incompatible ABI or
signer, invalid revision ancestry and unsafe capacities before reserving generation memory.
Transport observation is a composition property, never authority supplied by the manifest.

The loader re-verifies and compiles the signed source, checks exact file sizes, then binds
the prepared package to its recorded identity and condition count. Compilation high-water
marks can differ between architectures; each node enforces its own allocator ceiling rather
than treating a recorded peak as permission to allocate. A manifest does not authenticate
its contents or establish applied runtime state. Atomic file replacement, durable management
intent and actual publication completion remain separate responsibilities of the store.

Restart preparation accepts four fixed regular-file names in an operator-owned artifact
directory: `manifest.bin`, `archive.tar.gz`, `signature.asc` and `operator.conf`.
The bounded reader rejects symbolic links and nonregular files, checks declared sizes
before allocation and reads one extra byte to detect growth after the size check. It never
uses archive member paths as filesystem destinations. Retrieved and reloaded candidates
share one explicit owner for archive, signature, operator source and compiled package;
transferring the package leaves source buffers owned for staging. The signed-artifact gate
checks real disk reloads, altered identity/lengths, signature failure, missing files and prior
candidate retention. It does not establish filesystem commit durability or daemon reload.

Private staging rechecks the actual source buffers against the prepared identity and
signature before writing. Each fixed file is created atomically without replacement,
its contents are synchronized, and the manifest is written last. Source mutation,
transferred package ownership and existing files cause refusal. A failure can leave
private partial files for quota-bound reclamation; it never replaces an active artifact.
The management store must separately synchronize directory metadata, authorize the
expected revision and select the staged candidate. File-content synchronization is not
reported as a durable committed revision or an applied runtime effect.

*Lemma (manifest separation).* A decoded record cannot turn missing body observation or
unverified source bytes into an executable generation. Fixed-length decoding establishes
structure and capacities only. The composition layer supplies actual observation, and a
separately authenticated package must match the archive/operator identity, version, signature
creation time and condition count before generation construction. Successful decoding alone
therefore confers neither artifact authenticity nor runtime application. $square$

Cluster nodes validate the same content-addressed artifact and report applied revisions.
Large rule archives do not travel in telemetry WebSockets. Artifact transfer uses the
bounded authenticated management channel or independent verified retrieval. Nodes with an
unapplied security revision are visibly unhealthy; policy enforcement must not report them
as converged. Concurrent updates use existing storage-owner compare-and-swap discipline.

== Bounded package preparation

Authenticate the complete compressed archive before expansion. The native gzip adapter
uses Zig's fixed-window decoder, bounds compressed and expanded bytes, validates footer
CRC and size, and requires exact compressed consumption. Concatenated members and
trailing bytes are not silently accepted. The management work ledger charges compressed
input and expanded copy/CRC visits; it is separate from the transaction budget.

The minimal-release archive profile supports canonical USTAR and the plain GNU headers
used by the pinned release. It refuses links, devices, sparse files, PAX/GNU extensions,
noncanonical names, paths outside the expected version root, duplicate entries, nonzero
padding, invalid checksums and incomplete terminal blocks. Check numeric sizes against
the remaining source bound before block rounding, including on 32-bit targets. Unpacking
creates no filesystem entries. Copied relative names and borrowed file slices remain private
until every selected rule and data reference has compiled.

Canonical versions contain three unsigned 16-bit decimal components without leading zeros,
prerelease text or separators. The archive root and prepared component signature must match
that version. Load the setup example and every direct `rules/*.conf` file in lexical order;
resolve `*.data` references within that artifact. This stock profile does not activate plugins
or treat optional example exclusions as operator configuration.

Keep the package and its allocator identity at a stable heap address. A single-owner allocator
tracks live payload, permits growth only within the 64 MiB compiled ceiling, reclaims temporary
compiler buffers, and records its high-water mark. Distinguish ceiling exhaustion from a
backing allocator failure. Backend metadata and resident memory remain separately measured
quantities. A monotonic fixed arena is unsuitable here because temporary compilation storage
would consume the ceiling after release. Prepared programs own all retained source and
table bytes; staging buffers can be destroyed before evaluation.

An optional operator source is bounded to 64 KiB and compiled between the verified setup
example and the sorted upstream rules. It uses the same directive, ID, work and compiled-byte
limits; includes and external paths remain unsupported. Upstream signature verification
authenticates the release, not these locally authorized changes. Keep the SHA-256 digest of
the operator bytes separate from the signed archive digest in generation metadata. Changing
the local source requires a new reviewed revision even when the upstream version is unchanged.
Prepared actions retain owned copies, so queued publication does not borrow editor buffers.

Parser-selection controls must update `REQBODY_PROCESSOR` for following selectors and macro
expansion in the same phase. Store the selected static label in the transaction context and
replace the acquired scalar when constructing an evaluation view. There is one visible scalar,
and a slot reset clears the override. This update does not change the rule-local pre-chain
timing of `setvar`; entity acquisition still waits for complete phase-one execution.

*Lemma (private package bound).* A successful package owns an authenticated, complete
program whose live compilation payload never exceeded its configured ceiling.

*Proof.* Signature verification precedes decoding and tar parsing. Every decoded/archive
bound is checked before copying or rounding, and all selected directives must compile.
The allocator tests each allocation or resize against the remaining live capacity before
calling its backing allocator; accounting changes only after success and decreases on free.
The stable package outlives all retained allocator interfaces. A refusal unwinds private state
without publication; successful staging cleanup leaves only program-owned bytes. $square$

Package qualification prepares the actual signed release, destroys its archive/signature
contents before executing benign and malicious transactions, and rejects version mismatch,
tampering, truncation, duplicate local IDs, unknown directives and an oversized local source.
This gate qualifies preparation and ownership, not runtime update
publication or full FTW compatibility.

== Private phased evaluation

The private tester takes a borrowed immutable executable program, explicit activation and
thresholds, validated slot limits and one owned request/response sample. It shares request
acquisition, phased execution and bounded content decoding with the live connector. Transfer
framing has already been removed from sample entities; `Content-Encoding` still describes
the supplied bytes. Text entities and hexadecimal binary entities are mutually exclusive.
Each supplied entity is bounded to 64 KiB, headers to 128 fields and 16 KiB total, the target
to 8 KiB and the JSON envelope to 1 MiB. A fixed 8 MiB parser workspace refuses exhaustion.
The candidate's configured decoded-entity and work limits remain authoritative. A single
private slot has a 128 MiB hard allocation ceiling; backing arena overhead is counted.

The evaluator has no origin, publisher, telemetry producer or application storage reference.
Off allocates no evaluation slot. Enforce stops after a terminal denial; Audit records intent
and continues to eligible phases. Response-header rules precede handshake and streaming
exclusions. Headers profile, absent response, handshake and streaming endings have distinct
coverage. An absent response is labelled `response_not_supplied`, not an origin failure.
Acquisition, representation or work failures produce an incomplete report with a stable
engine error name; they cannot become inspected completion. Invalid sample structure is a
recoverable refusal, not a fabricated decision.

Reports own rule ID, phase, severity, save/audit flags and intervention metadata. They retain
at most 64 findings and count additional omitted findings. Unlogged or audit-suppressed
nonterminal matches are counted separately and do not displace security findings; terminal
decisions remain visible even with suppressed logging. Expanded messages, tags, matched
values, request data and response data are excluded. Blocking and detection anomaly scores
are copied separately from the actual CRS transaction variables, after successful evaluation.
Absent or invalid numeric variables remain absent. Reporting neither charges rule work nor
changes the decision. Private slot allocations are erased before release, including allocations
replaced during arena growth; inputs and parser memory have separately owned erasure.

The authenticated service transfers one bounded JSON allocation to the existing joined
CRS worker. Preparation and private testing share capacity; neither compiles on HTTP tasks.
The worker owns input and an 8 MiB parser workspace until evaluation ends. Storage checks
fresh administrator session/CSRF, expected revision and a retained usable source in the same
statement that records a redacted `crs.test` intent. It returns the immutable manifest; the
worker re-authenticates source, creates a private slot, and rechecks access and revision
before completing. It publishes no generation and writes no sample to storage.

One ephemeral result is bound to its issuing session and unpredictable test ID. Fresh
authorization is required for every poll. Queued/running work remains bounded; a completed
or refused result expires after one minute. New work cannot replace another session's
unexpired result. Shutdown joins this worker before storage closes, then erases queued input.
Budget accounting includes an additional 1 MiB queued body, 8 MiB parser and 128 MiB private
slot envelope; the shared private compiler/source envelope and selected live pools remain
separate. A console form limits each entity to 16 KiB and each header list to 32 entries so
its browser event and command buffers remain bounded. The native CLI accepts the full shared
sample contract. Both clients identify a retained source and explicit saved revision;
`--mode` affects private evaluation alone. Browser navigation/sign-out discard its sample
form and owned scalar result; stale replies cannot repopulate a later page.

*Lemma (private-test noninterference).* A private test cannot change the selected generation,
contact an origin or emit data-plane observations.

*Proof.* The evaluator's input contains an immutable program, scalar configuration, borrowed
sample and allocator. Every mutable execution object belongs to its private slot. No origin,
publication or telemetry capability is reachable. Reports copy bounded scalar metadata before
slot teardown, and all temporary allocation owners unwind on refusal. The live generation is
never mutated or released by evaluation. $square$

*Lemma (faithful score reporting).* A reported score is a completed evaluation's actual numeric
CRS variable, rather than a reconstruction from matched IDs or severity.

*Proof.* After phased execution succeeds, the observer scans the bounded immutable transaction
store for the blocking/detection inbound/outbound score keys. It copies values using checked
signed parsing; missing and invalid values are absent. Failed or poisoned execution skips score
observation. No sum over findings and no default zero enters this mapping. $square$

= Console and evidence

== Bounded rule-change review

Preparation retains an owned SHA-256 review fingerprint for each root rule. Its
length-delimited encoding includes the phase, complete ordered chain, resolved selectors
and target updates, local and inherited actions, operator arguments, referenced data bytes,
and the identity of a skip destination. Source locations and comments are excluded. An
unchanged fingerprint means these reviewed inputs are identical, subject to SHA-256's
collision resistance; it does not prove equivalent behavior between different fingerprints.
Configuration and upstream digests remain separate authenticated identities.

The comparison sorts copied root inventories by ID and merges them. It reports added,
removed, modified, reordered and unchanged roots. Root order is compared separately because
changing the relative order of retained rules within an execution phase can change
intervention or exclusion behavior. Cross-phase source interleaving does not change that
execution order. Insertions, removals and phase changes do not mark every following root
as reordered; a changed phase is a modified rule. At most
64 changed rows are returned, with exact totals and an omitted-row count. Configured target
exclusions and runtime exclusion entries are counted separately. A runtime exclusion remains
conditional on its controlling rule matching; a count cannot claim every request loses that
coverage. Neither the comparison nor its fingerprints are evaluated on the request path.

The prepared program also owns an exclusion inventory, capped at 4,096 entries. It lists
resolved static target exclusions, including target updates, and conditional runtime rule
or target exclusions. Each entry identifies its controlling root, phase and chain link,
selected rule ID/range or tag, collection and exact/regex/XML target semantics. A rule-wide
exclusion states that all targets of its selected rules lose inspection when its controller
matches. A tag or range is a selector, not a claim that a fixed set of rules always matches.

The review worker copies both inventories before releasing their respective packages.
Eight owned rows per page fit the existing 16 KiB response envelope. Every entry is reachable
by an explicit cursor; no entry disappears because the summary or first page filled.
Names retain their exact byte length, SHA-256 identity and first 256 bytes encoded as hex.
The interface decodes valid UTF-8 for display and labels longer or binary previews; a prefix
is never presented as the complete selector. This metadata is configuration, not expanded
request data. The same session, review ID, expiration, fresh authority and saved-revision
checks govern every page. Successful authorized page reads renew a one-minute idle lease,
with a fifteen-minute absolute cap. This permits a full scan within the existing 120-query
per-minute allowance without weakening that allowance. Idle expiration, replacement or
worker shutdown releases both inventories.

*Lemma (complete bounded exclusion review).* For $X <= 4096$ exclusions and $B$ name bytes,
preparation costs $O(X + B)$ time and $O(X)$ owned metadata. Reading all pages costs $O(X)$,
with constant-sized responses independent of $B$.

*Proof.* Each resolved excluded target and each prepared runtime exclusion contributes one
row, in condition/action declaration order. Each name is hashed once and its bounded prefix
is copied. The cursor partitions the immutable inventory into consecutive blocks of at most
eight rows; advancing to the returned end neither skips nor duplicates an entry. Names,
including embedded invalid UTF-8, cross the wire as bounded hex rather than unbounded JSON
escapes. Exhausting the inventory cap refuses the entire candidate. No preview borrow
survives compilation, so pages need no live generation lease. $square$

The authenticated comparison shares the joined preparation worker with private samples.
It reauthenticates and compiles the saved baseline, copies its fixed-width inventory, releases
that package, then reauthenticates and compiles the candidate. It never retains two compiled
packages together. Its owned result binds both artifact identities, the candidate ID and
expected saved revision. Atomic `crs.review` audit intent precedes work; fresh administrator,
retained-source and revision checks precede completion. No rule source enters that audit.
Results belong to the issuing session. Samples expire after one minute; comparisons use
the bounded pagination lease above. Every poll rechecks access.
The console enables selection after a completed comparison matches both current artifacts;
a changed candidate, baseline or revision requires a new comparison. The native `crs review`
command uses the same API, session ownership and monotonic deadline as private tests. It
collects both complete bounded exclusion inventories before emitting its result, follows
validated cursors and waits within its deadline after query-limit refusals. A caller may
extend this review deadline to fifteen minutes; other management deadlines remain capped
at five minutes. A failed page read cannot publish a partial inventory as a completed review.

*Lemma (bounded review).* For $R <= 4096$ root rules and $B$ reviewed source/data bytes,
fingerprint construction costs $O(B + R)$ after existing compilation resolution. Comparison
costs $O(R log R)$ time and $O(R)$ owned workspace, followed by a linear merge. Returned
metadata is bounded independently of the number of changed rules.

*Proof.* Each resolved condition contributes once to its root's incremental hash. The
inventory holds one fixed-width row per root. Sorting compares numeric IDs; the merge advances
at least one cursor per step and counts every change even after its 64-row output fills.
No source borrow survives preparation or enters the comparison result. $square$

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

== Retained scalar findings

=== Safe templates and actual score contributions

Retain the unexpanded source of executed `msg` and `tag` actions, never their expanded
transaction values. A chain's last executed message wins and its executed tags append,
including candidate messages produced by `multiMatch`. These slices borrow the immutable
generation during evaluation. Copy bounded owned previews before releasing the lease;
identify truncation and omitted tags explicitly. They describe rule templates, not a
reconstruction of the values that matched. Matched data and `logdata` remain excluded.

Attribute numeric score changes at the transaction store's successful commit boundary.
Observe the eight `inbound_anomaly_score_pl1` through `pl4` and corresponding outbound
buckets. Do not count blocking/detection rollups or category counters again. Each compiled
root binds one caller-reserved journal row while its conditions, chain continuations and
post-actions execute. Thus a write preceding a false chain and every repeated field or
`multiMatch` write retain their actual owner. Assignments and removals are included;
no score is inferred from severity or a final threshold event.

For a bucket, missing storage denotes the additive identity zero. A committed transition
from numeric $a$ to numeric $b$ contributes $b - a$ to its root. Numeric observation accepts
complete signed decimal values representable by `i64`; it does not replace the evaluator's
reference `stoi` conversion. Non-numeric, oversized or overflowing observations mark that
root/bucket unknown, without retaining either operand. Checked accumulation keeps unknown
sticky. A row also records observed writes, so an observed zero differs from no observation.
The contribution is net change per root and phase, not an individual repeated match score.
Attach it once to the first event of that root; later repeated events cannot double count it.
Report writes without a retained event separately and preserve incomplete execution labels.

*Axiom (commit observation).* Store updates publish only after key, capacity and work checks
succeed; committed value bytes remain immutable for the transaction lifetime. Execution
binds the root before evaluating any condition and clears the binding on every exit.

*Lemma (faithful attribution).* Every recorded delta belongs to a successful store mutation
of the indicated root, including mutations in a chain that subsequently fails.

*Proof.* Observation uses the actual previous and newly committed values at the store's
publication point. Failed writes never reach that point. The executor's binding encloses
condition and post-action execution and ends with scope unwinding, independently of chain
truth. No reconstruction from a finding's severity, ID or message occurs. $square$

*Theorem (numeric conservation).* When every observed transition and root sum is known,
the sum of all root deltas for one bucket equals its final numeric value minus its initial
value, excluding initialization outside rule execution.

*Proof.* Order successful writes as $v_0, v_1, dots, v_n$. Their deltas telescope:
$sum_(i=1)^n (v_i - v_(i-1)) = v_n - v_0$. Grouping these terms by the bound root changes
neither their values nor their sum. Reporting the root once prevents repeated findings
from duplicating its contribution. Unknown transitions invalidate the premise rather than
entering the sum as zero. This theorem does not identify rollup or threshold variables with
the per-paranoia buckets. $square$

*Lemma (bounded observation).* A journal reserves one fixed row per compiled condition
off the request path. Each commit classifies a bounded key and parses at most 20 bytes of
each numeric operand, then performs eight-bucket indexed checked arithmetic. It allocates,
formats and charges no evaluation work; observation failure changes reporting alone.
Reset and complete journal traversal cost $O(R)$ for $R$ compiled conditions, and journal
space is $O(R)$. These reservations are included in the slot ceiling and performance gate.

The Nodes page reports copied local generation metadata through the existing authorized
storage mailbox. The publisher's snapshot pins the immutable generation while copying its
revision, release and configuration digests, activation, thresholds, compilation peak and
effective reservations and limits. No generation pointer or source path crosses the console
contract. Authorization is checked before observation and again before delivering the result.
Publisher contention refuses the read rather than fabricating an Off selection. A null
reported selection means unconfigured; an absent contract means an older binary did not
report it. An explicit Off generation retains its applied revision while reserving no slots.
Boot-local coverage counters are independently observed and distinguish exchange properties,
not disjoint categories. They cannot be summed into total traffic or incident counts.
The snapshot is applied local state, not a durable committed revision or peer convergence.
The storage owner's snapshot access makes it a generation reader. Shutdown joins console
and data-plane work, then the storage thread, before destroying the stable publisher.
Threshold and paranoia settings initialize each transaction; authorized operator rules
may change TX variables during evaluation. The local status page labels these as initial
settings rather than claiming they describe every exchange's final scoring decision.

The current connector copies saved findings before releasing its transaction slot and
generation lease. The bounded incident queue owns rule ID, phase, severity, applied revision,
signed archive digest, mode, would-deny and final-denial flags, selected status, paranoia
levels and coverage. Expanded messages, tags, matched values and body contents are omitted
because their expansion can contain credentials. Configuration bookkeeping events do not
consume incident capacity. Logging and audit suppression affect retention, never denial.
Incomplete evaluation overrides any nominal complete coverage classification.

Schema 41 adds a scalar sidecar committed in the incident transaction under the existing
batch receipt guard. A failed sidecar write rolls back the incident and its indexes. An
unconfirmed committed batch is retried by receipt without duplicating either row. Deleting
an incident deletes its sidecar even on a connection without foreign-key enforcement.
Revisions use decimal text in storage and the browser protocol, preserving all 64 bits.
Missing historical or grouped evidence stays null. Findings without retained matched values
have no similarity vector or inferred campaign. JSON page exports carry the scalar envelope;
CSV retains its existing incident columns.

Opt-in head capture follows SID 0007's redaction before bounded copying. A caller-owned
response capture outlives the relay's temporary frame. A validated origin head is captured
before response inspection can finish an excluded stream or handshake and release its slot.
An observed origin head describes observation, not delivery; a request-side local denial
cannot invent an origin response. Console details preserve these distinctions and erase
findings and captured heads on sign-out.

*Lemma (retention ownership).* No queued CRS finding borrows transaction or relay storage.

*Proof.* The producer runs before lease release and passes scalar values and temporary
redacted slices to the incident hook. The hook copies them into its owned bounded record
before returning. Storage consumes that record on its own thread. Response capture occurs
before finalization and has caller-owned lifetime through the producer's return. Queue
exhaustion increments the existing loss counter without retaining any borrow. $square$

Native tests cover atomic rollback, committed-reply loss, full-width revisions, migration
replay, suppression and handshake capture ordering. Signed-package daemon qualification
checks Audit and Enforce findings through authenticated console reads, restart and revocation.
Chrome checks the real findings, incomplete coverage, local and observed response heads,
charset controls, clipboard copy and sign-out in desktop dark and mobile light layouts.
Static rule messages/tags and per-rule score contributions still need a safe retained
contract to satisfy the complete evidence requirement above. This scalar envelope does not
establish the management page, live activation, cluster convergence or release acceptance.

= Verification and acceptance

== Phase evidence and reference differences

The pinned FTW inventory contains 5,193 tests in 326 YAML files. The development
`crs-ftw-check` probe runs the same prepared signed package through complete metadata,
entity and rule phases. Its fixture serialization follows go-ftw 2.6.0. An optional loopback
Albedo 0.3.0 origin supplies actual response headers and entities. This probe does not
exercise Sibuna's socket connector, final HTTP status or origin delivery boundary.

Request qualification evaluates 5,037 rule-ID contracts: 4,939 match their upstream
assertions, 65 refuse malformed or exhausted inputs, and 33 disagree with an upstream
expectation while producing exactly the same rule-ID set as ModSecurity 3.0.14.
The 65 refusals include six work-budget exhaustions under the diagnostic ceiling.
Response qualification evaluates 104 rule-ID contracts against Albedo: 102 match; both
remaining logging differences reproduce ModSecurity's saved-message behavior.
Status, raw wire, regex-log and multi-stage contracts remain separate coverage gaps.

The reference uses Debian's `3.0.14-1+deb13u1` library, with SHA-256
`af98ca264e2834bd76507684caf0b41e9f1d14f99030fd1626abffad376b5694`.
The independent reference report retains every upstream mismatch. In particular,
multiMatch may save a root finding before a later chain link fails, XML names remain
visible through raw REQUEST_BODY, and `noauditlog` clears saved-message state in this
reference. Changing those behaviors merely to satisfy another connector's expectation
would weaken compatibility with the selected reference profile.

Diagnostic execution allows 128 million charged units to separate semantics from the
16-million production default. Seventy-seven request cases and twenty response cases
exceed that default. These are paranoia-level-four fixture results, not an admission or
performance guarantee for normal application traffic. Reports retain per-case work,
errors, observed IDs, the source commit and raw expectations. Reference annotations do
not convert failed assertions or coverage gaps into passed tests. The live-daemon gate
below must establish refusal status, withheld origin/client bytes and supported profile
coverage before activation or release.

== Cluster qualification

The three-node management check observes protected request decisions on every node before
and after separate selection. It checks Audit, Enforce and Off, leader loss, mutation refusal
without quorum, durable restoration after member restart, exact rollback and incompatible
preparation. Applied local revisions must agree with the saved revision on every running node.
Each member must stop cleanly. This functional check uses three loopback processes; it does
not establish multi-host latency, TLS deployment configuration or performance acceptance.
When storage cannot confirm fresh authorization, a management read may return unavailable
instead of a quorum view. That response is not a successful read or permission to mutate;
serving retains its last applied immutable generation.

== Release gates

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
- #link("https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.14/src/parser/seclang-parser.yy")[Reference default-action validation].
- #link("https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.14/src/run_time_string.cc")[Reference runtime-string expansion].
- #link("https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.14/src/variables/variable.h")[Reference dictionary selectors and counts].
- #link("https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.14/src/actions/set_var.cc")[Reference transaction-variable operations and arithmetic].
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
