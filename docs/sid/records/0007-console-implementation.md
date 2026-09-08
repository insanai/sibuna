# SID 0007 implementation checklist

Status: **Proposed**. This checklist records implementation, not acceptance by assertion.
Unchecked gates block delivery. The daemon composes the console; application libraries must
never import daemon code or acquire the database handle. Existing data-plane and proof
semantics remain unchanged unless a stage explicitly extends them.

## 1. Contracts, build integration and lifecycle

- [x] Remove comparison framing and the named product reference from SID 0007 only.
- [x] Correct the geographic asset contract to `world-110m.bin`.
- [ ] Native/Wasm shared protocol with bounded owned requests, roles and stream contracts.
- [ ] Bounded `ConsoleConfig`, `Budget`, storage and control interfaces.
- [ ] `libs/serve` owns transport; `libs/console` owns application services;
  `apps/console-ui` owns Zig state, components, forms and SVG; JS only bridges capabilities.
- [ ] Share metrics and incident types through libraries with compatibility aliases.
- [ ] Strict console CLI parsing in daemon composition without changing data-plane parsing.
- [x] `-Dconsole` defaults to storage; explicit console without storage fails.
- [x] Build-helper directory included in package, formatting and structural checks.
- [ ] `console-test`, `console-e2e`, `console-assets`, `console-impact` run real checks.
- [x] Storage starts first; console drains, cancels and joins before storage closes.
- [ ] Gate: storage-off, console-off, storage single-node and clustered builds work;
  console-off has no console integration or telemetry producers.

## 2. Storage bridge and transactions

- [ ] `Persistent` remains sole storage owner; bounded typed mailbox with correlation IDs,
  owned buffers, completion states, cancellation and disconnect ownership.
- [ ] Bounded fair scheduling prioritizes authorization/control and existing maintenance.
- [ ] Zaxonlite 0.6.1 prepared queries and query limits, including replicated facade limits;
  no unmanaged SQLite handle or assumption that caller timeout cancels execution.
- [ ] Serialized versioned additive migrations and indexes preserve policies, reputation,
  FTS and vectors; incompatible binaries refuse unsupported schema/features.
- [ ] Mutations and redacted audit commit together; expected revisions reject conflicts;
  committed and per-node applied revisions remain distinct.
- [ ] Local commands record intent and completion separately from runtime effects.
- [ ] Gate: deterministic storage ticks cover saturation, bounded queries, migration replay,
  conflicts, failed rebuilds and cancellation ownership.

## 3. HTTP, authentication and real-time transport

- [ ] Listener, routing, deadlines, static assets, reserved HTTP slots and separate peer quota.
- [ ] RFC 6455 framing, fragmentation, masking direction, UTF-8, controls and close handling;
  reader makes progress independently of a serialized bounded writer.
- [ ] Bootstrap, forced password change, Argon2id, session digests, roles, CSRF,
  TOTP/recovery and independent password-verification concurrency bounds.
- [ ] Off-loopback requires canonical HTTPS origin and explicit trusted-proxy allowlist.
- [ ] Authoritative authorization recheck for mutations and subscriptions.
- [ ] Snapshots, epochs, deltas, gaps, bounded fan-out and reconnect.
- [ ] Authentication shell loads no geometry, GeoIP or telemetry before full authentication.
- [ ] Gate: live daemon bootstrap/login/subscribe/expiry/sign-out, slow clients and revocation.

## 4. Single-node dashboard and globe

- [ ] Exact external outcomes, bounded allocation-free sampling, boot-aware buckets,
  persisted minutes, visible loss and coverage; preserve Prometheus meanings.
- [ ] Space-Saving summaries with error bounds and tested cross-window merge.
- [ ] DB-IP import then optional MaxMind; bounded downloads/ranges, immutable activation;
  failed updates retain the active generation.
- [ ] Authenticated Zig dashboard: live orthographic globe, Traffic/Attacks, country ranks,
  timeline, summary panels; geometry separate from authentication bundle.
- [ ] Rolling 60-second geography updated at 1 Hz; Unknown, loss, incident coverage and age.
- [ ] Desktop/mobile/kiosk reuse, rotation/pause/reset, flat map, accessible tables.
- [ ] Gate: actual traffic updates the dashboard; unauthenticated loads remain zero;
  unavailable GeoIP and disconnected streams display honest unavailable/stale states.

## 5. Events, challenges and policy

- [ ] Grouped/raw incidents, filters, bounded pagination/export, campaigns and similarity;
  absent history says “not recorded”.
- [ ] Versioned bounded evidence capture with redaction and truncation metadata.
- [x] Challenge submissions/rejections and optional untrusted timing on existing POST;
  configured/effective difficulty separate, PoSW conversion and proof format unchanged.
- [ ] Rule edit/order/import/export, private-engine tester with config/file fallbacks,
  revisions/revert and complete candidate validation.
- [ ] Per-category inspection: audit continues evaluation and cannot bypass enforcement.
- [ ] Terminal-rule GCRA before session bypass, global limiter retained; reject WEIGH limits.
- [ ] Reputation/group/country actions reject overflow/conflict without partial application.
- [ ] Gate: live decisions agree with controlled tester, audit preserves other denials,
  country operations respect rule/trie limits.

## 6. Cluster and operations

- [ ] Node health/coverage/applied revisions/drain/clear-local-bans via control interface.
- [ ] Dedicated TLS management WebSockets with certificate validation and separate
  domain-separated peer HMAC key; telemetry outside consensus.
- [ ] Deduplicate node/boot/sequence/interval; missing nodes are unknown; no aggregate re-sums.
- [ ] Preserve issuer-bound challenge verification and local rate limits.
- [ ] Users, scoped API tokens, audit investigation, kiosk, constrained templates,
  notifications and About.
- [ ] Fenced singleton job leases; bounded destinations/retries/queues.
- [ ] Retention: minutes 90 days, ranks 7 days/512 MiB, incidents 30 days, audit 365 days.
- [ ] Gate: three-node edit/failover/lost quorum/stale peer/revocation/local command/restart.

## Release verification

- [ ] `zig build fmt`, `zig build test`, `zig build sid`, console checks and build matrix.
- [ ] Native UI render tests and browser auth/update/accessibility/responsive/reconnect tests.
- [ ] Typst PDF/PNGs regenerated; every wireframe visually inspected; HTML embeds figures.
- [x] SID 0007 has no removed-product references; book comparisons preserved.
- [ ] Regenerate benchmark results when measured subsystems change.
- [ ] Impact matrix: compiled out, disabled, idle, eight dashboards; admitted, challenged,
  incident-heavy and policy reload workloads, including clustered runs.
- [ ] Throughput degradation <=1%, p99 increase <=10%, with uncertainty, peak memory and
  storage contention reported. Inconclusive measurements fail acceptance.
- [ ] All gates passed before advancing Proposed or enabling console by default at runtime.

## Implementation evidence

- 2026-09-08: `zig build fmt console-test test sid` passed for the contract foundation.
  The storage failure-injection test emits its expected retained-batch warning.
- Added native/Wasm protocol types, configuration and reservation validation, and a
  mutex-protected management mailbox with owned payloads, correlation IDs, bounded fair
  scheduling, single-consumption completions and cancellation ownership tests.
- `console-test` tests these foundations; runtime composition, wire serialization and
  application workflows remain unchecked. No live console or performance result is claimed.

### Transport and build verification (2026-09-08)

- Added a bounded RFC 6455 codec with fragmentation, masking direction, control frames,
  UTF-8 and close validation. Tests include the masked Hello vector, every partial prefix,
  interleaved ping/UTF-8 fragments, malformed lengths and aggregate message overflow.
- Added listener-owned admission accounting with reserved HTTP capacity and separate peer
  quota. These primitives are not yet connected to sockets or daemon startup.
- `zig build fmt test sid sid-site --summary all`: 108 tests passed, including 18 console
  and transport tests. `console-test` additionally checks Wasm compilation.
- Storage-off: 87 tests passed. Console-off: 90 tests passed. Cluster-enabled daemon builds.
  The existing overload test now reads admission rejection without racing a request write
  against immediate server closure; both disabled configurations pass with that fix.
- Invalid `-Dconsole=true -Dstorage=false` fails cleanly with `CONSOLE001` and a recovery hint.
- Typst generated PDF and page PNGs; wireframe overview pages were inspected. HTML export
  retains SVG figures. Full-resolution review remains part of the document release gate.
- No measured request subsystem changed, and the console primitives are not yet composed
  into the daemon. No impact benchmark has run or passed. `console-e2e`, `console-assets`
  and `console-impact` remain unimplemented, rather than reporting success without evidence.

Next implementation work: finish daemon composition and lifecycle, connect the mailbox to
`Persistent` with bounded prepared queries and migrations, then implement authentication and
live transport before building the authenticated GeoIP dashboard. Later workflow and cluster
stages remain required; these commits do not deliver the complete SID 0007 console.

### Live daemon and initial interface (2026-09-08)

- Persistent now executes bounded prepared console operations through the owned mailbox.
  Bootstrap, password hashing, sessions, CSRF, password changes, and revision revocation
  are connected to the opt-in listener. Off-loopback startup remains unavailable until
  mandatory TOTP and proxy authorization are implemented.
- The Zig/Wasm authentication and initial statistics dashboard compile with committed
  Tailwind/daisyUI CSS. `console-assets` regenerates assets and `console-assets-check`
  verifies them without npm. The globe currently shows an honest unavailable outline.
- Real-daemon E2E tests exercise setup, failed/successful login, CSRF rejection, durable
  restart, fragmented WebSocket subscriptions, interleaved ping/pong, unsolicited updates,
  and sign-out revocation. Native tests prevent forced password changes from opening streams.
- Exact external outcome counters and sampled request records are compiled out when console
  support is disabled. A bounded background collector drains samples at 4 Hz. Existing
  Prometheus counter meanings are preserved. Benchmarks were regenerated after instrumentation;
  these subsystem results do not establish the console impact acceptance gate.
- Incremental Chrome review exercised setup, sign-in, live traffic (12 requests/12 challenges),
  pause/resume, theme switching, 390 px mobile layout and sign-out. Fixed an observed light-theme
  contrast defect. Full UI/accessibility/browser acceptance remains open for later workflows.
- `zig build test console-test fmt sid` passed with 120 tests for the initial interface;
  subsequent focused collector, account-boundary and GeoIP parser checks extend that coverage.
  The older evidence above records the state at those earlier commits, not current feature support.
- Work remains on durable GeoIP activation, geography, minute history, complete authentication,
  event/policy/challenge workflows, cluster/operational features, and release performance gates.
  SID 0007 remains Proposed; no feature-complete or full browser-acceptance claim is made.

### Country import and globe verification (2026-09-08)

- Added a pinned Natural Earth 5.1.2 geographic binary with representative country centers,
  strict decoder bounds, native orthographic/horizon/seam tests, and an authenticated asset route.
- DB-IP gzip imports bound compressed bytes (16 MiB), expanded bytes (128 MiB), source rows
  (1,048,576), line length (128 bytes), and native generation allocations. CRC/size, optional
  operator SHA-256, address ordering, overlaps and country codes are checked before activation.
  The full September 2026 file validated and imported in the browser: 717,152 known ranges;
  compressed SHA-256 `a32bb3c384bd3de60ad9024596aa5b395a6dd5beaa27a7223407cc2edc681d0b`.
- Unknown provider super-ranges exposed an IPv4-mapping edge case; source ordering is validated
  before explicitly Unknown ranges are omitted. Full-size browser testing exposed a narrow
  inferred integer in 100-range batch packing; explicit sizing and a 200-range E2E regression
  now cover that path. Interrupted same-digest imports replay only identical immutable chunks
  under current authorization.
- One background importer publishes through Persistent, with bounded chunks and atomic activation
  audit. Native lookup uses the restored immutable active generation. The collector now reports
  rolling country samples, Unknown and Other totals alongside exact request outcome counters.
- Chrome verified the full HTTPS import, geographic activation, 2,048 controlled requests / 2,048
  challenges, 33 observed country samples with zero sample loss, country centering, rotation,
  pause with stale age, and the flat map at 390 px width. Values are observed test results,
  not sampling or performance guarantees.
- `zig build test` reached 130 passing tests; storage-off and console-off matrices passed 89 and
  93 tests respectively. The full release gates and all later SID workflows remain open.
- Storage completion notifications replace 10 ms caller polling while pinning waiter ownership;
  shutdown/cancellation cannot recycle an event still referenced by its caller. A full local
  generation restart became HTTP-ready in 15.6 seconds (one observation, not a performance gate).
- Browser verification after restart confirmed the active 717,152-range generation, restored
  authenticated subscriptions, labelled password fields, password change/session revocation,
  and successful login with the replacement password. Geographic markers are clipped at the
  visible globe horizon; returning to a visible GeoIP page refreshes import status.

### Authentication and journal restart verification (2026-09-08)

- TOTP uses the RFC 4226/6238 SHA-1 vectors, six digits and a bounded adjacent-step window.
  Seeds use separately provisioned console-key encryption, with user-bound authenticated
  envelopes. Enrollment revokes earlier sessions. Session insertion atomically consumes
  the accepted step or one of ten recovery digests; rollback does not consume a code.
- Authentication schema v2 migrates in one owner-executed transaction. Deterministic tests
  cover a failure after ALTER, replay, refusal of future schemas, idle expiry and absolute
  expiry. Sessions now use the SID's 12-hour absolute and 30-minute idle lifetimes;
  passive subscription checks do not extend idle access.
- Live-daemon tests cover enrollment, password-only rejection for an enrolled account,
  replayed codes, recovery use, and recovery rejection after restarting. Chrome exercised
  enrollment, recovery delivery, recovery login, sign-out and rejection of the consumed code.
  The mobile review found a minimum-content card width issue; recovery text now wraps and
  the card can shrink. QR provisioning and complete account-management workflows remain open.
- The full country-data fixture crossed a journal rotation boundary and exposed a pinned
  Zaxonlite 0.6.1 iterator defect on restart. The manifest and segment checksums were valid.
  A reviewed one-line generated-source patch selects the sealed-segment reader, preserving
  trailer validation. The downloaded dependency and on-disk format are unchanged. A new
  deterministic regression writes across multiple rotations and authorizes after reopening.
  See `build/patches/README.md` for the patch bounds and removal condition.
- A copy of the exact failed full-size fixture reopened with the sealed-reader fix in
  16.2 seconds and retained revision 1 with all 717,152 known ranges. The original fixture
  remains untouched. Storage-off and console-off test builds and the clustered TLS build
  passed. These observations close this regression, not the broader cluster/release gates.

### Local initialization verification (2026-09-08)

- `sibuna init-admin <username> --data-dir <path>` initializes through Persistent before
  any listeners start. The command prints a random temporary password once, stores only its
  Argon2id digest, and requires replacement within one hour. Duplicate initialization fails.
- HTTP setup now reports initialization status only; the UI explains the local command.
  Schema v3 adds temporary credential expiry and transactional explicit sign-out auditing.
- `zig build fmt test console-e2e sid` passed. Live tests cover an empty daemon, rejection
  of HTTP initialization, the local command, restricted temporary sessions, replacement,
  old-password rejection, authenticated geometry, TOTP and trusted-proxy restrictions.
  Password replacement currently revokes old sessions and requires another login; atomic
  replacement-session issuance remains the next authentication change.

### Atomic credential replacement (2026-09-08)

- Schema v4 commits password replacement, revision increment, old-session revocation,
  replacement-session insertion and redacted audit rows together. The owner rechecks the
  password-verification revision and current session/CSRF authorization inside that transaction.
  A failed replacement insertion rolls back the password and preserves the existing session.
- Password changes now return a new cookie and CSRF token. The UI continues through required
  TOTP enrollment or the dashboard using the replacement session. Reusing the same password
  is rejected. The previous re-login limitation above is resolved.
- All 144 unit tests, live console E2E tests, formatting and SID generation passed. Chrome
  verified the empty-instance notice, local initialization, restricted temporary login,
  forced password change and immediate live dashboard access at 390 px width.


### Joined daemon shutdown (2026-09-08)

- SIGTERM/SIGINT handlers set a lock-free flag. A normal monitor wakes acceptors; bounded
  task slots retain joinable connection threads. Shutdown stops admission, interrupts client
  and active upstream sockets, joins workers/reaper, drains pooled sockets, then releases
  console tasks before Persistent flushes incidents and closes storage.
- Idle slots remain owned until their connection unregisters. A deterministic regression
  covers the former reaper/reuse race. Startup/shutdown also release daemon-owned engine,
  slot and application state allocations after their borrowers have stopped.
- Zig 0.16's native connect-timeout option is unimplemented and panics. A fixed-buffer
  nonblocking POSIX connector uses a five-second monotonic deadline and restores blocking
  operation before handing the connected socket to Io. No request-path allocations were added.
- `zig build fmt test sid` passed, with 146 unit tests and live shutdown checks covering
  four accept workers, partial HTTP clients, an authenticated subscription, a silent origin,
  clean exit and restart. Tests fail on forced termination or a nonzero shutdown status.
  Storage-off, console-off, clustered TLS and x86_64 Linux/musl builds passed.
- The browser retained the last observed dashboard values and displayed Disconnected with
  stale age after the review daemon stopped. Broader release and feature gates remain open.

### Incident browsing and interface (2026-09-08)

- Owner-executed incident queries support time, node, category, address and path filters,
  timestamp/id keyset cursors, at most ten rows and a 4 KiB serialized response. Schema v5
  adds indexes without rewriting forensic/FTS/vector content. IDs cross the browser as strings.
- Historical query strings are removed from displayed paths. Unversioned payloads are withheld;
  absent country, response status, matched rule and capture metadata explicitly remain unrecorded.
  Existing campaign identifiers are labelled automated similarity candidates.
- The Events page provides time/category/address/path filters, bounded paging, UTC timestamps,
  expandable details and empty/error states. Filters use a compact desktop row and mobile stack.
  Stable heading/results targets preserve keyboard focus across asynchronous rendering.
- Repository tests, live query tests, SID generation and final native UI/asset checks passed.
  Live tests generated 15 honeypot incidents and verified filtering, complete pagination,
  authorization/CSRF, exact string IDs and omission of payload secrets. Browser checks verified
  two populated pages, address filtering, empty results, escaped script-like user-agent text,
  missing-evidence labels, mobile/desktop layouts and heading/results focus without overflow.
- Grouped investigation, exports, richer versioned evidence and remaining policy/operational
  workflows are still open; this entry does not close the full investigation acceptance gate.

### Source grouping and bounded exports (2026-09-08)

- Source groups retain node/address identity, exact filtered record counts and first/last
  capture times. Drill-down keeps the selected node, address and time boundary. Historical
  countries stay unrecorded. Query and export budgets are independently bounded per session
  and globally, with their fixed memory included in the console reservation estimate.
- JSON and CSV export only the selected bounded page. The owner rechecks authorization and
  records export preparation before returning bytes; the audit does not claim download delivery.
  CSV visibly prefixes formula-like text and quotes separators; JSON preserves returned strings.
- All 152 unit tests and live console tests passed; formatting passed after final corrections.
  Browser review covered grouped/raw switching, node/address drill-down and both export controls.
  A full-page CSV test exposed dynamic parser exhaustion that a one-record export missed. A
  typed bounded parser and full-page live regression resolve it; the browser repeated the
  full-page export successfully. Export feedback preserves button focus and uses status styling.
- Rich versioned evidence, rule/address actions, campaign-member and nearest-incident navigation,
  and the remaining policy/cluster/operational work still block full SID acceptance.

### Challenge observation foundation (2026-09-08)

- Console-owned atomic counters cover parsed verification submissions, early malformed/banned
  rejections, exhaustive verifier failures, issued and accepted authenticated parameter bins.
  Existing Prometheus counter meanings and proof/token formats remain unchanged. Console-off
  builds eliminate producers; console-disabled runtime work avoids parsing timing metadata.
- The interstitial sends solve duration measured before verification and an untrusted solver
  label. Only accepted proofs contribute timing: 16 bounded histogram buckets, separate missing
  and invalid counts, and finite nonnegative durations capped at one hour. A fixed scanner arena
  rejects ambiguous metadata without changing admission. Parameter bins use authenticated proof
  fields; client fields cannot select them. Reservation accounting includes these fixed counters.
- Required formatting, repository/live tests and SID generation passed. Live proof tests cover
  valid, missing and invalid timing, replay and missing challenge IDs. A storage-free,
  console-disabled daemon build passed. Benchmark regeneration follows for this measured change.
- Authenticated challenge presentation, historical windows and per-address observations remain
  pending; this foundation does not close the challenge or performance acceptance gates.


### Authenticated Challenges interface (2026-09-08)

- The bounded, CSRF-protected snapshot endpoint shows boot-local issued/submitted/accepted
  totals, exhaustive rejection causes and one selected timing histogram. Configured difficulty,
  converted default parameters and most recently issued authenticated parameters are distinct.
  Query budgets apply; the response remains below 16 KiB even with maximal bin counts.
- The Zig page offers populated parameter partitions, accepted timing/missing/invalid counts,
  reported solver labels, explicit untrusted-data explanations and manual refresh. Snapshot age
  advances, failed refresh retains labelled stale values, and recovered connections refresh them.
- Required repository/live tests, formatting and SID generation passed; final native UI tests
  passed after browser corrections. The live browser solved a real PoSW depth-13/16-opening
  challenge and observed one issued/submitted/accepted proof with Wasm timing in 64–128 ms.
  Mobile rendering had no horizontal overflow; partition selection retained keyboard focus.
  Stopping/restarting the isolated daemon verified stale feedback and successful refresh recovery.
- Browser testing exposed generic JSON-tree arena exhaustion on the 256-bin array. A typed
  response decoder fixes it, with a full browser-event native regression; refresh is no longer
  stuck disabled. The UI also ignores delayed responses after leaving the Challenges page.
- Benchmark snapshot `latest-20260907T225257Z.json` was regenerated for the preceding measured
  observation changes. This does not replace the outstanding SID console-impact release gate.

### Versioned incident metadata (2026-09-08)

- Additive schema v6 stores an incident metadata sidecar in the same idempotent transaction as
  forensic, FTS, vector and reputation writes. Historical content remains intact; historical
  and grouped rows have no inferred envelope. Console-disabled builds omit metadata producers
  and queue fields; the reservation estimate includes the incremental queue/batch metadata.
- Version 1 captures the selected firewall status, query/received/declared body lengths and
  separate capture truncation flags. The evidence view omits query/body values, cookies and
  other headers; it preserves the existing bounded User-Agent display. Selected status is not
  presented as proof of delivery. Country, matched rule and delivered status remain unrecorded.
- Required repository/live tests, SID compilation and final formatting/native UI checks passed.
  A deterministic failure trigger verifies incident/evidence rollback, retained-batch retry and
  migration replay. Live queries verify new metadata, private query omission and bounded CSV.
  A storage-free console-disabled build passed.
- Browser review checked mixed historical/new rows, address filtering, exact byte lengths,
  capture versus display truncation, escaped historical markup and successful versioned CSV
  export. A synthetic request's query/body/cookie/authorization values were absent from the view;
  its 810-byte body and User-Agent capture limit were represented explicitly.
- Rich matched evidence, policy revision, country-at-capture and configurable redaction remain
  future envelope extensions. Existing private forensic storage is not relabelled as sanitized
  evidence. Benchmark regeneration follows for this measured capture-path change.

### Candidate membership navigation (2026-09-08)

- Incident details link existing similarity candidates to raw or grouped membership. Navigation
  preserves exact string IDs and the selected time boundary, clears address/node restrictions,
  and retains a visible candidate filter through paging, regrouping and bounded export.
  The interface explicitly distinguishes automated similarity grouping from attribution.
- Schema v7 adds a campaign/time/id index. Candidate queries use an equality predicate so
  SQLite can use it within the existing VM-step budget. A deterministic fixture with 15,000
  unrelated records verifies exact membership for an ID above JavaScript's integer precision.
  Live tests verify all 15 related incidents across pages and reject oversized IDs.
- Required formatting, repository/live tests and SID compilation passed. Browser review exposed
  generic JSON-tree exhaustion on a full historical page; incident responses now use typed
  decoding, with a complete ten-row browser-event regression including versioned metadata.
  Browser repetition successfully displayed ten then five members and restored results focus.
- Nearest-incident search and policy/reputation actions remain pending. The preceding capture
  benchmark regeneration is committed as `latest-20260907T231647Z.json`; console-impact and
  storage-contention acceptance still require the release harness.

### Incremental nearest-incident queries (2026-09-08)

- Similarity requests read the source vector by ID and scan at most 64 time/id-ordered records
  per background mailbox operation. They recheck authorization on every part and retain existing
  prepared-query limits. This avoids claiming that VM-step limits bound a vec0 internal KNN scan.
- Each part returns at most ten IDs, node/time metadata and normalized cosine distances in a
  bounded response. Raw payloads and vectors are not returned. The shared fixed top-ten merger
  preserves global ordering across parts, including deterministic ties and duplicate rejection.
  Missing/invalid vectors and the continuation cursor make search coverage explicit.
- Deterministic storage tests scan 130 records in three parts, verify closest-match merging and
  per-part revocation. Live API tests cover CSRF/authentication, missing source vectors, exact
  IDs, bounded output and incident drill-down. UI progress and browser acceptance follow below.

### Similarity interface and HTML snippets (2026-09-08)

- The interface merges successive parts, exposes partial/complete coverage, and supports pause,
  resume and exact incident inspection. Generation checks reject delayed responses after pause
  or a replacement search. Returning from an incident preserves the previous search results.
- Browser checks on the isolated daemon scanned 146 retained records with zero missing vectors,
  rendered ten closest matches, opened the exact selected incident and restored completed results.
  The 390-pixel layout had no horizontal overflow; desktop rendering was inspected at 1280 pixels.
- Evaluated the sibling Kynetica ZMPL engine. Although used by its static generator, that engine
  parses and renders at runtime, with CMS inheritance, filters, maps and allocator-owned output.
  Sibuna instead adopts its strict lookup and escaping ideas in a small first-party renderer:
  trusted HTML snippets with build-time placeholder expansion and runtime typed Zig values.
- `libs/html` builds natively and for Wasm, allocates no memory, and writes to caller-owned output.
  It has no raw HTML path or runtime template interpreter. Conditions and bounded loops stay in
  Zig. Shared form fields, messages and the similarity page now use ordinary `.html` snippets;
  Tailwind scanning and committed input digests include those files. Other pages can migrate
  incrementally. Operator-editable data-plane templates require their separate constrained design.
- Required `zig build fmt test sid` passed, including native render and live daemon tests. Six
  compile-rejection probes verified missing fields, unclosed/invalid placeholders, unsupported
  tags, source-size limits and placeholder-count limits. Runtime tests cover escaping expansion,
  fixed-output exhaustion and exact 64-bit IDs. No measured data-plane subsystem changed.

### Consistent authenticated navigation (2026-09-08)

- Moved the sidebar out of the Statistics renderer into a shared authenticated shell. Every
  full-access view, including similarity and account security, now has one navigation landmark
  and the correct active section. Required password/TOTP gates retain the authentication shell.
- Uses the pinned daisyUI menu/navbar components, theme tokens, sticky desktop navigation and a
  Wasm-owned mobile disclosure with `aria-controls`/`aria-expanded`. Page selection closes the
  disclosure and restores heading focus. A skip link bypasses repeated navigation.
- Required formatting, tests and SID compilation passed. Browser checks traversed all current
  desktop sections and verified mobile disclosure, selection, focus and no overflow at 390 px.

### Authenticated earth without a GeoIP dependency (2026-09-08)

- The custom Zig/SVG orthographic earth now draws authenticated Natural Earth boundaries even
  when no GeoIP generation exists. No traffic locations are inferred: the unavailable notice
  and Unknown coverage remain explicit. Added ocean shading and a bounded geographic grid.
- Geometry requests remain behind full authentication and retry no more often than every 30
  seconds after failure. Superseded browser downloads cannot publish over a newer request.
- Native tests render the complete committed geography in four rotations and flat mode within
  the existing 512 KiB output budget, and reject geometry publication after authorization loss.
  Required formatting, tests and SID compilation passed. Browser review verified rotation,
  reset, unavailable coverage and the flat-map layout at 390 pixels without horizontal overflow.
- No Three.js dependency is needed for the current globe. Pointer gestures and richer traffic/
  attacks overlays remain separate work; existing keyboard-operable rotation controls remain.

### Applied policy inspection and evaluation (2026-09-08)

- Added authenticated, CSRF-protected owner-mailbox reads of the published policy engine and
  bounded request evaluation. Pages contain at most eight summaries and 4 KiB of JSON; pagination
  and tests can pin an applied revision. Committed storage stamps and applied engine stamps are
  reported separately. Pins never survive an operation or block publication across a tick.
- Summaries include file/default and database rules in effective order, with explicit omission
  of header/CIDR values and display truncation metadata. Tests include inspection, reputation
  and complete applied matchers. They do not simulate sessions, local limiters or origin replies.
  Operator-supplied request bodies and headers are not persisted by this read-only operation.
- Deterministic storage ticks verify file/database composition, inspection precedence, stale
  revision rejection and session revocation. Live daemon tests compare Amazonbot and XSS denials
  with actual traffic and verify authentication, CSRF, invalid input and revision conflicts.
- The Policies UI uses HTML snippets and shared navigation, preserves submitted fields, rejects
  late response generations, and provides error/result focus and a direct tester link. Browser
  checks verified deny and allow cases, revision 146 becoming stale after a synthetic incident,
  refresh to revision 147, invalid-IP recovery, and a 390-pixel layout without overflow.
- The initial browser query exposed empty tuple serialization as an array; it now sends an
  explicit offset object and has regression coverage. The bridge compares successive Wasm HTML
  outputs rather than browser-normalized innerHTML, avoiding needless form replacement on no-op
  events. Browser keyboard clearing and re-evaluation were verified.
- Reusing the existing JSON decoder and resetting owned State fields individually kept the
  interface below the 300 KiB gate (287,701 bytes before the final small navigation additions).
  A native regression verifies credential/body erasure and default restoration during reset.
  Required repository tests, formatting and SID compilation passed; subsequent UI refinements
  passed console-specific checks and browser review. Policy edits, history and candidate-engine
  validation remain pending and are not represented as implemented by this read/test view.

### Strict management documents and private candidates (2026-09-08)

- Added a separate management document compiler with owned strings, a 4 KiB input bound,
  strict field validation, and rejection of excess or ambiguous matchers. Existing startup
  file parsing remains compatible. Disabled documents receive the same validation.
- Private candidates own their engine and a fixed 2 MiB string/parser budget, include current
  file settings and fallbacks, and insert validated dynamic rules in priority/name/ID order.
  Their 128-rule limit includes fallbacks; reputation insertion rejects invalid actions,
  malformed networks and trie exhaustion. Failure releases the entire private candidate.
- Tests cover input ownership, allocator exhaustion, duplicate fields/IDs, matcher limits,
  deterministic order, disabled rules, fallback capacity and file/reputation composition.
  This is library support for upcoming management operations; no draft is published and no
  policy write endpoint is exposed by this change.

### Revision-bound draft preview service (2026-09-08)

- The policy test endpoint accepts an optional owned draft document and a required committed
  revision. The storage owner replaces the matching database ID, or inserts a new candidate,
  without writing or publishing it. Results explicitly distinguish previews and their committed
  basis from the currently applied revision.
- Snapshot reads use prepared query limits, eight-rule pages and 64-reputation pages. Source
  staging has a fixed 2 MiB budget, in addition to the private candidate's engine and 2 MiB
  parser budget. Revisions are checked before and after composition, and authorization is
  rechecked before returning the result. Existing malformed neighboring rules reject the draft;
  replacing a malformed rule itself allows it to be repaired.
- Storage tests cover replacement without publication, stale revisions, revoked sessions,
  invalid disabled neighbors and complete header/CIDR matchers across page boundaries. Live
  daemon tests verify a draft denial over an applied allowance, invalid input, missing revision,
  conflicts and the unchanged applied decision afterward. Formatting, tests and SID checks pass.
  Editor controls and transactional writes remain subsequent work.

### Atomic policy saves and revision history (2026-09-08)

- Schema 8 adds policy history, a redacted audit target, a deterministic ordering index and a
  temporary staging table. A conditional prepared statement rechecks session, CSRF, role and
  expected revision; its trigger commits the rule, history and audit together and clears staging.
  First edits preserve an encodable pre-existing database rule as a baseline. Invalid legacy
  rules without an encodable baseline can be repaired without inventing prior history.
- Operators and administrators can save validated documents through the authenticated edit
  endpoint. Candidate validation includes all neighboring policies, file settings and reputation.
  Responses distinguish the committed revision from the previously applied engine; publication
  occurs on the storage tick and failed rebuilds retain the old applied revision for retry.
  Priority/name/ID ordering now agrees between private candidates and published database rules.
- Tests cover stale edits, owner-side CSRF and role enforcement, revoked sessions, audit failure
  rollback, baseline preservation, migration replay and recovery after failed publication. Live
  daemon tests verify an edited denial against actual traffic and subsequently disable that rule.
  Formatting, repository tests and SID compilation passed.
- Regenerated primitive benchmarks with other review/test daemons stopped; the snapshot is
  `benchmarks/results/latest-20260908T014358Z.json`. This regeneration does not establish the
  separate console impact acceptance gate. Managed-rule browsing, editor forms and history/
  revert controls remain pending.

### Managed-rule and history reads (2026-09-08)

- Added authenticated, CSRF-protected catalog, complete-document and history reads. Catalogs
  and histories return at most eight rows and 4 KiB, with keyset cursors and revision checks
  around storage reads. Complete documents use a dedicated owned result rather than silently
  clipping editable fields to fit a summary. Historical documents retain their original content.
- Storage tests verify catalog page boundaries. Live daemon tests verify authorization, CSRF,
  complete-document round-trips, history reads, stale revisions, restoring an older document
  through the validated save transaction and restoring the current version afterward.
  Formatting, tests and SID checks passed. User-facing editor and history controls follow.

### Managed-rule editor and history interface (2026-09-08)

- Added structured rule forms, catalog/history pagination, private draft previews and saving
  historical documents as new validated revisions. Inputs survive validation and revision
  conflicts; existing IDs are read-only. Operator controls follow protocol permissions.
- HTML snippets render through Zig with escaped values. A responsive two-column form becomes
  one column on mobile. The browser bridge collects form fields; Zig owns document construction
  and application behavior. Successful saves use the daisyUI success alert treatment.
- Removed the initialized global Wasm state image, initializing explicitly before events, to
  keep the expanded editor inside the startup bundle gate. Native initialization and document
  ownership/validation tests pass along with formatting, repository tests and SID compilation.
- Live browser checks covered private denial previews, malformed matcher JSON, save/disable,
  historical restore and stale-save rejection with draft retention. Actual firewall requests
  followed the saved denial. Desktop and 390-pixel mobile layouts were inspected; the shared
  navigation remains accessible and the mobile form has no horizontal overflow.

### CLI country database loading (2026-09-08)

- Added `tools/console_geoip.py` with hidden password/TOTP prompts, HTTPS or literal loopback
  HTTP, bounded responses, monthly imports, optional compressed-file checksums, progress and
  status inspection. It uses the authenticated console service and never opens storage itself.
  Repeated requests for an already active month skip importing and verify any supplied digest.
- Downloaded September 2026 DB-IP data into the review instance: 717,152 known-country ranges.
  Verified durable restoration after restart and live US/Australia markers, country rankings,
  Unknown local-address samples and the flat-map fallback. Usage is in `docs/console-geoip.md`.
  This verifies development data loading, not the remaining SID telemetry or cluster gates.

### Dashboard reconnection after management navigation (2026-09-08)

- Browser verification with the full country database found that policy navigation disconnected
  transport without releasing the dashboard's busy guard. Returning to Statistics consequently
  kept old values labelled Live. Disconnect commands now consistently clear that guard and mark
  retained data stale until a fresh subscription snapshot arrives.
- A native regression exercises an active dashboard, policy navigation and return, checking
  both the emitted connection command and the stale state while waiting for new data.
  Formatting, full repository tests and SID generation pass. Browser verification after a
  restart and policy round-trip received 768 new requests, US/Australia samples and Unknown
  local samples through the reconnected stream.
