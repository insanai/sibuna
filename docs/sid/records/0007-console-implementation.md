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
- [ ] Challenge submissions/rejections and optional untrusted timing on existing POST;
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
