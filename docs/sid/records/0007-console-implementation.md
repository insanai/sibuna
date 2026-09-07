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
- [ ] `-Dconsole` defaults to storage; explicit console without storage fails.
- [ ] Build-helper directory included in package, formatting and structural checks.
- [ ] `console-test`, `console-e2e`, `console-assets`, `console-impact` run real checks.
- [ ] Storage starts first; console drains, cancels and joins before storage closes.
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
- [ ] SID 0007 has no removed-product references; book comparisons preserved.
- [ ] Regenerate benchmark results when measured subsystems change.
- [ ] Impact matrix: compiled out, disabled, idle, eight dashboards; admitted, challenged,
  incident-heavy and policy reload workloads, including clustered runs.
- [ ] Throughput degradation <=1%, p99 increase <=10%, with uncertainty, peak memory and
  storage contention reported. Inconclusive measurements fail acceptance.
- [ ] All gates passed before advancing Proposed or enabling console by default at runtime.

## Implementation evidence

Pending verification. No live console or performance result is claimed by this checklist.
