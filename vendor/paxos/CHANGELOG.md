# Changelog

## zaxonlite 0.7.0 - 2026-09-13

- Fix repeated background trim proposals while an earlier trim remains
  undecided (insanai/zaxonlite#10) by serializing maintenance at the applied
  proposal frontier.
- Identify each trim by its chosen global Paxos slot instead of an
  asynchronously derived counter. Exact replay is idempotent; stale and
  content-identical duplicate decisions retain the stronger installed anchor
  and increment an observable counter, while decision twins and conflicting
  history at one trim frontier fail closed.
- Keep trim proposal/history errors terminal, but treat physical reclamation
  errors as warn-and-retry work outside the commit path.
- Require transaction progress before a periodic state anchor so chosen trim
  commands cannot sustain an idle anchor/trim feedback loop.
- Make terminal host failure first-failure-wins, expose `health` and `failure`
  in status, wake all waiter classes, print one terminal diagnostic, and stop
  locally with exit code 4. Embedded, C, and Python hosts can inspect the local
  member state without routing through a healthy peer; gateway threads publish
  their first failure to the embedding host as well.
- Cut wire protocol 10, segmented journal/manifest 3, `TRIM` 2, and identity
  format 3. There is intentionally no migration or rolling upgrade path:
  stop all members, delete every member data directory (journal, manifest,
  `TRIM`, identity, anchors, payloads, and SQLite image), and recreate the
  cluster together.
- Keep a replacement's durable `JOIN` marker through registry fetch and image
  installation. It cannot process or vote on Paxos envelopes until its
  inherited anchor is published, so recovery cannot erase an accepted vote;
  publish the new configuration in an anchor at handover even when no page
  changed. Refuse a fresh later-configuration voter with no `JOIN` descriptor,
  and refuse a `JOIN` on any role other than the replacement data voter.
- Permit a later-configuration image transfer to a fresh joiner even when the
  sender still retains journal history from genesis.
- Make concurrent connection completion and shutdown share one interruption
  owner, avoiding duplicate socket closure during bounded teardown.
- Add the test-only `--test-anchor-interval-ms` server control alongside the
  existing storage and vote delays; all require `--enable-failpoints`.
- Add a deterministic three-process trim soak with monotonicity, convergence,
  reclamation, restart, integrity, and continued-write assertions, complementing
  the separate adverse-network schedule. `--record` writes its result artifact.

## 0.6.2 - 2026-09-09

- Avoid a macOS panic in Zig 0.16 when an interrupted socket connection
  completes before the runtime retries it. TCP and Unix connections now issue
  one nonblocking connect and wait cancelably for completion, preserving the
  existing connection deadline and restoring blocking mode before handoff.

- Fix Zaxonlite shutdown hanging when writes, read fences, or condition waits
  are blocked on consensus (insanai/zaxonlite#7). Shutdown and fatal failure
  wake all host waiters independently of protocol ticks; unresolved writes
  retain an unknown outcome, and failed condition waits cannot report success.
- Interrupt outbound peer authentication and I/O during shutdown and transport
  replacement. Bound peer and gateway dialing and stop embedded servers through
  a local lifecycle signal, including failed-startup cleanup.
- Skip the stop-reply grace period for local embedded shutdown; explicit
  stop RPCs wait on reply completion with one monotonic 250 ms deadline.
- Bound client connection establishment to ten seconds by default, across TCP
  or Unix connect, TLS, and PSK. Add explicit-deadline connection/RPC helpers and
  enforce one monotonic deadline for embedded startup readiness checks.
- Stop automatically replaying client requests after a transport failure once
  transmission begins. Seed connection failures and explicit leader redirects
  remain retryable; uncertain writes require session-based replay.
- Read retained journal segments with sealed-segment validation, so trailers
  are not mistaken for corrupt records during leader resynchronization,
  range catch-up, integrity checks, or image rebuilding after rotation.
- Align the Paxos, Zaxonlite, CLI UI, Python SDK, and book versions on 0.6.2.
  Wire and journal formats remain compatible with 0.6.1.

## 0.6.1 - 2026-09-07

- Record the first slot of each leadership term in the core and expose it
  as `leaderBase()` alongside `proposalFrontier()`. The opt-in
  `gate_proposals_on_inherited_prefix` option refuses proposals with
  `LeaderCatchingUp` until every slot inherited in phase one is delivered
  (insanai/paxos-zig#1).
- Admit a zaxonlite write only after the leader has applied everything
  below its proposal frontier, and serve `leader` and `linearizable` reads
  only after the inherited prefix is applied, so a freshly elected leader
  can no longer capture a transaction batch on a stale chain base
  (insanai/zaxonlite#5). A leader still owing itself inherited slots keeps
  requesting catch-up and falls back to a state transfer; a decided chain
  mismatch is reported with the failing check.
- Add the takeover cluster scenario and the test-only
  `--test-storage-delay-ms` and `--test-vote-delay-ms` flags that make it
  deterministic.
- Recheck failure and leadership after every frontier wake, including a
  wake that also settles the frontier, before admitting the request.
- Align the Paxos, Zaxonlite, CLI UI, and Python SDK packages on 0.6.1.
  Wire and journal formats remain compatible with 0.6.0.

## 0.6.0

paxos-zig 0.6.0 and zaxonlite 0.6.0 (ZDS 0011). This is a breaking format
cut with no bridge: wire protocol 9, journal format 2, and the new durable
state anchor replace their predecessors, and artifacts from earlier
releases fail closed at open.

- Replace the bounded epoch with a single `u64` global slot line that is
  never reset. The core keeps a fixed slot-tagged consensus window
  (`window_slots`, a power of two) with a host-licensed memory floor;
  `max_slots` and the 2,044-commit rollover are gone, and with them the
  write-path cost proportional to database size.
- Add chunked leader recovery (`PromiseRange`) with the trimmed-acceptor
  fences: an elected leader never proposes at or below the maximum quorum
  trim anchor or chosen-through. Message and write capacities derive from
  the recovery chunk, not the log length.
- Add certified log trimming: replicas publish durable-state reports, the
  leader proposes the conservative trim `G = min A_i` over data replicas
  as an ordinary chosen entry, and segments wholly below the adopted trim
  are physically unlinked with payload garbage collection behind them.
- Replace the epoch journal with a segmented, manifest-governed journal
  (`consensus/`): first-slot-named segments, sealed trailers carrying a
  `max_promised` ballot rollup, rename-free rotation, and orphan sweeps.
  Replay folds the lifetime journal across configuration changes and
  window reuse.
- Add the alternating durable state anchor (`APPLIED.0/1`): recovery
  replays only the journal suffix above the anchor, so startup cost
  follows the anchor cadence instead of the whole history.
- Add the domain-separated global history hash `H_s`, folding each
  transaction batch's result chain, with per-slot recent marks for
  quorum vouching.
- Rewire decided voter replacement (ZDS 0008) onto global slots: the stop
  sign carries only the next registry digest and the replacement seed,
  survivors continue the same slot line in place, and the joining voter
  fetches the decided registry and catches up from the retained journal.
  Snapshot generations, `CURRENT` pointers, and per-configuration
  journals are gone.
- Add the anchor-pinned state transfer for gaps beyond journal retention:
  the sender pins a fresh anchor and a private image copy, and the
  receiver installs only after a read quorum vouches the anchor's history
  binding and the image digest matches. The stop-sign checkpoint proof
  and its quorum probe are removed.
- Rename the `snapshot` CLI verb to `anchor`; `zaxonlite_snapshot`
  becomes `zaxonlite_state_anchor` in the C ABI. Status output reports
  the global frontier fields (`durable_state_slot`, `memory_floor`,
  `chosen_trim_slot`, `retained_first_slot`, journal totals) instead of
  epoch capacity. Slot fields in the JSON status are `u64`; readers that
  parse them as IEEE doubles lose precision past 2^53.
- Extend the crash matrix over the anchor, trim, reclamation, and payload
  GC failpoints (15 cases), add the nightly long-run retention gate
  (segment rotation, bounded retention, anchored restart), and add the
  moving-window benchmark family (256 window wraps on one slot line).
- Model the design in `specs/GlobalTrim.tla`: the slot-tagged window,
  eviction licensing, trimmed-acceptor election fences, conservative
  trim, and the joiner lease lifecycle, with deliberate-bug validation.



## 0.2.0 - 2026-07-30

- Add the native `zxlite` Python SDK for CPython 3.12 and newer, including a
  SQLite-shaped DB-API 2.0 interface and a SQLAlchemy 2.x dialect.
- Add Python-hosted zaxonlite servers plus redundant multi-seed remote
  connections, consistency-aware concurrent reads, serialized writes, and
  typed hybrid search over the native client protocol.
- Add stable C APIs for embedded servers, remote connection pools, prepared
  values and result rows, batched execution, and typed search.
- Add replicated FTS5 and sqlite-vec hybrid search with bounded candidate
  collection, reciprocal-rank and distribution-based fusion, and Zig SIMD
  reranking.
- Add voter replacement, durable stop-sign recovery, and the host-managed
  durability boundary for grouped write barriers.
- Harden Linux and macOS connection shutdown, strict C11 C-ABI builds, and
  Python native linking under Zig 0.16.
- Publish release CLI archives, CPython Stable ABI wheels, checksums, and the
  `zxlite` package on PyPI from the tagged GitHub workflow.

## 0.1.2 - 2026-07-28

- Expose the decided stop slot (`ReplicatedLog.Node.stopSlot`) and a
  by-reference stop-sign accessor (`stopSign`), and latch the slot across
  restore, so hosts no longer hand-track where the seal landed.
- Add `ReplicatedLog.Node.pendingStopSign`: the undecided stop value
  retained in durable accepted state or leader proposals, so a host can
  repair its own durable operation phase after a crash.
- Export `paxos.version`; the benchmarks now print it instead of a
  hard-coded release string.
- Make `StopSign.create` public and extract `StopSign.validateMembers`,
  letting host wire decoders reuse the zero/duplicate member-ID checks.
- Add changed-member `initFromStop` unit coverage and a deterministic
  one-for-one voter-replacement simulation (`sim/reconfiguration.zig`):
  seeded leaders, a dropped and a duplicated seal accept, handover to the
  survivor set, and rejection of the removed voter.
- Add `specs/VoterReplacement.tla`, the bounded host-level model for the
  zaxonlite decided voter replacement built on this library (ZDS 0008).
- Enforce the persist-then-send effect order in every optimize mode; a
  violation now stops the process with a stable diagnostic
  (`paxos: messagesSlice before confirmWritesDurable`,
  `paxos: reset discarded unconfirmed writes`).
- Remove the `assert_effect_order` option; the enforced check has no opt-out
  in normal `Options`.
- Add the `paxos.host_managed` namespace for audited hosts that own the
  durability boundary themselves (grouped write barriers). The durable
  benchmark is its first consumer.
- Replace compile-time option assertions with `@compileError` diagnostics
  across `Protocol`, `ReplicatedLog`, `Learner`, and the internal bit set,
  and reject derived effect capacities that overflow `usize`.
- Add `zig build test-misuse` (effect-order misuse fixtures run as child
  processes in Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall) and
  `zig build test-compile-errors` (compile-fail option fixtures); both run
  under `zig build test`, which now also drives the path-dependency
  integration consumer.

## 0.1.0 - 2026-07-18

- Implement bounded classic Paxos and stable-leader Multi-Paxos.
- Add reorder-safe phase-one recovery, learning, catch-up, and durable deltas.
- Add logical election ticks, priorities, heartbeats, resend, and reconnect repair.
- Add flexible quorums, compact vote sets, batch proposal, and decided reads.
- Add stop-sign reconfiguration and bounded checkpoint epochs.
- Add an in-memory replicated-counter example.
- Add locked benchmarks against OmniPaxos 0.2.2 and LibPaxos3 C.
- Add in-place initialization and explicit invariant checks following TigerStyle.
- Add the 97-page *Part Time Parliament* Typst book and Zig package metadata.
