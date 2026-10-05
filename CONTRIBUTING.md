# Contributing to Sibuna

Run `zig build fmt`, `zig build test`, and `zig build sid` before submitting a change. Regenerate
`benchmarks/results/latest.json` with `sh benchmarks/run-all.sh` whenever a change touches a
measured subsystem; the book renders its figures from that file.

The engine is LGPL-3.0 and the console is AGPL-3.0, as scoped in `LICENSE`.
Contributions must preserve dependency notices and the console's corresponding-source link.
Release packages are built with Zig 0.17.0 at `ReleaseSafe`, with storage and console enabled
and clustering disabled. A `v` tag must match `build.zig.zon` and the console source link.
The release workflow verifies the actual binaries before publishing archives and checksums;
it refuses to replace assets on an already published release. macOS packages are unsigned.
Windows packages contain a native executable qualified on a Windows runner. `python3 tools/build_site.py` builds the GitHub Pages documentation.
The release workflow also requires the native CRS contract suite, portable compile probes
and pinned detector, primitive, PCRE2 and native/GnuPG signature comparisons,
plus independent JSON, form, MIME, XML, URI and cookie acquisition comparisons, and native
signed-package unpacking, private compilation and staging ownership. These checks qualify
the CRS library; they do not establish daemon activation or complete phased HTTP coverage.
`crs-artifact-check` also re-verifies the signed package from its restart files and checks
tampering, changed lengths, identity mismatch and retention of a prior prepared candidate.
`compression-test`, `net-test` and `crs-http-test` check bounded representation decoding,
response publication and phase composition. They preserve encoded replay and verify that
streaming and WebSocket exclusions cannot bypass response-header denials.
`crs-daemon-e2e` exercises phased inspection through the actual TCP listener, including
encoded uploads, response holdback, configured denial statuses, pipeline retention,
forward-auth metadata, admission limits, absolute deadlines and early stream/tunnel release.
Run it with the console enabled to verify exact response-refusal telemetry as well.
`console-crs-evidence-test` drives deterministic storage ticks for atomic scalar findings,
lost-reply retries, migration replay and authorized reads. `console-crs-management-test`
checks the storage-owned candidate ledger, source chunk ownership, expected-revision selection,
audit rollback, bounded staging, authorization at execution, rollback and boot-fenced receipts. `crs-daemon-check -- --download`
also qualifies saved findings and redacted heads through authenticated console queries when
the console is compiled in, including restart retention and sign-out revocation.
`python3 tools/crs_restart_check.py <binary> --candidate <directory>` qualifies signed-source
adoption, durable restoration without the original path, refusal of conflicting startup
settings and clean management-worker shutdown.
`python3 tools/crs_management_check.py <binary> --candidate <directory>` drives authenticated
preparation, separate selection, Off/Enforce, rollback, conflicts, discard, revocation,
boot-fenced application and restart through the real daemon with a signed release.
`python3 tools/crs_ui_check.py <binary> --candidate <directory>` drives the shipped Wasm
through reviewed modes, exact rollback, operator edits, failed preparation and sign-out.
It requires Node; Chrome separately verifies form retention, focus and responsive layout.
`crs-start-test` checks startup option conflicts, observable profiles, resource bounds and
the disabled lifecycle. The signed-artifact probe also exercises the startup owner's
generation leases, forward-auth profile, exhaustion cleanup and joined-reader teardown.

---

## Code and architectural guidelines

Sibuna follows the engineering priorities shared across `insan.ai` projects (TigerStyle:
**safety, performance, developer experience, in that order**).

### 1. Structural limits (enforced by `zig build fmt`)

- **Function length:** at most **70 lines of code** (blank and comment-only lines excluded).
- **Line length:** at most **99 characters** in code files; `docs/` is exempt.
- **File length:** at most **1408 lines of code**.
- **No tabs.**

### 2. Engineering principles

- **Zero-allocation hot path.** Parsing, classification, inspection, cookie and proof
  verification must not allocate. Fixed-capacity tables and stack buffers only. Anything that
  must allocate (storage, policy reload) runs on its own thread and hands results to the
  workers through atomics.
- **Explicit control flow.** Never swallow errors; state invariants with assertions; keep the
  happy path unnested.
- **Explain the why** in comments, not the what.
- **Native verification.** Proofs are verified with native code; the server never hosts a
  virtual machine.
- **Proofs before folklore.** New cryptographic or algorithmic mechanisms need a published
  security or complexity argument recorded in an SID before they land.

### 3. Tests

`zig build test` runs every library's unit tests, the WASM entry tests on the host, the server
helpers, the end-to-end suite in `apps/sibuna/src/e2e_test.zig`, and the storage test in
`apps/sibuna/src/persistent.zig` (when `-Dstorage` is on, the default).

- Prefer **end-to-end coverage**: a new decision path or route should be exercised through the
  live daemon in `e2e_test.zig` (it boots the server on a loopback port in front of a stub
  origin and speaks raw HTTP/1.1). Use a distinct `X-Forwarded-For` address per scenario so the
  per-client tables do not interfere.
- `zig build daemon-e2e` runs that same native daemon harness separately, including its
  transitive ownership and storage checks, so a relay change can be qualified without
  rebuilding the complete console suite.
- Unit tests belong where a property is easier to state directly (a verifier rejecting a
  tampered proof, a limiter's exact bound, an automaton agreeing with a naive scan). Do not add
  tests for trivial accessors that the end-to-end suite already covers.
- Storage tests drive `Persistent.tick()` directly instead of relying on the background thread,
  and must release any pinned `EngineSlot` before a tick that can rebuild.

Native socket changes also run `zig build socket-test`; the release matrix runs it on
each native platform to check pending-I/O interruption without closing a borrowed handle.

Console changes also run `zig build console-test` and `zig build console-ui-e2e`.
`console-test` compares native page fixtures byte-for-byte with `apps/console-ui/golden/`.
When markup intentionally changes, run `zig build console-golden -- --update`, inspect the HTML
diff and verify the affected workflow in Chrome. Golden fixtures complement behavioral tests;
they do not prove responsive layout, accessibility or operator comprehension.

### 4. Benchmarks

`benchmarks/benchmark.zig` measures Sibuna rows over seven batches and reports the median, min,
and max per operation, with untimed warmup and independent mutable state per batch.
`python3 benchmarks/distributed.py` exercises three real local daemons with external clients.
`python3 benchmarks/tools.py --anubis <binary>` drives Sibuna Gate, Sibuna Shield, and Anubis as
whole processes with `wrk` and records throughput, latency percentiles, CPU time per request,
and peak resident memory; `python3 benchmarks/compare.py --anubis <binary>` measures admission
operations; `python3 benchmarks/cluster.py` compares one node with a three-node replicated
cluster under `wrk`. Third-party binaries are supplied from their official releases and never
committed.
`python3 benchmarks/bunkerweb.py` compares proxy and inspection profiles against a verified
official BunkerWeb image and optional Anubis binary, locally or with a separate SSH load host.
`admission_http.py` measures protected HTTP workloads; `admission_operations.py` measures native
proof and session operations with two clients on that load host. See
`benchmarks/results/README.md` for the isolated fixture, scope and replay commands.
Benchmarks must not add instrumentation to request code. Allocator statistics must be labelled
as instrumented, source-audited, or unknown. Competitor comparisons require pinned runnable
artifacts, equivalent workloads, and provenance; fixed unsourced model rows are not accepted.

---

## Shibuna Discussions (SID)

Architectural decisions, protocol revisions, and security assessments are recorded as SIDs under
`docs/sid/records/`:

```sh
zig build sid-new -- <slug>        # placeholder draft
zig build sid -Dsid=<slug>         # preview one record
zig build sid-promote -- <slug>    # assign the next number and register it
```

A record that no longer matches the code is a bug: revise it, note the revision date at the
top, and keep measured numbers traceable to `benchmarks/results/latest.json`.
