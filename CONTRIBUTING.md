# Contributing to Sibuna

Run `zig build fmt`, `zig build test`, and `zig build sid` before submitting a change. Regenerate
`benchmarks/results/latest.json` with `sh benchmarks/run-all.sh` whenever a change touches a
measured subsystem; the book renders its figures from that file.

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
- Unit tests belong where a property is easier to state directly (a verifier rejecting a
  tampered proof, a limiter's exact bound, an automaton agreeing with a naive scan). Do not add
  tests for trivial accessors that the end-to-end suite already covers.
- Storage tests drive `Persistent.tick()` directly instead of relying on the background thread,
  and must release any pinned `EngineSlot` before a tick that can rebuild.

### 4. Benchmarks

`benchmarks/benchmark.zig` measures Sibuna rows over seven batches and reports the median, min,
and max per operation, with untimed warmup and independent mutable state per batch.
`python3 benchmarks/distributed.py` exercises three real local daemons with external clients.
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
