# Contributing to Sibuna

Before submitting a change, run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo xtask check
```

A change to storage also runs the PostgreSQL suite (`SIBUNA_TEST_DATABASE_URL` set, `--features
postgres`), and a change to a measured subsystem reruns the matching `cargo xtask bench`
command and commits the files it writes under `benchmarks/results/`.

---

## Code and architectural guidelines

Sibuna follows the engineering priorities shared across `insan.ai` projects: **safety,
performance, developer experience, in that order**.

### 1. Structural limits (enforced by `cargo xtask check`)

- **Function length:** at most **70 logical lines** (blank lines, comments, the signature and
  lines holding only brackets do not count); `clippy.toml` sets the same threshold.
- **Line length:** soft limit **99** characters (`rustfmt.toml`), hard limit **108**.
- **File length:** at most **1,408 lines**; split large modules into submodules.
- **ASCII only** in code, comments and documentation, except where another language or a
  Unicode example needs it.

### 2. Engineering principles

- **Zero-allocation hot path.** Parsing, classification, inspection, cookie and proof
  verification must not allocate on a warm request; `cmd/sibuna/tests/steady_state.rs` asserts
  it. Anything that must allocate (storage, policy reload, the console) runs on its own thread
  and hands results to the request threads through atomics or a published engine slot.
- **No `unsafe` outside FFI.** The workspace denies `unsafe_code`; the few allowed blocks carry
  a `// SAFETY:` comment, and an `unsafe` added for speed needs a measurement in its SID.
- **Errors are values.** No `unwrap()` or `expect()` on input-dependent values in library code;
  libraries return structured errors and never print. Diagnostics for operators follow the
  Elm style: a title, the location, the excerpt, the explanation and a `Hint:`.
- **Bounded work on untrusted input.** Every loop over client data has an explicit limit on
  depth, size or steps that returns an error, never a panic.
- **Dependencies are liabilities.** The data plane depends on no external crate. An external
  crate is admitted only by a SID, declared once in the root `Cargo.toml` with the reason
  beside it, and confined to one crate (sqlx in `sibuna-storage`, rustls in `sibuna-tls`).
- **Tools are Rust.** Repository tools live in `tools/` and run through `cargo xtask`; no
  shell or Python scripts.
- **Explain the why** in comments, not the what. Every public item has a doc comment saying
  what it borrows, what it returns and how it fails.
- **Native verification.** Proofs are verified with native code; the server never hosts a
  virtual machine.
- **Proofs before folklore.** A new cryptographic or algorithmic mechanism needs a published
  security or complexity argument recorded in a SID before it lands.

### 3. Tests

Unit tests live in `#[cfg(test)] mod tests` beside the code; cross-crate and daemon tests live
in each crate's `tests/` directory.

- Prefer **end-to-end coverage**: a new decision path or route should be exercised through the
  live daemon in `cmd/sibuna/tests/` (the fixtures boot the server on a loopback port in front
  of a stub origin and speak raw HTTP/1.1). Use a distinct `X-Forwarded-For` address per
  scenario so the per-client tables do not interfere.
- Unit tests belong where a property is easier to state directly (a verifier rejecting a
  tampered proof, a limiter's exact bound, an automaton agreeing with a naive scan).

Console changes also run the interface tests (`cargo test -p sibuna-console-ui`), which compare
rendered pages byte for byte with `cmd/console-ui/tests/golden/`. When markup intentionally
changes, rerun them with `SIBUNA_UPDATE_CONSOLE_GOLDENS=1`, inspect the HTML diff, and check
the affected workflow with `cargo xtask browser console`, reviewing its screenshots. Golden
fixtures complement behavioural tests; they do not prove layout, accessibility or operator
comprehension.

### 4. Benchmarks

`cargo xtask bench primitives` times the Rust crates in seven batches and reports the median,
min and max per operation, with untimed warm-up and independent state per batch; `product`
drives whole daemons with `wrk`, and `latency` offers fixed rates from an open-loop generator.
Benchmarks must not add instrumentation to request code.

---

## Sibuna Discussions (SID)

Architectural decisions, protocol revisions and security assessments are recorded as SIDs under
`docs/sid/records/`, managed with guidedog:

```sh
guidedog dsc new "A proposal"
guidedog dsc check
guidedog dsc build
```

A substantive SID is reviewed by the maintainer before it is implemented. A record that no
longer matches the code is a bug: revise it with a dated revision note, and keep measured
numbers traceable to a file under `benchmarks/results/`.

## Commits

Small, related commits with a short imperative summary, optionally prefixed with the
component (`policy: do not treat parameters named like commands as injection`), ASCII only.
