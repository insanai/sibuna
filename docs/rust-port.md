# The Rust port of Sibuna

Sibuna began as a Zig 0.16 program. This document records how we carry it to Rust: the workspace layout, the conventions every crate follows, and how each Zig idiom maps to a Rust one. The Zig source is the specification of behaviour. It is not a template: we redesign each module the way a Rust programmer would, keep its behaviour and its tests, and note every deliberate change in the crate's documentation and in the README.

## Goals

- Behaviour parity with the Zig daemon: the same wire formats, the same decisions for the same requests, the same diagnostics.
- No external crates on the data plane. Every algorithm Sibuna depends on (SHA-256, BLAKE3, Ed25519, base64, JSON, DEFLATE, Aho-Corasick, GCRA) lives in a small, tested workspace crate.
- Reusable libraries. A crate under `crates/` that does not carry the `Sibuna` name in its description depends on no Sibuna application crate, so other projects can use it alone.
- The hot path stays allocation-free: one connection buffer per socket, borrowed slices into it, fixed-capacity tables.

## Workspace layout

```
crates/
  crypto      SHA-1, SHA-256 (SHA-NI), BLAKE3, HMAC, Ed25519, Wyhash; no_std
  encoding    base64 and hex; no_std
  json        bounded JSON parser and writer with located errors
  pow         Hashcash and Cohen-Pietrzak proofs of sequential work; no_std
  http        zero-copy HTTP/1.1 parser, chunked decoder, responses, WebSocket frames
  patterns    Aho-Corasick automata
  cidr        IP parsing and a radix trie of CIDR prefixes
  store       MPSC ring, spent set, GCRA limiter, ban list, striped counters
  inflate     DEFLATE and gzip
  geoip       IP to country lookup, CSV providers and snapshots
  core        Sibuna configuration, diagnostics, metrics, incident types
  policy      Sibuna policy engine and semantic WAF
  challenge   Sibuna keys, tokens, challenges, adaptive difficulty
  net         Sibuna streaming reverse proxy
cmd/
  sibuna            the daemon
  sibuna-pow-wasm   the browser solver (wasm32-unknown-unknown, no_std)
tools/
  xtask             size-limit checker, WebAssembly build, release helpers
web/                challenge page and solver worker served by the daemon
docs/               this document and the design records
```

Dependencies point one way: reusable crates, then `core`, then `policy`, `challenge` and `net`, then the binaries.

## Zig to Rust map

| Zig | Rust |
|---|---|
| `[]const u8` slices into the connection buffer | `&'a [u8]` / `&'a str` borrowed from the buffer; lifetimes replace "do not use after the next read" comments |
| error unions and error sets | `Result<T, E>` with an `enum E` per module that implements `Display` and `std::error::Error` |
| `?T` sentinels, `maxInt` "absent" values | `Option<T>` |
| `std.atomic.Value` | `std::sync::atomic` types with the same orderings |
| spin locks around small critical sections | `std::sync::Mutex` unless measurement shows a spin lock wins; keep the shard striping |
| `threadlocal var` | `thread_local!` with `Cell` |
| fixed arrays `[N]T` with a length | `[T; N]` plus a length, or `Vec::with_capacity` built once off the hot path |
| `inline for` over struct fields | an explicit list or a small macro only when a function cannot do it |
| `comptime` tables | `const` tables and `const fn` |
| `@embedFile` | `include_bytes!` / `include_str!` |
| `std.Io.Writer` sinks | `std::io::Write` or `std::fmt::Write`; write into caller buffers, never allocate per request |
| `defer`/`errdefer` cleanup | `Drop` and RAII guards |
| tests in the same file | `#[cfg(test)] mod tests` in the same file; cross-crate tests in `tests/` |

Hash functions must match Zig bit for bit where their output is persisted, exchanged between cluster members, or used as a stable identifier (rule hashes, ban keys, token tags). Each such function has test vectors generated with the Zig 0.16 standard library.

## Conventions

These follow the repository rules for every Rust project.

- Edition 2024, `rust-version` 1.88. `cargo fmt` with `max_width = 99`.
- A function body has at most 70 logical lines. A file has at most 1,408 lines. Lines are at most 99 characters. `cargo xtask check` enforces this.
- Plain, descriptive names. Small functions with one job. Comments explain why, not what.
- Every public item has a `///` comment: what it borrows, what it returns, how it fails. Every crate has a `//!` overview.
- No `unsafe` outside FFI and SIMD modules. Each `unsafe` block has a `// SAFETY:` comment. SIMD needs a measured reason.
- No `unwrap()` or `expect()` on input-dependent values in library code. Panics only for violated internal invariants.
- Errors are enums with `Display` and `std::error::Error`. Libraries never print.
- Plain data APIs: public-field structs with `Default`; verbs `load_*`, `begin_*`/`end_*`, `is_*`, `*_count`; no `get_` prefix.
- Bounded work on untrusted input: explicit limits that return errors, never panics, stack overflows or unbounded allocation.
- Unit tests port every Zig test in the module. Add a test when Rust makes a new property checkable.
- Before a crate is done: `cargo build`, `cargo test`, `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` pass for it.

## Diagnostics

Command-line, policy and configuration failures are reported in the Elm style used by the Zig daemon: a title rule, the location, the offending text, a plain explanation and a `Hint:`. Libraries return structured errors (a code, a title, a message, a hint and a location); only the binaries render them.

## Deliberate changes from the Zig version

Each crate lists its own changes in its crate documentation. The README collects them.
