# Contributing to Sibuna

Run `zig build fmt`, `zig build test`, and `zig build shd` before submitting a change.

---

## Code and Architectural Guidelines

Sibuna adheres strictly to the engineering and style principles established across `insan.ai` (mirroring `paxos-zig` and TigerStyle priorities: **safety, performance, and developer experience, in that order**).

### 1. Hard Structural Limits (Enforced by `zig build fmt` & `tools/check-style.sh`)

- **Function Length:** Functions must not exceed **70 lines of code** (excluding blank lines and comment-only lines). Break large functions into focused, cohesive helper functions.
- **Line Length:** Lines in code files must not exceed **99 characters**.
- **Documentation Exclusion:** The 99-character line limit is **not** applied to `docs/` (Typst documents and markdown), preserving clean prose, tables, and formula formatting.
- **File Length:** Source code files must not exceed **1408 lines of code** (excluding blank lines and comments).
- **No Tabs:** Tab characters (`\t`) are forbidden in all source code files; use standard 4-space indentation.

### 2. Engineering Principles

- **Zero-Allocation Hot Path:** Request classification, header lookups, cookie checks, and PoW solution validation must never perform dynamic heap allocations. Memory pools and ring buffers must be pre-allocated or arena-scoped.
- **Explicit Control Flow:** Never swallow or ignore errors. Avoid hidden side effects; keep execution paths clear, predictable, and traceable.
- **State Invariants Positively:** Use positive assertions (`std.debug.assert(...)`) to document and verify pre-conditions, loop invariants, and post-conditions.
- **Explain the "Why":** Comments should not simply restate what the code does; they must explain why design choices, memory limits, and protocol invariants exist.
- **Hardware-First Verification:** PoW verification on the server must execute native silicon instructions (x86 SHA-NI / ARM NEON / native C/Zig); never instantiate an interpreted/JIT VM on the server.

---

## Shibuna Discussions (SHD)

Major architectural decisions, protocol revisions, and security assessments must be drafted as an SHD record under `docs/shd/records/`:

```sh
# Create a placeholder draft
zig build shd-new -- <slug>

# Preview the document PDF
zig build shd -Dshd=<slug>

# Promote the draft to an official numbered discussion
zig build shd-promote -- <slug>
```
