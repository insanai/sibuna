# Shibuna Discussions (SID)

Shibuna Discussions (SID) are the RFC/RFD-style design records for the `sibuna` monorepo: the high-performance Web AI Firewall and anti-crawler daemon. Each SID is a standalone Typst file under `docs/sid/records`, while `docs/sid/registry.typ` drives the index and bundle output.

## Layout

- `records/`: one Typst source file per SID.
- `template/rfc-template.typ`: starting point for new SID drafts.
- `registry.typ`: metadata used by the index and bundle.
- `index.typ`: registry-driven discussion index.
- `bundle.typ`: experimental Typst bundle entry point that emits `index.html`, per-SID HTML pages, and per-SID PDFs.
- `../shared/sid.typ` and `../shared/theme.typ`: shared document frame, styling, and index components.

The monorepo uses matching package boundaries:

- `libs/core/`: foundational memory arenas, allocators, logging, and time primitives.
- `libs/crypto/`: hardware-accelerated SHA-256 (NEON/SHA-NI), native HashX, Argon2id, Ed25519, and zero-alloc tokens.
- `libs/net/`: zero-copy HTTP/1.1 & HTTP/2 streaming parser, reverse proxy, and subrequest/forward-auth engine.
- `libs/policy/`: SIMD Aho-Corasick multi-pattern matcher, Radix IPv4/IPv6 CIDR trie, and JA4H fingerprint calculator.
- `libs/challenge/`: proof-of-work issue/verify engine and load-based difficulty adjustment.
- `libs/store/`: lockless sharded decay map (Robin Hood hash map with atomic decay) and Valkey/Redis client.
- `apps/sibuna/`: the main server daemon binary.
- `apps/wasm-pow/`: browser-side PoW solver compiled directly with Zig to `wasm32-freestanding`.
- `apps/web/`: minimal client assets, worker scripts, and embedded HTML templates.

The code describes the current system; an SID records the architectural decisions that made it that way. `build.zig` discovers records by scanning `records/`, so only `registry.typ` and `bundle.typ` carry per-record metadata; the `zig build sid-promote` step maintains both.

## Build

The root `build.zig` owns the SID build steps:

```sh
zig build sid                  # per-record PDFs into docs/build/
zig build sid -Dshd=0002       # a single record, by number ...
zig build sid -Dshd=2          # ... unpadded also works
zig build sid -Dshd=sibuna-foundation-architecture  # ... or by slug
zig build sid-index            # registry-driven index PDF
zig build sid-site             # experimental HTML bundle into docs/build/sid-site/
```

`-Dshd=` also selects placeholder drafts by slug, so a draft can be proofread as a PDF before promotion.

## Manage

`tools/sid.zig` drives the numbering workflow from SID 0001:

```sh
zig build sid-list                 # registry entries, drafts, consistency warnings
zig build sid-new -- <slug>        # create records/XXXXX-<slug>.typ from the template
zig build sid-promote -- <slug>    # assign the next number, rewrite metadata,
                                   # and append registry.typ and bundle.typ entries
```

Promotion renames `XXXXX-<slug>.typ` to the next `NNNN-<slug>.typ`, sets the state to `discussion`, and stamps today's date. Review the generated registry summary and area fields before committing.

Direct Typst commands are useful while editing:

```sh
typst compile --root docs docs/sid/records/0001-sid-process.typ docs/build/sid-0001-sid-process.pdf
typst compile --root docs docs/sid/records/0002-sibuna-foundation-architecture.typ docs/build/sid-0002-sibuna-foundation-architecture.pdf
typst compile --root docs docs/sid/index.typ docs/build/sid-index.pdf
typst compile --features html,bundle --root docs --format bundle docs/sid/bundle.typ docs/build/sid-site
```

## Adding an SID

1. Run `zig build sid-new -- <slug>` (or copy `template/rfc-template.typ` to `records/XXXXX-<slug>.typ` by hand).
2. Fill in the `#let sid-*` metadata.
3. Write the discussion using the standard sections; preview with `zig build sid -Dshd=<slug>`.
4. When ready for discussion, run `zig build sid-promote -- <slug>` to assign the next four-digit number and append the `registry.typ` and `bundle.typ` entries.
5. Review the generated registry summary and area fields, then run `zig build sid` to build everything.
