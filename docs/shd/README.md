# Shibuna Discussions (SHD)

Shibuna Discussions (SHD) are the RFC/RFD-style design records for the `sibuna` monorepo: the high-performance Web AI Firewall and anti-crawler daemon. Each SHD is a standalone Typst file under `docs/shd/records`, while `docs/shd/registry.typ` drives the index and bundle output.

## Layout

- `records/`: one Typst source file per SHD.
- `template/rfc-template.typ`: starting point for new SHD drafts.
- `registry.typ`: metadata used by the index and bundle.
- `index.typ`: registry-driven discussion index.
- `bundle.typ`: experimental Typst bundle entry point that emits `index.html`, per-SHD HTML pages, and per-SHD PDFs.
- `../shared/shd.typ` and `../shared/theme.typ`: shared document frame, styling, and index components.

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

The code describes the current system; an SHD records the architectural decisions that made it that way. `build.zig` discovers records by scanning `records/`, so only `registry.typ` and `bundle.typ` carry per-record metadata; the `zig build shd-promote` step maintains both.

## Build

The root `build.zig` owns the SHD build steps:

```sh
zig build shd                  # per-record PDFs into docs/build/
zig build shd -Dshd=0002       # a single record, by number ...
zig build shd -Dshd=2          # ... unpadded also works
zig build shd -Dshd=sibuna-foundation-architecture  # ... or by slug
zig build shd-index            # registry-driven index PDF
zig build shd-site             # experimental HTML bundle into docs/build/shd-site/
```

`-Dshd=` also selects placeholder drafts by slug, so a draft can be proofread as a PDF before promotion.

## Manage

`tools/shd.zig` drives the numbering workflow from SHD 0001:

```sh
zig build shd-list                 # registry entries, drafts, consistency warnings
zig build shd-new -- <slug>        # create records/XXXXX-<slug>.typ from the template
zig build shd-promote -- <slug>    # assign the next number, rewrite metadata,
                                   # and append registry.typ and bundle.typ entries
```

Promotion renames `XXXXX-<slug>.typ` to the next `NNNN-<slug>.typ`, sets the state to `discussion`, and stamps today's date. Review the generated registry summary and area fields before committing.

Direct Typst commands are useful while editing:

```sh
typst compile --root docs docs/shd/records/0001-shd-process.typ docs/build/shd-0001-shd-process.pdf
typst compile --root docs docs/shd/records/0002-sibuna-foundation-architecture.typ docs/build/shd-0002-sibuna-foundation-architecture.pdf
typst compile --root docs docs/shd/index.typ docs/build/shd-index.pdf
typst compile --features html,bundle --root docs --format bundle docs/shd/bundle.typ docs/build/shd-site
```

## Adding an SHD

1. Run `zig build shd-new -- <slug>` (or copy `template/rfc-template.typ` to `records/XXXXX-<slug>.typ` by hand).
2. Fill in the `#let shd-*` metadata.
3. Write the discussion using the standard sections; preview with `zig build shd -Dshd=<slug>`.
4. When ready for discussion, run `zig build shd-promote -- <slug>` to assign the next four-digit number and append the `registry.typ` and `bundle.typ` entries.
5. Review the generated registry summary and area fields, then run `zig build shd` to build everything.
