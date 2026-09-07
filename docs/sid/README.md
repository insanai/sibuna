# Shibuna Discussions (SID)

Shibuna Discussions (SID) are the RFC/RFD-style design records for the `sibuna` monorepo: a web
firewall and anti-crawler daemon in pure Zig. Each SID is a standalone Typst paper under
`docs/sid/records`, while `docs/sid/registry.typ` drives the index and bundle output.

## Records

| SID | Title | Area |
|---|---|---|
| 0001 | The Shibuna Discussion process and engineering standards | process |
| 0002 | Foundation architecture, delivery record, and performance contract | architecture |
| 0003 | Declarative rule policy engine | policy |
| 0004 | Semantic attack inspection and GCRA rate limiting (Shield surface) | security |
| 0005 | Zaxonlite storage: dynamic policies, replicated reputation, forensics (Edge) | storage |
| 0006 | Mathematical foundations: sequential work, keyed authentication, rate limiting, hashing, automata | research |

## Layout

- `records/`: one Typst source file per SID.
- `template/rfc-template.typ`: starting point for new drafts.
- `registry.typ`: metadata used by the index and bundle.
- `index.typ`: registry-driven index; `bundle.typ`: experimental HTML bundle entry point.
- `../shared/sid.typ` and `../shared/theme.typ`: shared document frame and styling.

Package boundaries the records refer to:

- `libs/core/`: configuration and CLI parsing, Elm-style diagnostics, error explanations.
- `libs/crypto/`: key schedule, bit-level Hashcash, Cohen–Pietrzak proof of sequential work,
  keyed BLAKE3 and Ed25519 tokens.
- `libs/net/`: zero-copy HTTP/1.1 parser with smuggling defences, response builders, streaming
  proxy with audit headers.
- `libs/policy/`: tagged Aho–Corasick automata, IPv4/IPv6 radix trie, declarative rules and JSON
  loader, evaluation engine, semantic WAF and canonicaliser, payload embeddings.
- `libs/challenge/`: stateless challenge coordinator, load-adaptive difficulty.
- `libs/store/`: Robin Hood spent set, GCRA rate limiter, lock-free ban table, MPSC ring.
- `apps/sibuna/`: daemon entry point, request server, Zaxonlite persistent layer, end-to-end tests.
- `apps/wasm-pow/`: browser solver compiled from the same `pow.zig` and `posw.zig` sources.
- `apps/web/`: interstitial and Web Worker with JavaScript fallback provers.

`build.zig` discovers records by scanning `records/`; only `registry.typ` and `bundle.typ` carry
per-record metadata, which `zig build sid-promote` maintains.

## Build

```sh
zig build sid                  # per-record PDFs into docs/build/
zig build sid -Dsid=0002       # a single record, by number ...
zig build sid -Dsid=2          # ... unpadded also works
zig build sid -Dsid=sibuna-foundation-architecture  # ... or by slug
zig build sid-index            # registry-driven index PDF
zig build sid-site             # experimental HTML bundle into docs/build/sid-site/
```

## Manage

```sh
zig build sid-list                 # registry entries, drafts, consistency warnings
zig build sid-new -- <slug>        # create records/XXXXX-<slug>.typ from the template
zig build sid-promote -- <slug>    # assign the next number, rewrite metadata, register
```

Promotion renames `XXXXX-<slug>.typ` to the next `NNNN-<slug>.typ`, sets the state to
`discussion`, and stamps today's date. Review the generated registry summary and area fields
before committing. When an implementation review changes what a published record claims, revise
the record in place and add a dated revision note near the top.
