#import "theme.typ": *

#title_page()
#pagebreak()

#align(center)[
  #text(size: 16pt, weight: "bold")[About This Book]
]

This book explains the architecture, the cryptographic foundations, and the implementation of
*Sibuna*, a web firewall and anti-crawler daemon written in pure Zig. Sibuna sits in front of an
origin as a reverse proxy, or beside an ingress as a forward-auth validator, and decides every
request in a few hundred nanoseconds without touching the heap: it inspects the request for
application attacks, consults reputation and declarative rules, and, when the client is not yet
known, asks the browser to pay a small, verifiable amount of computation before a session token
is minted.

The design is research-driven rather than convention-driven. Proof of work is not a single
hash-search loop but a two-tier system: bit-level Hashcash for the cheapest possible verification,
and the Cohen–Pietrzak *Proof of Sequential Work*, a construction with a published security
proof (including a post-quantum proof) whose solve time cannot be shortened by parallel hardware.
Session and challenge authentication use a keyed pseudorandom function rather than a signature,
so verification costs one BLAKE3 compression. Rate limiting is the Generic Cell Rate Algorithm
with a one-integer state per client. The hot path never allocates.

Sibuna ships as three surfaces built from one binary:

#table(
  columns: (0.8fr, 2.6fr, 1.2fr),
  table.header([*Surface*], [*What it does*], [*Enable*]),
  [*Gate*], [Proof-of-work admission only: challenge unknown clients, admit sessions, allow listed paths.], [`--gate`],
  [*Shield*], [Gate plus the semantic WAF (SQL injection, XSS, traversal, command injection), GCRA rate limits, honeypot bans.], [default, `--shield`],
  [*Edge*], [Shield plus Zaxonlite storage: dynamic policies, cluster-wide reputation, incident forensics, replicated by Multi-Paxos.], [`--data-dir`, `--cluster-*`],
)

#v(4mm)
#book_quote([
  In Egyptian mythology, Anubis weighed the heart against the feather of truth. Sibuna reverses
  the balance: the weight is placed on the machine that wants in, and the door itself weighs
  nothing.
], [Sibuna Engineering Manifesto])

#v(8mm)
#callout([The Core Promise], [
  A reader of this book will be able to derive the cost model of both proof-of-work tiers, read
  the sequential-work prover and verifier line by line, trace a request through the
  zero-allocation pipeline down to the byte-class table, understand why a keyed hash is the right
  primitive for session tokens, operate the daemon in all three surfaces, and reproduce every
  number in Part VIII from the committed benchmark file.
], kind: "idea")

#v(6mm)
#table(
  columns: (1.4fr, 1fr, 2fr),
  table.header([*Measured on the reference host*], [*Value*], [*Where*]),
  [Hashcash verification], [62.6 ns], [Part VIII, `pow_verify`],
  [Proof of Sequential Work verification (depth 13, 16 openings)], [16.9 µs], [Part VIII, `pow_verify`],
  [Session token verification (keyed BLAKE3)], [134 ns], [Part VIII, `token_auth`],
  [Forty bot signatures, single pass], [85 ns], [Part VIII, `bot_matcher`],
  [Full classification, Gate profile], [295 ns], [Part VIII, `policy_engine`],
  [Full classification, Shield profile], [1.46 µs], [Part VIII, `policy_engine`],
  [Browser solver module], [8,831 bytes], [Part VII],
  [Idle resident memory / static binary], [7.6 MB / 4.2 MB], [Part VIII],
)

#v(1fr)
#align(center, text(size: 8.5pt, fill: gray)[
  Version 0.2.0 · Numbers rendered from `benchmarks/results/latest.json` · Built with Typst 0.15
])

#pagebreak()

= Preface

The open web is being harvested. Foundation-model training pipelines, data brokers, and private
agents crawl public sites around the clock, consuming bandwidth and database capacity while
returning nothing to the people who publish. The two traditional defences no longer hold:
`robots.txt` is an honour system that harvesters ignore, and CAPTCHAs are now solved by vision
models more reliably than by the humans they inconvenience. IP reputation fails against
residential proxy pools that rotate through millions of consumer addresses.

What remains is economics. If every admission costs the requester a verifiable slice of
computation, and the server's cost to verify it is negligible, then mass harvesting becomes a
power bill while a human reading twenty pages in an evening pays a fraction of a second once.
This is the client-puzzle idea of Dwork and Naor (1992) and Back's Hashcash (1997), and it is the
foundation Sibuna builds on.

== What This Book Adds

Sibuna is a complete, measured implementation of that idea in a single static binary, and this
book documents both the engineering and the mathematics behind it:

1. *Two proof-of-work tiers with known security properties.* Hashcash is retained for its
   one-hash verification. Above it sits the Cohen–Pietrzak Proof of Sequential Work, whose
   soundness and sequentiality are proven in the random-oracle model and, by Blocki, Lee and
   Zhou, against quantum adversaries. Part III derives both cost models and explains why the
   memory-hard alternatives were rejected for a server-verified puzzle.
2. *Stateless challenges and symmetric authentication.* A challenge is a self-authenticating
   record; the server remembers only solved challenges, so its state grows with work the
   client actually paid for. Tokens are keyed-hash tags, verified in 134 nanoseconds.
3. *A zero-allocation request pipeline.* One 64 KB buffer per connection, slices everywhere,
   a single-pass signature automaton, a byte-class tokenizer for the semantic firewall, Robin
   Hood hashing for the spent set, and the Generic Cell Rate Algorithm for rate limiting.
4. *Distributed edge state without external services.* Zaxonlite, an embedded SQLite
   replicated by Multi-Paxos, holds dynamic policies, reputation, and incident forensics with
   full-text and vector search, while the hot path reads an immutable engine snapshot swapped
   with read-copy-update semantics.
5. *Honest numbers.* Every figure in Part VIII is rendered from a committed benchmark file with
   its host, revision, and spread. Where a comparison to other systems is drawn, the reference
   values are labelled as models.

Prior work is credited where it is used. Anubis showed that a proof-of-work interstitial is a
practical anti-scraping tool; SafeLine shows what a semantic WAF must detect; Cloudflare shows
what a replicated edge control plane looks like. Sibuna's contribution is to build all three
layers on primitives with proofs, in one small binary, and to measure the result.
