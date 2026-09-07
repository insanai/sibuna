#import "theme.typ": *
#import "figures.typ": *

#part_page("II", [Prior Art and the Design Space], [
  We place Sibuna among the systems it learned from: client puzzles, proof-of-work
  interstitials, semantic application firewalls, and replicated edge control planes, and
  record the engineering facts that shaped its design.
])

= Where Sibuna Comes From

#objectives([
  By the end of this chapter, you should be able to trace the lineage of client puzzles,
  name the three systems Sibuna draws on and what each contributed, and state the design
  constraints Sibuna adopted in response.
])

== Client Puzzles

Dwork and Naor's "Pricing via Processing" (CRYPTO 1992) proposed that a service require a
moderately hard, easily checked computation before doing work for a requester. Back's Hashcash
(1997) made the puzzle a partial hash inversion, and Juels and Brainard's client puzzles (NDSS
1999) applied the idea to TCP connection floods. All three share the shape Sibuna keeps: a
server-chosen statement, a solution whose cost is tunable, and verification that is orders of
magnitude cheaper than solving.

== Anubis: The Proof-of-Work Interstitial

Anubis (2024, Go) popularised the idea for the modern web: a reverse proxy that serves an
interstitial, runs a WebAssembly solver in the browser, and admits the client with a cookie.
Three of its engineering decisions are instructive for a systems designer:

- *Server-side verification through a WebAssembly runtime.* To reuse the browser's solver code,
  the Go server instantiated a WebAssembly VM (Wazero) per verification. The design guarantees
  client and server agree, at the cost of VM entry, guest memory copies, and JIT dispatch on
  every solution. Sibuna obtains the same guarantee differently: the browser module is compiled
  from the *server's* verifier sources, so both are one Zig implementation and the server runs
  it natively.
- *A fragmented toolchain.* The solver was rewritten in Rust to escape Go's multi-megabyte
  WebAssembly output, which required checking prebuilt binaries into the repository. Sibuna's
  single `zig build` emits the daemon, the native verifiers, and the 8.8 KB browser module.
- *Difficulty granularity.* Early releases counted hexadecimal digits, so each step multiplied
  work by sixteen; bit-level difficulty had to be retrofitted. Sibuna measures work in bits from
  the start.

Anubis remains the reference point for the *Gate* surface: the same admission model, the same
declarative policy actions (`ALLOW`, `DENY`, `CHALLENGE`, `WEIGH`), and compatible policy files.

== SafeLine: The Semantic WAF

Chaitin's SafeLine defines what a modern application firewall must catch: SQL injection,
cross-site scripting, path traversal, and command injection, detected by tokenising the request
rather than by regular expressions, plus rate limiting against request floods. Its deployment is
a multi-container composition with PostgreSQL and Redis. Sibuna adopts the detection categories
and the tokenizer philosophy, and implements them as a single-pass automaton plus byte-class
tokenizers inside the same binary (Part VI), with GCRA rate limiting in 16 bytes per client.

== Cloudflare: The Replicated Edge

At hyperscale, policy and reputation live in a replicated store that every edge node reads
locally and a control plane writes once. Sibuna's *Edge* surface reproduces the shape with
Zaxonlite, an embedded SQLite replicated by Multi-Paxos, so a ban raised on one node reaches
every node without PostgreSQL, Redis, or a message bus (Part IX).

== The Design Constraints Sibuna Adopted

#table(
  columns: (1.2fr, 1.1fr, 1.1fr, 1.4fr),
  table.header([*Property*], [*Anubis*], [*SafeLine*], [*Sibuna*]),
  [Proof of work], [Hashcash / HashX / Argon2id, WebAssembly VM verification], [none (CAPTCHA)], [Hashcash and Proof of Sequential Work, native verification],
  [Session token], [JWT, Ed25519], [server session], [Keyed BLAKE3 tag, 64 characters; Ed25519 optional],
  [Challenge state], [stored per issued challenge], [n/a], [stateless; only solved challenges stored],
  [Semantic WAF], [no], [tokenizer engine, C++/Go services], [single-pass automaton plus byte-class tokenizers, in-process],
  [Rate limiting], [basic], [Redis sliding window], [GCRA, one integer per client],
  [Dynamic state], [restart or reload], [PostgreSQL + Redis], [Zaxonlite (SQLite + Multi-Paxos), embedded],
  [Deployment], [Go binary], [docker-compose, four services], [one static binary; storage optional at build time],
  [Hot-path allocation], [Go heap], [service IPC], [zero],
)

#callout([What the comparison is not], [
  Nothing above measures those systems on our host. Where Part VIII shows a "reference model"
  for Anubis, it is a fixed per-call constant taken from public profiling and it is drawn in a
  different colour and labelled as a model, not a measurement.
])

#exercise([2.1], [
  Anubis verifies solutions by running the browser's WebAssembly module inside the server.
  List two correctness benefits of that choice and two costs, then explain how compiling the
  browser module from the server's own verifier source obtains the benefits without the costs.
])

#teach_back([
  Name one design element Sibuna took from each of Anubis, SafeLine, and Cloudflare, and one
  element it deliberately changed, with the reason.
])
