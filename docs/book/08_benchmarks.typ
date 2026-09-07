#import "theme.typ": *
#import "figures.typ": *

#part_page("VIII", [Empirical Evaluation], [
  We present the benchmark results recorded on bare metal, explain how they were measured,
  and trace each number to the mechanism that produces it.
])

= Methodology

#objectives([
  By the end of this chapter, you should be able to reproduce every number in this part,
  explain what the spread column means, and say precisely which figures are measurements and
  which are reference models.
])

The suite in `benchmarks/benchmark.zig` is built in `ReleaseFast` and run by
`sh benchmarks/run-all.sh`, which also records the host, CPU, operating system, git revision,
binary and module sizes, and the daemon's idle resident memory, then writes
`benchmarks/results/latest.json`. This chapter renders that file at compile time; nothing here
is typed by hand.

Each workload runs seven independent batches of many thousand operations. The table reports
the per-operation cost of the *median* batch and the *min–max spread* across batches. Timing
every single operation would perturb work that costs tens of nanoseconds, so no per-operation
percentiles are reported; earlier drafts that derived "p99" figures from a multiplier have been
removed.

#callout([Reference models are not measurements], [
  Rows labelled `anubis-model` are fixed per-call constants for a Go Anubis deployment, taken
  from public profiling of the Wazero VM boundary, Go `regexp` scans, `net.IPNet` slices, JWT
  parsing, mutex-guarded maps, and `net/http` request allocation. They give the reader a sense of
  scale; they were not run on this host and must not be quoted as Sibuna's measurements of
  Anubis.
], kind: "warning")

#v(4mm)
#benchmark_results_table()
#v(6mm)

= Reading the Numbers

#objectives([
  Trace each measured latency to its mechanism.
])

== Proof-of-Work Verification

Hashcash verification is one SHA-256 evaluation of a 70-byte challenge plus a nonce: the
hardware SHA extensions of the host run it in about 62 ns. The sequential-work verifier
recomputes $t(n + 1) = 224$ compressions for depth 13 with sixteen openings, about 17 µs, well
inside the 50 µs budget of the performance contract and still 300 times cheaper than the
prover's 15–20 ms in a browser.

== Signature Matching and Classification

The dense automaton scans a browser User-Agent against forty signatures in 85 ns; the
sequential substring scan of the same signatures on the same host, included as `sibuna-naive`,
costs 4.2 µs. Full classification of a seven-header browser request costs 295 ns on the Gate
surface and 1.46 µs on the Shield surface; the difference is the semantic firewall inspecting
each non-structural field once plus the byte-class pass. An 8 KB body scans at about 2.9 ns
per byte.

== Tokens, State, and Parsing

The keyed BLAKE3 token verifies in 134 ns against 52.8 µs for the Ed25519 alternative, the
400-fold difference that motivated Part III's choice of primitive. A Robin Hood spend-and-lookup
pair costs 23 ns, a GCRA check 4.8 ns, and parsing a request with seven headers plus a cookie
lookup about 730 ns, most of it the header loop over the zero-copy buffer.

== Memory and Size

The daemon's idle resident set after start is rendered in the tile above from the committed
file (7.6 MB on the reference host with storage off). With Zaxonlite storage active, the live
daemon measured 12–14.5 MB resident while serving requests and writing incidents. The
`ReleaseFast` binary is 4.2 MB with storage compiled in, and the browser module 8,831 bytes.

#callout([Design expectations, not measurements], [
  Sibuna's architecture is intended to keep tail latency flat under floods because no request
  allocates, no lock is held longer than tens of instructions, and every table is bounded. That
  expectation has not yet been measured with a load generator against a running daemon; a
  `wrk`-style throughput gate remains open work and is listed as such in SID 0002.
])

#exercise([8.1], [
  Run `sh benchmarks/run-all.sh` on your machine, rebuild the book, and compare the
  Hashcash verification and token verification rows with the reference host. Which of the two
  depends most on hardware hash instructions, and why?
])

#teach_back([
  Explain the difference between a median-of-batches figure and a per-operation p99, and why
  the book reports the former.
])
