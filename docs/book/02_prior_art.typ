#import "theme.typ": *
#import "figures.typ": *

#part_page("II", [Prior Art and the Design Space], [
  We place Sibuna among the systems it learned from: client puzzles, proof-of-work
  interstitials, semantic application firewalls, and replicated edge control planes, and
  record the engineering facts that shaped its design.
])

== Where Sibuna Comes From

#objectives([
  By the end of this chapter, you should be able to trace the lineage of client puzzles,
  identify the three architectural ideas Sibuna combines, and state the design
  constraints Sibuna adopted in response.
])

=== Client Puzzles

Dwork and Naor's "Pricing via Processing" (CRYPTO 1992) proposed that a service require a
moderately hard, easily checked computation before doing work for a requester. Back's Hashcash
(1997) made the puzzle a partial hash inversion, and Juels and Brainard's client puzzles (NDSS
1999) applied the idea to TCP connection floods. All three share the shape Sibuna keeps: a
server-chosen statement, a solution whose cost is tunable, and verification that is orders of
magnitude cheaper than solving.

=== Admission, Inspection, and Replicated State

Sibuna combines three architectural ideas: a browser work challenge for admission, bounded
application-payload inspection, and a replicated control plane publishing local policy snapshots.
Gate and Shield are the two product surfaces. Storage and distributed edge deployment are
options for either surface.

#table(
  columns: (1fr, 2fr, 2fr),
  table.header([*Property*], [*Gate*], [*Shield*]),
  [Admission], [Native Hashcash or sequential-work verification], [Same],
  [Session], [Keyed BLAKE3; optional Ed25519], [Same],
  [Local controls], [Rules, CIDRs, GCRA, bans], [Same],
  [Inspection], [Disabled], [Bounded signatures and structural tokenizers],
  [State], [Optional replicated policy and reputation], [Also inspection forensics],
)

The browser solver compiles from the same proof sources as the native verifier. Dense literal
matching avoids backtracking and keeps scan work linear in input length. Immutable policy
snapshots isolate request handling from SQL and consensus. None of these choices establishes
universal algorithmic optimality: short headers, long bodies, pattern diversity, core count and
cache size change the tradeoffs.

#exercise([2.1], [
  Explain why compiling one verifier source to native code and WebAssembly reduces protocol
  drift. Which properties still require independent testing or cryptographic review?
])

#teach_back([
  Describe how Gate, Shield, and optional replicated storage divide admission, inspection and
  policy distribution. Identify one local-state limitation in a multi-node deployment.
])
