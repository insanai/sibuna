#import "theme.typ": *
#import "figures.typ": *
#import "comparison.typ": *

#part_page("II", [Prior Art and the Design Space], [
  We place Sibuna among the systems it learned from: client puzzles and sequential work from
  the cryptography literature, signature and semantic application firewalls, proof-of-work
  interstitials, and hosted edge networks. We then compare the four tools an operator is most
  likely to weigh against each other, feature by feature, and record which facts were checked.
])

== Where Sibuna Comes From

#objectives([
  By the end of this chapter, you should be able to trace the lineage of client puzzles from
  1992 to the sequential-work constructions of 2018, name the three architectural ideas Sibuna
  combines, place Sibuna, Anubis, SafeLine, and the Cloudflare WAF in one design space, and
  say which comparison claims were verified and which were only read from documentation.
])

=== Client Puzzles and Sequential Work

Dwork and Naor's "Pricing via Processing" (CRYPTO 1992) proposed that a service require a
moderately hard, easily checked computation before doing work for a requester. Back's Hashcash
(1997, written up in 2002) made the puzzle a partial hash inversion whose difficulty is one
integer, and Juels and Brainard's client puzzles (NDSS 1999) applied the idea to connection
floods, where the server must not remember anything about an unsolved puzzle. All three share
the shape Sibuna keeps: a server-chosen statement, a solution whose cost is tunable, and
verification that is orders of magnitude cheaper than solving.

Hash search is embarrassingly parallel, so a requester with more cores finishes sooner. Mahmoody,
Moran, and Vadhan (CRYPTO 2013) defined proofs of *sequential* work, in which the prover must
perform a long chain of dependent steps whatever its core count, and Cohen and Pietrzak
(EUROCRYPT 2018) gave the simple hash-graph construction whose verifier needs only $O(t log N)$
work. Blocki, Lee, and Zhou (ITC 2021) proved the same construction sound against quantum
provers in the quantum random-oracle model. Part III derives Sibuna's Tier Two from that line
of work; SID 0006 records the assumptions.

#book_figure([Lineage of the ideas Sibuna combines. Solid arrows are direct descent; the shaded
row is the system layer where Sibuna sits.], design_lineage())

=== Application Firewalls

The first generation of web application firewalls matched request bytes against regular
expressions. ModSecurity (2002) and the OWASP Core Rule Set made that approach open and
widely deployed, and also made its costs familiar: hundreds of backtracking patterns per
request, anomaly scores tuned by hand, and a long tail of false positives on ordinary
input. libinjection (Hanson, 2012) replaced pattern lists with a tokenizer that asks whether a
string *parses* as SQL, cutting both cost and false positives. Chaitin's SafeLine carries that
semantic idea into a full product, and Hyperscan (Wang et al., NSDI 2019) showed how far
vectorised literal matching can be pushed when inputs are long. Part VI explains why Sibuna
chose a dense automaton plus small structural tokenizers over either regular expressions or a
SIMD engine for the short fields it inspects.

=== Interstitials and Edges

The proof-of-work interstitial in front of a website became common in 2025, when scraper
traffic feeding language-model training made ordinary origins unaffordable to run. Anubis
(Techaro) is the best-known open implementation: a Go reverse proxy that serves a JavaScript
puzzle, signs a session token, and otherwise passes traffic through. Sibuna's Gate surface
solves the same problem with a stateless challenge, a symmetric token, and a second work tier;
the comparison below records where the two differ.

At the other end of the scale, hosted edges such as Cloudflare place inspection, rate limiting,
and bot scoring in hundreds of points of presence with a global control plane. Sibuna's Edge
deployment borrows the shape (a replicated policy and reputation plane feeding local, immutable
snapshots) while staying self-hosted, which is why the storage layer is an embedded consensus
database rather than a service call.

== Three Ideas in One Binary

Sibuna combines a browser work challenge for admission, bounded application-payload inspection,
and a replicated control plane that publishes local policy snapshots. Gate and Shield are the
two product surfaces; storage and distributed deployment are options for either.

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

#definition([Design constraints adopted], [
  1. No heap allocation on the request path; every table has a fixed capacity and a stated
     saturation behaviour.
  2. Issuing a challenge writes nothing; only a paid-for solution occupies memory.
  3. A session admits; it never exempts a request from inspection or an explicit denial.
  4. Every claimed number is either measured by a committed harness or labelled as a model.
  5. Cryptographic choices cite a venue and a proof, and state their quantum posture.
])

== Feature Comparison

The table compares Sibuna with the three tools most often mentioned alongside it. Facts about
the other products were read from their public documentation and release artefacts in
September 2026: Anubis 1.27.0 (MIT licence, Go), SafeLine community edition 9.x (GPL-3.0
management code around closed detector images, Docker Compose), and the Cloudflare WAF
developer documentation. Anubis was also run on the benchmark host; SafeLine and Cloudflare
were not (Part VIII explains why). A dash means the product does not offer the feature; a
plan name means the feature exists but only on that plan.

#feature_comparison_table()

Three differences carry most of the weight in a selection decision.

- *Where the work goes.* Anubis and Sibuna Gate make the *client* pay before the origin does
  anything. SafeLine and Cloudflare inspect first and challenge selectively; their default
  posture is to admit and filter. Sibuna Shield does both, in that order: inspection can deny a
  request that already holds a valid session.
- *What the server remembers.* Anubis keeps challenge state in a store (memory, bbolt, Valkey,
  or S3) and signs a JSON Web Token with Ed25519; Sibuna issues a self-authenticating record
  and remembers only solved tags in a fixed table. SafeLine keeps attack logs in PostgreSQL;
  Cloudflare keeps everything, with sampled visibility on the Free plan.
- *What you have to run.* Sibuna is one static binary with an optional embedded database;
  Anubis is one Go binary; SafeLine is seven containers behind a Docker daemon on a Linux
  host with at least one core, one gigabyte of memory, and five gigabytes of disk; Cloudflare
  is a DNS change and a subscription.

#callout([Current product boundary], [
  Sibuna leaves ingress TLS termination to the deployment proxy and does not score bots with
  a trained model or publish paid signatures. Its opt-in console preview now provides
  authenticated dashboards, DB-IP country enrichment, policy editing and local management.
  Country lookup and storage work run outside request classification. SID 0007 remains
  Proposed: cluster management and the full operational and performance acceptance gates
  are still unfinished.
], kind: "warning")

#exercise([2.1], [
  Explain why compiling one verifier source to native code and WebAssembly reduces protocol
  drift. Which properties still require independent testing or cryptographic review?
])

#exercise([2.2], [
  Using only the comparison table, write down the smallest deployment that gives a static
  site (a) a proof-of-work gate, (b) SQL-injection inspection, and (c) a cluster-wide ban.
  Which rows forced each choice?
], hint: [Start from the "runs as" and "multi-node" rows.])

#teach_back([
  Describe how Gate, Shield, and optional replicated storage divide admission, inspection and
  policy distribution. Then name one row of the comparison table you would want to re-verify
  before quoting it to a customer, and say how you would verify it.
])
