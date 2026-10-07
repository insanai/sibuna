#import "theme.typ": *
#import "figures.typ": *
#import "comparison.typ": *

#part_page("II", [Prior Art and the Design Space], [
  Sibuna draws on client puzzles, sequential work, application firewalls and hosted edge
  networks. This chapter traces those ideas, then compares four products feature by feature.
  It distinguishes tested behaviour from information reported in product documentation.
])

== Where Sibuna Comes From

#objectives([
  By the end of this chapter, you should be able to trace the lineage of client puzzles from
  1992 to the sequential-work constructions of 2018, name the three architectural ideas Sibuna
  combines, compare Sibuna with Anubis, SafeLine and the Cloudflare WAF, and distinguish
  tested claims from documented features.
])

=== Client Puzzles and Sequential Work

Dwork and Naor's "Pricing via Processing" (CRYPTO 1992) proposed that a service require a
moderately hard, easily checked computation before doing work for a requester. Back's Hashcash
(1997, written up in 2002) asks for an input whose hash meets a chosen difficulty. Juels and
Brainard's client puzzles (NDSS 1999) applied the idea to connection floods. The server must
not retain state for an unsolved puzzle, because an attacker could exhaust that state for free.
Sibuna retains the three shared ideas: the server chooses the statement, the solution cost
can be adjusted, and verification is much cheaper than solving.

Hash trials are independent, so a requester with more cores can finish sooner. Mahmoody,
Moran, and Vadhan (CRYPTO 2013) defined proofs of *sequential* work, in which the prover must
perform a long chain of dependent steps regardless of its core count. Cohen and Pietrzak
(EUROCRYPT 2018) gave a hash-graph construction with $O(t log N)$ verification work.
Blocki, Lee, and Zhou (ITC 2021) proved the same construction sound against quantum
provers in the quantum random-oracle model. Part III derives Sibuna's Tier Two from that line
of work; SID 0006 records the assumptions.

#book_figure([Lineage of the ideas Sibuna combines. Solid arrows are direct descent; the shaded
row is the system layer where Sibuna sits.], design_lineage())

=== Application Firewalls

The first generation of web application firewalls matched request bytes against regular
expressions. ModSecurity (2002) and the OWASP Core Rule Set made that approach open and
widely deployed. Their costs include evaluating many patterns, tuning anomaly scores and
investigating false positives on ordinary input. libinjection (Hanson, 2012) uses a tokenizer
to recognise SQL-injection patterns. Chaitin's SafeLine applies semantic detection in a full
firewall product. Hyperscan (Wang et al., NSDI 2019) studies vectorised matching for long inputs.

Part VI explains Sibuna's small structural inspector. It combines a dense literal automaton
with tokenizers for short fields. The optional native CRS engine evaluates a broader maintained
rule set under a separate transaction work budget.

=== Interstitials and Edges

Interest in proof-of-work interstitials grew in 2025 as websites faced scraper traffic
feeding language-model training. Anubis
(Techaro) is an open implementation: a Go reverse proxy that serves a JavaScript
puzzle, signs a session token, and otherwise passes traffic through. Sibuna's Gate surface
solves the same problem with a stateless challenge, a symmetric token, and a second work tier;
the comparison below records where the two differ.

At the other end of the scale, hosted edges such as Cloudflare place inspection, rate limiting,
and bot scoring in hundreds of points of presence with a global control plane. Sibuna's Edge
deployment distributes policy and reputation through replicated storage. Each node reads a
local, immutable snapshot when making request decisions. The storage layer is an embedded
consensus database; the request path makes no remote storage call.

== Three Ideas in One Binary

Sibuna combines a browser work challenge for admission, bounded application-payload inspection,
and a replicated control plane that publishes local policy snapshots. Gate and Shield are the
two operating configurations; storage and distributed deployment are options for either.

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

Three differences help an operator choose between them.

- *Where the work goes.* Anubis and Sibuna Gate make the *client* pay before the origin does
  anything. SafeLine and Cloudflare inspect first and challenge selectively; their default
  posture is to admit and filter. Sibuna Shield combines admission and inspection. Inspection
  can deny a request that already holds a valid session.
- *What the server remembers.* Anubis keeps challenge state in a store (memory, bbolt, Valkey,
  or S3) and signs a JSON Web Token with Ed25519; Sibuna issues a self-authenticating record
  and stores solved tags in a fixed table. SafeLine keeps attack logs in PostgreSQL;
  Cloudflare provides attack visibility, with sampling on the Free plan.
- *What you have to run.* Sibuna is one static binary with an optional embedded database;
  Anubis is one Go binary; SafeLine is seven containers behind a Docker daemon on a Linux
  host with at least one core, one gigabyte of memory, and five gigabytes of disk; Cloudflare
  is a hosted service configured through DNS and a subscription plan.

#callout([Current product boundary], [
  Sibuna leaves ingress TLS termination to the deployment proxy and does not score bots with
  a trained model or publish paid signatures. Its opt-in console provides authenticated
  dashboards, country enrichment, policy editing, investigation and cluster management.
  Country lookup and storage work run outside request classification. SID 0007 is Committed;
  functional verification is complete. The fresh container measurements do not establish
  the console's strict performance isolation target; Part VIII records that distinction.
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
  before quoting it to a customer, and explain how you would verify it.
])
