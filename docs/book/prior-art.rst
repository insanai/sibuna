Part II: Prior Art and the Design Space
=======================================

We place Sibuna among the systems it learned from: client puzzles and sequential work from the cryptography literature, signature and semantic application firewalls, proof-of-work interstitials, and hosted edge networks. We then compare the four tools an operator is most likely to weigh against each other, feature by feature, and record which facts were checked.

Where Sibuna Comes From
-----------------------

.. admonition:: Objectives

   By the end of this chapter, we should be able to trace the lineage of client puzzles from 1992 to the sequential-work constructions of 2018, name the three architectural ideas Sibuna combines, place Sibuna, Anubis, SafeLine, and the Cloudflare WAF in one design space, and say which comparison claims were verified and which were only read from documentation.

Client Puzzles and Sequential Work
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Dwork and Naor's "Pricing via Processing" (CRYPTO 1992) proposed that a service require a moderately hard, easily checked computation before doing work for a requester. Back's Hashcash (1997, written up in 2002) made the puzzle a partial hash inversion whose difficulty is one integer, and Juels and Brainard's client puzzles (NDSS 1999) applied the idea to connection floods, where the server must not remember anything about an unsolved puzzle. All three share the shape Sibuna keeps: a server-chosen statement, a solution whose cost is tunable, and verification that is orders of magnitude cheaper than solving.

Hash search is embarrassingly parallel, so a requester with more cores finishes sooner. Mahmoody, Moran, and Vadhan (CRYPTO 2013) defined proofs of *sequential* work, in which the prover must perform a long chain of dependent steps whatever its core count, and Cohen and Pietrzak (EUROCRYPT 2018) gave the simple hash-graph construction whose verifier needs only :math:`O(t \log N)` work. Blocki, Lee, and Zhou (ITC 2021) proved the same construction sound against quantum provers in the quantum random-oracle model. Part III derives Sibuna's Tier Two from that line of work; SID 0006 records the assumptions.

.. graphviz::
   :caption: Lineage of the ideas Sibuna combines. The top row is the cryptography of client puzzles and sequential work, the middle row the algorithms and systems Sibuna builds on, and the third row the products in the same space; arrows are direct descent. An earlier storage design drew on Multi-Paxos (Lamport 1998; SID 0005); Sibuna now stores its state in SQLite or PostgreSQL (SID 0011).
   :alt: A lineage graph. Dwork-Naor 1992 leads to Hashcash 1997, Juels-Brainard 1999, Mahmoody et al. 2013, Cohen-Pietrzak 2018 and Blocki-Lee-Zhou 2021. Aho-Corasick 1975 leads to Hyperscan 2019; ModSecurity and CRS 2002 lead to libinjection 2012. Hashcash leads to the Anubis interstitial and libinjection to the SafeLine semantic WAF; the Cloudflare hosted edge stands beside them. Sibuna (Gate, Shield, Edge) descends from Hashcash, Cohen-Pietrzak, Blocki-Lee-Zhou, Aho-Corasick, libinjection, GCRA (ATM Forum 1996), Anubis, SafeLine and Cloudflare.

   digraph lineage {
     rankdir=TB;
     node [shape=box, fontname="Helvetica", fontsize=10];
     edge [fontname="Helvetica", fontsize=9];
     subgraph puzzles {
       rank=same;
       dwork [label="Dwork-Naor\n1992"];
       hashcash [label="Hashcash\n1997"];
       juels [label="Juels-Brainard\n1999"];
       mahmoody [label="Mahmoody et al.\n2013"];
       cohen [label="Cohen-Pietrzak\n2018"];
       blocki [label="Blocki-Lee-Zhou\n2021"];
     }
     subgraph systems {
       rank=same;
       aho [label="Aho-Corasick\n1975"];
       modsec [label="ModSecurity, CRS\n2002"];
       libinj [label="libinjection\n2012"];
       hyperscan [label="Hyperscan\n2019"];
       gcra [label="GCRA\nATM Forum 1996"];
     }
     subgraph products {
       rank=same;
       anubis [label="Anubis\ninterstitial"];
       safeline [label="SafeLine\nsemantic WAF"];
       cloudflare [label="Cloudflare\nhosted edge"];
     }
     sibuna [label="Sibuna\nGate, Shield, Edge", style="filled,bold"];
     dwork -> hashcash -> juels -> mahmoody -> cohen -> blocki;
     modsec -> libinj;
     aho -> hyperscan;
     dwork -> aho [style=invis];
     aho -> anubis [style=invis];
     hashcash -> anubis;
     libinj -> safeline;
     hashcash -> sibuna;
     cohen -> sibuna;
     blocki -> sibuna;
     aho -> sibuna;
     libinj -> sibuna;
     gcra -> sibuna;
     anubis -> sibuna;
     safeline -> sibuna;
     cloudflare -> sibuna;
   }

Application Firewalls
~~~~~~~~~~~~~~~~~~~~~

The first generation of web application firewalls matched request bytes against regular expressions. ModSecurity (2002) and the OWASP Core Rule Set made that approach open and widely deployed, and also made its costs familiar: hundreds of backtracking patterns per request, anomaly scores tuned by hand, and a long tail of false positives on ordinary input. libinjection (Hanson, 2012) replaced pattern lists with a tokenizer that asks whether a string *parses* as SQL, cutting both cost and false positives. Chaitin's SafeLine carries that semantic idea into a full product, and Hyperscan (Wang et al., NSDI 2019) showed how far vectorised literal matching can be pushed when inputs are long. Part VI explains why Sibuna chose a dense automaton plus small structural tokenizers over either regular expressions or a SIMD engine for the short fields it inspects.

Interstitials and Edges
~~~~~~~~~~~~~~~~~~~~~~~

The proof-of-work interstitial in front of a website became common in 2025, when scraper traffic feeding language-model training made ordinary origins unaffordable to run. Anubis (Techaro) is the best-known open implementation: a Go reverse proxy that serves a JavaScript puzzle, signs a session token, and otherwise passes traffic through. Sibuna's Gate surface solves the same problem with a stateless challenge, a symmetric token, and a second work tier; the comparison below records where the two differ.

At the other end of the scale, hosted edges such as Cloudflare place inspection, rate limiting, and bot scoring in hundreds of points of presence with a global control plane. Sibuna's Edge deployment borrows the shape (a shared policy and reputation plane feeding local, immutable snapshots) while staying self-hosted, which is why the storage layer is a database the operator runs (a SQLite file on one node, one PostgreSQL database shared by a cluster) read by a storage thread off the request path, rather than a service call.

Three Ideas in One Binary
-------------------------

Sibuna combines a browser work challenge for admission, bounded application-payload inspection, and a shared control plane that publishes local policy snapshots. Gate and Shield are the two product surfaces; storage and distributed deployment are options for either.

.. list-table::
   :header-rows: 1
   :widths: 20 40 40

   * - **Property**
     - **Gate**
     - **Shield**
   * - Admission
     - Native Hashcash or sequential-work verification
     - Same
   * - Session
     - Keyed BLAKE3; optional Ed25519
     - Same
   * - Local controls
     - Rules, CIDRs, GCRA, bans
     - Same
   * - Inspection
     - Disabled
     - Bounded signatures and structural tokenizers
   * - State
     - Optional persistent policy and reputation, shared across a cluster
     - Also inspection forensics

The browser solver compiles from the same proof sources as the native verifier. Dense literal matching avoids backtracking and keeps scan work linear in input length. Immutable policy snapshots isolate request handling from SQL and from the availability of the database. None of these choices establishes universal algorithmic optimality: short headers, long bodies, pattern diversity, core count and cache size change the tradeoffs.

.. admonition:: Design constraints adopted

   1. No heap allocation on the request path; every table has a fixed capacity and a stated saturation behaviour.
   2. Issuing a challenge writes nothing; only a paid-for solution occupies memory.
   3. A session admits; it never exempts a request from inspection or an explicit denial.
   4. Every claimed number is either measured by a committed harness or labelled as a model.
   5. Cryptographic choices cite a venue and a proof, and state their quantum posture.

Feature Comparison
------------------

The four tables below compare Sibuna with the three tools most often mentioned alongside it. Facts about the other products were read from their public documentation and release artefacts in September 2026: Anubis 1.27.0 (MIT licence, Go), SafeLine community edition 9.x (GPL-3.0 management code around closed detector images, Docker Compose), and the Cloudflare WAF developer documentation. Anubis was also run on the benchmark host; SafeLine and Cloudflare were not (Part VIII explains why). A dash means the product does not offer the feature; a plan name means the feature exists but only on that plan. Each Sibuna measurement names the committed result file it comes from.

.. list-table:: Feature comparison, part 1: deployment
   :header-rows: 1
   :stub-columns: 1
   :widths: 16 24 20 20 20

   * - Feature
     - Sibuna
     - Anubis 1.27
     - SafeLine CE 9
     - Cloudflare WAF
   * - Runs as
     - One binary; reverse proxy or forward auth; optional SQLite file or shared PostgreSQL database
     - One Go binary; reverse proxy or forward auth
     - Seven Docker containers (tengine, detector, mgt, luigi, fvm, chaos, PostgreSQL)
     - Hosted network; DNS points at Cloudflare
   * - Language, runtime
     - Rust, no garbage collector; no external crate when storage is off
     - Go, garbage collected
     - C/C++ proxy and detector, Go management, PostgreSQL
     - Proprietary edge software
   * - Licence
     - Source in the repository
     - MIT
     - GPL-3.0 management code; closed detector images
     - Proprietary service
   * - Host footprint
     - 35.7 MiB binary (``benchmarks/results/comparison-latest.json``); 5.9 MiB idle RSS (``benchmarks/results/primitives-latest.json``); at most 16.0 MiB peak RSS under load (``benchmarks/results/product-latest.md``)
     - 38.1 MiB binary; 21 MiB idle RSS; Linux fixture, console off
     - 1 CPU core, 1 GB RAM, 5 GB disk minimum, Docker 20.10+
     - None on premises

.. list-table:: Feature comparison, part 2: admission and sessions
   :header-rows: 1
   :stub-columns: 1
   :widths: 16 24 20 20 20

   * - Feature
     - Sibuna
     - Anubis 1.27
     - SafeLine CE 9
     - Cloudflare WAF
   * - Proof-of-work admission
     - Hashcash (bit-level) and Cohen-Pietrzak sequential work, chosen per rule; WebAssembly with JavaScript fallback
     - SHA-256 Hashcash in hex nibbles (``fast``, ``slow``); non-work ``metarefresh`` and ``preact`` challenges
     - JavaScript anti-bot challenge and CAPTCHA; not work-bound
     - Managed challenge, JS challenge, Turnstile; Bot Fight Mode issues a compute challenge
   * - Challenge state on the server
     - None until solved; solved tags in a fixed Robin Hood table
     - Store backend: memory, bbolt, Valkey, or S3
     - Managed by the stack
     - Managed by Cloudflare
   * - Session token
     - Keyed BLAKE3 tag, 75-character cookie bound to the work paid; Ed25519 optional
     - JSON Web Token signed with Ed25519; HS512 optional
     - Cookie issued by the stack
     - ``cf_clearance`` cookie
   * - Post-quantum posture of the default token
     - Symmetric: only Grover's quadratic speedup applies
     - Ed25519: broken by Shor's algorithm
     - Not documented
     - Not documented
   * - Policy language
     - JSON rules: path, User-Agent, headers, IPv4/IPv6 CIDR; ALLOW, DENY, CHALLENGE, WEIGH with thresholds; dynamic rules from the database
     - YAML/JSON bots: regex on UA, path, headers; CIDR; CEL expressions; WEIGH with thresholds
     - Console-defined custom rules, ACLs, IP groups
     - Rules language expressions; *5 / 20 / 100 / 1000 custom rules by plan*

.. list-table:: Feature comparison, part 3: inspection and state
   :header-rows: 1
   :stub-columns: 1
   :widths: 16 24 20 20 20

   * - Feature
     - Sibuna
     - Anubis 1.27
     - SafeLine CE 9
     - Cloudflare WAF
   * - SQLi, XSS, RCE, traversal inspection
     - Shield: tagged automaton plus structural tokenizers, first 8 KB of body
     - \-
     - Semantic analysis engine over OWASP categories, also SSRF, XXE, CRLF
     - Managed rulesets *(Pro and above)*; OWASP Core Ruleset; attack score *(Business and above)*
   * - Rate limiting
     - GCRA per client, local to a node
     - \- (system load is exposed to CEL rules)
     - Per IP, path, session
     - *1 / 2 / 5 / 100 rules by plan*; IP-only keys below Enterprise
   * - Bans and reputation
     - Honeypot bans; reputation trie loaded from the reputation table shared across the cluster
     - DNSBL; ASN and GeoIP through Thoth *(paid, closed)*
     - IP groups and blacklists; threat intelligence *(Pro)*
     - IP lists; managed lists and bot score *(Enterprise)*
   * - Forensics
     - SQLite or PostgreSQL: full-text search over incidents, vector campaign clustering
     - Prometheus metrics only
     - PostgreSQL attack log with console
     - Security Events; sampled on Free
   * - Multi-node
     - One PostgreSQL database shared by every node for policy and reputation; shared seed; sticky challenge verification
     - Shared signing key; shared Valkey store
     - One stack per host
     - Global anycast

.. list-table:: Feature comparison, part 4: operations
   :header-rows: 1
   :stub-columns: 1
   :widths: 16 24 20 20 20

   * - Feature
     - Sibuna
     - Anubis 1.27
     - SafeLine CE 9
     - Cloudflare WAF
   * - Metrics
     - Prometheus at ``/__sibuna/metrics``
     - Prometheus on a separate port
     - Console dashboards
     - Dashboard and analytics
   * - TLS termination
     - \- (ingress)
     - \- (ingress)
     - **Yes**
     - **Yes**
   * - Management console
     - Opt-in; SID 0007 Committed
     - \-
     - **Yes**
     - **Yes**
   * - Measured on the benchmark host
     - **Yes** (Part VIII)
     - **Yes**
     - \- (Docker only)
     - \- (hosted)

Three differences carry most of the weight in a selection decision.

- *Where the work goes.* Anubis and Sibuna Gate make the *client* pay before the origin does anything. SafeLine and Cloudflare inspect first and challenge selectively; their default posture is to admit and filter. Sibuna Shield does both, in that order: inspection can deny a request that already holds a valid session.
- *What the server remembers.* Anubis keeps challenge state in a store (memory, bbolt, Valkey, or S3) and signs a JSON Web Token with Ed25519; Sibuna issues a self-authenticating record and remembers only solved tags in a fixed table. SafeLine keeps attack logs in PostgreSQL; Cloudflare keeps everything, with sampled visibility on the Free plan.
- *What an operator has to run.* Sibuna is one binary with an optional SQLite file, or a PostgreSQL database shared by a cluster; Anubis is one Go binary; SafeLine is seven containers behind a Docker daemon on a Linux host with at least one core, one gigabyte of memory, and five gigabytes of disk; Cloudflare is a DNS change and a subscription.

.. admonition:: Current product boundary
   :class: warning

   Sibuna leaves ingress TLS termination to the deployment proxy and does not score bots with a trained model or publish paid signatures. Its opt-in console provides authenticated dashboards, country enrichment, policy editing, investigation and cluster management. Country lookup and storage work run outside request classification. SID 0007 is Committed, and the console passes its browser workflows (SID 0010). Its formal performance isolation gate, with eight active dashboards under load, is not yet measured; Part VIII records what is.

.. admonition:: Exercise 2.1

   Explain why compiling one verifier source to native code and WebAssembly reduces protocol drift. Which properties still require independent testing or cryptographic review?

.. admonition:: Exercise 2.2

   Using only the comparison tables, write down the smallest deployment that gives a static site (a) a proof-of-work gate, (b) SQL-injection inspection, and (c) a cluster-wide ban. Which rows forced each choice?

   Hint: Start from the "runs as" and "multi-node" rows.

.. admonition:: Explain the invariant

   Describe how Gate, Shield, and optional shared storage divide admission, inspection and policy distribution. Then name one row of the comparison tables we would want to re-verify before quoting it to a customer, and say how we would verify it.
