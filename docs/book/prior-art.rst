Part II: Prior Art and the Design Space
=======================================

We place Sibuna among the systems it learned from: client puzzles and sequential work from the cryptography literature, signature and semantic application firewalls, proof-of-work interstitials, and hosted edge networks. We then compare the four tools an operator is most likely to weigh against each other, feature by feature, and record which facts were checked. Last we place the edge load balancer of Part VIII beside HAProxy and Envoy.

Where Sibuna Comes From
-----------------------

.. admonition:: Objectives

   By the end of this chapter, we should be able to trace the lineage of client puzzles from 1992 to the sequential-work constructions of 2018, name the three architectural ideas Sibuna combines, place Sibuna, Anubis, SafeLine, and the Cloudflare WAF in one design space, name the papers behind the scheduling and caching of the edge load balancer, compare it with HAProxy and Envoy, and say which comparison claims were verified and which were only read from documentation.

Client Puzzles and Sequential Work
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Dwork and Naor's "Pricing via Processing" (CRYPTO 1992) proposed that a service require a moderately hard, easily checked computation before doing work for a requester. Back's Hashcash (1997, written up in 2002) made the puzzle a partial hash inversion whose difficulty is one integer, and Juels and Brainard's client puzzles (NDSS 1999) applied the idea to connection floods, where the server must not remember anything about an unsolved puzzle. All three share the shape Sibuna keeps: a server-chosen statement, a solution whose cost is tunable, and verification that is orders of magnitude cheaper than solving.

Hash search is embarrassingly parallel, so a requester with more cores finishes sooner. Mahmoody, Moran, and Vadhan (CRYPTO 2013) defined proofs of *sequential* work, in which the prover must perform a long chain of dependent steps whatever its core count, and Cohen and Pietrzak (EUROCRYPT 2018) gave the simple hash-graph construction whose verifier needs only :math:`O(t \log N)` work. Blocki, Lee, and Zhou (ITC 2021) proved the same construction sound against quantum provers in the quantum random-oracle model. Part III derives Sibuna's Tier Two from that line of work; SID 0006 records the assumptions.

.. graphviz:: diagrams/lineage.dot
   :caption: Lineage of the ideas Sibuna combines. The left column is the cryptography of client puzzles and sequential work, the right column the algorithms and systems Sibuna builds on, and the middle column the products in the same space; time runs downward. Thin arrows are direct descent, and the filled boxes are the ideas Sibuna takes directly. An earlier storage design drew on Multi-Paxos (Lamport 1998; SID 0005); Sibuna now stores its state in SQLite or PostgreSQL (SID 0011).
   :alt: A lineage graph. Dwork-Naor 1992 leads to Hashcash 1997, Juels-Brainard 1999, Mahmoody et al. 2013, Cohen-Pietrzak 2018 and Blocki-Lee-Zhou 2021. Aho-Corasick 1975 leads to Hyperscan 2019; ModSecurity and CRS 2002 lead to libinjection 2012. Hashcash leads to the Anubis interstitial and libinjection to the SafeLine semantic WAF; the Cloudflare hosted edge stands beside them. Sibuna (Gate, Shield, Edge) descends from Hashcash, Cohen-Pietrzak, Blocki-Lee-Zhou, Aho-Corasick, libinjection, GCRA (ATM Forum 1996), Anubis, SafeLine and Cloudflare.

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

The four tables below compare Sibuna with the three tools most often mentioned alongside it. Facts about the other products were read from their public documentation and release artefacts in September 2026: Anubis 1.27.0 (MIT licence, Go), SafeLine community edition 9.x (GPL-3.0 management code around closed detector images, Docker Compose), and the Cloudflare WAF developer documentation. Anubis was also run on the benchmark host; SafeLine and Cloudflare were not (Part X explains why). A dash means the product does not offer the feature; a plan name means the feature exists but only on that plan. Each Sibuna measurement names the committed result file it comes from. The TLS fingerprint row was checked in October 2026, against the Anubis changelog (1.21.0 and 1.26.0), the SafeLine release notes (8.10.0 and 9.2.0), and Cloudflare's page "JA3/JA4 fingerprint".

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
     - One binary; reverse proxy or forward auth; optional SQLite file or shared PostgreSQL database; or an edge load balancer with the firewall per route (Part VIII)
     - One Go binary; reverse proxy or forward auth
     - Seven Docker containers (tengine, detector, mgt, luigi, fvm, chaos, PostgreSQL)
     - Hosted network; DNS points at Cloudflare
   * - Language, runtime
     - Rust, no garbage collector; no external crate when storage is off
     - Go, garbage collected
     - C/C++ proxy and detector, Go management, PostgreSQL
     - Proprietary edge software
   * - Licence
     - LGPL-3.0-or-later
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
     - JSON rules: path, User-Agent, headers, IPv4/IPv6 CIDR, JA4 fingerprint; ALLOW, DENY, CHALLENGE, WEIGH with thresholds; dynamic rules from the database
     - YAML/JSON bots: regex on UA, path, headers; CIDR; CEL expressions; WEIGH with thresholds
     - Console-defined custom rules, ACLs, IP groups
     - Rules language expressions; *5 / 20 / 100 / 1000 custom rules by plan*
   * - TLS fingerprint (JA4)
     - Rules match a JA4 fingerprint exactly or by prefix; a trusted ingress computes it and forwards it in a header (``--ja4-header``); Sibuna does not compute it
     - Not documented; policies may reference the HTTP fingerprint JA4H, which Anubis computes and adds as the header ``X-Http-Fingerprint-JA4H``
     - Computed at its own TLS termination; shown in attack details; custom rules match it (equals, not equals); a built-in rule denies fingerprints from its malicious JA4 intelligence
     - JA3 and JA4 fingerprints in WAF custom rules and analytics *(Enterprise with Bot Management)*

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
     - Daemon: one PostgreSQL database shared by every node for policy and reputation; shared seed; sticky challenge verification. Edge: a mesh shares bans (SID 0022)
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
     - Daemon: \- (ingress). Edge: **Yes**, with automatic HTTPS (SID 0021)
     - \- (ingress)
     - **Yes**
     - **Yes**
   * - Management console
     - Opt-in; SID 0007 Committed
     - \-
     - **Yes**
     - **Yes**
   * - Measured on the benchmark host
     - **Yes** (Part X)
     - **Yes**
     - \- (Docker only)
     - \- (hosted)

Three differences carry most of the weight in a selection decision.

- *Where the work goes.* Anubis and Sibuna Gate make the *client* pay before the origin does anything. SafeLine and Cloudflare inspect first and challenge selectively; their default posture is to admit and filter. Sibuna Shield does both, in that order: inspection can deny a request that already holds a valid session.
- *What the server remembers.* Anubis keeps challenge state in a store (memory, bbolt, Valkey, or S3) and signs a JSON Web Token with Ed25519; Sibuna issues a self-authenticating record and remembers only solved tags in a fixed table. SafeLine keeps attack logs in PostgreSQL; Cloudflare keeps everything, with sampled visibility on the Free plan.
- *What an operator has to run.* Sibuna is one binary with an optional SQLite file, or a PostgreSQL database shared by a cluster; Anubis is one Go binary; SafeLine is seven containers behind a Docker daemon on a Linux host with at least one core, one gigabyte of memory, and five gigabytes of disk; Cloudflare is a DNS change and a subscription.

.. admonition:: Current product boundary
   :class: warning

   The firewall daemon leaves TLS termination to the deployment proxy; the edge terminates TLS itself (Part VIII). Sibuna does not score bots with a trained model or publish paid signatures. The HTTP firewall matches the JA4 fingerprint that a trusted ingress computes and cannot compute one itself (SID 0014, Part XI); the edge computes JA4 only from the ClientHello of a TCP frontend that inspects it, for its routing rules, its hooks and its PROXY header (SID 0015). Its opt-in console provides authenticated dashboards, country enrichment, policy editing, investigation and cluster management. Country lookup and storage work run outside request classification. SID 0007 is Committed, and the console passes its browser workflows (SID 0010). Its formal performance isolation gate, with eight active dashboards under load, is not yet measured; Part VIII records what is.

Load Balancers
--------------

Since SID 0015 Sibuna is also an edge load balancer: it forwards TCP and UDP, terminates TLS, HTTP/2 and HTTP/3, and routes HTTP requests to pools of servers, with the firewall on the routes that ask for it. This section names what the load balancer draws on and compares it with two open load balancers.

Where the Load Balancer Comes From
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The vocabulary is HAProxy's. A *frontend* binds addresses, a *backend* is a pool of *servers*, and an operator drains a server through a local socket with ``set server app/s1 state drain``. Part XI keeps a table that translates HAProxy directives into the keys of the edge. nginx made the event-driven worker the ordinary design of a proxy: a few processes, each with its own event loop, and no thread per connection. SID 0016 builds the HTTP workers of the edge in that way. Envoy made a proxy a programmable platform: filters at fixed points of the path, extensions in WebAssembly, and a configuration that a control plane pushes. The hooks of SID 0030 also attach at fixed stages, in three tiers, and each decision is one call with a deadline.

Four papers decide how the edge places a flow and what it remembers.

- *Maglev* (Eisenbud et al., NSDI 2016) fills a table of a prime number of slots from one permutation per server, so a lookup is one hash and one load, and a change of servers moves few clients. The pool kind ``bounded_maglev`` builds a weighted table of 65,537 slots (``crates/lb/src/maglev.rs``), and a mesh in its regional regime places clients with it (SID 0015).
- *Consistent hashing with bounded loads* (Mirrokni, Thorup and Zadimoghaddam, SODA 2018) caps the load of the chosen server at a factor of the mean and passes the excess on. ``bounded_maglev`` applies such a cap to the server that the table names, with ``load_factor_pct``, 125 by default. HAProxy applies the same idea to its consistent hashing with ``hash-balance-factor``.
- *Rendezvous hashing* (Thaler and Ravishankar, IEEE/ACM Transactions on Networking 1998) gives each server a score from a hash of its name and the key, and the largest score wins. Losing a server moves only its own keys and needs no table. Source stickiness ranks servers in this way (SID 0019), and peer forwarding chooses the owner of a client among the nodes in this way (SID 0026).
- *TinyLFU* (Einziger, Friedman and Manes, ACM Transactions on Storage 2017) admits a new entry to a full cache only when a small frequency sketch says that it is used more often than the entry it would push out. The spill cache of SID 0027 admits hints to its file by this rule.

.. graphviz:: diagrams/lb-lineage.dot
   :caption: What the edge load balancer takes from earlier systems and papers. Solid arrows are ideas taken directly; dashed lines are ideas shared.
   :alt: HAProxy gives the vocabulary and the admin socket, nginx the event-driven workers, and Envoy shares the idea of hook stages. Maglev and bounded loads give the bounded Maglev pool, rendezvous hashing gives source stickiness and the owner of a client, and TinyLFU gives the admission of the spill cache. HAProxy's hash-balance-factor shares the idea of bounded loads.

Load Balancing Compared
~~~~~~~~~~~~~~~~~~~~~~~

The table compares the load balancing of Sibuna with HAProxy and Envoy. We read their public documentation on 25 November 2026: the HAProxy 3.4.8 Configuration Manual and Management Guide (docs.haproxy.org; 3.4 is the newest long-term-support branch), and the Envoy 1.40.2 documentation (envoyproxy.io). We ran neither for this table; Part X compares Sibuna with HAProxy 3.0.11 on one host and runs a cluster of three hosts. A cell that says *not checked* names a fact that the pages we read did not settle. For Sibuna the code and the SID records decide, and a feature that is not built says so.

.. list-table:: Load balancing: Sibuna, HAProxy and Envoy
   :header-rows: 1
   :stub-columns: 1
   :widths: 16 28 28 28

   * - Feature
     - Sibuna edge
     - HAProxy 3.4
     - Envoy 1.40
   * - Protocols
     - TCP, UDP, HTTP/1.1, HTTP/2, HTTP/3 and gRPC, toward clients and toward servers; WebSocket, but not toward an HTTP/2 or HTTP/3 pool
     - TCP, HTTP/1.1, HTTP/2 and HTTP/3; QUIC toward servers is experimental; UDP listeners only in ``log-forward`` sections
     - TCP, UDP (UDP proxy filter), HTTP/1.1, HTTP/2, and HTTP/3 toward clients and toward servers
   * - Scheduling
     - Least connections (default), round robin, power of two choices with peak EWMA, bounded Maglev; slow start
     - ``roundrobin``, ``static-rr``, ``leastconn``, ``first``, ``hash``, ``source``, ``uri``, ``url_param``, ``hdr``, ``random``, ``rdp-cookie``, ``sticky``; bounded loads with ``hash-balance-factor``; ``slowstart``
     - Weighted round robin, least request (power of two choices), ring hash, Maglev with 65,537 slots, random, client-side weighted round robin
   * - TLS termination
     - **Yes**: PEM bundles chosen by server name; HTTP/2 over TLS and HTTP/3 over QUIC
     - **Yes**: ``bind ... ssl crt``
     - **Yes**: certificates from files or the secret discovery service
   * - TLS passthrough
     - **Yes**: ``tcp`` frontends route or refuse by server name, ALPN or JA4 read from the ClientHello; QUIC is validated by connection ID (SID 0032); edge-generated Retry is not built
     - **Yes**: ``mode tcp`` with content inspection of ``req.ssl_sni``
     - **Yes**: the TLS Inspector reads server name and ALPN to choose a filter chain
   * - ACME
     - **Built in**: HTTP-01, TLS-ALPN-01 and DNS-01 (hook, RFC 2136, Cloudflare), wildcards, issuance on demand, OCSP stapling, and a local authority that can serve other machines over ACME (SID 0021)
     - **Experimental** ``acme`` section: HAProxy answers HTTP-01 itself; DNS-01 and dns-persist-01 need the Data Plane API or another tool
     - Not checked
   * - Health checks
     - Active TCP connect or HTTP ``GET`` with ``rise`` and ``fall``; passive ejection by real failures (SID 0019)
     - Active checks (``check``, ``option httpchk``); passive observation with ``observe`` and ``error-limit``
     - Active HTTP, gRPC, L3/L4, Redis and Thrift checks; passive outlier detection
   * - Sticky sessions
     - Keyed cookie, source address, or a learned table by source or cookie that a mesh replicates and a file can keep over a restart (SID 0025, SID 0027)
     - ``cookie`` (insert, rewrite, prefix); stick tables (``stick on src``)
     - A hash policy on the route with ring hash or Maglev; the stateful session filter with a cookie or a header
   * - Runtime API
     - Unix admin socket and ``sibuna ctl``: drain, weight, add and remove servers, lift bans, reload, show; a subset in the operator console (SID 0018, SID 0031)
     - Runtime API on the stats socket: ``set server ... state|weight``, ``add server``, ``del server``, ``show stat``, ``show table``, ``clear table``, ``acme renew``
     - Admin interface: stats, ``config_dump``, ``drain_listeners``, ``healthcheck/fail``, ``runtime_modify``; endpoints and listeners change through xDS from a control plane
   * - Hot reload
     - In the same process by SIGHUP, ``reload`` or a file watcher; established flows keep their server; ``reload cluster`` for a mesh; a database revision in persistent mode (SID 0023, SID 0028)
     - A reload starts a new worker that takes the listening sockets of the old one (``-x``; automatic in master-worker mode)
     - Dynamic configuration through xDS without a restart
   * - Binary replacement
     - ``global.upgrade_socket``: the listening sockets and the live UDP mappings pass to the new process, and TCP streams drain in the old one; Linux only (SID 0029). Or ``global.reuse_port``
     - The same reload passes the listening sockets to the new process
     - Hot restart passes the listening sockets over a Unix socket; existing connections are not transferred; HTTP/3 is not handled gracefully yet
   * - Clustering of state
     - A mesh of at most 64 nodes shares bans, server commands, the sticky table and fleet-wide ``max_flows``, and forwards each client to its owner node (SID 0022, SID 0025, SID 0026); request limiters count on each node
     - ``peers`` sections push stick-table entries between instances over TCP, multi-master; values overwrite without aggregation
     - Global rate limits through an external gRPC rate limit service; other shared state not checked
   * - Extension mechanism
     - Native Rust hooks, WebAssembly on an in-house metered interpreter, and agents on a Unix socket, at the connection, request and telemetry stages; no hook on a response or a body (SID 0030)
     - Lua (``lua-load``); filters, among them the Stream Processing Offload Engine (SPOE)
     - Filters, among them Lua, external authorization and external processing; WebAssembly through the Proxy-Wasm ABI
   * - Built-in bot protection
     - Proof-of-work admission (Gate) and the semantic firewall (Shield), chosen per frontend and per route; off in ``sibuna lb`` unless asked
     - None in the Configuration Manual; stick-table rates and deny rules
     - Not checked

Three differences matter most when we choose.

- *What changes at run time.* HAProxy and Sibuna both change servers through a local socket. Envoy expects a control plane: its admin interface inspects and drains, and xDS changes the configuration. Sibuna's socket changes servers, bans and certificates of its local authority; frontends, routes and policy change by reload (SID 0018).
- *What a cluster shares.* HAProxy replicates stick tables between peers. Sibuna's mesh replicates more kinds of state, each with its own merge rule, and adds fleet-wide caps and peer forwarding, but only within one fixed roster of at most 64 nodes and only on a network that is trusted, because the mesh authenticates and does not encrypt (SID 0026).
- *What a replacement keeps.* All three keep the listening sockets. Sibuna also passes live UDP mappings, so a UDP client keeps its server; none of the three moves an established TCP connection to the new process.

.. admonition:: Current boundary of the load balancer
   :class: warning

   The edge is new. HAProxy and Envoy have served production traffic for years; Sibuna's edge has run in tests and in benchmarks on up to three hosts (Part X). Its known gaps are listed in each SID: among them, TCP and UDP frontends do not consult the ban table, the admin socket cannot change frontends or routes, the spill cache missed the retention target at 50 million distinct keys, and an agent call at the request stage holds its thread.

.. admonition:: Exercise 2.1

   Explain why compiling one verifier source to native code and WebAssembly reduces protocol drift. Which properties still require independent testing or cryptographic review?

.. admonition:: Exercise 2.2

   Using only the comparison tables, write down the smallest deployment that gives a static site (a) a proof-of-work gate, (b) SQL-injection inspection, and (c) a cluster-wide ban. Which rows forced each choice?

   Hint: Start from the "runs as" and "multi-node" rows.

.. admonition:: Exercise 2.3

   A pool has four servers of equal weight and 1,000 clients. Using only the descriptions of Maglev and rendezvous hashing above, say how many clients move when one server is removed under each scheme, and why peer forwarding (SID 0026) chose rendezvous hashing for the owner of a client.

   Hint: Ask which clients a removal must move, and which ones a rebuilt table may move as well.

.. admonition:: Explain the invariant

   Describe how Gate, Shield, and optional shared storage divide admission, inspection and policy distribution. Then name one row of the comparison tables we would want to re-verify before quoting it to a customer, and say how we would verify it.
