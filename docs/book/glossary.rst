Glossary
========

.. glossary::

   Admin socket
      A Unix socket of mode 0600, named by ``global.admin_socket`` or ``sibuna lb --admin``, that takes one command line at a time from ``sibuna ctl``: show the servers, drain, weigh, add or remove a server, lift a ban, reload. There is no TCP listener for administration (SID 0018).

   Admission
      The decision to forward a request to the origin. In Sibuna it is made by a valid session, an ``ALLOW`` rule, a static bypass path, or a reputation ``allow`` prefix, and it never overrides a WAF denial.

   Affinity
      The rule that sends the flows of one client to one server: by a cookie, by the source address, or by a sticky table. It gives way when the server is down, full, ejected or drained (SID 0019, SID 0025).

   Aho-Corasick automaton
      A finite automaton that finds any of a fixed set of patterns in one pass over the input. Sibuna folds failure links into a dense transition table so each byte costs one table load.

   Authority
      In the edge, the database that owns the published topology in persistent mode: ``frontends``, ``backends`` and ``http``. Each node follows its head and composes it with its own file, which keeps ``global``, ``mesh``, ``observability`` and ``authority`` (SID 0028).

   Backend
      A pool of servers of one protocol, with its scheduler, health check, timeouts and stickiness. The word follows HAProxy; *pool* names the same thing.

   Ban table
      Lock-free slots of banned client addresses with expiry, 65,536 by default (``--ban-table-slots``), written by the honeypot, by rule quotas, by reputation shared across a cluster and, in the edge, by the mesh; read on every request.

   Breaker
      The circuit breaker of an agent plugin. It opens after ``failures`` failures in a row and stays open for ``open``; while it is open a call fails at once with the result ``unavailable`` (SID 0030).

   Campaign
      A cluster of security incidents whose payload embeddings lie within cosine distance 0.35 of one another; a heuristic grouping, not a proof of common origin.

   Challenge record
      The 70-character stateless identifier a client must solve: version, algorithm, difficulty, openings, issue time, client fingerprint, PRF nonce, rule hash, and a 16-byte keyed BLAKE3 tag. Issuing one writes nothing on the server.

   ClientHello inspection
      On a ``tcp`` frontend with ``tcp_inspect``, reading the first TLS record of a connection without terminating TLS, to route or refuse it by server name, ALPN or JA4. A connection that does not send a whole ClientHello within ``inspect_bytes`` takes the configured fallback (SID 0015, SID 0032).

   Difficulty, work bits
      The single integer that scales both tiers: the number of leading zero bits for Hashcash, or three more than the tree depth for sequential work.

   Drain
      The state of a server that takes no new flow and keeps its established ones. ``set server POOL/NAME state drain`` sets it, a reload keeps it, and a restart ends it. A node drains as a whole at shutdown, while readiness answers 503.

   Edge
      A Sibuna deployment with ``--data-dir`` (a SQLite file on one node), or with ``--database-url`` and ``--cluster-node`` (one PostgreSQL database shared by a cluster), giving persistent policies, shared reputation, and incident forensics to either surface.

   Edge mode
      The daemon started with ``--config-file``. It forwards TCP and UDP, terminates TLS, HTTP/2 and HTTP/3, and routes HTTP requests to server pools, with the firewall on the routes that ask for it. It is unrelated to the storage sense of *Edge* above.

   Engine slot
      The place where the published policy engine lives, as a reference-counted pointer. Workers hold a reference while classifying; the storage thread builds a new engine off the request path and publishes it by pointer swap, and the old engine is freed when its last reader releases it.

   Fingerprint
      A keyed hash of client address and User-Agent, bound into challenges and tokens so neither can be replayed from another client.

   Fleet cap
      The ``max_flows`` of a server bounding the flows of all nodes of a mesh together, with ``max_flows_scope: "fleet"``. Each node holds a share of the limit, and unused shares move to the nodes that have the flows (SID 0025).

   Flow
      One unit of work of the edge that holds a slot of ``global.max_flows``: a TCP connection, a UDP mapping, or an HTTP connection.

   Forward auth
      Deployment mode in which an ingress asks Sibuna whether to admit a request (``200``) or challenge, deny, or limit it (``401``, ``403``, ``429``), and proxies the origin itself.

   Frontend
      A named set of listening addresses of one protocol, ``tcp``, ``udp`` or ``http``, with its routes, its limits and its default backend.

   Gate
      The surface with proof-of-work admission, sessions, rules, reputation, GCRA limits and bans, but no application inspection (``--gate``).

   GCRA
      The Generic Cell Rate Algorithm: one theoretical arrival time per client that admits a burst of :math:`N` then one request per emission interval, with no window boundaries.

   Handoff
      The replacement of a running edge binary with ``global.upgrade_socket``: the old process passes its listening sockets and its live UDP mappings to the new one over a Unix socket and then drains its TCP streams. Linux only (SID 0029).

   Hashcash
      Tier One: find a nonce such that SHA-256 of the challenge, a colon, and the decimal nonce has :math:`b` leading zero bits. Expected :math:`2^b` trials, verified with one hash.

   Honeypot
      An invisible link to ``/__sibuna/honeypot``; a client that follows it is banned and an incident with reputation :math:`-100` is recorded.

   Hook
      A decision of the operator's own on the path of the edge, run by a plugin at the stage ``connection``, ``request`` or ``telemetry``. A plugin is native Rust, a metered WebAssembly module, or an agent in another process (SID 0030).

   Idle reaper
      A thread that closes connections that have been silent longer than ``--idle-timeout``, so a slow client cannot pin a connection thread.

   Interstitial
      The embedded HTML page served in place of a protected page; it fetches a challenge, solves it in a Web Worker, posts the solution, and reloads.

   JA4
      A 36-character fingerprint, defined by FoxIO, of how a client opens a TLS connection: protocol, TLS version, server name, cipher and extension counts, ALPN, and hashes of the sorted cipher suites and extensions. Sibuna does not compute it; it reads the value a trusted ingress forwards in the header named by ``--ja4-header``, and rules match it with the ``ja4`` field (SID 0014). It is unrelated to the client fingerprint bound into challenges and tokens.

   Judge
      A thread that decides a parked connection whose chain of hooks names an agent, so that the edge worker never waits for the agent (SID 0030).

   Keyed BLAKE3
      The pseudorandom function behind Sibuna's key schedule, challenge tags, session tags, fingerprints, and challenge nonces.

   Local authority
      The certificate authority that the edge runs itself for internal names. It keeps a root and an intermediate in the storage of automatic HTTPS, writes a revocation list, and can serve other machines as an ACME server (SID 0021).

   MAC token
      The default session cookie: a 40-byte payload (version, work level, timestamp, expiry, rule hash, fingerprint) and a 16-byte keyed BLAKE3 tag, verified in constant time.

   Maglev
      A consistent-hash table of a prime number of slots (65,537 in Sibuna), filled by permutations of the servers, that places a client on a server in constant time (Eisenbud et al., NSDI 2016). Sibuna builds a weighted table and bounds the load of the chosen server by a factor (``bounded_maglev``, SID 0015).

   Mesh
      The nodes of an edge cluster, listed in the ``mesh`` section with a shared key. They probe each other over UDP every half second and share bans, commands, the sticky table and the shares of fleet caps; with ``forward`` they also send flows to their owner. At most 64 nodes (SID 0022 to SID 0026).

   Node
      One edge process in a mesh, known by its mesh address; in persistent mode also by the name ``authority.node``.

   Work level
      The mechanism and work bits a session's holder actually solved, carried in the token; a route admits a session only when its level reaches the route's requirement.

   Opening
      In a sequential-work proof, one leaf label plus the sibling labels along its path to the root; the verifier recomputes the path and compares with the commitment.

   Owner
      The node of a mesh that serves a client under peer forwarding: the live node with the largest rendezvous score for the client's address (SID 0026).

   Passive health
      Ejecting a server for ``ejection`` after ``failures`` consecutive failures of real requests, while another server can serve (SID 0019).

   Passthrough
      Relaying the bytes of a TLS or QUIC connection to a server without terminating it. The edge may still read the ClientHello, or validate QUIC by connection ID (SID 0032).

   Peer forwarding
      The mesh feature that hands a new connection or UDP client to the node that owns the client, so that its sticky server, rate counters and UDP session stay on one node. An established TCP connection that the network moves is not repaired (SID 0026).

   Pool
      See *Backend*.

   Proof of Sequential Work (PoSW)
      Tier Two: the Cohen-Pietrzak hash graph whose labels depend on all earlier labels, forcing :math:`2^{n+1}-1` sequential hashes however many cores the prover has. Verified with :math:`t(n+1)` hashes.

   Regime
      The routing mode of a mesh, chosen from the 95th percentile of the round trip to the peers: *standalone* without a live peer, *regional* while the round trip stays at or below 3 ms, and *wide-area* above 3 ms. A mesh returns from wide-area to regional only below 1.5 ms (``Regime::step`` in ``crates/lb/src/mesh.rs``).

   Rendezvous hashing
      Highest-random-weight hashing (Thaler and Ravishankar, 1998): each candidate gets a score from a hash of its name and the key, and the largest score wins. A lost candidate moves only its own keys. Sibuna uses it for source stickiness (SID 0019) and for the owner of a client (SID 0026).

   Reputation trie
      The 128-bit radix trie holding ``allow``, ``deny``, and ``challenge`` prefixes from the policy file and from the ``ip_reputation`` table.

   Revision
      In the edge, one published state of the topology. With a file it is the digest of the file; with a database it is a number that only grows, and a rollback is a new revision (SID 0028).

   Robin Hood spent set
      The fixed-capacity open-addressed table of solved challenge tags, which prevents a valid solution from being submitted twice.

   Route
      A rule of an HTTP frontend that selects a backend by host name and path prefix, and may switch the firewall off or on for its requests.

   Rule hash
      A 64-bit hash of the rule name that demanded a challenge, carried in the challenge, the token, and the ``X-Sibuna-Rule-Hash`` header.

   Server
      One address of a pool, with a name, a weight and an optional ``max_flows``. ``sibuna ctl`` addresses it as ``POOL/NAME``.

   Share
      The part of a fleet cap that one node may hold now (SID 0025).

   Shield
      The default surface: Gate plus the semantic firewall (``--shield``).

   SID
      A Sibuna Discussion record: a paper-style design document under ``docs/sid/records`` with the assumptions, proofs, and measurements behind one part of the system.

   Slow start
      The ramp of ``slow_start`` during which a server that entered service takes a weight that grows in proportion to the time, so that a cold server is not flooded (SID 0019).

   Spill cache
      A file mapped into memory under the sticky table that keeps the hints of clients that left memory, and keeps them over a restart. Admission to it follows TinyLFU (SID 0027).

   Sticky table
      The table of a pool with ``sticky: "table"`` that remembers the server of each client, by source address or by cookie, for ``ttl`` after the last use. A mesh replicates it, and the later choice wins (SID 0025).

   Surface
      One of the two product shapes, Gate or Shield; storage and clustering are options for either.

   WEIGH
      A rule action that adds a signed weight to a request's score instead of deciding; totals at or above the thresholds challenge with extra work bits or deny.

   Worker
      In the edge, a thread that serves traffic. The edge worker accepts for every frontend and owns the flow table and the UDP mappings; relay threads carry TCP streams; on Linux the event-driven HTTP workers, one per processor, serve HTTP connections (SID 0015, SID 0016).

   Zaxonlite
      The embedded SQLite replication engine (Multi-Paxos) of SID 0005, replaced by SQLite and PostgreSQL storage in SID 0011; its cluster options now stop startup with ``RemovedOption``.

Bibliography
============

- Aho, A. V., and Corasick, M. J. "Efficient string matching: an aid to bibliographic search." *Communications of the ACM* 18(6), 1975.
- ATM Forum. *Traffic Management Specification Version 4.0*, af-tm-0056.000, 1996 (the Generic Cell Rate Algorithm).
- Back, A. "Hashcash: a denial of service counter-measure." Technical report, 2002.
- Blocki, J., Lee, S., and Zhou, S. "On the security of proofs of sequential work in a post-quantum world." *Information-Theoretic Cryptography (ITC)*, 2021.
- Celis, P. *Robin Hood Hashing*. PhD thesis, University of Waterloo, 1986.
- Cohen, B., and Pietrzak, K. "Simple proofs of sequential work." *EUROCRYPT*, 2018.
- Dwork, C., and Naor, M. "Pricing via processing or combatting junk mail." *CRYPTO*, 1992.
- Fiat, A., and Shamir, A. "How to prove yourself: practical solutions to identification and signature problems." *CRYPTO*, 1986.
- Fielding, R., Nottingham, M., and Reschke, J. *HTTP Semantics*, RFC 9110, and *HTTP/1.1*, RFC 9112. IETF, 2022.
- FoxIO. *JA4+ Network Fingerprinting*. https://github.com/FoxIO-LLC/ja4, 2023 (the JA4 TLS client fingerprint).
- Einziger, G., Friedman, R., and Manes, B. "TinyLFU: a highly efficient cache admission policy." *ACM Transactions on Storage* 13(4), 2017.
- Eisenbud, D. E., Yi, C., Contavalli, C., Smith, C., Kononov, R., Mann-Hielscher, E., Cilingiroglu, A., Cheyney, B., Shang, W., and Hosein, J. D. "Maglev: a fast and reliable software network load balancer." *NSDI*, 2016.
- Hanson, N. "libinjection: SQL injection detection by tokenization." Black Hat USA, 2012.
- Juels, A., and Brainard, J. "Client puzzles: a cryptographic countermeasure against connection depletion attacks." *NDSS*, 1999.
- Lamport, L. "The part-time parliament." *ACM Transactions on Computer Systems* 16(2), 1998; and "Paxos made simple." *ACM SIGACT News* 32(4), 2001.
- Mahmoody, M., Moran, T., and Vadhan, S. "Publicly verifiable proofs of sequential work." *Innovations in Theoretical Computer Science (ITCS)*, 2013.
- Mirrokni, V., Thorup, M., and Zadimoghaddam, M. "Consistent hashing with bounded loads." *SODA*, 2018.
- O'Connor, J., Aumasson, J.-P., Neves, S., and Wilcox-O'Hearn, Z. *BLAKE3: one function, fast everywhere*. Specification, 2020.
- Thaler, D. G., and Ravishankar, C. V. "Using name-based mappings to increase hit rates." *IEEE/ACM Transactions on Networking* 6(1), 1998.
- Vyukov, D. "Bounded MPMC queue." 1024cores.net, 2011 (the sequence-stamped ring used for the incident queue).
- Wang, X., Hong, Y., Chang, H., Park, K., Langdale, G., Hu, J., and Zhu, H. "Hyperscan: a fast multi-pattern regex matcher for modern CPUs." *NSDI*, 2019.
- Sibuna Discussions 0001 to 0032, ``docs/sid/records``, 2026: process, foundation architecture, declarative policy engine, semantic inspection, Zaxonlite storage architecture, mathematical foundations, console management interface, AI bot traffic monitoring, chunked request bodies, the Rust port, storage through sqlx, outbound TLS for the console through rustls, console storage, trusted JA4 fingerprints from the ingress, the distributed edge load balancer, event-driven HTTP workers, in-process exchanges, simple setup and run-time configuration, traffic policy, edge observability, automatic HTTPS, replicated bans, cluster configuration, TLS on the workers, shared affinity and fleet caps, peer forwarding, the spill cache, the database authority, the upgrade handoff, plugin tiers, the operator console of the edge, and staged admission.
