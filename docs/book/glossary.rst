Glossary
========

.. glossary::

   Admission
      The decision to forward a request to the origin. In Sibuna it is made by a valid session, an ``ALLOW`` rule, a static bypass path, or a reputation ``allow`` prefix, and it never overrides a WAF denial.

   Aho-Corasick automaton
      A finite automaton that finds any of a fixed set of patterns in one pass over the input. Sibuna folds failure links into a dense transition table so each byte costs one table load.

   Ban table
      4,096 lock-free slots of banned client addresses with expiry, written by the honeypot and by reputation shared across a cluster, read on every request.

   Campaign
      A cluster of security incidents whose payload embeddings lie within cosine distance 0.35 of one another; a heuristic grouping, not a proof of common origin.

   Challenge record
      The 70-character stateless identifier a client must solve: version, algorithm, difficulty, openings, issue time, client fingerprint, PRF nonce, rule hash, and a 16-byte keyed BLAKE3 tag. Issuing one writes nothing on the server.

   Difficulty, work bits
      The single integer that scales both tiers: the number of leading zero bits for Hashcash, or three more than the tree depth for sequential work.

   Edge
      A Sibuna deployment with ``--data-dir`` (a SQLite file on one node), or with ``--database-url`` and ``--cluster-node`` (one PostgreSQL database shared by a cluster), giving persistent policies, shared reputation, and incident forensics to either surface.

   Engine slot
      The place where the published policy engine lives, as a reference-counted pointer. Workers hold a reference while classifying; the storage thread builds a new engine off the request path and publishes it by pointer swap, and the old engine is freed when its last reader releases it.

   Fingerprint
      A keyed hash of client address and User-Agent, bound into challenges and tokens so neither can be replayed from another client.

   Forward auth
      Deployment mode in which an ingress asks Sibuna whether to admit a request (``200``) or challenge, deny, or limit it (``401``, ``403``, ``429``), and proxies the origin itself.

   Gate
      The surface with proof-of-work admission, sessions, rules, reputation, GCRA limits and bans, but no application inspection (``--gate``).

   GCRA
      The Generic Cell Rate Algorithm: one theoretical arrival time per client that admits a burst of :math:`N` then one request per emission interval, with no window boundaries.

   Hashcash
      Tier One: find a nonce such that SHA-256 of the challenge, a colon, and the decimal nonce has :math:`b` leading zero bits. Expected :math:`2^b` trials, verified with one hash.

   Honeypot
      An invisible link to ``/__sibuna/honeypot``; a client that follows it is banned and an incident with reputation :math:`-100` is recorded.

   Idle reaper
      A thread that closes connections that have been silent longer than ``--idle-timeout``, so a slow client cannot pin a connection thread.

   Interstitial
      The embedded HTML page served in place of a protected page; it fetches a challenge, solves it in a Web Worker, posts the solution, and reloads.

   JA4
      A 36-character fingerprint, defined by FoxIO, of how a client opens a TLS connection: protocol, TLS version, server name, cipher and extension counts, ALPN, and hashes of the sorted cipher suites and extensions. Sibuna does not compute it; it reads the value a trusted ingress forwards in the header named by ``--ja4-header``, and rules match it with the ``ja4`` field (SID 0014). It is unrelated to the client fingerprint bound into challenges and tokens.

   Keyed BLAKE3
      The pseudorandom function behind Sibuna's key schedule, challenge tags, session tags, fingerprints, and challenge nonces.

   MAC token
      The default session cookie: a 40-byte payload (version, work level, timestamp, expiry, rule hash, fingerprint) and a 16-byte keyed BLAKE3 tag, verified in constant time.

   Work level
      The mechanism and work bits a session's holder actually solved, carried in the token; a route admits a session only when its level reaches the route's requirement.

   Opening
      In a sequential-work proof, one leaf label plus the sibling labels along its path to the root; the verifier recomputes the path and compares with the commitment.

   Proof of Sequential Work (PoSW)
      Tier Two: the Cohen-Pietrzak hash graph whose labels depend on all earlier labels, forcing :math:`2^{n+1}-1` sequential hashes however many cores the prover has. Verified with :math:`t(n+1)` hashes.

   Reputation trie
      The 128-bit radix trie holding ``allow``, ``deny``, and ``challenge`` prefixes from the policy file and from the ``ip_reputation`` table.

   Robin Hood spent set
      The fixed-capacity open-addressed table of solved challenge tags, which prevents a valid solution from being submitted twice.

   Rule hash
      A 64-bit hash of the rule name that demanded a challenge, carried in the challenge, the token, and the ``X-Sibuna-Rule-Hash`` header.

   Shield
      The default surface: Gate plus the semantic firewall (``--shield``).

   SID
      A Sibuna Discussion record: a paper-style design document under ``docs/sid/records`` with the assumptions, proofs, and measurements behind one part of the system.

   Surface
      One of the two product shapes, Gate or Shield; storage and clustering are options for either.

   WEIGH
      A rule action that adds a signed weight to a request's score instead of deciding; totals at or above the thresholds challenge with extra work bits or deny.

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
- Hanson, N. "libinjection: SQL injection detection by tokenization." Black Hat USA, 2012.
- Juels, A., and Brainard, J. "Client puzzles: a cryptographic countermeasure against connection depletion attacks." *NDSS*, 1999.
- Lamport, L. "The part-time parliament." *ACM Transactions on Computer Systems* 16(2), 1998; and "Paxos made simple." *ACM SIGACT News* 32(4), 2001.
- Mahmoody, M., Moran, T., and Vadhan, S. "Publicly verifiable proofs of sequential work." *Innovations in Theoretical Computer Science (ITCS)*, 2013.
- O'Connor, J., Aumasson, J.-P., Neves, S., and Wilcox-O'Hearn, Z. *BLAKE3: one function, fast everywhere*. Specification, 2020.
- Vyukov, D. "Bounded MPMC queue." 1024cores.net, 2011 (the sequence-stamped ring used for the incident queue).
- Wang, X., Hong, Y., Chang, H., Park, K., Langdale, G., Hu, J., and Zhu, H. "Hyperscan: a fast multi-pattern regex matcher for modern CPUs." *NSDI*, 2019.
- Sibuna Discussions 0001 to 0014, ``docs/sid/records``, 2026: process, foundation architecture, declarative policy engine, semantic inspection, Zaxonlite storage architecture, mathematical foundations, console management interface, AI bot traffic monitoring, chunked request bodies, the Rust port, storage through sqlx, outbound TLS for the console through rustls, console storage, and trusted JA4 fingerprints from the ingress.
