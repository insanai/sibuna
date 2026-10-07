#import "theme.typ": *

#heading(numbering: none)[Glossary]

#set par(justify: false, spacing: 0.5em)
#let term(name, body) = [*#name.* #body #v(1pt)]

#term([Admission], [The decision to forward a request to the origin. In Sibuna it is made by a
  valid session, an `ALLOW` rule, a static bypass path, or a reputation `allow` prefix, and it
  never overrides a WAF denial.])
#term([Aho–Corasick automaton], [A finite automaton that finds any of a fixed set of patterns in
  one pass over the input. Sibuna folds failure links into a dense transition table so each byte
  costs one table load.])
#term([Ban table], [4,096 lock-free slots of banned client addresses with expiry, written by the
  honeypot and by replicated reputation, read on every request.])
#term([Campaign], [A heuristic group of similar incidents. A new payload joins a campaign
  when its vector is within cosine distance 0.35 of the nearest recorded incident.
  Grouping does not establish a common attacker.])
#term([Candidate], [A prepared rule package and its settings. Verification and review precede
  a separate selection; preparing a candidate leaves live protection unchanged.])
#term([Challenge record], [The 70-character stateless identifier a client must solve: version,
  algorithm, difficulty, openings, issue time, client fingerprint, PRF nonce, rule hash, and a
  16-byte keyed BLAKE3 tag. Verification needs no stored challenge record. Issuance can
  still update counters and optional telemetry.])
#term([Core Rule Set (CRS)], [OWASP's application-security rules. Sibuna verifies a signed
  release, compiles it natively and evaluates it within configured input and work bounds.])
#term([Coverage], [The parts of an exchange that inspection observed. Complete, incomplete,
  headers-only, local-response, handshake and excluded-stream states describe different
  limits; missing coverage does not establish an absence of attacks.])
#term([Difficulty, work bits], [The single integer that scales both tiers: the number of leading
  zero bits for Hashcash, or three more than the tree depth for sequential work.])
#term([Edge], [A Sibuna deployment with `--data-dir`, and optionally `-Dcluster` replication,
  giving persistent policies, replicated reputation, and incident forensics to either surface.])
#term([Engine slot], [One of two policy-engine instances with a reader count. Workers pin a slot
  while classifying; the storage thread rebuilds the other and publishes it by pointer swap.])
#term([Fingerprint], [A keyed hash of client address and User-Agent, included in challenges
  and tokens. A different address or User-Agent fails the binding. Clients sharing both,
  such as browsers behind one NAT, can share a fingerprint.])
#term([Forward auth], [Deployment mode in which an ingress asks Sibuna whether to admit a request
  (`200`) or challenge, deny, or limit it (`401`, `403`, `429`), and proxies the origin itself.])
#term([Gate], [Proof-of-work admission, sessions, rules, reputation, GCRA limits and bans
  (`--gate`). It disables the lightweight inspector. Native CRS is configured separately.])
#term([GCRA], [The Generic Cell Rate Algorithm: one theoretical arrival time per client that
  admits a burst of $N$ then one request per emission interval, with no window boundaries.])
#term([Hashcash], [Tier One: find a nonce such that SHA-256 of the challenge, a colon, and the
  decimal nonce has $b$ leading zero bits. Expected $2^b$ trials, verified with one hash.])
#term([Honeypot], [An invisible link to `/__sibuna/honeypot`; a client that follows it is banned
  and an incident with reputation $-100$ is recorded.])
#term([Idle reaper], [A thread that closes connections after their idle deadline.
  `--idle-timeout` bounds HTTP silence; uploads also have a minimum progress rate.])
#term([Interstitial], [The embedded HTML page served in place of a protected page; it fetches a
  challenge, solves it in a Web Worker, posts the solution, and reloads.])
#term([Keyed BLAKE3], [The pseudorandom function behind Sibuna's key schedule, challenge tags,
  session tags, fingerprints, and challenge nonces.])
#term([MAC token], [The default session cookie: a 40-byte payload (version, work level,
  timestamp, expiry, rule hash, fingerprint) and a 16-byte keyed BLAKE3 tag, verified in
  constant time.])
#term([Opening], [In a sequential-work proof, one leaf label plus the sibling labels along its
  path to the root; the verifier recomputes the path and compares with the commitment.])
#term([Paranoia level], [A CRS setting that enables additional rules at higher levels.
  Blocking and detection levels are separate. Higher levels can add work and findings;
  review their effect on the application before enforcing them.])
#term([Proof of Sequential Work (PoSW)], [Tier Two: a proof built from the Cohen–Pietrzak
  dependent hash graph. Under the construction's assumptions, the stated work bound is
  $2^(n+1)-1$ sequential hashes, with verification using $t(n+1)$ hashes. Part III explains
  the assumptions and the implemented variant.])
#term([Reputation trie], [The 128-bit radix trie holding `allow`, `deny`, and `challenge` prefixes
  from the policy file and from the replicated `ip_reputation` table.])
#term([Resident memory (RSS)], [Memory pages currently resident for a process. Summing RSS
  across several processes can count shared pages more than once.])
#term([Robin Hood spent set], [The fixed-capacity open-addressed table of solved challenge tags,
  which prevents a valid solution from being submitted twice.])
#term([Rule hash], [A 64-bit hash of the rule name that demanded a challenge, carried in the
  challenge, the token, and the `X-Sibuna-Rule-Hash` header.])
#term([Shield], [The default surface: Gate plus the semantic firewall (`--shield`).])
#term([SID], [A Shibuna Discussion record: a paper-style design document under `docs/sid/records`
  with the assumptions, proofs, and measurements behind one part of the system.])
#term([Surface], [One of the two product shapes, Gate or Shield; storage and clustering are
  options for either.])
#term([WEIGH], [A rule action that adds a signed weight to a request's score instead of deciding;
  totals at or above the thresholds challenge with extra work bits or deny.])
#term([Work level], [The mechanism and work bits a session's holder actually solved, carried in
  the token; a route admits a session only when its level reaches the route's requirement.])
#term([Zaxonlite], [The SQLite storage and Multi-Paxos replication library behind
  `--data-dir` and cluster mode. `build.zig.zon` pins its release; `vendor/` contains the
  reviewed compatibility sources.])

#pagebreak()
#heading(numbering: none)[Bibliography]

#set par(justify: false, spacing: 0.55em, hanging-indent: 1.2em)
#set text(size: 9.5pt)

Aho, A. V., and Corasick, M. J. "Efficient string matching: an aid to bibliographic search."
_Communications of the ACM_ 18(6), 1975.

ATM Forum. _Traffic Management Specification Version 4.0_, af-tm-0056.000, 1996 (the Generic
Cell Rate Algorithm).

Back, A. "Hashcash: a denial of service counter-measure." Technical report, 2002.

Blocki, J., Lee, S., and Zhou, S. "On the security of proofs of sequential work in a
post-quantum world." _Information-Theoretic Cryptography (ITC)_, 2021.

Celis, P. _Robin Hood Hashing_. PhD thesis, University of Waterloo, 1986.

Cohen, B., and Pietrzak, K. "Simple proofs of sequential work." _EUROCRYPT_, 2018.

Dwork, C., and Naor, M. "Pricing via processing or combatting junk mail." _CRYPTO_, 1992.

Fiat, A., and Shamir, A. "How to prove yourself: practical solutions to identification and
signature problems." _CRYPTO_, 1986.

Fielding, R., Nottingham, M., and Reschke, J. _HTTP Semantics_, RFC 9110, and _HTTP/1.1_,
RFC 9112. IETF, 2022.

Hanson, N. "libinjection: SQL injection detection by tokenization." Black Hat USA, 2012.

Juels, A., and Brainard, J. "Client puzzles: a cryptographic countermeasure against connection
depletion attacks." _NDSS_, 1999.

Lamport, L. "The part-time parliament." _ACM Transactions on Computer Systems_ 16(2), 1998;
and "Paxos made simple." _ACM SIGACT News_ 32(4), 2001.

Mahmoody, M., Moran, T., and Vadhan, S. "Publicly verifiable proofs of sequential work."
_Innovations in Theoretical Computer Science (ITCS)_, 2013.

O'Connor, J., Aumasson, J.-P., Neves, S., and Wilcox-O'Hearn, Z. _BLAKE3: one function, fast
everywhere_. Specification, 2020.

Vyukov, D. "Bounded MPMC queue." 1024cores.net, 2011 (the sequence-stamped ring used for the
incident queue).

Wang, X., Hong, Y., Chang, H., Park, K., Langdale, G., Hu, J., and Zhu, H. "Hyperscan: a fast
multi-pattern regex matcher for modern CPUs." _NSDI_, 2019.

Sibuna Shibuna Discussions 0001–0010, `docs/sid/records`, 2026: process, foundation
architecture, policy, inspection, storage, mathematical foundations, the console, AI-bot
identification, chunked request bodies and native CRS evaluation. The registry identifies each record's status.
