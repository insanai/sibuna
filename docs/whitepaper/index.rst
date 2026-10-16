Sibuna: Architecture, Algorithms, and Empirical Foundations of Work-Bound Web Defense
=====================================================================================

.. only:: html

   **Vikrant Rathore**, with assistance from Ronak Rathore and Kanak Rathore. Insan AI. Whitepaper, October 2026, for Sibuna 1.0.0-beta.2.

.. topic:: Abstract

   Web application firewalls and edge defenses tend to suffer from three architectural problems. The first is *cost inversion*: a sender spends almost nothing to emit a request, while the defender parses it, scans it with regular expressions that may backtrack, and asks an external store about it. The second is *runtime unpredictability*: heap allocation on the request path, garbage-collection pauses, and deployments of several containers make the tail of the latency distribution hard to bound. The third is *operational weight*: shared state for bans, tokens and limits often lives in services that the operator must run beside the firewall. **Sibuna** is our attempt to address these problems with a small number of plain mechanisms in one self-contained binary, and this paper explains the reasoning behind each. (i) *Work-bound admission*: a browser earns a session by solving a Hashcash puzzle or a Cohen-Pietrzak proof of sequential work, chosen per rule, and the server verifies the answer in 70.2 ns or 22.3 us against a challenge it never stored. (ii) *A bounded, allocation-free request path*: a byte-class Aho-Corasick automaton matches 40 bot signatures in 55.7 ns, 13.7 times faster than sequential search; a GCRA limiter decides in 6.2 ns with 16 bytes of state per client; and a Robin Hood spent set records a solution in 21.0 ns. Inspection for SQL injection, cross-site scripting, command injection and path traversal runs in the same pass, in time linear in the input. (iii) *Shared state without a consensus protocol of our own*: an embedded SQLite file serves one node and one shared PostgreSQL database serves a cluster, read by one storage thread that requests never wait on. On one AMD Ryzen 9 5950X, with the daemon on four CPUs, Sibuna answers about 200,000 forward-auth requests per second (197,532 to 211,636 across the workloads) with a p99 of 305 to 327 us, keeps its p99.9 at 62 us under an open-loop load of 100,000 requests per second, and peaks at about 16 MiB of resident memory. We report how each number was obtained, and we list what we have not measured.

.. only:: pdf

   .. raw:: typst

      #wp-metrics(
        source: [Sibuna on one AMD Ryzen 9 5950X core, or four CPUs for the daemon, 15 October 2026: benchmarks/results/primitives-latest.md and product-latest.md; the evaluation section gives the method.],
        ("6.2 ns", "GCRA RATE CHECK", "hashed client | 16 shards"),
        ("55.7 ns", "BOT MATCHER", "Aho-Corasick | 40 signatures"),
        ([22.3 #(sym.mu)s], "PoSW VERIFICATION", "depth 13 | 16 openings"),
        ("16 MiB", "PEAK DAEMON RSS", "under wrk load | 4 CPUs"),
      )

.. only:: html

   Four figures of Sibuna on an AMD Ryzen 9 5950X, 15 October 2026 (``benchmarks/results/primitives-latest.md`` and ``product-latest.md``; the evaluation section gives the method):

   - **6.2 ns**: a GCRA rate check on a hashed client, 16 shards.
   - **55.7 ns**: the bot matcher, Aho-Corasick over 40 signatures.
   - **22.3 us**: verification of a proof of sequential work, depth 13 with 16 openings.
   - **16 MiB**: peak daemon resident memory under ``wrk`` load, on four CPUs.

Prologue: The Economics of a Request
------------------------------------

Every request that reaches a server makes a claim on its attention. A method, a path and some headers do not establish that serving the request is worthwhile. A defense therefore places a decision between the request and the origin: admit it, refuse it, or ask the sender to do verifiable work first. This paper follows that decision from its mathematics to the bytes in memory, in Sibuna.

.. admonition:: Feynman on Physical Intuition: Who Pays for the Work?

   Think of a turnstile that spins at the lightest tap. Behind it sits a guard who, for every tap, must stand up, check three ledgers and telephone the head office. A child outside can tap the turnstile all afternoon without effort, while the guard is worn out before lunch. That is the arrangement of many firewalls: the cheap side is the attacker's. Physics suggests a better arrangement. Connect the turnstile to a pump, so that whoever wants to pass must lift a bucket of water into a tank above the gate. Lifting takes a little honest effort; the guard only glances at the tank to see that the water rose. Glancing costs the guard almost nothing, and lifting costs the visitor something real. The commuter lifts once and walks through all day; the prankster soon goes home.

The voice boxes in this paper are our own words, written in the spirit of Richard Feynman, Donald Knuth and Leslie Lamport, whose way of explaining things we try to follow. They are not quotations, except where a box names its source.

An automated sender pays very little for each request it emits. When a request reaches a conventional firewall, the defender may complete a TLS handshake, allocate memory to copy and split the request, run a list of regular expressions over it, and make a network round trip to a shared store to update a counter. We do not attach a universal ratio to this asymmetry, because none exists: it depends on the origin, the cache and the attack. A simple model makes the decision visible instead. Let :math:`c_o` be the origin's work per admitted request, :math:`c_g` the gate's work per request, and :math:`a` the fraction of requests the gate admits. The gate pays for itself only when

.. math::

   c_g < (1 - a)\, c_o,

that is, when the work it saves the origin exceeds its own cost [#cost-model]_. Two consequences follow. The gate's own cost :math:`c_g` must be small and bounded whatever the input, and the decision to admit must be expensive for the sender rather than for the server.

Sibuna reverses the asymmetry by conditioning admission on a proof of work. To earn a session, a browser finds a nonce whose SHA-256 digest has :math:`b` leading zero bits, or computes a proof of sequential work. The expected search is :math:`2^b` hash trials, 65,536 at :math:`b = 16`; the server checks one candidate. The server's check is also stateless: issuing a challenge writes nothing, and only a solution that was paid for occupies memory.

.. graphviz::
   :caption: Where the work goes. Above, a defense that inspects first spends its own work on every request a sender emits. Below, Sibuna asks the sender for :math:`2^b` expected hash trials and verifies the answer with one hash. The trial counts are a model; the verification time is measured (Hashcash verification at 16 bits, ``benchmarks/results/primitives-latest.md``).
   :alt: Two rows. In the first, a sender emits one cheap request to a defense that parses, scans with regular expressions and queries a shared store for every request. In the second, the sender solves a puzzle of 2 to the b expected hash trials, 65,536 at b equal to 16, and Sibuna verifies one hash in 70.2 ns, keeps no state for unsolved challenges, and reuses the session afterwards.

   digraph cost {
     graph [rankdir=LR, bgcolor="transparent", nodesep=0.35, ranksep=0.6, fontname="Helvetica", fontsize=10];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=9.5, color="#64748b", fillcolor="#ffffff", fontcolor="#0f172a"];
     edge [fontname="Helvetica", fontsize=9, color="#64748b", fontcolor="#334155"];
     subgraph cluster_work {
       label="Work first (Sibuna)"; style="rounded,filled"; fillcolor="#ecfdf5"; color="#86efac"; fontcolor="#047857";
       s2 [label=<Sender<BR/>solves a puzzle:<BR/>2<SUP>b</SUP> expected SHA-256 trials<BR/>(65,536 at b = 16)>, color="#b45309"];
       d2 [label="Sibuna\nverifies one hash: 70.2 ns\nno state until solved\nsession reused afterwards", color="#047857"];
       s2 -> d2 [label="costly to earn,\ncheap to check", color="#047857", fontcolor="#047857"];
     }
     subgraph cluster_inspect {
       label="Inspect first"; style="rounded,filled"; fillcolor="#fef2f2"; color="#fca5a5"; fontcolor="#b91c1c";
       s1 [label="Sender\none cheap request", color="#b91c1c"];
       d1 [label="Defense\nparse and copy, regex scan,\nshared-store round trip\non every request", color="#b91c1c"];
       s1 -> d1 [label="cheap to send,\ncostly to answer", color="#b91c1c", fontcolor="#b91c1c"];
     }
   }
   }

A proof of work does not establish humanity, identity or intent. A sender can rent computers, share a session within its lifetime, or spread work across machines. The puzzle changes the price of admission; policy and inspection still decide what an admitted request may do.

Design Overview: Three Decisions in One Pass
--------------------------------------------

Sibuna keeps admission, inspection and reputation as three separate decisions, and it takes them in one pass over a request, in one process, before the origin does any work. It offers them as two product surfaces. *Gate* provides proof-of-work admission with rules, CIDR reputation and local flood controls. *Shield*, the default, adds bounded inspection of the request payload. Either surface runs as a reverse proxy in front of an origin or as a forward-auth endpoint that an ingress such as Caddy or Nginx consults. Persistent storage of policy, reputation and incident history is an option for either: local to one node, or shared by a cluster [#surfaces]_.

.. list-table:: The two product surfaces (SID 0002; book Part II)
   :header-rows: 1
   :widths: 20 40 40

   * - Capability
     - Gate (``--gate``)
     - Shield (``--shield``, default)
   * - Admission
     - Hashcash or sequential-work browser challenge; a session token bound to the client and to the work it paid
     - Same
   * - Policy
     - Declarative rules (path, User-Agent, headers, IPv4 and IPv6 CIDR, a JA4 TLS fingerprint from a trusted ingress) with ALLOW, DENY, CHALLENGE and WEIGH; bot signatures; reputation
     - Same
   * - Flood controls
     - GCRA rate limits, honeypot, temporary bans
     - Same
   * - Payload inspection
     - Disabled
     - SQL injection, cross-site scripting, command injection and path traversal, over the first 8 KiB of the body
   * - Optional state
     - Policy and reputation in SQLite, or shared through PostgreSQL
     - Also incident forensics: full-text search and campaign clustering

The Design Choices
~~~~~~~~~~~~~~~~~~

Most of the ideas below come from the research literature or from earlier systems, and the book's Part II traces their lineage. What we have tried to do is to combine them in one bounded request path, to keep each step cheap, and to measure the result honestly. We list the choices with the reason for each.

1. *Challenges that cost the server nothing to issue.* A challenge is a self-authenticating record sealed with a keyed hash, so issuing one writes no state; only a solution that was paid for occupies memory, and it leaves when the challenge expires (:ref:`algorithms`).
2. *Two tiers of work, chosen per rule.* Next to Hashcash, Sibuna offers the Cohen-Pietrzak proof of sequential work, whose soundness has been proved even against quantum provers, and whose proof verifies in microseconds. A checkout route may demand 20 work bits of sequential work while a blog demands 16 bits of Hashcash (:ref:`proofs-of-work`).
3. *Sessions that remember the work paid.* A session token records the mechanism and the work bits its holder solved. It admits only routes that demand no more, so a cheap session cannot open an expensive route.
4. *Symmetric tokens.* Sessions are sealed with keyed BLAKE3, which verifies in 155.8 ns, about 260 times less work than an Ed25519 signature, and against which quantum search gives only a quadratic speedup.
5. *Inspection that a session cannot bypass.* Admission and inspection run in the same pass, and a valid session satisfies only a challenge: a request with a session and ``q=' OR 1=1--`` is still refused.
6. *Linear-time, structure-aware inspection.* One byte-class scan, one automaton pass and small structural tokenizers decide in time linear in the input, without regular expressions that could backtrack.
7. *Bounded state with keyed placement.* Every table has a fixed capacity and a stated behaviour when it is full, and keys are placed by a keyed hash, so an attacker cannot aim collisions at a victim (:ref:`keyed-hashing`).
8. *No allocation per request, and policy updates without pauses.* A connection serves every decision from one fixed buffer, and a new policy engine is published without any request or writer waiting (:ref:`mechanical-sympathy`).
9. *Difficulty that follows the load.* Above a baseline of 50 verified solutions per second, each doubling of the rate adds one work bit, up to six, so a flood pays exponentially more while quiet traffic keeps the base cost.
10. *Campaigns from incidents.* Denied requests are recorded with a small embedding, and similar incidents are grouped into campaigns that an operator can investigate from the console.

.. _mechanical-sympathy:

Mechanical Sympathy: Zero Allocation and Bounded State
-------------------------------------------------------

.. admonition:: Knuth on Mechanical Precision: Cache Lines and Concrete Mathematics

   A programmer who calls a general-purpose allocator inside the inner loop of a real-time system has handed part of the design to a stranger. The allocator may be fast on average, but its cost depends on the history of the heap, and that history is written by whoever sends the requests. Before we optimise anything we should count: how many bytes each step touches, how many cache lines, how many dependent loads. Then we should measure, because counting can be wrong too. A program is elegant when every byte it needs has a known home before the first socket is opened, and when each loop does exactly the work its mathematics requires.

The Zero-Allocation Invariant
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every dynamic allocation on a request path is a lever for denial of service: fragmentation over days, contention on the allocator's locks, and amplification by requests crafted to allocate. Sibuna's rule is that classification, verification and the proxy hand-off run without heap allocation. A connection owns a 64 KiB read buffer and a 16 KiB write buffer for the life of its socket, and a 40 KiB proxy workspace allocated once when the connection starts. Everything else is a slice into them: the parser locates the method, path, query, headers and cookies of a request inside the read buffer and copies none of them [#zero-alloc]_. The implementation's type system enforces that a parsed request cannot outlive the bytes it describes, so the buffer cannot be refilled while a request still reads it.

The rule is a contract of the request path, not a claim about the whole process. Thread creation, startup and storage allocate. The contract is checked by tests that count allocations: the daemon's steady-state test counts its allocations, and the proxy's finds none over 500 proxied keep-alive requests [#steady-state]_.

Bounded Threads, Reused
~~~~~~~~~~~~~~~~~~~~~~~

Each accepted connection is served on a thread of its own, so a slow client delays only itself, and the request path stays synchronous. We considered an event loop and kept the thread model: the speed of the request path comes from a zero-copy parser, a fixed per-connection buffer and allocation-free decisions, none of which an event loop improves [#threads]_. The number of connection threads is bounded by ``--max-connections`` (1,024 by default); beyond it the accept loop answers ``503`` without spawning anything. One socket peer address may hold at most 64 connections by default, and an IPv6 peer is counted with its /64 network.

Threads come from a fixed table of joinable slots. A finished thread keeps its stack until it is joined, so a new task joins and takes the *lowest* finished slot rather than advancing a cursor; resident memory then follows the connections open, not the connections served. A thread that finishes its connection parks and takes the next one. The section :ref:`what-measurement-changed` tells how a measurement taught us to add that last rule.

The Request Pipeline
~~~~~~~~~~~~~~~~~~~~

A request passes the checks below in a fixed order. The cheap checks come first, and each decision that ends the request does so before any more expensive stage runs.

.. graphviz::
   :caption: The request pipeline, with the median time of each primitive on one core where the primitive suite measures it (``benchmarks/results/primitives-latest.md``). Stages run in the numbered order; dashed arrows show early refusals (the GCRA limiter and the reputation trie refuse in the same way). The whole classification of a browser request takes 75.9 ns in the Gate profile and 790.8 ns in the Shield profile.
   :alt: A pipeline. Accept and read into the 64 KiB buffer, then the zero-copy parse (132.5 ns), the ban table, the internal routes for challenges and verification, the GCRA limiter (6.2 ns), then the policy snapshot: Shield inspection of an 8 KiB body (12.8 us), the reputation trie (IPv4 32.0 ns), ordered rules and WEIGH scores, and the bot automaton (55.7 ns). A challenge decision checks the session token (155.8 ns); with a valid session the request is admitted, without one the interstitial is served. Admitted requests are proxied to the origin through the pool or answered with a forward-auth verdict. Banned, rate-limited and denied requests end early.

   digraph pipeline {
     graph [rankdir=TB, bgcolor="transparent", nodesep=0.28, ranksep=0.5, fontname="Helvetica", fontsize=9, newrank=true];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=8.5, color="#0369a1", fillcolor="#f0f9ff", fontcolor="#0f172a", width=1.25, height=0.5];
     edge [color="#64748b", fontname="Helvetica", fontsize=7.5, fontcolor="#334155", arrowsize=0.6];
     accept [label="Accept, read head\ninto 64 KiB buffer", color="#0f172a", fillcolor="#ffffff"];
     parse [label="1. Zero-copy parse\n132.5 ns"];
     ban [label="2. Ban table\nlock-free readers"];
     routes [label="3. Internal routes\nchallenge, verify"];
     gcra [label="4. GCRA limiter\n6.2 ns"];
     waf [label="5. Shield inspection\n8 KiB body: 12.8 us", color="#6d28d9", fillcolor="#f5f3ff"];
     trie [label="6. Reputation trie\nIPv4: 32.0 ns", color="#6d28d9", fillcolor="#f5f3ff"];
     rules [label="7. Ordered rules\nWEIGH scores", color="#6d28d9", fillcolor="#f5f3ff"];
     bots [label="8. Bot automaton\n55.7 ns", color="#6d28d9", fillcolor="#f5f3ff"];
     session [label="9. Session token\nkeyed BLAKE3: 155.8 ns", color="#b45309", fillcolor="#fffbeb"];
     refuse [label="Refuse\n403, 429 or a ban", color="#b91c1c", fillcolor="#fef2f2"];
     challenge [label="Challenge\ninterstitial (200)\nor JSON (401)", color="#b45309", fillcolor="#fffbeb"];
     admit [label="Admit\nproxy via the origin pool,\nor a forward-auth verdict", color="#047857", fillcolor="#ecfdf5"];
     { rank=same; accept; parse; ban; routes; gcra; }
     { rank=same; bots; rules; trie; waf; }
     { rank=same; refuse; session; challenge; admit; }
     accept -> parse -> ban -> routes -> gcra;
     gcra -> waf [label=" pass"];
     bots -> rules [dir=back]; rules -> trie [dir=back]; trie -> waf [dir=back];
     bots -> session [label=" challenge"];
     bots -> admit [label=" allow"];
     session -> admit [label=" enough work"];
     challenge -> session [dir=back, label=" none or\n too little"];
     ban -> refuse [style=dashed, color="#b91c1c", constraint=false];
     waf -> refuse [style=dashed, color="#b91c1c", constraint=false, label="waf:*", fontcolor="#b91c1c"];
     rules -> refuse [style=dashed, color="#b91c1c", constraint=false];
     refuse -> challenge [style=invis];
   }

A valid session satisfies a challenge; it never overrides a denial or a WAF finding. The proxy, in turn, reads the origin's response head, classifies its framing (no body, a length, chunked coding, or until close), relays the body exactly, and returns origin sockets left at a clean boundary to a striped pool of 256, so a proxied client connection stays open and the origin is not reconnected for every request.

Publishing Policy Without Stopping Requests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The policy engine is rebuilt off the request path when policies change, and requests must never see a half-built engine. The storage thread builds a complete engine and publishes it, reference counted, in a slot with a generation counter. Each connection keeps a cache: it loads the generation with one acquire load, and it takes a new reference only after a publication. An old engine is freed when the last cache that holds it lets go, and no writer ever waits for readers to drain. Under contention the cached read is more than 400 times cheaper than taking a read-write lock. The engine itself holds about 200 KiB of compact tables (209,052 bytes), with capacity for 128 rules and 8,192 trie nodes.

.. list-table:: The cost of one engine read with 1 and 16 threads reading in a loop, on a Ryzen 9 5950X (book Part V, October 2026)
   :header-rows: 1
   :widths: 50 25 25

   * - Reader
     - 1 thread
     - 16 threads
   * - Read-write lock, read guard only
     - 4.2 ns
     - 752 ns
   * - Read-write lock and a new reference
     - 7.6 ns
     - 833 ns
   * - Generation check with a cached reference
     - 0.8 ns
     - 1.8 ns

Locks in Shards
~~~~~~~~~~~~~~~

The tables that connection threads share (the spent set, the limiter, the ban table) are split into 16 shards by a hash of the key, and each shard sits on a cache line of its own. Their critical sections are tens of instructions long, so we measured a spin lock against an adaptive mutex, which spins briefly and then sleeps. A spin lock saves about a nanosecond when nobody contends, but an edge server runs more threads than CPUs, and a spin lock whose holder is preempted makes every waiter burn its time slice. The mutex won under contention, so we kept it.

.. list-table:: Shard lock throughput in millions of operations per second on a Ryzen 9 5950X (book Part V; SID 0010)
   :header-rows: 1
   :widths: 52 24 24

   * - Workload
     - Adaptive mutex
     - Spin lock
   * - Spent set, 16 threads
     - 10.8
     - 8.6
   * - Spent set, 64 threads
     - 11.2
     - 6.9
   * - GCRA on six hot addresses, 16 threads
     - 44.9
     - 19.3
   * - GCRA on six hot addresses, 64 threads
     - 37.4
     - 6.5

.. _algorithms:

Algorithms and Their Guarantees
-------------------------------

Each primitive on the request path has a statement of what it costs and what it guarantees. We give three of them as theorems, with the argument in brief; SID 0006 and Parts III to VI of the Sibuna book give the full proofs, the definitions and the references.

.. admonition:: Theorem 1 (Linear-time inspection with a byte-class Aho-Corasick automaton)

   Let :math:`\mathcal{P}` be a set of patterns of total length :math:`m` whose bytes fall into :math:`c \le 256` classes, and let a text have length :math:`M`. Sibuna builds the automaton in :math:`O(mc)` time and space and reports whether any pattern occurs in the text in :math:`O(M)` time, with one dependent table load per input byte, independent of the number of patterns. No input can make it backtrack.

   *Proof sketch.* The automaton of Aho and Corasick scans a text once after building a trie with failure links. Sibuna folds the failure links into the transition table at build time, so each input byte is one transition and no failure chain is ever followed. A byte class is a byte that occurs in some pattern, with both cases of a letter in one class, or the single class of all other bytes; a row of the table therefore has :math:`c` entries instead of 256. Match states are numbered after all other states, so detecting a match is one comparison.

   *Measurement.* On 40 bot signatures the automaton takes 55.7 ns against 763.0 ns for sequential substring search with the same patterns and any-match semantics, 13.7 times faster. With byte classes the whole bot signature table takes 42,244 bytes [#automaton]_.

.. admonition:: Theorem 2 (The GCRA interval bound)

   Fix a limit of :math:`N` requests per window :math:`W`, with emission interval :math:`T = \max(1, \lceil W/N \rceil)` and burst tolerance :math:`\tau = (N-1)T`. A client keeps one theoretical arrival time :math:`\mathrm{TAT}`. An arrival at time :math:`t` conforms if and only if :math:`\mathrm{TAT} \le t + \tau`, after which :math:`\mathrm{TAT} \leftarrow \max(\mathrm{TAT}, t) + T`. Then any interval of length :math:`L` that begins with a conforming arrival contains at most :math:`N + \lfloor L/T \rfloor` conforming arrivals.

   *Proof sketch.* Number the conforming arrivals :math:`1, \dots, k` at times :math:`t_1 \le \dots \le t_k`. Each conforming arrival raises the TAT by at least :math:`T`, so after the :math:`j`-th one :math:`\mathrm{TAT}_j \ge t_1 + jT`. Arrival :math:`k` conformed, so :math:`\mathrm{TAT}_{k-1} \le t_k + \tau \le t_1 + L + \tau`. Together these give :math:`(k-1)T \le L + (N-1)T`, so :math:`k \le N + L/T`, and :math:`k` is a whole number.

   *Implementation.* The state of a client is one 16-byte cell, with no per-request history and no fixed-window boundary effect. The 16 shards share ``--rate-table-cells`` cells (262,144 by default, 4 MiB), placed by a keyed hash, and a drained cell is reclaimed in place without a sweeper. A check on a client whose hash the daemon has already computed takes 6.2 ns [#gcra]_.

.. admonition:: Theorem 3 (State grows only with paid work)

   Let :math:`S` be the set of challenge tags the daemon remembers. A tag enters :math:`S` only after a valid proof for its challenge was accepted, and it leaves when the challenge expires. If :math:`r` bounds the rate of accepted distinct solutions over one challenge lifetime, then :math:`|S| \le r \cdot \mathrm{TTL}`. A challenge that was fetched but not solved occupies no memory.

   *Proof sketch.* A challenge identifier is a self-authenticating record: version, algorithm, difficulty, opening count, issue time, the client's keyed fingerprint, a nonce derived by a pseudorandom function, and the hash of the rule that demanded it, 36 bytes followed by a 16-byte keyed-BLAKE3 tag, 70 characters in URL-safe base64. Issuing one writes nothing. Verification checks the tag in constant time, then the age and the client binding, then the proof, and only then inserts the tag into the spent set. With BLAKE3 in keyed mode modelled as a pseudorandom function, an adversary making :math:`q` verification queries forges a tag with probability at most :math:`q \cdot 2^{-128}` plus the PRF advantage.

   *Implementation.* The spent set is 16 shards of Robin Hood open addressing. An expired entry may be overwritten in place only by a key at least as far from its home slot, or a later lookup could stop early and miss a live tag; with that rule no sweeper thread is needed, and a refused insertion never evicts a live tag. A spend and a lookup together take 21.0 ns [#spent]_.

The Semantic Firewall
~~~~~~~~~~~~~~~~~~~~~

Shield inspects the path, the query, the User-Agent, the headers that are not structural, and the first 8 KiB of the body. Its first version taught us a lesson. It matched a flat list of substrings against every header, the list contained ``/*``, and every browser sends ``Accept: text/html,...,*/*;q=0.8``. Every real browser was classified as SQL injection. Since then a detector may fire only on *structure*, and a test passes a complete Chrome request through the engine and requires it to come out clean [#waf]_.

Inspection has four stages, each linear in the field.

1. *A byte-class pre-scan.* One pass with a 256-entry table records which classes of byte occur: quotes, ``=``, ``<``, shell separators, ``%``, NUL and the triggers of canonicalisation. Every later detector consults these classes instead of rescanning, so a field without a quote or an equals sign never enters the SQL tokenizer.
2. *A tagged signature automaton.* All strong signatures of every category live in one automaton (Theorem 1). A hit is a terminal denial named ``waf:sqli``, ``waf:xss``, ``waf:path-traversal`` or ``waf:rce``.
3. *Structural tokenizers.* The SQL tokenizer looks up each short word in a keyword table and checks ``literal = literal`` tautologies after ``or`` and ``and``; otherwise a quote is mandatory and the evidence must reach a small score. The phrase "it's a group order from the shop" scores 3 and passes. Cross-site scripting requires a tag that can host script together with an event-handler attribute in attribute position, and command injection requires a separator followed by a command name that is not an assignment, so ``a=1&id=5`` is a parameter, not a command.
4. *Canonicalisation.* A field with percent escapes, comment openers, JSON or HTML escapes, or collapsible white space is decoded and inspected again, so ``1%27/**/UnIoN/**/SeLeCt`` and ``%252e%252e/`` collapse onto the raw signatures.

An 8 KiB body scans in 12,784.3 ns, about 1.56 ns per byte. An operator may audit a category rather than enforce it, so that its findings are logged but not acted on. A field must then be judged per category, so that an audited finding cannot hide an enforced one. Rather than scanning the field once per category, Sibuna scans it once for the set of categories whose signatures occur, and then searches only the wanted categories among them; the same 8 KiB body with SQL injection audited takes 15,485.4 ns [#waf-cost]_. Shield remains a bounded heuristic inspector, not a full SQL or HTML parser, and bytes beyond the inspection bound are not inspected.

TLS Fingerprints From the Ingress
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A User-Agent is a string that any client may write as it likes. A JA4 fingerprint is harder to forge. It summarises how a client opens a TLS connection: protocol, version, cipher suites, extensions and the first ALPN value. The client's TLS library fixes these before the first HTTP byte is sent. Only the component that terminates TLS sees the handshake, so only it can compute JA4. Sibuna terminates no inbound TLS, so it does not compute JA4. It reads the fingerprint that a trusted ingress computed and forwarded in a request header, named with ``--ja4-header`` [#ja4]_.

- *Trust.* The header is read only when forwarded headers are trusted, by the decision that governs ``X-Forwarded-For``. From an untrusted peer it is ignored, and in reverse-proxy mode every copy of it is removed before the request reaches the origin.
- *Validation.* A value is accepted only in the 36-byte JA4 form, and only when exactly one field of that name is present. A malformed or repeated value is treated as absent and counted.
- *Policy.* A rule matches a whole fingerprint, or a prefix followed by ``*``; a request without a fingerprint never matches such a rule. Matching is a byte comparison, and the warm request path still makes no heap allocation.
- *Records.* Incidents store the fingerprint of their request, and the console shows it in the incident evidence and filters events by it. Bans and reputation stay keyed by address, because many legitimate clients share one TLS library.

.. _keyed-hashing:

Keyed Hashing and the Security Review
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An adversarial review of the request path in October 2026 found weaknesses in mechanisms we had considered settled. We fixed each one and recorded the fix in the design record of the mechanism [#security]_.

- *Predictable table placement.* The limiter and the ban table placed keys with a hash under seeds written in the source, so anyone could compute addresses that share a victim's probe window. Placement now uses SipHash-1-3 under a key drawn from operating-system randomness, and each table derives its own key. The daemon hashes the client once per request (8.7 ns) and passes the hash to every table; the store path of a request fell from 43 to 26 ns.
- *Ban eviction.* A ban in effect is never evicted. When every slot a key may take holds a live ban, the new ban is refused and counted, so a banned client cannot evict its own ban.
- *Forwarded identity.* The leftmost ``X-Forwarded-For`` entry can be written by the client. Sibuna takes the entry ``--trusted-hops`` positions from the right, the one the nearest trusted proxy appended.
- *Cookie tossing.* A request may carry several values of the session cookie; the daemon tries up to eight, so a cookie planted by a sibling domain cannot keep a visitor in a challenge loop.
- *Spent-set capacity.* A table of 65,536 tags was exhausted by about 220 verified solutions per second within a five-minute challenge lifetime, after which honest solutions were refused. The capacity is now configurable, 1,048,576 tags (24 MiB) by default.
- *Adaptive difficulty.* The controller that raises the work under load now counts verified solutions instead of issued challenges, which cost a flooder nothing.

Keyed placement has a price, and we pay it once per request rather than once per table. A limiter check that hashes raw client bytes itself takes 12.8 ns; the check on a hashed client, the path the daemon uses, takes 6.2 ns. Because the limiter and the spent set are allocated zeroed, idle tables are not resident, so their configured capacity costs no memory until it is used.

.. _proofs-of-work:

Proofs of Work: Parallel Search and Sequential Work
---------------------------------------------------

The Hashcash Tier
~~~~~~~~~~~~~~~~~

The first tier is Hashcash at bit granularity. For a challenge string :math:`C` and difficulty :math:`b`, the client finds a nonce :math:`N` such that :math:`\text{SHA-256}(C \parallel \texttt{":"} \parallel \mathrm{dec}(N))` has :math:`b` leading zero bits. The decimal rendering of the nonce keeps the wire format identical between the WebAssembly solver, the JavaScript fallback and the native verifier. For ideal digests the number of trials :math:`K` is geometric with :math:`p = 2^{-b}`:

.. math::

   P(K > k) = (1 - p)^k, \qquad E[K] = 2^b, \qquad \mathrm{median}(K) \approx 2^b \ln 2.

Search has two limits. Its variance is large, so one slow solve is not a broken worker. And independent trials run in parallel, so a sender with more cores finishes sooner, even though the expected total work is the same [#hashcash]_.

The Sequential-Work Tier
~~~~~~~~~~~~~~~~~~~~~~~~

The second tier follows the proof of sequential work of Cohen and Pietrzak (EUROCRYPT 2018). Its labels form a complete binary tree of depth :math:`n`. An internal node hashes its two children. A leaf hashes the *left siblings of its ancestors* wherever its root path turned right. Those left-sibling edges make the computation sequential: a leaf cannot be labelled until every subtree to its left is complete, so the root label depends on all :math:`2^{n+1} - 1` labels in order. After computing the root :math:`\varphi`, the prover derives :math:`t` leaves by Fiat-Shamir and, for each, sends the leaf label and the :math:`n` sibling labels along its path. The verifier recomputes each opened leaf and hashes up to :math:`\varphi`, at a cost of :math:`O(tn)` label computations in a fixed workspace.

.. graphviz::
   :caption: Parallel search against sequential work. Left, Hashcash: independent nonce trials, so :math:`M` cores finish about :math:`M` times sooner. Right, the Cohen-Pietrzak tree at depth 3: the dashed left-sibling edges make leaf 3.5 wait for the subtrees to its left, and an opening of leaf 3.5 sends its label and the three green siblings (after book Part III).
   :alt: Left, four cores each try a disjoint share of the nonces against one target, and any core may find the solution. Right, a binary tree of depth three. The path of leaf 3.5 is amber, the siblings 1.0, 2.3 and 3.4 sent in its opening are green, and dashed red edges run from 1.0 and 3.4 into leaf 3.5.

   digraph pow {
     graph [rankdir=TB, bgcolor="transparent", nodesep=0.18, ranksep=0.35, fontname="Helvetica", fontsize=9, ordering=out];
     node [fontname="Helvetica", fontsize=8.5, fontcolor="#0f172a"];
     edge [color="#64748b", arrowsize=0.5];
     subgraph cluster_hashcash {
       label="Hashcash: parallel search"; style="rounded,filled"; fillcolor="#fef2f2"; color="#fca5a5"; fontcolor="#b91c1c";
       node [shape=box, style="rounded,filled", fillcolor="#ffffff", color="#b91c1c"];
       c1 [label="core 1\nnonces 0, 4, 8"];
       c2 [label="core 2\nnonces 1, 5, 9"];
       c3 [label="core 3\nnonces 2, 6, 10"];
       c4 [label="core 4\nnonces 3, 7, 11"];
       target [label="SHA-256(C : N)\nhas b zero bits?\nany core may win", fillcolor="#fff7ed"];
       c1 -> target; c2 -> target; c3 -> target; c4 -> target;
     }
     subgraph cluster_posw {
       label="Proof of sequential work: forced order"; style="rounded,filled"; fillcolor="#ecfdf5"; color="#86efac"; fontcolor="#047857";
       node [shape=circle, fixedsize=true, width=0.42, style=filled, fillcolor="#ffffff", color="#0369a1"];
       edge [arrowhead=none];
       "0.0" [fillcolor="#fffbeb", color="#b45309", penwidth=1.4, label="root"];
       "1.1" [fillcolor="#fffbeb", color="#b45309", penwidth=1.4];
       "2.2" [fillcolor="#fffbeb", color="#b45309", penwidth=1.4];
       "3.5" [fillcolor="#fffbeb", color="#b45309", penwidth=1.4];
       "1.0" [fillcolor="#ecfdf5", color="#047857", penwidth=1.4];
       "2.3" [fillcolor="#ecfdf5", color="#047857", penwidth=1.4];
       "3.4" [fillcolor="#ecfdf5", color="#047857", penwidth=1.4];
       "0.0" -> "1.0"; "0.0" -> "1.1";
       "1.0" -> "2.0"; "1.0" -> "2.1"; "1.1" -> "2.2"; "1.1" -> "2.3";
       "2.0" -> "3.0"; "2.0" -> "3.1"; "2.1" -> "3.2"; "2.1" -> "3.3";
       "2.2" -> "3.4"; "2.2" -> "3.5"; "2.3" -> "3.6"; "2.3" -> "3.7";
       "3.5" -> "1.0" [style=dashed, color="#b91c1c", dir=back, arrowtail=normal, constraint=false];
       "3.5" -> "3.4" [style=dashed, color="#b91c1c", dir=back, arrowtail=normal, constraint=false];
     }
   }

The parameters are chosen so that the numbers stay small. Work bits map to depth by :math:`n = b - 3`, clamped to :math:`[4, 24]`. A proof has :math:`32(1 + t(n+1))` bytes, which at depth 13 with 16 openings is :math:`32(1 + 16 \times 14) = 7200` bytes. The prover keeps only the top levels of the tree and recomputes the subtree it must open, so its whole workspace, the proof included, stays under 100 KB; a browser tab and the native tests use the same prover [#posw]_. Blocki, Lee and Zhou (ITC 2021) proved the construction sound against quantum provers in the quantum random-oracle model.

We should be careful about what this establishes. The security results hold under the random-oracle assumptions of the papers, for the constructions and bounds they state. They are not an independent audit of our concrete SHA-256 protocol, its parameter mapping or its browser timing. The elementary sampling bound :math:`(1-\alpha)^t`, the chance that :math:`t` independent openings all miss a fixed bad fraction :math:`\alpha`, explains why more openings help; it is not by itself a proof against a prover who grinds many roots. We make no unconditional claim that cheating is never cheaper.

The Round Trip and the Session
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A navigation without a valid session receives the interstitial page, which carries a *requirement ticket*: the challenge this decision demands (algorithm, work bits, openings) and the rule's hash, sealed for this client and valid for one challenge lifetime. The page fetches its challenge with the ticket, so the work is fixed by the decision that demanded it. A Web Worker solves the challenge with the WebAssembly prover, or with a JavaScript fallback where WebAssembly is unavailable, and posts the answer. On success the server sets a session cookie of 75 characters, bound by a keyed fingerprint to the client's address and User-Agent, and the page reloads. The prover in the browser is compiled from the same source as the server's verifier, so the two cannot drift apart [#round-trip]_.

What Verification Costs
~~~~~~~~~~~~~~~~~~~~~~~

Both tiers are bound by SHA-256, and Sibuna selects the processor's SHA instructions at run time where they exist, so one binary is fast on every machine that has them. Hashcash verification at 16 bits takes 70.2 ns, and verifying a depth-13 proof with 16 openings takes 22,272.4 ns. The browser prover is a WebAssembly module of 14,744 bytes. In the end-to-end browser check, headless Chromium solved the interstitial's challenge in 29 to 34 ms with WebAssembly and in 84 to 91 ms with the JavaScript fallback [#verify-cost]_. The primitive suite measures verification only; a native timing does not stand for a browser's solve time.

Sessions use a symmetric token. The verifier is the issuer, or a cluster that shares one seed, so a keyed pseudorandom function supplies exactly the authentication needed. A keyed-BLAKE3 token verifies in 155.8 ns and an Ed25519 token in 40,587.5 ns, so one signature verification costs about as much as 260 MAC verifications. There is a second reason for the choice: Shor's algorithm breaks the discrete logarithms beneath Ed25519, while against a keyed hash quantum search gives at most a quadratic speedup. Ed25519 remains an option for deployments that need verifiers who cannot mint tokens.

Shared State Without a Consensus Protocol of Our Own
----------------------------------------------------

.. admonition:: Lamport on Distributed Invariants: Safety, Liveness, and Who Owns the Log

   In 1987 Leslie Lamport described a distributed system as one in which the failure of a computer you did not even know existed can render your own computer unusable. Read as advice, it asks us to count the computers we depend on, and to state what must hold when any of them fails. Two kinds of statement are enough. *Safety*: nothing bad ever happens, for example a node never acts on a policy that no committed transaction wrote. *Liveness*: something good eventually happens, for example a node that can reach the database eventually serves the latest policy. A consensus protocol is a beautiful way to obtain both. It is also a large thing to own, and the question for a firewall is not whether consensus is good but who should maintain the log.

Why SQL, and Why Not a Consensus Protocol of Our Own
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sibuna stores little: a few hundred policy rows, a reputation table, and forensic incidents that operators also export to other systems. That state does not need a bespoke replicated engine. It needs a reliable SQL store, local for one node and shared for many. A single node therefore keeps its state in an embedded SQLite file in its data directory, in WAL mode, and a cluster points every node at one PostgreSQL database [#zaxonlite]_.

We chose not to run a consensus protocol inside the firewall. A consensus engine is a large system to own beside a firewall, with its own formats and its own failure modes, and it adds work to shutdown and to every upgrade. The availability and replication of a cluster's state are instead PostgreSQL's concern, served by its streaming replication and failover tools or by a managed service. We think this is the humbler choice: PostgreSQL's replication has been exercised by far more deployments than ours could be, and Sibuna's write rate (batched incidents and rare policy changes) is small enough that one primary is not a bottleneck.

Storage also stays optional. Without ``--data-dir`` or ``--database-url`` the daemon is an in-memory firewall whose policies come from a file.

One Storage Thread
~~~~~~~~~~~~~~~~~~

One storage thread owns the database connections; nothing else touches SQL. Request threads never wait on it. They push incident records into a bounded ring of 512 slots, which drops and counts a record when it is full, and they read the published engine. Every 500 ms by default the storage thread runs one tick: it writes up to 32 queued incidents in one transaction, reads the policy revision and, when it changed, rebuilds the engine and publishes it. A rebuild reads the revision before and after loading; if a writer committed in between, the candidate is discarded and the old engine stays live. Operators may write the policy tables directly: triggers advance the revision in the writer's transaction, and under PostgreSQL a ``NOTIFY`` lets nodes tick at once, while polling remains the guarantee [#storage-thread]_.

.. graphviz::
   :caption: A Sibuna cluster. Every node keeps its request path in memory and gives all SQL to one storage thread; the nodes share one PostgreSQL database, whose replication and failover are PostgreSQL's (SID 0011). A single node uses an embedded SQLite file instead.
   :alt: An ingress sends traffic to three Sibuna nodes. In each node, connection threads read a published engine and push incidents into a bounded ring; a storage thread drains the ring, writes batches and rebuilds the engine. All three storage threads connect to one PostgreSQL primary, optionally over TLS with verify-full. The primary replicates to a standby by streaming replication, which the operator runs.

   digraph cluster {
     graph [rankdir=TB, bgcolor="transparent", nodesep=0.3, ranksep=0.4, fontname="Helvetica", fontsize=9, size="6.2,3.6"];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=8.5, color="#0369a1", fillcolor="#f0f9ff", fontcolor="#0f172a"];
     edge [color="#64748b", fontname="Helvetica", fontsize=8, fontcolor="#334155", arrowsize=0.6];
     ingress [label="Ingress (TLS termination)\nCaddy or Nginx", color="#0f172a", fillcolor="#ffffff"];
     subgraph cluster_n1 {
       label="Node 1 (cluster node 1)"; style="rounded"; color="#94a3b8"; fontcolor="#334155";
       r1 [label="connection threads\nread the engine, push incidents"];
       s1 [label="storage thread\nbatches, rebuilds", fillcolor="#fffbeb", color="#b45309"];
       r1 -> s1 [label=" ring of 512", style=dashed];
     }
     subgraph cluster_n2 {
       label="Node 2"; style="rounded"; color="#94a3b8"; fontcolor="#334155";
       r2 [label="connection threads"];
       s2 [label="storage thread", fillcolor="#fffbeb", color="#b45309"];
       r2 -> s2 [style=dashed];
     }
     subgraph cluster_n3 {
       label="Node 3"; style="rounded"; color="#94a3b8"; fontcolor="#334155";
       r3 [label="connection threads"];
       s3 [label="storage thread", fillcolor="#fffbeb", color="#b45309"];
       r3 -> s3 [style=dashed];
     }
     pg [label="PostgreSQL primary\npolicies, reputation, incidents,\nconsole tables", shape=cylinder, style=filled, fillcolor="#ecfdf5", color="#047857"];
     standby [label="Standby\n(operator's replication)", shape=cylinder, style="filled,dashed", fillcolor="#ffffff", color="#94a3b8"];
     ingress -> r1; ingress -> r2; ingress -> r3;
     s1 -> pg [label=" SQL, TLS verify-full"]; s2 -> pg; s3 -> pg;
     pg -> standby [label=" streaming replication", style=dashed];
   }

Each node of a cluster has a distinct ``--cluster-node`` identifier between 1 and 8,388,607. Challenge keys are bound to the issuing node, so a solution must return to the node that issued its challenge, while session tokens and requirement tickets are valid on every node that shares the seed. Incident identifiers carry the node in their top bits, and each node keeps a durable receipt advanced in the same transaction as its batch, so a batch replayed after an ambiguous failure writes nothing twice.

.. admonition:: Invariants of the storage layer (SID 0011)

   **S1 (one owner).** All SQL runs on the storage thread; no request thread ever waits on the database. **S2 (complete engines).** Every engine a request reads was built completely before it was published, from one consistent revision of the policy tables. **L1 (eventual publication).** A committed change to the policy tables reaches every node that can reach the database by its next tick. **F1 (graceful loss).** When the database is down, the last published engine keeps serving, incidents queue in the bounded ring and are dropped with a counter once it is full, and the storage thread retries with backoff.

A Typed Schema
~~~~~~~~~~~~~~

The schema states in SQL what the program's types state, so the database refuses a row the storage layer could not represent. SQLite tables are ``STRICT``; an enumerated column has a ``CHECK`` that lists exactly the names the program writes; a bounded integer has a range check; and a column is ``NOT NULL`` exactly when the value is never absent. Every statement binds its values as parameters, so no SQL is built by quoting. The console's storage follows the same rules: one baseline migration of 33 typed tables and no triggers. Each invariant of the console, such as "every change to a token writes an audit row", is enforced by exactly one function that runs its statements in one transaction, on SQLite and PostgreSQL alike [#schema]_.

Connections to PostgreSQL are protected as the URL says, with libpq's ``sslmode`` and ``sslrootcert``, when the daemon is built with the ``postgres-tls`` feature. A build without that feature refuses ``require``, ``verify-ca`` and ``verify-full`` at startup; it never falls back to plaintext. Production clusters use ``sslmode=verify-full``.

Incidents that look alike are grouped into campaigns. Each incident carries a 64-dimension embedding stored as 256 bytes. The storage thread keeps the most recent 16,384 embeddings of all nodes in memory (4 MiB) and assigns an incident to the campaign of its nearest neighbour when the cosine distance is at most 0.35. Clustering against older incidents is a deliberate omission: campaigns are recent by nature, and the bound keeps memory and work fixed.

What This Design Does Not Do
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We should be plain about the limits of this choice. Sibuna contains no consensus protocol of its own, and a cluster's consistency is PostgreSQL's: a node that loses the database keeps its last policy until it reconnects. A session minted on one node is accepted by every node, and a solution spent on one node is refused when replayed to another, because the nodes share one seed and challenge keys are bound to the issuing node; neither property needs the database. SID 0011 is committed: a functional test with three nodes on one PostgreSQL database shows that a policy inserted on one node is enforced by all three within one tick, that a honeypot ban on one node reaches the others, and that incident identifiers never collide. No harness yet drives several nodes on one PostgreSQL database under load, so this paper reports no cluster measurements. The release executables are built without PostgreSQL support; a cluster builds Sibuna from source with the ``postgres-tls`` feature [#gave-up]_.

.. _console:

The Console
-----------

Sibuna includes an opt-in management console: authenticated dashboards with live traffic, an investigation path from a denial to its recorded evidence, policy editing, address groups, country enrichment from open GeoIP data, users with Argon2id passwords and a TOTP second factor, an audit trail, webhooks, and the management of a cluster. It is compiled into the same binary, and its interface runs in the browser as a WebAssembly module [#console-sources]_.

.. graphviz::
   :caption: The console. The browser runs the interface as a WebAssembly module; the console server reads the data plane's counters and gives its SQL to the storage thread; outbound connections to peers, webhooks and GeoIP publishers use TLS with verified certificates (SIDs 0007, 0012, 0013).
   :alt: A browser runs the console interface, a WebAssembly module, and talks to the console server over HTTP and a WebSocket. The console server reads the data plane's counters without entering a request thread and submits jobs to the storage thread, which owns SQLite or PostgreSQL. Outbound HTTPS and WSS connections to peer consoles, webhooks and GeoIP publishers use TLS.

   digraph console {
     graph [rankdir=LR, bgcolor="transparent", nodesep=0.3, ranksep=0.5, fontname="Helvetica", fontsize=9];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=8.5, color="#0369a1", fillcolor="#f0f9ff", fontcolor="#0f172a"];
     edge [color="#64748b", fontname="Helvetica", fontsize=8, fontcolor="#334155", arrowsize=0.6];
     browser [label="Browser\nconsole interface\n(WebAssembly)", color="#6d28d9", fillcolor="#f5f3ff"];
     server [label="Console server\nbounded listener", style="rounded,filled,bold"];
     plane [label="Data plane\ncounters and stats\n(read only)", color="#047857", fillcolor="#ecfdf5"];
     storage [label="Storage thread\nSQLite or PostgreSQL", color="#b45309", fillcolor="#fffbeb"];
     tls [label="Outbound TLS\npeers (WSS), webhooks,\nGeoIP downloads", color="#0f172a", fillcolor="#ffffff"];
     browser -> server [label="HTTP and\nWebSocket", dir=both];
     server -> plane [label="reads", style=dashed];
     server -> storage [label="jobs (at most 32 queued)"];
     server -> tls [label="verified\ncertificates"];
   }

The console's defining constraint is isolation from the request path. It may read the data plane's counters and its database and write the database, but it never enters a request thread, never allocates on one, and never holds a lock a connection thread needs. Its listener admits at most 96 connections, of which 16 are reserved for HTTP, 64 may be browser streams and 16 peer streams. In 1.0.0-beta.2 the complete interface module measures 724,311 bytes (272,441 bytes compressed with gzip). That is below the ceiling of 768 KiB, which the build enforces, and above the review threshold of 640 KiB, which SID 0007 records for review [#console-size]_.

The console makes outbound TLS connections for long-lived peer streams, webhooks and GeoIP downloads. Certificates are verified against the system roots or an operator's CA file, host-name verification cannot be disabled, plain HTTP is allowed only to literal loopback addresses, and a certificate error never falls back to plaintext. Sibuna still terminates no inbound TLS; that remains the job of the ingress.

SID 0007 sets the console's performance target: enabling it may cost at most 1% of data-plane throughput and at most 10% of p99 latency. One measurement exists: with the console compiled in but disabled, with storage only, or enabled and idle, the 16 whole-product workloads stayed within about 1% of a daemon built without it, which is within noise. The formal gate, with eight active dashboards under load, has not been run, so we do not claim that the target is met. A functional run with eight live dashboards passed.

.. list-table:: Eight Traffic dashboards on one SQLite node with its console, in headless Chromium 155 (``benchmarks/results/console-8-dashboards-2026-10-15.md``, recorded 2026-10-15). Result: PASS
   :header-rows: 1
   :widths: 42 58

   * - Measure
     - Value
   * - Data-plane requests
     - 6,000 in 30.0 s (200 per second, one connection per request)
   * - Answered
     - 6,000: 200 x 1,200, 401 x 3,000, 403 x 600, 404 x 600, 500 x 600
   * - Errors (no reply)
     - 0
   * - Latency p50 / p90 / p99 / max
     - 246 / 311 / 373 / 552 us (connect included)
   * - Daemon resident memory at start, with 8 dashboards, after the traffic
     - 36,152 KiB; 38,028 KiB; 41,496 KiB
   * - Dashboards
     - 3 administrator sessions and 5 wall displays; each received 134 to 139 ``stats`` deltas and ended with the same totals, with no exception, console error or Content-Security-Policy violation

Empirical Evaluation
--------------------

Method
~~~~~~

Three harnesses, run through ``cargo xtask bench``, measure Sibuna. The *primitive* suite times the operations of the request path in seven timed batches after an untimed warm-up, rebuilds mutable state outside the timer, and reports the median batch per operation with the fastest and slowest batch beside it. The *whole-product* harness drives the daemon with ``wrk`` (2 threads, 64 connections, 5 seconds, 3 repetitions) in forward-auth and reverse-proxy modes, on the Gate and Shield surfaces, over four workloads: ``admitted`` (a valid session), ``challenged`` (no session), ``allowed_static`` (``/robots.txt``) and ``attack`` (a session plus ``q=' OR 1=1--``, which only Shield refuses). The *latency* harness uses an open-loop generator that sends at a fixed rate whatever the daemon does, and times each request from when it was due, so that queueing in the daemon is charged to the daemon [#method-sources]_.

The runs were recorded on 15 October 2026 on one host: an AMD Ryzen 9 5950X (16 cores, 32 threads) running Linux 7.0.0-28. The daemon ran on CPUs 0 to 3 with four workers, the load generator and a stub origin on CPUs 8 to 15 (the other CCD), and the primitive suite on CPU 4. The daemon was the default release build, with SQLite and the console compiled in, and ran in memory, without storage.

.. admonition:: Measurement scope

   Every run uses one host over loopback: no TLS, no wide-area network, no real browsers. The harnesses do not count allocations; the allocation-free request path is checked by the steady-state tests instead. They run the release binary unmodified, identified by its SHA-256. A ranking on this host is not a ranking on another.

Primitive Latencies
~~~~~~~~~~~~~~~~~~~

.. list-table:: Primitive timings of Sibuna in nanoseconds per operation on one Ryzen 9 5950X core: the median of seven batches, with the fastest and slowest batch (``benchmarks/results/primitives-latest.md``, generated 2026-10-15T22:34:59Z)
   :header-rows: 1
   :widths: 20 46 16 18

   * - Subsystem
     - Workload
     - Median
     - Min-max
   * - Proof of work
     - Hashcash verify, 16 bits
     - 70.2
     - 69.9-71.0
   * - Proof of work
     - PoSW verify, depth 13, 16 openings
     - 22,272.4
     - 22,257.0-22,316.4
   * - Bot matcher
     - Aho-Corasick, 40 signatures
     - 55.7
     - 55.3-57.2
   * - Bot matcher
     - Sequential substring search, 40 signatures (for reference)
     - 763.0
     - 762.2-763.5
   * - IP classifier
     - IPv4 CIDR lookup
     - 32.0
     - 31.8-32.2
   * - IP classifier
     - IPv6 CIDR lookup
     - 79.3
     - 78.5-79.6
   * - Token
     - Keyed BLAKE3 session token
     - 155.8
     - 155.3-156.4
   * - Token
     - Ed25519 session token
     - 40,587.5
     - 40,544.6-40,631.1
   * - Spent set
     - Robin Hood spend and look up
     - 21.0
     - 20.8-21.3
   * - Rate limiter
     - GCRA, hashed client
     - 6.2
     - 6.1-6.3
   * - Rate limiter
     - GCRA, four rule scopes, hashed client
     - 6.3
     - 6.2-6.4
   * - Rate limiter
     - GCRA, client as bytes (keyed hash included)
     - 12.8
     - 12.7-12.8
   * - Rate limiter
     - GCRA, four rule scopes, client as bytes
     - 13.1
     - 13.0-13.2
   * - HTTP parser
     - Zero-copy request and cookie
     - 132.5
     - 132.3-133.2
   * - Policy engine
     - Full classification, Shield profile
     - 790.8
     - 787.2-793.1
   * - Policy engine
     - Classification, Gate profile
     - 75.9
     - 75.6-76.1
   * - WAF
     - 8 KiB body, semantic scan
     - 12,784.3
     - 12,771.5-12,809.2
   * - WAF
     - 8 KiB body, SQL injection audited
     - 15,485.4
     - 15,460.9-15,530.1

The spreads are narrow: no batch of any row lies more than 4.2% from its row's median [#spread]_. The daemon uses the rows on a hashed client, because it hashes the client once per request; the rows that pass raw bytes include that keyed hash on every check. Timers surround whole batches, never single operations, so the table reports no per-operation percentiles.

.. _whole-products:

Whole Products
~~~~~~~~~~~~~~

.. list-table:: Sibuna under ``wrk``: requests per second, latency in microseconds, CPU time per request in microseconds and peak resident memory; medians of three runs (``benchmarks/results/product-latest.md``, generated 2026-10-15T23:15:24Z)
   :header-rows: 1
   :widths: 13 9 22 13 8 8 10 11

   * - Mode
     - Surface
     - Workload (status)
     - req/s
     - p50
     - p99
     - CPU
     - Peak KiB
   * - forward auth
     - Gate
     - ``admitted`` (200)
     - 211,345
     - 151
     - 305
     - 11.84
     - 15,912
   * - forward auth
     - Gate
     - ``challenged`` (401)
     - 198,315
     - 160
     - 326
     - 13.15
     - 16,176
   * - forward auth
     - Gate
     - ``allowed_static`` (200)
     - 211,053
     - 152
     - 305
     - 11.73
     - 16,176
   * - forward auth
     - Gate
     - ``attack`` (200)
     - 211,618
     - 151
     - 305
     - 11.84
     - 16,176
   * - forward auth
     - Shield
     - ``admitted`` (200)
     - 208,101
     - 152
     - 308
     - 12.87
     - 15,928
   * - forward auth
     - Shield
     - ``challenged`` (401)
     - 197,532
     - 161
     - 327
     - 13.77
     - 16,192
   * - forward auth
     - Shield
     - ``allowed_static`` (200)
     - 211,636
     - 151
     - 305
     - 11.78
     - 16,192
   * - forward auth
     - Shield
     - ``attack`` (403)
     - 210,549
     - 152
     - 307
     - 12.32
     - 16,192
   * - reverse proxy
     - Gate
     - ``admitted`` (200)
     - 142,498
     - 427
     - 768
     - 27.68
     - 15,896
   * - reverse proxy
     - Gate
     - ``challenged`` (200)
     - 199,465
     - 160
     - 324
     - 12.98
     - 16,160
   * - reverse proxy
     - Gate
     - ``allowed_static`` (200)
     - 147,303
     - 411
     - 759
     - 26.88
     - 16,324
   * - reverse proxy
     - Gate
     - ``attack`` (200)
     - 143,900
     - 422
     - 745
     - 27.67
     - 16,348
   * - reverse proxy
     - Shield
     - ``admitted`` (200)
     - 138,965
     - 438
     - 857
     - 28.57
     - 16,064
   * - reverse proxy
     - Shield
     - ``challenged`` (200)
     - 195,188
     - 162
     - 328
     - 13.73
     - 16,328
   * - reverse proxy
     - Shield
     - ``allowed_static`` (200)
     - 145,673
     - 415
     - 746
     - 27.27
     - 16,328
   * - reverse proxy
     - Shield
     - ``attack`` (403)
     - 209,507
     - 151
     - 306
     - 12.17
     - 16,328

In forward-auth mode the ingress asks Sibuna whether to admit a request, and there is no origin; every workload lies between 197,532 and 211,636 requests per second with a p99 of 305 to 327 us. The four daemon CPUs are not saturated there (between 2.47 and 2.72 of them are busy), which points to the load generator as the ceiling. In reverse-proxy mode the admitted and static rows include the stub origin and one more loopback hop, and the daemon's CPUs are saturated (3.95 to 3.98 of four busy); requests that Sibuna answers itself (challenges, and Shield's refusal of the attack) still run at about 195,000 to 210,000 per second. Peak resident memory stays between 15,896 and 16,348 KiB in every workload [#product]_.

A few answers in about two million in three reverse-proxy rows were ``503``: ``wrk`` reconnected before a closing connection had given back its place under the per-address connection limit. The daemon now gives the place back before it writes the closing response; these files predate that fix.

.. list-table:: Footprint of the Sibuna daemon (``product-latest.json`` and ``primitives-latest.json``, 15 October 2026, as tabulated in book Part VIII)
   :header-rows: 1
   :widths: 60 40

   * - Measure
     - Value
   * - Daemon binary, default build with SQLite and the console
     - 49,113,856 bytes
   * - Idle resident memory, product runs
     - 5,592 to 5,788 KiB
   * - Peak resident memory during a workload
     - 15,896 to 16,348 KiB
   * - Resident memory after the workloads
     - 16,176 to 16,348 KiB
   * - Policy engine tables
     - 209,052 bytes
   * - Bot signature table
     - 42,244 bytes
   * - WAF signature table
     - 164,908 bytes
   * - Browser prover (WebAssembly)
     - 14,744 bytes

A later change to the release profile drops the bundled SQLite's debug information, about 13 MB of the 49 MB by the note in the build manifest; the result files have not been regenerated since, so we quote the measured size [#binary]_.

Latency at Equal Offered Load
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``wrk`` keeps 64 requests in flight, so the request rate depends on the daemon, and ``wrk``'s percentiles leave out the requests it did not send while it waited. The open-loop harness fixes the offered rate instead and charges every delay to the daemon, which is what a visitor experiences.

.. list-table:: Sibuna, Shield, admitted requests at fixed offered rates; latency in microseconds and CPU time per request, medians of three 10-second runs (``benchmarks/results/latency-latest.md``, generated 2026-10-15T23:07:14Z)
   :header-rows: 1
   :widths: 14 12 12 9 9 9 10 10 10

   * - Mode
     - Offered req/s
     - Achieved req/s
     - p50
     - p90
     - p99
     - p99.9
     - Errors
     - CPU us
   * - forward auth
     - 10,000
     - 10,000
     - 30
     - 32
     - 37
     - 58
     - 0
     - 16.92
   * - forward auth
     - 25,000
     - 25,000
     - 28
     - 31
     - 34
     - 45
     - 0
     - 15.83
   * - forward auth
     - 50,000
     - 50,000
     - 25
     - 27
     - 30
     - 40
     - 0
     - 13.83
   * - forward auth
     - 100,000
     - 99,998
     - 24
     - 26
     - 41
     - 62
     - 0
     - 13.48
   * - forward auth
     - 150,000
     - 149,996
     - 25
     - 36
     - 51
     - 74
     - 0
     - 14.16
   * - reverse proxy
     - 10,000
     - 10,000
     - 56
     - 61
     - 65
     - 76
     - 0
     - 32.25
   * - reverse proxy
     - 25,000
     - 25,000
     - 51
     - 54
     - 58
     - 72
     - 0
     - 28.63
   * - reverse proxy
     - 50,000
     - 50,000
     - 47
     - 50
     - 60
     - 74
     - 0
     - 27.45
   * - reverse proxy
     - 100,000
     - 99,996
     - 55
     - 75
     - 100
     - 150
     - 0
     - 28.42
   * - reverse proxy
     - 150,000
     - 134,344
     - 583,934
     - 1,544,160
     - 1,906,273
     - 1,967,134
     - 4
     - 29.22

In forward-auth mode the p99.9 stays below 75 us up to 150,000 requests per second. In reverse-proxy mode, with the origin in the path, the p99 is 100 us and the p99.9 150 us at 100,000 requests per second. At 150,000 requests per second in reverse-proxy mode the daemon is past its capacity: it completes 134,344 requests per second, close to the 138,965 that ``wrk`` measured for the same workload, and latency grows to seconds, as an open-loop test should show above capacity. The four errors of that row occurred in the overload [#latency]_.

.. _what-measurement-changed:

What the Measurement Changed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The latency harness changed the design of the connection threads. In its first runs, with 64 connections each closed by the daemon after 4,096 requests, the 99.9th percentile at 100,000 admitted requests per second was 0.3 to 2 ms, a tail that ``wrk`` had not shown. Creating and ending a thread maps and unmaps its signal stack and returns its stack pages, and those changes to the address space stalled the other threads. One experiment settled the diagnosis: a build that never closed connections, and so created no thread during the run, gave 54 to 60 us at the same rate. The fix lets a thread that finishes its connection park and take the next one; a thread parked for 10 seconds ends, so a burst does not leave its stacks resident. After the fix the p99.9 at 100,000 requests per second is 62 us in forward-auth mode and 150 us in reverse-proxy mode [#thread-reuse]_.

A rare, periodic stall moves the far tail long before it moves p99. At 100,000 requests per second over 64 connections, each connection lasts :math:`4096 / 1562.5 \approx 2.6` s, so about 24 threads start and end every second; in a run of one million requests the top 0.1% is only 1,000 requests, and a few delayed requests per thread turnover are enough to fill it. Such a defect needs p99.9 and a timer on every request to be seen.

Key Takeaways
~~~~~~~~~~~~~

1. *Classification below a microsecond.* In the Gate profile the policy engine classifies a browser request in 75.9 ns; with full inspection in the Shield profile it takes 790.8 ns.
2. *Symmetric verification.* A keyed-BLAKE3 session token verifies in 155.8 ns, against 40,587.5 ns for an Ed25519 token: about 260 times less work for the same integrity within one trust domain.
3. *A small, steady footprint.* About 200,000 forward-auth requests per second on four CPUs, with peak resident memory near 16 MiB in every workload and under 6 MiB at idle.
4. *Tails need open-loop measurement.* The thread-turnover stall was invisible to the closed-loop harness and obvious at p99.9 under an open-loop generator.

Market Comparison: Sibuna and Its Neighbours
--------------------------------------------

We compare Sibuna with the tools an operator is most likely to weigh against it. The facts about the other products were read from their public documentation and release artefacts in September 2026, and the Sibuna book records them with their sources in Part II [#prior-art]_. Each of these products serves its users well, and each made design choices whose benefits our harness does not measure. We describe the differences in architecture, not a ranking.

.. list-table:: Feature comparison (book Part II; facts about other products read from public documentation in September 2026, the JA4 row in October 2026)
   :header-rows: 1
   :widths: 16 24 20 20 20

   * - Feature
     - Sibuna 1.0.0-beta.2
     - Anubis 1.27
     - SafeLine CE 9
     - Cloudflare WAF
   * - Runs as
     - One binary; reverse proxy or forward auth; optional SQLite file or shared PostgreSQL database
     - One Go binary; reverse proxy or forward auth
     - Seven Docker containers (tengine, detector, mgt, luigi, fvm, chaos, PostgreSQL)
     - Hosted network; DNS points at Cloudflare
   * - Runtime
     - Native code, no garbage collector; no third-party dependency when storage is off
     - Go, garbage collected
     - C/C++ proxy and detector, Go management, PostgreSQL
     - Proprietary edge software
   * - Licence
     - LGPL-3.0-or-later
     - MIT
     - GPL-3.0 management code; closed detector images
     - Proprietary service
   * - Proof-of-work admission
     - Hashcash (bit-level) and Cohen-Pietrzak sequential work, chosen per rule
     - SHA-256 Hashcash in hex nibbles; non-work challenges
     - JavaScript challenge and CAPTCHA; not work-bound
     - Managed challenge, JS challenge, Turnstile
   * - Challenge state on the server
     - None until solved; solved tags in a fixed Robin Hood table
     - Store backend: memory, bbolt, Valkey or S3
     - Managed by the stack
     - Managed by Cloudflare
   * - Session token
     - Keyed BLAKE3, 75 characters, bound to the work paid; Ed25519 optional
     - JSON Web Token signed with Ed25519; HS512 optional
     - Cookie issued by the stack
     - ``cf_clearance`` cookie
   * - Payload inspection
     - Shield: tagged automaton plus structural tokenizers, first 8 KiB of body
     - None
     - Semantic analysis over OWASP categories
     - Managed rulesets (Pro and above)
   * - TLS fingerprint (JA4)
     - Rules match a JA4 value that a trusted ingress forwards; not computed by Sibuna
     - Not documented; policies may reference the HTTP fingerprint JA4H, which Anubis computes
     - Computed at its own TLS termination; custom rules and a built-in deny list
     - JA3 and JA4 in custom rules and analytics (Enterprise with Bot Management)
   * - Shared state
     - One PostgreSQL database for policy, reputation and forensics
     - Shared signing key; shared Valkey store
     - One stack per host
     - Global anycast network
   * - TLS termination
     - No (ingress)
     - No (ingress)
     - Yes
     - Yes

.. _anubis-comparison:

Measured Comparison With Anubis
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We measured the official Anubis v1.27.0 release binary beside Sibuna with the harness of :ref:`whole-products`: the same four workloads, the same four CPUs for every product thread, the same ``wrk`` load, matched Hashcash work (8 zero bits for Sibuna, 2 zero hex digits for Anubis), a session obtained by solving each product's challenge as a browser would, and ``caddy respond`` as the origin [#comparison]_. Sibuna runs its Shield surface here, so it also inspects every payload, which Anubis does not.

.. admonition:: Reading these rows

   These numbers describe four workloads on one machine, not every deployment, and several rows are not like for like. In forward-auth mode Anubis answers ``/robots.txt`` and the attack path itself; Anubis inspects no payloads, so Shield's refusal does more work; a challenge bootstrap is two requests for Sibuna and one page for Anubis; and the symmetric token explains much of the session-check gap, since Anubis's own HS512 scheme is 55% faster than its Ed25519 default. Anubis is a widely used and capable tool, and its maintainers made different choices for good reasons. What the measurement does show is that a small, bounded request path can make admission cheap for the defender.

.. list-table:: Sibuna (Shield) and Anubis 1.27.0 under ``wrk``: requests per second and p99 latency in microseconds, medians of three five-second runs (``benchmarks/results/comparison-latest.md``). The status is 200 unless shown; Shield refuses the attack with 403.
   :header-rows: 1
   :widths: 13 17 12 10 12 10

   * - Mode
     - Workload
     - Sibuna req/s
     - Sibuna p99
     - Anubis req/s
     - Anubis p99
   * - forward auth
     - ``admitted``
     - 208,635
     - 308
     - 36,509
     - 7,477
   * - forward auth
     - ``challenged``
     - 193,087
     - 342
     - 113,170
     - 3,781
   * - forward auth
     - ``allowed_static``
     - 212,444
     - 304
     - 89,904
     - 4,547
   * - forward auth
     - ``attack``
     - 211,347 (403)
     - 306
     - 36,853
     - 7,283
   * - reverse proxy
     - ``admitted``
     - 103,298
     - 3,321
     - 19,398
     - 11,062
   * - reverse proxy
     - ``challenged``
     - 197,327
     - 328
     - 28,842
     - 9,546
   * - reverse proxy
     - ``allowed_static``
     - 106,819
     - 3,316
     - 28,862
     - 30,124
   * - reverse proxy
     - ``attack``
     - 210,483 (403)
     - 306
     - 23,399
     - 14,124

Anubis spends 106 us of CPU per admitted request in forward-auth mode, where Sibuna spends 13; its peak resident memory was about 32 MiB in forward-auth mode and grew to about 600 MiB in reverse-proxy mode, while Sibuna's stayed near 16 MiB throughout. Behind ``caddy respond`` Sibuna's proxied rows are limited by the origin, which shares the load generator's CPUs: with the lighter stub origin of :ref:`whole-products` the same rows reach about 139,000 requests per second.

.. list-table:: Admission operations per second on two CPUs, median of seven batches (``benchmarks/results/admission-latest.md``). Anubis runs once with each of its token schemes.
   :header-rows: 1
   :widths: 24 15 15 15 16 15

   * - Product (token)
     - Session check
     - Unauthenticated
     - Bootstrap
     - Proof verification
     - Resident memory
   * - Sibuna (keyed BLAKE3)
     - 88,104
     - 78,997
     - 42,664
     - 57,924
     - 7.6 MiB
   * - Anubis (Ed25519)
     - 10,951
     - 28,619
     - 7,893
     - 12,668
     - 32.6 MiB
   * - Anubis (HS512)
     - 16,976
     - 27,785
     - 7,952
     - 19,261
     - 29.1 MiB

Detailed Architectural Comparison
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SafeLine (Chaitin Technology)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

SafeLine carries the semantic idea of libinjection into a complete product with a management console, and its vendor reports detection rates of 71.65% (balanced mode) and 76.17% (strict mode) with false-positive rates of 0.07% and 0.22% [#safeline]_. These are measurements of detection quality, which Sibuna has not published for its own engine.

- *Deployment.* The community edition ships as seven Docker containers on a Linux host with at least one CPU core, 1 GB of memory and 5 GB of disk. It terminates TLS itself, which Sibuna does not.
- *State.* It keeps its attack log in PostgreSQL within the stack, one stack per host.
- *Where Sibuna differs.* Sibuna is one binary that starts with an optional SQLite file, and a cluster shares one PostgreSQL database that the operator may already run. Its idle resident memory was 5,592 to 5,788 KiB in the product runs. We have not run SafeLine on our host, which had no Docker daemon, so we make no performance comparison.

Anubis and Coraza
^^^^^^^^^^^^^^^^^

The proof-of-work interstitial became common in 2025, when scraper traffic for language-model training made ordinary origins expensive to run, and Anubis is its best-known open implementation. It is a capable, widely deployed Go reverse proxy: it serves a JavaScript puzzle, signs a JSON Web Token with Ed25519, and keeps challenge state in a store. Coraza implements the ModSecurity rule language (SecLang) and runs the OWASP Core Rule Set; it is one way to add rule-based inspection beside such a gate.

- *Where the work goes.* Anubis and Sibuna Gate both make the client pay before the origin does anything. Sibuna adds a second tier of sequential work, chosen per rule, for routes that deserve a stronger gate, and its sessions remember how much work was paid.
- *What the server remembers.* Anubis stores challenges; Sibuna issues a self-authenticating record and remembers only solved tags, in a fixed table (Theorem 3). Its default token is symmetric, which is cheaper to verify and leaves a quantum attacker only a quadratic speedup.
- *Inspection.* Sibuna Shield performs its own structural inspection in the same pass as admission, so one process and one parser serve both roles. It does not run the OWASP Core Rule Set. We evaluated the existing SecLang engines, including bindings to libmodsecurity and Coraza, and admitted none: an inspection engine on an edge server is security-critical code we prefer to own and review. If Sibuna adds compatibility with the Core Rule Set, a design record will specify the subset first [#crs]_.
- *Measurement.* On one host under the same load, Sibuna answered more than five times as many admitted requests in forward-auth mode with a lower p99 and about an eighth of the CPU per request (:ref:`anubis-comparison`).

Cloud Edge WAFs (Cloudflare and Others)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Hosted edges place inspection, rate limiting and bot scoring in many points of presence with a global control plane. They absorb volumetric attacks that no single server can, and they need no hardware from the operator. Sibuna's cluster deployment borrows their shape, a shared policy plane feeding local immutable snapshots, while staying self-hosted.

- *Data residency.* A hosted WAF terminates the operator's TLS and sees request payloads on shared infrastructure, which can conflict with data-residency requirements.
- *Plans and quotas.* Features are tied to plans: Cloudflare's published quotas allow 5, 20, 100 and 1,000 custom rules and 1, 2, 5 and 100 rate-limiting rules on the Free, Pro, Business and Enterprise plans.
- *Where Sibuna differs.* Sibuna runs on the operator's own machines with no per-request fee, and its policy changes reach every node on the next storage tick (500 ms by default). It does not mitigate volumetric network attacks, does not score bots with a trained model, and does not terminate TLS; a deployment that needs those still needs an ingress or an edge network in front of it.

Implementation: Small Crates and Few Dependencies
-------------------------------------------------

Sibuna is written in Rust, as a workspace of small crates whose dependencies point one way: reusable libraries, then a core of configuration and diagnostics, then the application libraries, then the daemon and the browser prover. Three engineering choices matter to an operator, so we record them briefly [#sid-0010]_.

*Few dependencies.* We treat every third-party library as a liability: it must be reviewed, updated and trusted. The data plane uses none. Hashing, signatures, base64, JSON, DEFLATE, Aho-Corasick and the HTTP/1.1 parser are small libraries of our own, which other projects may use on their own. A dependency is admitted only when it is mature, self-contained and solves a genuinely large problem, and the reason is written beside it in the build manifest and in a design record. Two have been admitted, each confined to one library: ``sqlx`` for SQLite and PostgreSQL storage, which brings about one hundred transitive crates [#sqlx]_, and ``rustls`` for the console's outbound TLS and PostgreSQL's TLS, thirteen crates at run time, because a TLS client written in-house would be a security-critical project larger than Sibuna's data plane [#rustls]_. A build without storage and the console has no third-party dependency at all.

.. graphviz::
   :caption: The libraries of Sibuna, simplified (after SID 0010). Arrows point from a library to what it uses. Reusable libraries depend on no application library, and only the storage and console libraries bring third-party code.
   :alt: A layered graph. The daemon uses policy, challenge, net and storage. Policy uses patterns, cidr, json and core. Challenge uses crypto, pow, store and encoding. Net uses http and core. Storage uses policy and core and brings sqlx. The browser prover uses pow. Pow and http use crypto; geoip uses inflate and crypto.

   digraph crates {
     graph [rankdir=TB, bgcolor="transparent", nodesep=0.18, ranksep=0.5, fontname="Helvetica", fontsize=9, newrank=true];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=9, color="#0369a1", fillcolor="#f0f9ff", fontcolor="#0f172a", height=0.32];
     edge [color="#94a3b8", arrowsize=0.55];
     sibuna [label="sibuna (daemon)", fillcolor="#ecfdf5", color="#047857", style="rounded,filled,bold"];
     wasm [label="browser prover (WebAssembly)", fillcolor="#ecfdf5", color="#047857"];
     storage [label="storage (sqlx)", fillcolor="#fffbeb", color="#b45309"];
     policy [fillcolor="#f5f3ff", color="#6d28d9"];
     challenge [fillcolor="#f5f3ff", color="#6d28d9"];
     net [fillcolor="#f5f3ff", color="#6d28d9"];
     core [fillcolor="#f5f3ff", color="#6d28d9"];
     subgraph cluster_reusable {
       label="reusable libraries, no third-party code"; labelloc=b; style="dashed,rounded"; color="#94a3b8"; fontcolor="#64748b";
       patterns; cidr; json; store; pow; http; geoip;
       crypto; encoding; inflate;
     }
     { rank=same; sibuna; wasm; }
     { rank=same; policy; challenge; net; core; }
     { rank=same; patterns; cidr; json; store; pow; http; geoip; }
     { rank=same; crypto; encoding; inflate; }
     sibuna -> storage; sibuna -> policy; sibuna -> challenge; sibuna -> net;
     storage -> policy; storage -> core;
     policy -> patterns; policy -> cidr; policy -> json; policy -> core;
     challenge -> store; challenge -> pow; challenge -> crypto; challenge -> encoding;
     net -> http; net -> core;
     wasm -> pow;
     pow -> crypto; http -> crypto; http -> encoding; geoip -> inflate; geoip -> crypto;
   }

*Memory safety.* Code that bypasses the compiler's memory-safety checks is denied by default, and a module that needs it must opt in by name and justify each use in a comment. A few modules do: the paths that use the processor's SHA instructions, one write that wipes secrets, the declarations of a few C library functions for signal handling, the exports of the two WebAssembly modules, and the ring that carries incidents to the storage thread. The ring is the one place where we kept such code for speed, and only after a measurement: the standard library's bounded channel cost 20 to 45% more per push with 16 producers [#ring]_. Elsewhere ownership does the work that hand-written memory management would otherwise do: a parsed request cannot outlive its buffer, an engine is freed with its last reader, and a socket cannot be closed while any thread can still reach it.

*Discipline and tests.* A function body has at most 70 logical lines and a file at most 1,408 lines, enforced by a checker. Library code returns structured errors and never prints, and every error a user sees names its location, shows an excerpt, and gives a hint. The workspace suite of 1.0.0-beta.2 runs about 2,200 tests on SQLite and about 700 more against PostgreSQL; the console's interface has 298 tests, including golden fixtures; and browser checks drive headless Chromium through the interstitial and through every console page [#tests]_.

Limitations and Open Work
-------------------------

We list what this paper does not establish, so that no claim is read more widely than its evidence.

- *One measured neighbour.* We measured Anubis on one host (:ref:`anubis-comparison`). We have measured neither SafeLine nor a hosted WAF.
- *No cluster under load.* A functional test runs three nodes on one PostgreSQL database (SID 0011, committed), but no harness drives several nodes under load.
- *PostgreSQL needs a source build.* The release executables have SQLite storage and the console but no PostgreSQL support; a cluster builds Sibuna with the ``postgres-tls`` feature.
- *The console's isolation gate* with eight active dashboards under load has not been run (:ref:`console`).
- *Loopback only.* No measurement covers TLS, a wide-area network or real browsers under load; a deployment should measure its own path.
- *Bounded inspection.* Shield is a heuristic inspector of the first 8 KiB of a body, not a full SQL or HTML parser, and forward-auth inspection sees only the bytes the ingress sends.
- *Protocol scope.* Sibuna speaks HTTP/1.0 and HTTP/1.1; it has no HTTP/2 and no inbound TLS termination.
- *TLS fingerprints come from the ingress.* Sibuna cannot compute JA4 itself. A fingerprint is only as trustworthy as the ingress that writes it, and that ingress must overwrite any copy a client sent. A client can imitate a browser's handshake with specialised libraries, so JA4 raises the cost of automation; it does not prove identity [#ja4]_.
- *Cryptographic assurance.* The sequential-work tier rests on published proofs in the random-oracle model; our concrete protocol has tests against a reference labeller, not an independent cryptographic audit.
- *One machine.* Every number was taken on one AMD Ryzen 9 5950X. A ranking on this host is not a ranking on another.

Conclusion
----------

Web defense has often grown by accretion: interpreted runtimes, containers, regular-expression rule sets and external stores piled in front of an application. With Sibuna we have tried the opposite direction, guided by a few plain ideas:

- make the sender pay for admission with verifiable work, keep the server's check cheap and stateless, and let a session remember how much work it paid;
- inspect by structure in linear time, in the same pass as admission, so that no session can bypass inspection;
- respect the machine: one buffer per connection, no allocation on the request path, bounded tables with keyed placement, and threads that are reused rather than recreated; and
- let a mature database own durable shared state, behind one storage thread that the request path never waits on.

On one 16-core machine, these choices let Sibuna serve more than 200,000 admitted requests per second in forward-auth mode on four CPUs, with about 16 MiB of resident memory under that load and a p99.9 of 62 us at 100,000 requests per second. These are the numbers of one host over loopback, and we offer them as evidence that the design holds together, not as a ranking. We removed our own consensus protocol and say so plainly; in return the system is smaller and its data plane has no third-party dependency. Much remains to be measured, and we have tried to say exactly what.

Sources and Reproduction
------------------------

Every number in this paper comes from a committed result file of the Sibuna repository, from a Sibuna Discussion (SID) record, or from the Sibuna book, and each table or footnote names its source. The result files are written by ``cargo xtask bench primitives``, ``cargo xtask bench product`` and ``cargo xtask bench latency``, and ``benchmarks/results/README.md`` gives the commands, the CPU sets and the provenance of each file.

- ``benchmarks/results/primitives-latest.md``, ``product-latest.md``, ``latency-latest.md`` and their ``.json`` files; ``console-8-dashboards-2026-10-15.md``.
- SID 0002 (foundation architecture and its revision notes), SID 0004 (the Shield surface), SID 0006 (mathematical foundations), SID 0007 (the console), SID 0010 (workspace, crates and dependency policy), SID 0011 (storage through sqlx), SID 0012 (console TLS), SID 0013 (console storage) and SID 0014 (JA4 fingerprints from the ingress), in ``docs/sid/records/``.
- The Sibuna book, ``docs/book/``: Part I (the cost of a request), Part II (prior art), Part III (cryptography), Part IV (the protocol), Part V (zero-allocation engineering), Part VI (automata and the semantic firewall), Part VIII (empirical evaluation) and Part IX (operations).
- The primary literature: Back, Hashcash (1997); Cohen and Pietrzak, Simple Proofs of Sequential Work (EUROCRYPT 2018); Blocki, Lee and Zhou, On the Security of Proofs of Sequential Work in a Post-Quantum World (ITC 2021); Aho and Corasick, Efficient String Matching (1975); Celis, Robin Hood Hashing (1986); the ATM Forum's Generic Cell Rate Algorithm (1996).

.. only:: html

   .. rubric:: Notes

.. [#cost-model] Book Part I, "Admission Is an Economic Decision". The inequality is a capacity model, not a measurement; it omits bandwidth, connection state and client delay.
.. [#surfaces] SID 0002, "Decision"; book Part II, "Three Ideas in One Binary"; book Part VI, "The Declarative Policy Engine". The per-rule example, the requirement ticket and the work-level session are from book Part IV; the adaptive baseline from book Part IV and SID 0006 (revision note, Part H).
.. [#zero-alloc] Book Part V, "One Thread per Connection, Bounded" and "One Buffer per Connection".
.. [#steady-state] Book Part V, "The Connection Loop"; ``cmd/sibuna/tests/steady_state.rs`` and ``crates/net/tests/steady_state.rs``.
.. [#threads] SID 0010, "Concurrency model" and "Rationale and alternatives"; SID 0002, "Request contract" and its revision notes (connections per address, IPv6 prefix, the striped origin pool).
.. [#automaton] ``benchmarks/results/primitives-latest.md`` (55.7 and 763.0 ns); the table size from ``primitives-latest.json`` as given in book Part VIII, "Footprint"; SID 0006, Part F, and its revision note on byte classes.
.. [#gcra] SID 0006, Part D (Definition 22, Theorem 23); SID 0004, revision notes (keyed placement, ``--rate-table-cells``); ``benchmarks/results/primitives-latest.md`` (``gcra_check_hashed``).
.. [#spent] Book Part III (Lemma 3 and Lemma 4, wire formats); book Part V, "The Robin Hood Spent Set"; SID 0006, Part E (Lemma 28); ``benchmarks/results/primitives-latest.md`` (``robin_hood_spend_and_lookup``).
.. [#waf] SID 0004, "Revision note (2026-09-07)" and "Verification"; book Part VI, "A Lesson in False Positives".
.. [#waf-cost] ``benchmarks/results/primitives-latest.md`` (``8kb_body_semantic_scan``, ``8kb_body_sqli_audit_other_enforce``); SID 0004, revision note "inspection modes"; book Part VIII, "WAF Inspection".
.. [#ja4] SID 0014, "Specification" and "Security and operational considerations"; book Part IX, "JA4 Fingerprints From the Ingress"; ``.github/release-notes.txt``.
.. [#security] SID 0002, revision notes (forwarded identity; cookie values); SID 0004, revision notes (keyed placement, ban table, measured costs, zeroed tables); SID 0006, revision notes (spent-set capacity, adaptive controller input); SID 0010, review history (security review, 2026-10-15); ``benchmarks/results/primitives-latest.md`` (``gcra_check`` and ``gcra_check_hashed``).
.. [#hashcash] Book Part III, "Hashcash: The Mathematics of Tier One"; book Part I, "Hash Search as a Random Variable".
.. [#posw] Book Part III, "Proof of Sequential Work: Tier Two", "Prover Memory" and "Parameters Are Not Timings"; SID 0006, Part B and its implementation review of 2026-09-07.
.. [#round-trip] Book Part IV, "The Challenge Round Trip" and "The Session Cookie"; SID 0010, "The browser solver".
.. [#verify-cost] ``benchmarks/results/primitives-latest.md``; the WebAssembly size from ``primitives-latest.json`` as given in book Part VIII, "Footprint"; browser solve times from SID 0010, criterion 3 (Chromium 155, ``cargo xtask browser``); run-time detection of SHA instructions from SID 0006, revision note (Parts A to C).
.. [#zaxonlite] SID 0011, "Abstract", "Motivation and scope" and "Why PostgreSQL for clusters"; SID 0005 describes the earlier replicated design.
.. [#storage-thread] SID 0011, "The storage thread", "Policy revision" and "Incidents and campaigns".
.. [#schema] SID 0011, "Schema and migrations" and its review history (transport security); SID 0013, "Abstract".
.. [#gave-up] SID 0011, "Security and operational considerations" and "Acceptance criteria and implementation status" (criterion 2, ``crates/storage/tests/multi_node.rs``); ``.github/release-notes.txt``, "Known limitations"; SID 0002, "Authentication and work" (node-bound challenge keys); book Part VIII, "Not Measured".
.. [#console-sources] SID 0007, "Abstract" and its revision notes (listener admission, interface module, GeoIP and passwords); SID 0010, review history (console port, TOTP); SID 0012; SID 0013. The isolation measurement is in SID 0010's review history (console port); book Part VIII, "Console Overhead", notes that the record names no result file for it.
.. [#console-size] SID 0007, review history (Rust port, consolidation; daemon integration), which records 719,406 bytes before the JA4 fields of SID 0014. The size for 1.0.0-beta.2 is of the module built as the daemon's build script builds it (``cargo rustc --lib -p sibuna-console-ui --target wasm32-unknown-unknown --profile wasm -- -C link-arg=--compress-relocations``), compressed with ``gzip -9``.
.. [#method-sources] ``benchmarks/results/README.md``, "Method" and "Provenance and limits" (rustc 1.99.0; the daemon is ``cargo build --release -p sibuna``, 49,113,856 bytes); book Part VIII, "Methodology".
.. [#spread] Book Part VIII, "Primitive Latencies", computed from ``primitives-latest.json``.
.. [#product] ``benchmarks/results/product-latest.md``; CPUs busy from ``cores_busy_median`` in ``product-latest.json``; the ``503`` answers and their fix from ``benchmarks/results/README.md`` and SID 0002, revision note (bug fix).
.. [#binary] Book Part VIII, "Footprint"; the root ``Cargo.toml``, profile ``[profile.release.package.libsqlite3-sys]``.
.. [#latency] ``benchmarks/results/latency-latest.md``; the rows at 25,000 requests per second and the reverse-proxy rows at 150,000 are in that file.
.. [#thread-reuse] SID 0002, revision note (performance, connection threads reused); book Part VIII, "What the Measurement Changed"; ``benchmarks/results/latency-latest.md``.
.. [#comparison] ``benchmarks/results/comparison-latest.md`` and ``admission-latest.md``, recorded on 16 October 2026 with ``cargo xtask bench product --anubis`` and ``cargo xtask bench admission --anubis``; book Part VIII, "Sibuna and Anubis", lists the method and every difference between the products.
.. [#tests] SID 0010, "Acceptance criteria and implementation status" (criteria 1, 3 and 5), which recorded about 2,100 workspace tests and 290 interface tests before SID 0014; the counts for 1.0.0-beta.2 are from ``cargo test --workspace -- --list``.
.. [#prior-art] Book Part II, "Feature Comparison" and "Interstitials and Edges"; the Sibuna licence is the workspace's ``license`` in ``Cargo.toml``.
.. [#safeline] Book Part VIII, "Not Measured": vendor-reported figures checked in September 2026.
.. [#crs] SID 0010, "The OWASP Core Rule Set".
.. [#sid-0010] SID 0010, "Workspace", "Dependency policy" and "Engineering standards".
.. [#sqlx] SID 0011, "Why sqlx"; ``Cargo.toml``, where each third-party crate carries its reason.
.. [#rustls] SID 0012, "Specification", "Rationale and alternatives" and review history (PostgreSQL TLS built).
.. [#ring] SID 0010, review history (security review, 2026-10-15): the standard bounded channel against the Vyukov ring, ``tests/timing.rs``. The opt-in modules are ``crates/crypto/src/sha256/`` (x86-64 and AArch64), ``crates/crypto/src/ct.rs``, ``cmd/sibuna/src/signals.rs``, ``cmd/sibuna-pow-wasm/src/lib.rs``, ``cmd/console-ui/src/abi.rs`` and ``crates/store/src/ring.rs``; the workspace sets ``unsafe_code = "deny"`` and Clippy's ``undocumented_unsafe_blocks = "deny"``.
