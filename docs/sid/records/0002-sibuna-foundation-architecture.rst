:sid-number: 0002
:sid-title: Sibuna: Foundation Architecture, Delivery Plan, and Performance Contract
:sid-state: published
:sid-status: Published
:sid-type: Architectural Specification
:sid-authors: ["Sibuna Contributors <team@sibuna.local>"]
:sid-created: 2026-09-07
:sid-updated: 2026-10-15
:sid-discussion: No external discussion URL assigned
:sid-summary: Foundational architectural specification, zero-allocation pipeline, two-tier proof-of-work engine, keyed-hash session tokens, product surfaces, measured performance contract, and delivery record for the Sibuna pure-Zig monorepo
:sid-labels: ["architecture", "firewall", "pow", "performance"]

Sibuna: Foundation Architecture, Delivery Plan, and Performance Contract
========================================================================

Revision note
-------------

2026-10-15: Ported from the Typst original in the Zig repository. The record describes the Zig implementation as it was decided; SID 0010 maps its packages to the Rust crates of the port.

2026-10-15 (Rust port): the reverse proxy (``sibuna-net``) changes three mechanisms of the request contract. First, the origin pool still holds at most 256 idle sockets, but in 16 stripes of 16 sockets with a lock each; a connection thread gives to and takes from its home stripe first and looks into the other stripes before it connects afresh. Zig kept one pool under one spin lock, which every proxied request contended for. Second, an accepted WebSocket upgrade is relayed by two threads: the connection's own thread carries origin-to-client bytes, and a scoped thread with a 128 KiB stack carries client-to-origin bytes. Zig served both directions from one thread with ``poll(2)``, which the Rust standard library does not expose; two threads with socket timeouts keep the relay free of ``unsafe``. An upgraded connection therefore holds two threads, so the number of connection threads can reach twice ``--max-connections`` when every connection is upgraded. Half closes, failure handling and the idle bound over both directions are unchanged. Third, the proxy borrows the parsed request instead of re-reading the connection buffer, and reads the rest of a streamed upload into a per-connection upload buffer (SID 0009). Bytes on the wire, the retry rule and the keep-alive decisions are unchanged; the port replays scenarios recorded from the Zig proxy and compares what the origin and the client receive.

2026-10-15 (Rust port): the policy engine is no longer a fixed-capacity value held in two double-buffered slots with an arena per slot and a reader count. ``sibuna-policy`` builds an owned ``Engine`` off the request path (about 200 KiB of compact heap tables, reported by ``Engine::heap_bytes``, where the Zig value was 853,728 bytes), and the daemon publishes it behind an ``Arc``. Each request thread reads it through a cache that checks a generation counter with one acquire load and clones the ``Arc`` only after a publication; an old engine is freed when the last thread holding it moves on, and no writer ever waits for readers to drain. The reason is ownership: reference counting replaces the slot protocol and its arena reset rules, so an engine cannot be freed or rebuilt while a request still reads it. The capacities (128 rules, 128-byte rule names, 8,192 trie nodes) and every decision are unchanged. The signature automata use byte classes instead of 256 columns per state (SID 0006, Part F). Storage is SQLite or PostgreSQL through sqlx (SID 0011) instead of Zaxonlite.

2026-10-15 (security review, Rust port): the reverse proxy and the accept path gain five protections; they change behaviour only towards faulty origins and hostile clients. First, an origin socket returns to the pool only at a clean message boundary: the origin keeps the connection, the body was framed by ``Content-Length`` or chunked coding and read to its end, and no byte follows it in the read buffer. Bodiless responses (HEAD, 204, 304) and exchanges whose request carried a body are never pooled, because an origin that sends a body after a bodiless reply, or that ignores a body and answers it later as a request of its own (CL.0), would hand that answer to the next client. Taking a socket from the pool first peeks at it without blocking; a socket with bytes waiting or at end of stream is closed. This costs about 1 us per pooled exchange and one fresh origin connection per request with a body. Second, ``--max-connections-per-ip <n>`` (default 64, 0 disables) bounds the connections one socket peer address may hold; an IPv4-mapped IPv6 address counts with its IPv4 address, and forwarded headers play no part. Beyond the bound the accept loop answers ``503`` and closes the socket as for ``--max-connections``, counting the event in ``sibuna_overloaded_total``. The counts live in a fixed keyed-hash table of 1,024 buckets of 16 clients. Third, progress is required in both directions: the client socket carries a write timeout equal to ``--idle-timeout``, so a client that accepts no byte for that long loses the connection whatever the origin sends, and each direction of an upgraded connection must deliver a byte per ``--websocket-idle-timeout`` on its own, so traffic one way no longer keeps a stalled reader alive. A client that never reads can still occupy the slack of the socket buffers, which the standard library gives no way to shrink. Fourth, every response Sibuna writes to a HEAD request, its own pages included, carries the head, with the ``Content-Length`` of the GET response, and no body. Fifth, a request field whose name equals a field Sibuna sets or strips with ``_`` written for ``-`` (``X_Forwarded_For``) is dropped, a request with more than one ``Host`` field is answered ``400`` (RFC 9112 section 3.2), and a ``Connection`` field cannot nominate ``Host``. The origin's ``Content-Length`` and chunk sizes must be plain digits (no sign, underscore or surrounding junk), chunk data must end in CRLF, and trailer lines must be field lines; anything else is a malformed upstream response: ``502`` before the head is relayed, an aborted exchange after it. Zig accepted ``+3`` and ``1_0`` through ``parseInt`` and relayed them as sent.

2026-10-15 (Rust port, security fix): with forwarded identity trusted, the client is the ``X-Forwarded-For`` entry ``--trusted-hops`` positions from the right (default 1, the address the nearest trusted proxy appended), reading all ``X-Forwarded-For`` fields as one list; ``X-Real-IP`` is read only without ``X-Forwarded-For``. An entry that is not an IP address is not trusted: the request is judged by the socket peer and counted (``sibuna_forwarded_invalid_total``). Zig took the leftmost entry, which appending ingresses pass through from the client, so a client could choose its own identity: ban others, reuse one solved proof across addresses and evade every per-client limit. The address is parsed once per request.

2026-10-15 (Rust port): the origin receives ``X-Forwarded-For`` as a reverse proxy passes it on: the received chain when forwarded identity is trusted, followed by ``, `` and the socket peer; without trust, the socket peer alone, never a client-written entry. ``X-Real-IP`` is the client the request was judged by. Zig wrote the judged client into both fields. Origins behind Sibuna must read the client from ``X-Real-IP`` or from the right of ``X-Forwarded-For``, never from its leftmost entry.

2026-10-15 (Rust port, security fix): ``--max-connections-per-ip`` counts an IPv6 socket peer with its ``--ipv6-prefix`` network (a /64 by default), as limits and bans do, so a client holding a /64 can no longer open the allowed connections from each of its addresses. IPv4 addresses are counted one by one, as before.

Abstract
--------

Foundational architectural specification, zero-allocation pipeline, two-tier proof-of-work engine, keyed-hash session tokens, product surfaces, measured performance contract, and delivery record for the Sibuna pure-Zig monorepo.

.. admonition:: Implementation review (2026-09-07)

   This revision follows code review and regression tests. Performance results live in ``benchmarks/results/latest.json`` and ``distributed-latest.json``; earlier fixed latency tables and unsupported competitor cost models have been removed. Measurements are host-specific, not proofs of optimality or deployment capacity.

.. admonition:: Whole-product measurement (2026-09-07, later the same day)

   Driving the daemon with an external load generator (``benchmarks/tools.py``, results in ``tools-comparison-latest.json``) exposed three limits invisible to the primitive suite: accept threads served one connection to completion (tail latency over 100 ms at 64 clients), every proxied response closed the client connection, and every proxied request opened a new origin connection (about 1,400 requests per second before ephemeral-port exhaustion). The request contract below now describes bounded per-connection threads with a ``503`` overload path, origin response framing, and a pooled origin connection with one safe retry.

Decision
--------

Sibuna provides two product surfaces from one Zig binary. Persistent storage and distributed edge deployment are options for these surfaces, not a third product.

.. list-table::
   :header-rows: 1
   :widths: 20 40 40

   * - Capability
     - Gate (``--gate``)
     - Shield (``--shield``, default)
   * - Admission
     - Hashcash or sequential-work browser challenge; bound session token
     - Same
   * - Policy
     - Declarative rules, bot signatures, CIDR reputation
     - Same
   * - Flood controls
     - GCRA, honeypot, temporary bans
     - Same
   * - Payload inspection
     - Disabled
     - SQL injection, XSS, traversal, command-injection heuristics
   * - Deployment
     - Reverse proxy or forward auth
     - Reverse proxy or forward auth
   * - Optional state
     - Embedded persistent policy and reputation
     - Also WAF incident forensics
   * - Distributed deployment
     - Cluster build and configured members
     - Same

Request contract
----------------

The server runs bounded blocking accept threads (``--workers``, one per CPU by default). Each accepted connection is served on its own thread with a one-megabyte stack, so a slow or idle peer never delays another connection; the number of connection threads is bounded by ``--max-connections`` (1,024 by default), beyond which the accept loop answers ``503`` and closes the socket without spawning, counting the event in ``sibuna_overloaded_total``. A finished connection thread still owns its stack until it is joined, and it is joined when its slot is next taken, so slots are taken lowest first and the number of allocated stacks follows the connections currently open rather than the number served. The idle reaper closes connections silent for longer than ``--idle-timeout``. Each active connection owns a 64 KB read buffer, with a 16 KB head limit, and bounded write buffers. HTTP/1.0 and HTTP/1.1 are supported. Chunked request bodies are decoded in place and re-framed for the origin (SID 0009); other transfer codings are refused with 501. Invalid header names, request-line control bytes, conflicting lengths, and invalid decimal lengths are refused. Truncated bodies fail closed. Requests whose declared body exceeds the buffered prefix do not reuse the client connection after a local response.

The response path applies these checks in order:

#. Local ban table.
#. Reserved internal routes (assets, challenge issuance, verification, honeypot, health, metrics).
#. Local GCRA admission.
#. Active policy snapshot: Shield inspection, reputation, ordered rules, scoring, static paths, bot signatures and default admission.
#. A valid session satisfies an admission challenge; it never overrides a denial or WAF finding.
#. An admitted reverse-proxy request streams to the origin; forward auth returns a verdict. The proxy reads the origin's response head (at most 16 KB), classifies the body framing by RFC 9112 (no body, ``Content-Length``, chunked, or close-delimited), relays it exactly, and keeps the client connection open unless the response was close-delimited. Origin sockets left at a clean boundary by a persistent response return to a fixed pool of 256; a pooled socket the origin has closed is retried once on a fresh connection before any byte reaches the client, and only when the request body was fully buffered.

.. admonition:: Rust port note (2026-10-15)

   The pool of 256 is striped (16 stripes of 16 sockets, a lock each), and an upgraded WebSocket connection uses a second relay thread. See the revision note.

The server's primitive parsing, evaluation and verification routines take no allocator. This is a source/API contract, not a claim that the networking runtime, thread creation, startup, or persistent storage perform no allocation. Benchmark instrumentation is linked only into the standalone benchmark executable. Production metrics and snapshot reader counts still have real atomic costs; they are not benchmark overhead.

Authentication and work
-----------------------

A 32-byte master seed derives independent token, challenge, fingerprint and signing keys. The normal token is a 40-byte payload (version, the work level the holder solved, timestamp, expiry, rule hash, fingerprint) plus a 16-byte keyed BLAKE3 tag, URL-safe base64 encoded; a session admits only routes whose demanded work level it reaches (amended 2026-10-01). Ed25519 is an optional asymmetric token format. Tokens are bound to client address and User-Agent and expire. Trust forwarded identity only behind an ingress that overwrites it.

Issuing a challenge stores no entry. Successful verification inserts the authenticated tag into a 16-shard spent set. Failed bounded insertions leave every live tag intact and refuse admission. The set is per process and disappears on restart. In cluster mode, challenge keys are additionally derived from the node id at startup, while token keys remain shared. Challenge issuance and solution submission must reach the same node; the resulting token works on every member with the same seed. Distinct cluster node ids are required. This avoids cross-node replay without a request-path consensus transaction. It does not make replay state durable across restarts.

Tier 1 verifies ``SHA256(challenge || ":" || decimal(nonce))`` with bit-level difficulty. Tier 2 labels the sequential-work graph in ``libs/crypto/src/posw.zig``; both native verification and the WASM prover import the same source. SID 0006 separates graph/hash evaluations from SHA-256 compression counts and states the research assumptions. Tests against a reference labeller are correctness evidence, not an independent cryptographic audit.

Policy and memory
-----------------

The engine owns fixed-capacity rules, a radix trie, and dense Aho-Corasick tables. Signature capacity is one plus the sum of pattern lengths: no trie can require more states. This retains one transition lookup per input byte while avoiding the former oversized tables. Exact engine and table sizes are emitted by the benchmark using ``@sizeOf``.

Dynamic storage owns two engine slots and an arena dedicated to each slot. A slot's arena is reset only when that slot is inactive and prior readers have drained. Response rule names are copied into a bounded 128-byte buffer, then the reader releases its slot before any proxy I/O. Pointer publication and reader-counter operations use sequential consistency so the cross-atomic ordering argument is valid. Storage polling, SQL, vector search and persistence stay on the storage thread.

.. admonition:: Rust port note (2026-10-15)

   The Rust daemon has no engine slots, slot arenas or reader counts: it publishes an owned engine behind an ``Arc``, and sizes come from ``Engine::heap_bytes`` instead of ``@sizeOf``. See the revision note.

Measurement gates
-----------------

.. code-block:: sh

   zig build fmt
   zig build test
   zig build test -Dstorage=false
   zig build test -Dcluster=true
   sh benchmarks/run-all.sh
   python3 benchmarks/distributed.py
   zig build sid

The primitive harness warms inputs, resets mutable stores outside the timer before each of seven batches, and prevents pure work from being hoisted out of loops. No operation reads a clock. Its bot implementations search identical pattern sets with equivalent any-match semantics. Allocation values are source-audited expectations, not allocator measurements.

The distributed harness starts three actual daemon processes and six external client processes. It checks status codes, sessions across nodes, authenticated WAF denial, issuer-bound challenge rejection, reputation propagation, and continued HTTP service with one member down. Batch timings include client and loopback costs. The harness tests loopback PSK and mutual TLS. WAN behavior needs separate measurements.

Remaining limits
----------------

Shield is a bounded heuristic inspector, not a full SQL/HTML parser. Only the first 8 KB of body is inspected, and encoded fields longer than the canonical buffer are inspected raw. There is no HTTP/2, native TLS termination, global rate quota, durable replay set, administrative UI, or measured volumetric network mitigation. Forward-auth inspection sees only bytes the ingress sends. Blocking workers and slow origins limit concurrency. No claim of full managed edge-service equivalence follows from a local benchmark.

References
----------

- SID 0006, *Mathematical Foundations of Sibuna: Sequential Work, Symmetric Authentication, Bounded State, and Linear-Time Inspection*, which separates graph/hash evaluations from SHA-256 compression counts and states the research assumptions.
- SID 0009, *Chunked Request Bodies: Strict In-Place Decoding, Canonical Re-Framing, and Inspection Equivalence*, which specifies the decoding and re-framing of chunked request bodies.
- RFC 9112, HTTP/1.1, which defines the message body framing the proxy classifies.
- ``benchmarks/results/latest.json``, ``distributed-latest.json`` and ``tools-comparison-latest.json``, the measured results in the Zig repository.

.. rubric:: Lifecycle event

::

   2026-10-15: prediscussion -> discussion. Ported from the Zig repository's
   Typst record

.. rubric:: Lifecycle event

::

   2026-10-15: discussion -> published. State carried over from the Zig
   repository's registry
