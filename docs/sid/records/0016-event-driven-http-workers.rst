:sid-number: 0016
:sid-title: Event-Driven HTTP Workers
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-24
:sid-updated: 2026-11-24
:sid-discussion: No external discussion URL assigned
:sid-summary: Serves edge HTTP connections and WebSocket tunnels on per-core event loops that drive sans-I/O protocol machines, so a connection costs a record and a socket, not a thread.
:sid-labels: ["architecture","load-balancer","network","performance","websocket"]

Event-Driven HTTP Workers
=========================

Abstract
--------

We serve the HTTP frontends of the edge (SID 0015) on a small, fixed set of worker threads. Each worker owns an event loop and the connections assigned to it. A connection is a record in the worker and a socket in the kernel. It has no thread and, while idle, no buffer. The firewall decision stays the synchronous code we have. It runs on the worker when a complete request is in memory, and it performs no I/O. The exchange with the server and the WebSocket tunnel are state machines that consume and produce bytes and never touch a socket.

An operator observes three changes. HTTP throughput approaches that of TCP forwarding. The number of concurrent HTTP connections and WebSockets is bounded by the flow table and by memory, not by 8,192 threads. A WebSocket costs no thread.

Motivation and scope
--------------------

SID 0015 measured the edge beside HAProxy 3.0. TCP forwarding matched it. Plaintext HTTP reached 59% at 256 connections, TLS 53% and HTTP/2 39%. The firewall serves each connection on a thread with blocking reads. At 256 connections it made 2.9 context switches per request and spent four fifths of its CPU time in the kernel. Each connection held about 145 KiB of resident memory, and an upgraded connection held two threads.

The sibling services use long-lived connections. jlavi and jlavideploy keep a WebSocket per browser tab. jlavici runners hold long polls. anahita carries live audio over two WebSockets per session, with binary frames up to 512 KiB at 50 frames per second. A thread per connection bounds all of them together at a few thousand.

This record covers the HTTP frontends of edge mode on Linux. The classic single-upstream listener, forward-auth mode and the console keep the thread-per-connection path of SID 0002 and SID 0010. Other operating systems keep it too, until they have a non-blocking connect. TLS, HTTP/2 and HTTP/3 termination stay in the protocol runtime of SID 0015, and its handoffs become connections of the workers. io_uring, kernel splicing and kernel TLS are outside this record.

Specification
-------------

Invariants
~~~~~~~~~~

#. A worker never waits for a peer. Every socket it owns is non-blocking, and every wait is the one ``epoll_wait`` of its loop.
#. A connection belongs to one worker from accept to close. No lock protects connection state.
#. The firewall decision sees a complete request head, and the body bytes that the thread path would have buffered. It is the same function on both paths.
#. Bytes reach a server only after the decision admitted the request. A server socket returns to a pool only at a clean message boundary, under the rules of SID 0010.
#. Responses leave a connection in the order of its requests. The worker decides the next request only after the previous response is complete.
#. Every buffer has a bound. A slow reader stops the reads of its peer.
#. Every state has a deadline.
#. A fault in one connection closes that connection only.

Workers and connection ownership
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The edge starts one HTTP worker for each processor the process may use, up to 64. The edge worker of SID 0015 accepts connections, applies the frontend's connection rate limit and the flow budget, and assigns each connection to the HTTP worker with the fewest connections. The protocol runtime assigns its handoffs the same way, and passes the client address and the listener with each one. The assignment crosses threads once, through a queue and a wake-up.

.. graphviz::
   :caption: Ownership. One thread accepts, the HTTP workers own connections and server sockets, and nothing is shared on the request path except the admission tables.
   :alt: The edge worker accepts connections and assigns them to HTTP workers. The TLS runtime hands exchanges to the same workers. Each worker holds a connection table, a server pool, a buffer pool and a timer wheel, and reaches the servers.

   digraph workers {
     graph [rankdir=LR, bgcolor="transparent", fontname="Helvetica", fontsize=9, nodesep=0.25, ranksep=0.5];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=8.5, fillcolor="#eff6ff", color="#1e40af", penwidth=1.0, margin="0.1,0.05"];
     edge [color="#64748b", fontname="Helvetica", fontsize=7.5, fontcolor="#475569", arrowsize=0.6];
     accept [label="Edge worker\naccept, rate, budget"];
     tls [label="TLS, HTTP/2, HTTP/3\nruntime", fillcolor="#f5f3ff", color="#6d28d9"];
     w1 [label="HTTP worker 1\nconnections, server pool,\nbuffers, timer wheel", fillcolor="#f0fdf4", color="#15803d"];
     wn [label="HTTP worker n", fillcolor="#f0fdf4", color="#15803d"];
     shared [label="Shared, lock-free or striped:\npolicy engine, limiter,\nbans, routes", fillcolor="#fffbeb", color="#b45309"];
     servers [label="Servers", fillcolor="#ffffff"];
     accept -> w1 [label="assign"];
     accept -> wn;
     tls -> w1 [label="socket pair"];
     tls -> wn;
     w1 -> shared [style=dashed, label="decide"];
     wn -> shared [style=dashed];
     w1 -> servers;
     wn -> servers;
   }

The life of a connection
~~~~~~~~~~~~~~~~~~~~~~~~

.. graphviz::
   :caption: States of a connection. Each arrow is taken inside the worker without blocking.
   :alt: Idle leads to Head when bytes arrive. Head leads to Body or Decide. Decide leads to Respond for a local answer or to Connect and Exchange for an admitted request. Exchange leads to Idle on keep-alive, to Tunnel after a 101 response, or to Closed.

   digraph states {
     graph [rankdir=LR, bgcolor="transparent", fontname="Helvetica", fontsize=9, nodesep=0.3, ranksep=0.4];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=8.5, fillcolor="#eff6ff", color="#1e40af", penwidth=1.0, margin="0.08,0.04"];
     edge [color="#64748b", fontname="Helvetica", fontsize=7.5, fontcolor="#475569", arrowsize=0.6];
     idle [label="Idle\nno buffer"];
     head [label="Head"];
     body [label="Body\nup to 64 KiB"];
     decide [label="Decide\nsynchronous, no I/O", fillcolor="#fffbeb", color="#b45309"];
     respond [label="Respond"];
     connect [label="Connect"];
     exchange [label="Exchange"];
     tunnel [label="Tunnel", fillcolor="#f0fdf4", color="#15803d"];
     closed [label="Closed", fillcolor="#ffffff"];
     idle -> head [label="bytes"];
     head -> body;
     head -> decide;
     body -> decide;
     decide -> respond [label="deny, challenge,\ninternal route"];
     decide -> connect [label="admit, no pooled socket"];
     decide -> exchange [label="admit"];
     connect -> exchange;
     exchange -> idle [label="keep-alive"];
     respond -> idle [label="keep-alive"];
     exchange -> tunnel [label="101"];
     exchange -> closed;
     respond -> closed;
     tunnel -> closed;
   }

*Idle.* The connection holds no buffer. When the socket becomes readable the worker borrows a 64 KiB buffer from its pool.

*Head and Body.* The worker reads until the blank line, with the 16 KiB head limit of SID 0002. It then buffers the body exactly as the thread path does: all of a ``Content-Length`` body that fits the buffer, or a chunked body decoded in place until it ends or the buffer is full (SID 0009). ``Expect: 100-continue`` is answered as on the thread path, before the body is read. A second request that arrives early stays in the buffer until the first response is complete.

*Decide.* The worker parses the request and calls the firewall's dispatch function with a writer that appends to the connection's output buffer. Dispatch runs the limiter, bans, policy, challenge and semantic inspection, and the routes under ``/__sibuna/``. It either writes a complete local response or admits the request. On admission it selects a server (SID 0015), encodes the request head for the server with the audit fields, and returns a plan in place of relaying. The plan holds the server reservation, the encoded bytes, the upload framing, the WebSocket handshake if one was offered, and whether the request may be retried and its socket pooled.

*Connect.* The worker takes an idle socket of that server from its pool. If there is none it starts a non-blocking connect with a deadline of five seconds.

*Exchange.* The worker writes the request, relays the rest of an upload, and feeds the server's bytes to the response machine. The machine's output goes to the client. When the machine finishes, the worker records the outcome on the reservation, pools or closes the server socket, and returns the connection to Idle or closes it. The encoded request is kept until the first response byte, so that a retry can send it again.

A request whose body was larger than the request buffer keeps its connection too. The upload framing tells the worker where the body ends, so the next byte of the client begins a request. The thread path cannot tell that and closes the connection after such a request.

Three cases end an exchange early. If the response completes while upload bytes remain, the server did not read the body, and the worker closes both sockets after the response. If the client closes its sending side with a complete request, the exchange finishes and the connection closes after the response. If the client closes or fails before the response is complete, the worker closes the server socket.

*Tunnel.* After a validated 101 the two sockets form a byte pipe with one bounded buffer per direction. End of stream on one side shuts down the sending side of the other. A failure closes both.

Sans-I/O machines
~~~~~~~~~~~~~~~~~

The protocol logic of the proxy lives in ``sibuna-net``. Its relays are written against ``Read`` and ``Write`` and block. We add three machines beside them. Each takes input bytes and appends output bytes. None performs I/O, keeps time or allocates per call.

.. list-table:: Machines
   :header-rows: 1
   :widths: 22 78

   * - Machine
     - Behavior
   * - Request encoder
     - Writes the server-bound head with the existing field writer, then the buffered body. Reports the handshake, whether the request is safe to retry, whether its socket may be pooled, and what remains of the upload.
   * - Upload relay
     - Passes the rest of a length-framed body unchanged and counts it. Decodes the rest of a chunked body and re-frames each read as one chunk, then writes the last chunk.
   * - Response relay
     - Finds and parses heads with the existing strict parser, relays up to eight informational heads, rewrites the final head with Sibuna's connection fields, and relays the body by its framing: none, a length, chunks checked line by line, or until close. Validates a 101 against the offered handshake. Reports the status, whether the client connection may continue, and whether the server socket is at a clean boundary.

The machines call the same pure helpers as the blocking relays: the head parser, the field writers, the chunk-size and trailer checks, the upgrade checks. We test each machine against its blocking relay. For the same server bytes, fed in arbitrary pieces, the client bytes and the result must be equal.

Server sockets
~~~~~~~~~~~~~~

Each worker keeps its own idle sockets, at most 64 per server address and 1,024 in all. An idle socket stays registered with the loop. If the server closes it or sends a byte, the worker drops it at once, so a request rarely meets a stale socket. When it does, the worker retries once on a fresh connection, and only a safe, fully buffered request. A socket is pooled only after a framed response read to its end, never after a request that carried a body, a ``HEAD``, a 204 or a 304, and never with a byte left over. These are the rules of the thread path. A reload drops the idle sockets of servers that left the topology.

Buffers and backpressure
~~~~~~~~~~~~~~~~~~~~~~~~

A worker pools 64 KiB request buffers. A connection holds one only while it has unprocessed request bytes. A socket is read into the worker's own block first when the connection holds no buffer, so a connection that waits, a tunnel included, holds none. Response bytes and server-bound bytes wait in vectors that are released when they empty. The worker reads from a socket only while the buffer toward the other side is below its high-water mark of 64 KiB. Level-triggered readiness would spin on a socket we refuse to read, so the worker clears the read interest of a paused socket and restores it when the buffer drains. In the steady state of a keep-alive exchange no interest changes: the client socket stays registered for reading, and so does the pooled server socket.

One readiness event reads each socket of a connection at most once, 64 KiB at most, and causes at most eight rounds of work. The worker then serves the next ready connection, so a bulk transfer or a long pipeline cannot starve small requests.

Deadlines
~~~~~~~~~

A worker keeps a timer wheel with one-second slots. Each connection has one deadline.

.. list-table:: Deadlines
   :header-rows: 1
   :widths: 26 74

   * - State
     - Rule
   * - Idle
     - ``http.idle_timeout`` since the last response.
   * - Head
     - ``http.idle_timeout`` from the first byte of the request. Further bytes do not extend it.
   * - Body and upload
     - The client must deliver 16 KiB per ``http.idle_timeout``.
   * - Connect
     - Five seconds.
   * - Exchange
     - ``http.idle_timeout`` of server silence. Server bytes extend it.
   * - Any write
     - A peer that accepts no byte for ``http.idle_timeout`` loses the connection.
   * - Tunnel
     - ``http.websocket_idle_timeout`` without a byte in either direction. A direction with unsent bytes must make progress within that time on its own.

Limits
~~~~~~

``http.max_connections`` bounds HTTP connections and multiplexed exchanges. Its ceiling rises from 8,192 to the flow table's one million. ``http.max_connections_per_ip`` is unchanged. A connection serves at most 4,096 requests. A worker that cannot obtain a buffer answers 503 and closes.

WebSocket
~~~~~~~~~

The firewall judges the upgrade request like any other request: bans, limits, policy and the challenge of its route apply. The handshake must be a well-formed version 13 offer. The 101 must carry the matching accept key. ``Sec-WebSocket-Protocol`` and ``Sec-WebSocket-Extensions`` pass unchanged in both directions, so subprotocols and permessage-deflate work. After the 101 Sibuna does not parse frames. This is also what hosted firewalls do: the rules run on the handshake.

A frontend or a route may carry ``"websocket": {"origins": ["https://app.example.org"], "max_per_ip": 16}``. With ``origins``, an upgrade whose ``Origin`` field is absent or not listed is refused with 403. This stops cross-site WebSocket hijacking for applications that authenticate by cookie. ``max_per_ip`` bounds the concurrent tunnels of one client on that frontend, and a client over it receives 429. Both checks apply whether or not the route uses the firewall.

HTTP/2 clients may open WebSockets with extended CONNECT (RFC 8441). The protocol runtime advertises the setting, translates such a stream to an HTTP/1.1 upgrade on its handoff, and pipes the stream's data. A pool with ``http_version`` ``"2"`` or ``"3"`` does not receive WebSockets yet and answers 501. HTTP/3 clients do not carry WebSockets. No browser ships RFC 9220, and browsers fall back to HTTP/1.1.

Faults, shutdown and reload
~~~~~~~~~~~~~~~~~~~~~~~~~~~

A panic while a worker serves one connection is caught. The worker closes that connection, counts the fault and continues.

A reload changes nothing for a connection in flight. The next request on a keep-alive connection uses the new routes. On shutdown a worker closes idle connections at once, lets exchanges finish within the drain period of five seconds, and then closes the rest, tunnels included. When one side of a tunnel ends its stream, the worker delivers the bytes already received to the other side and closes both. A tunnel receives no close frame from Sibuna, because Sibuna does not speak the framing.

Observability
~~~~~~~~~~~~~

``/__sibuna/metrics`` gains counters summed over the workers: ``tunnels_opened``, ``origin_reused``, ``origin_connects``, ``origin_retries``, ``deadline_closes`` and ``worker_faults``. Open connections are the existing connection count.

Worked example
~~~~~~~~~~~~~~

A client sends ``GET /a`` on a keep-alive connection. The socket becomes readable. The worker borrows a buffer, reads 80 bytes, finds the blank line and calls dispatch. The policy allows the request. Dispatch reserves server ``s1`` and encodes 210 bytes. The worker finds an idle socket for ``s1``, writes the 210 bytes and returns to the loop. The socket of ``s1`` becomes readable. The worker reads 300 bytes and feeds them to the response relay, which emits 310 bytes and reports a clean boundary. The worker writes them to the client, pools the socket, returns the buffer and leaves the connection Idle. The exchange cost four socket calls and two returns from ``epoll_wait``, each of which may also carry other connections.

Rationale and alternatives
--------------------------

*A complete rewrite of the firewall as asynchronous code* would put every policy function behind a future and discard the tested blocking path. The decision needs no I/O, so it can stay a function.

*An async runtime* (tokio) on this path would add a scheduler between the socket and the decision and a dependency to the firewall, which SID 0010 keeps on the standard library. The protocol runtime uses tokio because rustls, hyper and quinn need it.

*Keeping threads and parking idle connections in epoll* would cut memory for idle connections. It would not cut the context switches of a busy one, which waits for the server on a thread.

*One listener per worker with SO_REUSEPORT* removes the accepting thread from the path. HAProxy and Envoy do this. The kernel then spreads connections by hash, which balances worse under overload in published measurements, and our accepting thread also applies the frontend limits and the flow budget in one place. We keep one acceptor and can add per-worker listeners when accept rate, not request rate, becomes the bound.

*A shared server pool* raises the reuse ratio. Pingora reports 99.92% against 87.1% for per-worker pools at Cloudflare's scale. HAProxy keeps per-thread pools and lets a thread take a socket from a sibling. We start with per-worker pools, which need no lock, and count reuse so that the question can be answered by measurement.

*io_uring* would batch the socket calls. Published comparisons show small gains for small requests without zero-copy, and several platforms disable it. *Kernel splicing* of tunnels loses to plain reads and writes for small frames. Both can be added behind the same machines later, because the machines do not know how bytes arrive.

Security and operational considerations
---------------------------------------

The decision function and the parsers are unchanged, so request validation, smuggling defences and the audit fields are the ones already reviewed. The new risks are in the driver.

- *Starvation.* One slow decision delays the other connections of its worker. Decisions are bounded: the head is at most 16 KiB, the inspected body 64 KiB, and proof verification a fixed number of hashes. The per-turn byte budget bounds transfers.
- *Memory.* A client that opens many connections and sends one byte holds one buffer each until the head deadline. The per-client connection limit and ``http.max_connections`` cap this.
- *Slow readers.* Backpressure stops reading the server. The write deadline closes the connection.
- *Desynchronisation.* Bytes after the end of a response make the socket unpoolable. A pooled socket that becomes readable is closed. A response that ends before its request body closes both sockets.
- *Descriptor reuse.* A record carries a generation. An event for a closed connection whose slot was reused is ignored.
- *Tokens in URLs.* anahita passes a media token in the query string of its WebSocket. Sibuna writes no access log, and incident records redact query strings as before.

Backwards compatibility
-----------------------

The configuration is unchanged except for the higher ceiling of ``http.max_connections`` and the optional ``websocket`` object on a route. Bytes on the wire are those of the thread path, which the differential tests check. ``"http": {"event_loop": false}`` selects the thread path, for comparison and as a fallback.

Acceptance criteria and implementation status
---------------------------------------------

The design is implemented for edge mode on Linux. The classic listener and other platforms keep the thread path.

.. list-table:: Where the design lives
   :header-rows: 1
   :widths: 34 66

   * - Part
     - Code
   * - Poller, waker, record table, timer wheel, non-blocking connect
     - ``crates/reactor`` (``sibuna-reactor``), standard library only
   * - Request encoder, upload relay, response relay
     - ``crates/net/src/machine.rs``
   * - Planned exchange in place of a blocking relay
     - ``Defer`` and ``Plan`` in ``cmd/sibuna/src/dispatch.rs``
   * - Worker, connection states, server pool, tunnels
     - ``cmd/sibuna/src/edge/workers``
   * - WebSocket rules
     - ``crates/lb/src/websocket.rs``
   * - WebSocket over HTTP/2
     - ``crates/ingress/src/tunnel.rs``
   * - Formal model
     - ``docs/sid/assets/event-driven-http-workers.lean``

#. The differential tests pass for the response relay, the upload relay and the request encoder. **Met.** The response relay agrees with the blocking relay on 150,000 mutated responses, each fed whole, in random pieces and one byte at a time.
#. The existing edge tests pass on both paths. **Met.** ``cmd/sibuna/tests/edge_http.rs`` also runs pipelining, every response framing, streamed uploads, WebSocket tunnels, WebSocket rules, server failures and the deadlines on both paths.
#. Beside HAProxy on the host of SID 0015, plaintext HTTP at 256 connections reaches at least 85% of HAProxy's throughput, with a 99th percentile below 5 ms. **Met.** 229,139 against 243,864 requests per second, which is 94%, with a 99th percentile of 2.60 ms.
#. 20,000 idle keep-alive connections hold less than 100 MiB of resident memory. **Met.** They added 8 MiB.
#. 10,000 concurrent WebSockets exchange messages on one node. **Met.** They held 27 MiB of resident memory and every echo was correct.
#. A slow header, a slow body, a slow reader and a silent server are each closed by their deadline, and the other connections of the worker keep their latency. **Met.** Tests cover the slow header, the slow body, the slow reader, the silent server, the idle connection and the idle tunnel. The slow-body and slow-reader test runs one worker and checks that another connection of that worker answers within 500 ms meanwhile.
#. On three nodes with a mesh, clients keep being served while one node stops and returns, and a WebSocket through a surviving node stays open. **Met.** ``benchmarks/results/edge-workers-2026-11-24.md`` holds the record.

Formal model
~~~~~~~~~~~~

The companion file is ``docs/sid/assets/event-driven-http-workers.lean``. From the repository root we check it with Lean 4.19.0.

.. code-block:: console

   lean docs/sid/assets/event-driven-http-workers.lean

.. list-table:: What the model proves
   :header-rows: 1
   :widths: 30 70

   * - Theorem
     - Statement
   * - ``stale_key_never_answers``
     - A readiness key issued for a record does not match after that record was removed, whatever happens to its slot afterwards.
   * - ``arm_after_turned``, ``arm_within_one_turn``, ``slot_is_unique_within_a_turn``
     - A timer entry is filed under a second that has not turned, within one turn of the wheel, and seconds within one turn have distinct slots. So every entry fires, and at the second it was filed under.
   * - ``arm_not_early``, ``far_deadline_makes_progress``
     - A deadline inside the wheel does not fire early. A deadline beyond it fires at the last slot and is armed again.
   * - ``backlog_bounded``
     - With reads only below the high-water mark :math:`H`, a read of at most :math:`B` bytes and framing of at most :math:`g` bytes, the bytes held for a peer stay below :math:`H + B + g`.
   * - ``upload_conserves``, ``upload_never_exceeds``
     - A body with a declared length forwards exactly that many bytes, in any pieces.
   * - ``assign_keeps_balance``
     - Giving each new connection to a worker at the minimum keeps all workers within one connection of the minimum.
   * - ``rounds_bounded``
     - One event causes at most the budgeted number of rounds.

The kernel, socket readiness, the HTTP grammar, generation wrap-around and Rust memory safety are outside the model. The differential tests cover the HTTP grammar.

Known gaps
~~~~~~~~~~

#. HTTP/2 reached 53% to 58% of HAProxy, because each stream crossed a socket pair between the protocol runtime and a worker. SID 0017 removes that hop for HTTP/2 and HTTP/3 requests.
#. *Closed by SID 0019.* The route table was behind one mutex, which every request took once to select a server. A request now reads a snapshot cached by its thread, ``Shared::read`` in ``crates/lb/src/http.rs``, and takes the mutex only when the table changed since its last request.
#. A pool with ``http_version`` 2 or 3 cannot receive a WebSocket.
#. A request that is not safe to repeat and meets a stale pooled socket answers 502. The worker watches idle sockets, so this needs a server that closes in the instant of reuse.
#. The telemetry hooks of the console do not run on the workers. The console of the edge (SID 0031) reads the counters of the edge instead, so it does not depend on them.

Open questions
--------------

#. Should a worker take idle server sockets from its siblings?
#. Should the classic listener move to the workers once this path is qualified?

Review history
--------------

- 2026-11-24. Initial draft: per-core loops, a synchronous decision, sans-I/O relays, per-worker pools.
- 2026-11-24. Implementation and its review. Three-node tests and the load tests found two defects, both fixed: a tunnel kept an empty 64 KiB request buffer for its whole life, and vectors kept the capacity of their largest burst. With them 10,000 tunnels held 106 MiB; without them 27 MiB. The review also moved the protocol-free parts into ``sibuna-reactor``, added the counters, changed the per-turn byte budget into a bound on reads and rounds per event, and recorded the known gaps above. WebSocket toward HTTP/2 pools was specified and is not implemented; the specification now says so.
- 2026-11-24. Second review, after comparing with HAProxy and Envoy. A silent server now answers 504 on the workers. ``http.workers`` sets the worker count. A test covers the slow-body and slow-reader deadlines and checks that other connections of the same worker are not delayed. Those three items left the known gaps.
- 2026-11-25. A connection now stays open after a request body that the worker streamed. Until then both paths closed it, and only the thread path needs to. A test in ``cmd/sibuna/tests/edge_http.rs`` sends a body with a length and a chunked body of 700 kB, each with a request behind it on the same connection.
- 2026-11-24. Author's review before promotion. It added the ordering invariant for pipelined requests, the three early endings of an exchange (a response before the end of an upload, a half-closed client, a failed client), the retention of the encoded request for a retry, fault isolation by connection, the per-turn byte budget, the counters, and the scope of the ``websocket`` route options. It replaced a claim that decisions are cheap with their bounds.

References
----------

- SID 0002, SID 0009, SID 0010 and SID 0015.
- HAProxy, "How HAProxy takes advantage of multi-core CPUs", https://www.haproxy.com/blog/how-haproxy-takes-advantage-of-multi-core-cpus
- Envoy threading model, https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/intro/threading_model
- Cloudflare, "How we built Pingora", https://blog.cloudflare.com/how-we-built-pingora-the-proxy-that-connects-cloudflare-to-the-internet/
- Cloudflare, "The sad state of Linux socket balancing", https://blog.cloudflare.com/the-sad-state-of-linux-socket-balancing/
- Cloudflare, "SOCKMAP - TCP splicing of the future", https://blog.cloudflare.com/sockmap-tcp-splicing-of-the-future/
- Kettle, "HTTP/1.1 must die: the desync endgame", https://portswigger.net/research/http1-must-die
- Kapteko, "15 million web servers", https://kapteko.com/15-million-webservers/
- RFC 6455, RFC 8441, RFC 9112, RFC 9220.
- ``benchmarks/results/edge-workers-2026-11-24.md``.

.. rubric:: Lifecycle event

::

   2026-11-24: prediscussion -> discussion. Design reviewed by the author; open
   for discussion before implementation
