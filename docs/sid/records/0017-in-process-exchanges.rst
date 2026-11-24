:sid-number: 0017
:sid-title: In-Process Exchanges for HTTP/2 and HTTP/3
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-24
:sid-updated: 2026-11-24
:sid-discussion: No external discussion URL assigned
:sid-summary: Decides each HTTP/2 and HTTP/3 request on the thread that decoded it and sends it to its server from there, so a request no longer crosses a socket pair and a second thread.
:sid-labels: ["architecture","load-balancer","network","performance","http2"]

In-Process Exchanges for HTTP/2 and HTTP/3
==========================================

Abstract
--------

The protocol runtime of SID 0015 terminates TLS, HTTP/2 and HTTP/3. Until now it wrote each request as HTTP/1.1 into a socket pair, and an HTTP worker of SID 0016 read it, parsed it again, decided it and forwarded it. We remove that hop. The runtime renders the request head once in memory, calls the firewall decision as a function, and sends an admitted request to its server on a connection it pools itself.

The HTTP/2 and HTTP/3 implementations stay the maintained libraries we use today. We do not write our own framing or header compression. An operator observes one change: HTTP/2 serves 20% to 37% more requests on the same processors.

Motivation and scope
--------------------

SID 0016 measured the CPU time per request by thread group. An HTTP/2 request cost 76 microseconds. The protocol runtime spent 46 of them before a worker saw the request, and the worker spent 30 more to read the same request from a socket and decide it. HAProxy describes the same design in its own history: its first HTTP/2 support converted each stream to HTTP/1 and parsed it twice, and it replaced that with one internal message form and one thread per stream. We take the lesson and keep our libraries.

Writing our own HTTP/2 would remove more overhead. It would also make every known attack on the protocol our own work for as long as the code lives: rapid resets, CONTINUATION floods, HPACK expansion, control-frame floods and flow-control abuse. The libraries carry those defences now. Sibuna is already faster than Envoy on every workload we measured, so we do not need that risk.

This record covers the requests of HTTP/2 and HTTP/3 clients in edge mode when the event-driven workers are on. Three paths keep the socket pair: HTTP/1.1 over TLS, which is a byte relay to a worker; WebSockets over HTTP/2, which are tunnels on a worker; and every request when ``http.event_loop`` is false.

Specification
-------------

Invariants
~~~~~~~~~~

#. The firewall decision is the function of SID 0016. It sees the same request head, as HTTP/1.1 text, and the same bounded start of the body. It performs no I/O and does not wait.
#. No byte reaches a server before the decision admitted the request.
#. The request translation of SID 0015 runs before the decision. A request that could mean two things as HTTP/1.1 is refused there, as before.
#. The server receives the request head that the decision wrote, not the head that the client sent.
#. The server receives the whole body in order: the part that the decision saw, then the rest.
#. A server connection carries one exchange at a time, and returns to the pool only after a complete response.
#. Every wait has a bound.

.. graphviz::
   :caption: One request. The decision is a function call, and the server connection belongs to the runtime.
   :alt: A stream is translated to an HTTP/1.1 head and the start of its body. The decision either answers or admits. An admitted request goes to a pooled server connection and the response returns to the stream.

   digraph inline {
     graph [rankdir=LR, bgcolor="transparent", fontname="Helvetica", fontsize=9, nodesep=0.3, ranksep=0.45];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=8.5, fillcolor="#eff6ff", color="#1e40af", penwidth=1.0, margin="0.1,0.05"];
     edge [color="#64748b", fontname="Helvetica", fontsize=7.5, fontcolor="#475569", arrowsize=0.6];
     stream [label="HTTP/2 or HTTP/3\nstream"];
     offer [label="Offer\nhead, start of body"];
     decide [label="Decide\nfirewall, routes", fillcolor="#fef3c7", color="#92400e"];
     answer [label="Answer\nSibuna's response"];
     server [label="Server\npooled HTTP/1.1"];
     stream -> offer [label="translate, render"];
     offer -> decide [label="call"];
     decide -> answer [label="refused, challenged"];
     decide -> server [label="Forward: target, head"];
     server -> stream [label="response"];
     answer -> stream;
   }

The interface
~~~~~~~~~~~~~

The ingress crate defines the interface and knows nothing of the firewall. It is plain data and one trait:

.. code-block:: rust

   pub struct Offer<'a> {
       pub head: &'a [u8],        // the request head as HTTP/1.1 text
       pub body: &'a [u8],        // the start of the body
       pub body_complete: bool,   // `body` is the whole body
       pub declared: Option<u64>, // the length of the whole body, when known
       pub peer: SocketAddr,
       pub vip: SocketAddr,
   }

   pub enum Verdict {
       Answer(Vec<u8>),           // one HTTP/1.1 response
       Forward(Forward),
   }

   pub struct Forward {
       pub target: HttpTarget,    // the server reservation of SID 0015
       pub head: Vec<u8>,         // the request head for the server
       pub guard: Box<dyn Any + Send>,
   }

   pub trait Decide: Send + Sync + 'static {
       fn decide(&self, offer: &Offer<'_>) -> Verdict;
   }

``Ingress::start`` takes an optional ``Decide``. With one, requests take the in-process path. Without one, they take the socket pair.

The binary implements ``Decide`` with the checks of the connection loop and the dispatch of SID 0016. Each runtime thread holds one scratch space for it: the workspace, the policy snapshot, and the buffers of the planned request. An admitted request is planned exactly as on a worker, and the plan's head becomes ``Forward::head``.

The body
~~~~~~~~

The runtime reads body frames until it holds 64 KiB of head and body together, or the body ends. This is the amount a worker buffers. The decision sees those bytes. If the body is longer, the decision is told so, and the rest streams to the server after admission. The framing toward the server follows the decision's head: a length when the client declared one or the body ended inside the buffer, and chunked coding otherwise.

Server connections
~~~~~~~~~~~~~~~~~~

The runtime keeps idle HTTP/1.1 connections per server address, at most 256 per address, for at most 30 seconds. A connection that the server closed is discarded when it is taken. A safe request without a body is sent once more on a fresh connection when a pooled one fails before any response. Any other request on a failed connection answers 502.

Deadlines
~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 40 20 40

   * - Wait
     - Bound
     - Ending
   * - The start of the request body
     - 15 s
     - 400
   * - Connect to the server
     - 5 s
     - 502, and the server is marked failed
   * - The response head
     - 60 s
     - 504
   * - The next piece of the response body
     - 60 s
     - The stream ends with an error and the server connection closes

A client that reads slowly does not count against the last bound. The body is not polled while the client's window is closed.

Worked example
~~~~~~~~~~~~~~

A browser sends ``GET /app.js`` on stream 5 of an HTTP/2 connection. The runtime translates it and renders 180 bytes of head. The body is empty, so ``declared`` is zero and ``body_complete`` is true. The decision normalises the path, finds no rule that refuses it, selects server ``10.0.0.2:80`` and returns a head with ``X-Forwarded-For``. The runtime takes an idle connection to that address, sends the head, and relays the response frames to stream 5. When the last frame is read, the server's load is recorded and the connection returns to the pool. No other thread took part.

Rationale and alternatives
--------------------------

**Our own HTTP/2 and HPACK inside the workers.** This is the design of HAProxy and removes the second runtime altogether. We rejected it for now because of the security burden above. It stays possible: the ``Decide`` interface does not depend on who decodes the stream.

**A binary handoff in place of HTTP/1.1 text.** SID 0015 proposed it. It would save the second parse and keep the thread hop, which is the larger cost.

**Passing the parsed request instead of text.** The decision and the policy engine read an HTTP/1.1 head. Rendering the head costs one copy of a few hundred bytes. Changing the decision's input would touch every rule and its tests for a small gain.

**Per-thread connection pools.** HAProxy keeps idle connections per thread and lets a thread take from a sibling. Our runtime moves tasks between threads, so we keep one pool behind a lock. The lock is held for a push or a pop.

Security and operational considerations
---------------------------------------

The translation that defends against request smuggling is unchanged and still runs first. The decision is unchanged. The defences of the HTTP/2 and HTTP/3 libraries are unchanged. The path that is new is the client side of an HTTP/1.1 exchange with a server, and it is the library's client, which the socket pair path used too.

The decision runs on a runtime thread, so a slow decision delays the other streams of that thread. The decision is bounded by the limits of SID 0003 and SID 0004 and performs no I/O.

The node-wide bound on concurrent exchanges and the bound of 32 streams per connection apply as before. The per-client connection bound of the firewall counted socket pairs. It does not apply to in-process exchanges; the TLS connection itself is still counted by the flow budget.

Backwards compatibility
-----------------------

No configuration changes. Responses are the same except for one case: a server that sends no response head within 60 seconds now answers 504 on this path.

Acceptance criteria and implementation status
---------------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 50 15 35

   * - Criterion
     - Status
     - Evidence
   * - No request of an HTTP/2 or HTTP/3 client crosses the socket pair
     - met
     - ``crates/ingress/tests/inline.rs`` counts zero handoffs
   * - The firewall's verdicts are the same
     - met
     - Shield mode over HTTP/2: 200, 403 for an injection, 400 for a path traversal, 200 for POST and HEAD
   * - Bodies with and without a length arrive whole
     - met
     - 200,000 bytes over HTTP/2 with a length, 100,000 bytes over HTTP/3 without
   * - A silent and a stalled server end within the bound
     - met
     - The same test, with a bound of 400 ms
   * - HTTP/2 throughput rises by at least 15% with no failed request
     - met
     - See the table below

Requests per second on eight processors, ten streams per connection, before and after:

.. list-table::
   :header-rows: 1
   :widths: 25 25 25 25

   * - Connections
     - Socket pair
     - In process
     - Change
   * - 16
     - 102,774
     - 140,728
     - +37%
   * - 256
     - 97,271
     - 119,084
     - +22%
   * - 2,048
     - 80,277
     - 96,136
     - +20%

No request failed. Resident memory at 2,048 connections fell from 771 MiB to 592 MiB. HTTPS over HTTP/1.1 is unchanged, as expected: it does not use this path.

Formal model
~~~~~~~~~~~~

``docs/sid/assets/in-process-exchanges.lean`` models the two bounded structures of the path and is checked with Lean 4 core.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Theorem
     - Statement
   * - ``shown_is_bounded``
     - The decision is shown at most the budget.
   * - ``server_receives_the_body``
     - The shown part followed by the rest is the body.
   * - ``short_body_is_shown_whole``
     - A body within the budget is decided whole.
   * - ``give_keeps_the_bound``
     - The idle pool never exceeds its capacity.
   * - ``take_shrinks``, ``give_then_take``
     - A connection that was taken is not in the pool, so it has one owner.

The decision itself is the function modelled in SID 0016 and earlier records.

Known gaps
~~~~~~~~~~

#. The worker counters of SID 0016 (``origin_connects``, ``origin_reused``, ``origin_retries``) do not count this path.
#. The response bounds are fixed at 60 seconds. They should follow a per-pool timeout once pools have one.
#. The idle pool is one lock for all runtime threads. At 120,000 requests per second it did not show in the measurements.
#. WebSockets over HTTP/2 and HTTP/1.1 over TLS keep the socket pair.
#. The per-client connection bound does not see HTTP/2 streams.
#. The runtime uses at most eight threads. The worker count option of SID 0016 does not set it.

Open questions
--------------

#. Should plaintext HTTP/2 (h2c) be accepted on HTTP frontends, now that the path exists?
#. Should the runtime's thread count follow ``http.workers``?

Review history
--------------

- 2026-11-24. Initial draft and implementation in one pass, after measuring where an HTTP/2 request spends its time.
- 2026-11-24. Author's review of the implementation. It found that a response body had no deadline: a server that stopped inside a body held its stream until the client gave up. The stall bound and its test were added. It also recorded the known gaps above, of which the missing per-client bound and the fixed timeouts are the ones that matter for production.

References
----------

- SID 0003, SID 0004, SID 0015 and SID 0016.
- HAProxy, ``doc/internals/api/htx-api.txt``, on why it stopped converting HTTP/2 to HTTP/1.
- RFC 9113, HTTP/2, section 8.2.2 on connection-specific fields, and RFC 9114, HTTP/3.
