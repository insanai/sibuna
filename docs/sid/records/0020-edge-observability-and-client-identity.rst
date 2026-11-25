:sid-number: 0020
:sid-title: Edge Observability and Client Identity
:sid-state: accepted
:sid-status: Accepted
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-24
:sid-updated: 2026-11-24
:sid-discussion: No external discussion URL assigned
:sid-summary: Gives the edge load balancer an access log, counters per frontend and per server, a readiness answer, a closed default for its internal routes, the client address behind trusted proxies and the PROXY protocol, and a check of the descriptor limit.
:sid-labels: ["architecture","load-balancer","network","observability","security"]

Edge Observability and Client Identity
======================================

Abstract
--------

An operator of the edge load balancer of SID 0015 cannot yet answer three questions. Which server answered this request, with what status, and how fast? Is this node ready for traffic? Who is the client, when a content network or a cloud balancer stands in front? This record answers them.

We add one access log line per HTTP request, written by one thread from a bounded queue. We add counters and latency histograms per frontend and per server, the health state of each server, and the flow counters of the node. We add a readiness route that turns to 503 when the node drains. We close the health, readiness and metrics routes to everyone outside an allow-list, which is the loopback network by default, and we offer a separate listener for them. We let a frontend name the proxies it trusts, so that ``X-Forwarded-For`` from them names the client, and we let an HTTP or a TCP frontend require the PROXY protocol, version 1 or 2. A shutdown can serve on for a configured time while readiness answers 503. At startup we compare the descriptor limit of the process with what the topology can use, raise the soft limit when the hard limit allows it, and warn when it does not.

Motivation and scope
--------------------

A read-only audit of the edge mode found six gaps that block production use.

#. There is no access log.
#. The counters are process-wide. Nothing is counted per frontend, per backend or per server. There is no health state, no latency and nothing about TCP and UDP flows.
#. There is a liveness route on the data port and no readiness route. A balancer in front cannot see that a node drains.
#. The routes under ``/__sibuna/`` are public on every HTTP frontend. Health and metrics are among them.
#. Behind a content network every client has the address of that network. Rate limits and bans then apply to the network, not to the client.
#. The topology can ask for a million flows while the process may open 1,024 descriptors. Nothing says so until accepts fail.

This record covers edge mode only (``sibuna --config-file``). The daemon of SID 0002 keeps its behaviour: its health and metrics routes stay open, and its ``--trust-forwarded`` option is unchanged.

Out of scope: log shipping and tracing. The section *Known gaps* lists what remains.

Specification
-------------

Invariants
~~~~~~~~~~

#. A request path never waits for the log. A full queue drops the line and counts the drop.
#. Every HTTP request that receives a response from Sibuna or from a server produces at most one line, on each of the three request paths.
#. The health, readiness and metrics routes answer only a client inside the allow-list. Everyone else receives the 404 of an unknown route.
#. A forwarded address is believed only when the socket peer is a trusted proxy of that frontend. A client cannot move the chosen address by writing entries of its own.
#. A PROXY header is read with a bound on its size and on the wait, and only from a trusted proxy. A connection without a valid header is closed before any byte reaches TLS or HTTP.
#. Counters survive a reload. A server keeps its counters while its backend and its name stay in the topology.

.. graphviz::
   :caption: One request and the three places that observe it. The log queue is the only shared structure on the path.
   :alt: A connection passes the optional PROXY stage and reaches one of three request paths. Each path fills one entry. A finished entry updates the counters and is offered to the bounded queue. One writer thread takes entries from the queue and writes lines.

   digraph observe {
     graph [rankdir=LR, bgcolor="transparent", fontname="Helvetica", fontsize=9, nodesep=0.3, ranksep=0.45];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=8.5, fillcolor="#eff6ff", color="#1e40af", penwidth=1.0, margin="0.1,0.05"];
     edge [color="#64748b", fontname="Helvetica", fontsize=7.5, fontcolor="#475569", arrowsize=0.6];
     accept [label="accept"];
     stage [label="PROXY stage\nbounded, optional", fillcolor="#fef3c7", color="#92400e"];
     paths [label="request path\nworker, in-process\nor thread"];
     entry [label="entry\none per request"];
     stats [label="counters\nper frontend, per server"];
     queue [label="bounded queue\ndrop and count", fillcolor="#fef3c7", color="#92400e"];
     writer [label="writer thread\nJSON lines"];
     accept -> stage [label="proxy_protocol"];
     accept -> paths;
     stage -> paths [label="client address"];
     paths -> entry [label="dispatch"];
     entry -> stats [label="settle"];
     entry -> queue [label="try_send"];
     queue -> writer;
   }

Configuration
~~~~~~~~~~~~~

The topology gains one object at its root, one key in ``global`` and two options on a frontend. In JLV:

.. code-block:: text

   observability {
     access_log {
       output: "/var/log/sibuna/access.log"   // a path, "stdout" or "stderr"
       queue: 8192                             // entries; 64 to 1048576
     }
     internal_allow: ["127.0.0.0/8", "::1/128"]
     listen: "127.0.0.1:9180"
   }
   global { drain_delay: "10s" }

.. list-table::
   :header-rows: 1
   :widths: 34 22 44

   * - Key
     - Default
     - Meaning
   * - ``observability.access_log.output``
     - no log
     - A file path, ``stdout`` or ``stderr``. Without the ``access_log`` object nothing is logged.
   * - ``observability.access_log.format``
     - ``json``
     - Only ``json`` exists: one JSON object per line.
   * - ``observability.access_log.queue``
     - ``8192``
     - The capacity of the queue in entries, from 64 to 1,048,576.
   * - ``observability.internal_allow``
     - ``["127.0.0.0/8", "::1/128"]``
     - The networks that may read ``/__sibuna/health``, ``/__sibuna/ready`` and ``/__sibuna/metrics`` on an HTTP frontend. At most 64 entries. An empty list closes the routes on the data ports.
   * - ``observability.listen``
     - none
     - A numeric ``IP:port`` for a separate listener that serves ``/health``, ``/ready`` and ``/metrics``. It applies no allow-list of its own: its bind address is its access control.
   * - ``global.drain_delay``
     - ``0s``
     - How long a shutdown keeps serving while readiness answers 503, before the listeners stop. At most ``10m``.
   * - ``frontends.<name>.trusted_proxies``
     - ``[]``
     - HTTP and TCP frontends. The networks of the proxies in front of this frontend, at most 64. A TCP frontend reads it only with ``proxy_protocol``.
   * - ``frontends.<name>.proxy_protocol``
     - ``false``
     - HTTP and TCP frontends. Every connection must begin with a PROXY header, version 1 or 2. It needs a non-empty ``trusted_proxies``.

A reload changes the output of the access log, turns the log on and off, and replaces ``internal_allow``. The new file is opened before anything is reloaded, so a path that cannot be opened refuses the reload as a whole. The writer changes the file between two lines. Two settings are fixed when the process starts: ``observability.listen``, because its socket is bound once, and the ``queue`` of a running log, because the channel has its length from its creation. A reload that changes one of them is refused, and the node keeps its routes. The frontend options and ``global.drain_delay`` follow a reload.

The default is no log. A line per request costs disk and holds client addresses, so we do not write one unasked. The quick start takes ``--access-log PATH|stdout|stderr`` and prints the same ``observability`` object with ``--print-config``.

The access log
~~~~~~~~~~~~~~

A request path fills one entry and settles it when the response ends. Settling updates the counters and offers the entry to the queue with ``try_send``. The queue is the bounded channel of the standard library. One thread, ``edge-access-log``, takes entries, formats each as one JSON object and writes it through a buffer. It flushes when the queue is empty, and at least once per second.

The queue holds entries, not text, so that formatting runs on the writer thread. An entry owns one string for the client, host, method and path, and shares the names of the frontend, the backend and the server.

A full queue drops the entry. The drop is counted in ``sibuna_edge_access_log_dropped_total``. A write error drops the line, counts it in ``sibuna_edge_access_log_errors_total``, and reports the first error of each minute on standard error.

SIGHUP reopens a file destination, before the topology is read again and whether or not the new topology is accepted. The admin command ``reopen log`` reopens it without reading the topology. A log rotation therefore renames the file and sends the command, or SIGHUP when a reload of the file does no harm. The writer reopens the path between two lines, so no line is split.

The fields are fixed. Their order is the order below.

.. list-table::
   :header-rows: 1
   :widths: 18 82

   * - Field
     - Meaning
   * - ``time``
     - When the request was dispatched, as UTC in RFC 3339 with milliseconds.
   * - ``client``
     - The address the request was judged by: the forwarded address from a trusted proxy, the source of a PROXY header, or the socket peer.
   * - ``frontend``
     - The name of the frontend, or ``-`` when the listener is unknown.
   * - ``protocol``
     - ``http/1.1``, ``h2`` or ``h3``.
   * - ``scheme``
     - ``https`` when the client reached a TLS frontend, else ``http``.
   * - ``tls_version``
     - ``1.2`` or ``1.3``, or ``-`` without TLS.
   * - ``tls_cipher``
     - The IANA name of the cipher suite, such as ``TLS13_AES_128_GCM_SHA256``. ``-`` without TLS, and ``-`` for ``h3``: the QUIC library does not tell which suite it negotiated.
   * - ``method``
     - The request method, or ``-`` for a request that did not parse.
   * - ``host``
     - The ``Host`` field, at most 255 bytes.
   * - ``path``
     - The path in normal form, without the query, at most 1,024 bytes.
   * - ``status``
     - The status sent to the client. ``499`` when the client gave the request up before any response: it closed the connection or reset the stream. No client receives a 499.
   * - ``bytes_in``
     - See the table of byte counts below.
   * - ``bytes_out``
     - See the table of byte counts below.
   * - ``duration_ms``
     - From the dispatch of the request to the end of the response, in milliseconds with three decimals.
   * - ``ttfb_ms``
     - From the dispatch to the first response byte of the server, or ``null`` when no server answered.
   * - ``backend``
     - The backend pool, or ``-``.
   * - ``server``
     - The server name, or ``-``.
   * - ``verdict``
     - What the firewall decided: ``pass``, ``deny``, ``challenge``, ``rate_limited``, ``banned``, ``internal`` for a reserved route, or ``-`` when the request was refused before the decision.

``bytes_in`` and ``bytes_out`` have one meaning on every path: the bytes of the HTTP message as HTTP/1.1 carries it, without TLS. For ``http/1.1`` that is the message itself. HTTP/2 and HTTP/3 compress heads and frame bodies inside the protocol libraries, which do not tell us the sizes. For them a head counts as its HTTP/1.1 text and a body as its data bytes. Each count has a test on its path.

.. list-table::
   :header-rows: 1
   :widths: 22 39 39

   * - Client protocol
     - ``bytes_in``
     - ``bytes_out``
   * - ``http/1.1``
     - The head exactly as received, with its blank line, plus the body. A body with a length counts that length. A chunked body counts its data bytes: the chunk framing is removed before the request is judged, and its size is not kept. Of a chunked body that is larger than one connection buffer, only the buffered part is counted.
     - Exact: every byte written towards the client before TLS, with heads, interim heads and chunk framing. The body of a response to HEAD, which is dropped, is not counted.
   * - ``h2``, ``h3``
     - The head as HTTP/1.1 text, plus the body data bytes that the client sent and that went on towards the server. Of a request that Sibuna answers itself, the body bytes that were read for the decision.
     - The head as HTTP/1.1 text, the body data bytes, and the trailers as text. The fields that the protocol library adds itself, such as ``date``, are not counted.
   * - ``h2``, ``h3`` on the thread path
     - As ``http/1.1``, of the HTTP/1.1 text that the runtime hands to the thread.
     - As ``http/1.1``, of the HTTP/1.1 text that the thread writes.
   * - Refused before the decision
     - 0
     - 0 for ``h2`` and ``h3``. Exact for ``http/1.1``.

Strings are escaped as JSON. Bytes outside printable ASCII are written as ``\u00XX``, so a line is always ASCII and one line.

The query string is not logged. It often carries tokens, and the challenge routes carry solutions in it.

The three request paths
~~~~~~~~~~~~~~~~~~~~~~~

The dispatch of SID 0002 is one function for all paths. At its end it captures the entry from the request context: the time, the client, the names and the verdict. What remains differs by path.

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Path
     - Where the entry is settled
   * - Thread per connection
     - After each request, from the response writer of the connection. The writer counts the bytes and reads the status from the first twelve bytes of the final head. It passes over interim heads wherever the writes cut them. When the relay to the server failed, the dispatch says so, and only then is a 502 or 504 Sibuna's own.
   * - Event-driven worker
     - A response of Sibuna's own is settled where the request was decided. An admitted request moves its entry to the connection record. The entry is settled when the exchange finishes, when Sibuna answers for a failed server, or when the connection closes inside the exchange.
   * - In process (HTTP/2, HTTP/3)
     - A response of Sibuna's own is settled in the decision. An admitted request gives the protocol runtime a ``Report``. The runtime calls it once with the status, the body bytes and the wait for the response head, when the body ends or is dropped. The binary measures the whole duration itself.

The ingress crate does not depend on the binary. Its interface of SID 0017 gains one trait and two fields:

.. code-block:: rust

   pub struct Completion {
       pub status: u16,                  // 0 when the client left before a response head
       pub bytes_out: u64,               // response body bytes
       pub first_byte: Option<Duration>, // from the send to the response head
   }

   pub trait Report: Send + 'static {
       fn done(self: Box<Self>, completion: &Completion);
   }

   // Offer gains `protocol: &'static str`; Forward gains `report: Option<Box<dyn Report>>`.

A request that does not parse has no context. The paths that own a response writer log it with the client, the status and ``-`` for the fields they do not know.

The protocol runtime answers some requests before any decision: 503 when the node runs as many HTTP/2 and HTTP/3 requests as it may, 417 for an expectation it cannot meet, 400 or 501 for a request that does not translate to HTTP/1.1, and 400 for a body that does not arrive. The trait ``Decide`` gains ``refused(&Refused)``, with the client, the listener, the protocol, the status, the method, the authority and the path. The binary counts the refusal by its reason and writes a line with verdict ``-``. Without the event-driven workers there is no decision in the runtime. The runtime then tells a hook of its own, ``Ingress::report_refusals``, so a refusal is logged and counted on every path. A request whose body the client cut off while it was read is reported with status 499 and counted as ``client_closed``.

Counters
~~~~~~~~

The registry lives in the load balancer crate. It maps a frontend name, and a backend and server name, to a block of atomic counters. A reload looks the names up again, so counters continue. Names that left the topology are removed.

A request reads no map to count. The routing table of SID 0015 hands the frontend's block to the request context, and the server reservation carries the server's block.

The metrics route and the separate listener write the process counters of SID 0002 first and then these series:

.. list-table::
   :header-rows: 1
   :widths: 52 48

   * - Series
     - Meaning
   * - ``sibuna_edge_frontend_requests_total{frontend,code}``
     - HTTP requests by status class: ``1xx`` to ``5xx``, and ``none`` for no status.
   * - ``sibuna_edge_frontend_bytes_in_total{frontend}``, ``..._bytes_out_total``
     - The byte counts of the log.
   * - ``sibuna_edge_frontend_request_seconds{frontend}``
     - A histogram of ``duration_ms``.
   * - ``sibuna_edge_frontend_flows_total{frontend}``
     - TCP connections and UDP mappings accepted by a frontend.
   * - ``sibuna_edge_server_requests_total{backend,server,code}``
     - Requests a server was chosen for, by status class.
   * - ``sibuna_edge_server_failures_total{backend,server}``
     - Requests a server was chosen for that ended without its response, because the server failed. A request that its client gave up is not one of them.
   * - ``sibuna_edge_server_client_closed_total{backend,server}``
     - Requests a server was chosen for that their client gave up before the server answered.
   * - ``sibuna_edge_server_response_seconds{backend,server}``
     - A histogram of ``ttfb_ms``.
   * - ``sibuna_edge_server_up{backend,server}``
     - 1 when the last health check passed or the pool has none, else 0.
   * - ``sibuna_edge_server_active_requests{backend,server}``
     - HTTP requests that chose the server and have not ended. A request that moved to another server (SID 0019) counts under the one it moved to.
   * - ``sibuna_edge_refused_total{reason}``
     - Connections and requests refused before the firewall decided. See the reasons below.
   * - ``sibuna_edge_flows_active``, ``sibuna_edge_flows_limit``, ``sibuna_edge_drops_total``
     - The flow table of the node.
   * - ``sibuna_edge_ready``
     - 1 until the node drains.
   * - ``sibuna_edge_access_log_written_total``, ``..._dropped_total``, ``..._errors_total``
     - The log.
   * - ``sibuna_edge_access_log_queue_length``
     - The length of the log queue in force, or 0 without a log.
   * - ``sibuna_edge_flow_log_dropped_total``
     - Flow lines dropped between the load balancer and the log queue.
   * - ``sibuna_edge_proxy_protocol_accepted_total``, ``..._rejected_total``
     - Connections of PROXY frontends.

The histograms have fixed bounds: 1, 2.5, 5, 10, 25, 50, 100, 250, 500 ms, 1, 2.5, 5, 10 and 30 s.

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - ``reason``
     - What was refused
   * - ``rate_limit``
     - A TCP connection of a client above ``rate_limit.conn_per_10s``.
   * - ``flow_limit``
     - A TCP connection when the node holds ``global.max_flows`` flows.
   * - ``draining``
     - A TCP connection that arrived while the listeners stop.
   * - ``connection_limit``
     - An HTTP connection above ``http.max_connections``.
   * - ``client_limit``
     - An HTTP connection above ``http.max_connections_per_ip`` of its client.
   * - ``task_limit``
     - An HTTP connection for which no thread was free, on the thread path.
   * - ``exchange_limit``
     - An HTTP/2 or HTTP/3 request above the request bound of the runtime (503).
   * - ``bad_request``
     - An HTTP/2 or HTTP/3 request that the runtime answered 400, 417 or 501.
   * - ``client_closed``
     - An HTTP/2 or HTTP/3 request whose client reset the stream while the request was read. Nothing was refused. The reason keeps it apart from ``bad_request``.
   * - ``no_server``
     - A TCP connection or a UDP datagram for which no server of the pool was eligible.
   * - ``udp_rate_limit``
     - A datagram of a client above ``udp_defense.threshold_pps``.
   * - ``udp_flow_limit``
     - A datagram of a new client when no UDP mapping was free.
   * - ``udp_reply_limit``
     - An answer of a UDP server larger than three times what its client sent.

A refused request has a counter and a request line. A refused connection has a counter and a flow line, at most ten lines per second for the whole node.

**A client that leaves is not a failed server.** Every answer has a status: the server's, or Sibuna's own 502 or 504 for a server that failed. So an exchange that ends without a status was given up by its client. We log it with status 499, count it in ``sibuna_edge_server_client_closed_total``, and count no failure. The frontend counts it in the class ``4xx``. Passive health (SID 0019) is told of a failure only where a server event is seen: a refused or timed out connect, a connection that the server closed without an answer, and a silence longer than the response bound. None of these sites runs when the client leaves. This holds for the workers, the in-process path and the thread path.

A server that ``sibuna ctl`` adds at run time gets its series at once. A server that a command removes loses its series at once. A request that was decided before a reload and is routed by the retired revision (SID 0018) is counted under the server of that revision, by name: the retired revision keeps its own table of names.

Readiness and access control
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``/__sibuna/ready`` answers 200 with ``{"status":"ready"}`` while the node serves, and 503 with ``{"status":"draining"}`` after a shutdown or drain began. ``/__sibuna/health`` stays a liveness answer.

A shutdown has three steps:

.. code-block:: text

   SIGTERM
     |  readiness answers 503; listeners accept; requests are served
     |<------------ global.drain_delay (default 0s) ------------>|
     |  listeners stop; established flows and requests finish
     |<------------ global.shutdown_timeout (default 5s) ------->|
     v  what is still open is closed; the process ends

The delay exists for a balancer in front that learns of the drain from the readiness answer. It should be a little longer than the probe interval times the failure threshold of that balancer. The default is zero, because without such a balancer the delay only makes every stop slower. The longest time from the signal to the end of the process is the sum of the two settings.

When a new process takes the port over with ``reuse_port`` (SID 0018), nothing in front needs to notice, and the delay can stay zero. With a delay, the old and the new process both accept during it, and the kernel shares new connections between them.

In edge mode the three routes answer only when all of the following hold. Otherwise the answer is the 404 of an unknown route.

#. The socket peer is inside ``internal_allow``.
#. The client address the request is judged by is inside ``internal_allow``.
#. The request has no ``X-Forwarded-For``, ``X-Real-IP`` or ``Forwarded`` field.

The third rule exists for a proxy on the same host. Its requests arrive from the loopback address on behalf of anyone. A proxy that forwards adds one of these fields; a local probe does not.

The solver assets, the challenge routes and the honeypot stay public, because clients need them.

The separate listener is the module ``probe``. One thread accepts. Up to eight connections are served at once, each on a short-lived thread, so that a client that sends nothing does not delay a health check. A ninth is served by the accepting thread itself, which bounds the threads. Each connection carries one request. The listener reads at most 4,096 bytes of head within two seconds, and answers ``GET`` and ``HEAD`` for ``/health``, ``/ready`` and ``/metrics``, with or without the ``/__sibuna`` prefix. Another method is answered 501 and another path 404. It also runs without any HTTP frontend. The admin socket of SID 0018 prints the same series of the edge with ``show stats``.

Trusted proxies
~~~~~~~~~~~~~~~

A frontend lists the networks of the proxies in front of it. When the socket peer of a request is inside the list, we read the ``X-Forwarded-For`` fields as one list and walk it from the right. The client is the first entry that is not a trusted proxy. When every entry is a trusted proxy, the client is the leftmost entry. When there is no field, or an entry on the walk is not an address, the client is the socket peer, and ``sibuna_forwarded_invalid_total`` counts a malformed entry.

Each proxy appends the address it received the request from. The entries a client can write are therefore to the left of the first untrusted address, and the walk never reads them.

The chosen address is the client for the ban table, the request limiter, policy rules, the challenge fingerprint and the log. The per-client connection bound of the firewall counts socket peers, so it does not apply to a connection from a trusted proxy.

The connection rate of a frontend, ``rate_limit.conn_per_10s``, has the same rule. A connection whose socket peer is a trusted proxy is not counted: the proxy carries the connections of many clients, and one budget for all of them would throttle them together. An HTTP connection through such a proxy does not name one client, so nothing replaces the count there; the request limiter counts each client by its forwarded address. With the PROXY protocol the connection does name its client, and the rate counts that client.

The PROXY protocol
~~~~~~~~~~~~~~~~~~

A frontend with ``proxy_protocol: true`` holds each accepted connection until its header arrives. This happens in the worker of the load balancer crate, which accepts the connection, so HTTP and TCP frontends share it and no extra thread exists. The worker holds at most 4,096 such connections, each for at most five seconds, and each holds a flow permit.

When a connection becomes readable, the worker looks at the first bytes without taking them (``MSG_PEEK``, at most 536 bytes) and parses them:

.. code-block:: text

   v1  "PROXY TCP4 <src> <dst> <sport> <dport>\r\n"   at most 107 bytes
       "PROXY TCP6 ..."   "PROXY UNKNOWN ...\r\n"
   v2  12 signature bytes, version and command, family and protocol,
       a 16-bit length, then addresses and extensions   at most 16 + 520 bytes

The parser is one function over a byte slice with three results: a header of ``n`` bytes with a source address, a header of ``n`` bytes without one (``UNKNOWN`` or ``LOCAL``), or a refusal. A complete header must be inside the first look. This is the rule of HAProxy's own receiver and of the protocol text, which requires a sender to write the header in one piece. The worker then reads exactly ``n`` bytes, so the first byte of TLS, HTTP or the TCP payload is the next one.

A connection is closed and counted when its socket peer is not a trusted proxy, when the header is malformed, incomplete or longer than the bound, or when the five seconds pass. A v1 address must be canonical: no leading zeros, a port from 0 to 65535 without a sign. A v2 header must have version 2, a known command, and a length that covers its address block.

The source address replaces the socket peer for everything that follows. On an HTTP frontend that is the connection rate, the connection bounds, the trusted-proxy walk, the allow-list of the internal routes and the log. On a TCP frontend it is the connection rate, the choice of the server, source stickiness (SID 0019, ``sticky: "source"``) and the PROXY header that a pool with ``proxy_v2`` sends to its server. A header without a source keeps the socket peer.

A source inside ``trusted_proxies`` is itself a trusted proxy. Its ``X-Forwarded-For`` is then read, and its connections are not rate limited. A source outside the list is a client, and what it wrote in the field is ignored.

The bound of 536 bytes is the 16 fixed bytes, the largest address block (216 bytes, for the Unix family, which we accept and ignore) and 304 bytes of extensions. A sender that adds longer extensions, such as a full TLS client certificate, is refused.

The descriptor limit
~~~~~~~~~~~~~~~~~~~~

A flow uses two descriptors: one to the client and one to the server. A server connection that waits for reuse uses one. At startup we compute

.. math::

   need = 2 \cdot max\_flows + 2 \cdot http.max\_connections + idle + 512

where the HTTP terms are zero without an HTTP frontend. ``idle`` is the bound on the server connections kept for reuse:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Who keeps them
     - Bound
   * - The event-driven workers
     - Each worker keeps at most its share of ``http.max_connections``: the quotient by the number of workers, at least 1 and at most 1,024. Together that is at most ``http.max_connections``, or the number of workers when that is larger.
   * - The protocol runtime, with a TLS frontend and the workers
     - 256 for each server of an HTTP pool.
   * - The thread path
     - 256 in all. They are inside the 512.

The 512 hold what has a fixed bound: at most 128 listeners, the 256 idle server connections of the thread path, the one socket of the mesh, and the files and pollers of the threads. A compile-time assertion keeps these inside the reserve. When the soft limit is below the need, we raise it to the smaller of the need and the hard limit. When it is still below, we print a warning and continue:

.. code-block:: text

   -- DESCRIPTOR LIMIT TOO LOW ------------------------------------ edge.jlv

   This topology can use 19968 file descriptors, but the process may open 4096.

   global.max_flows = 8192, http.max_connections = 1024, idle server connections = 1024
   need = 2 * 8192 + 2 * 1024 + 1024 + 512 = 19968

   Hint: Raise the limit (`LimitNOFILE=19968` in the systemd unit, or `ulimit -n 19968`),
   or lower `global.max_flows` and `http.max_connections`.

The two system calls live in a new FFI module of the reactor crate, beside the poller.

Worked example
~~~~~~~~~~~~~~

A content network at 198.51.100.0/24 reaches the frontend ``web``. A client at 203.0.113.7 sends ``X-Forwarded-For: 10.9.9.9`` of its own. The network appends the client's address. The request arrives from 198.51.100.4 with ``X-Forwarded-For: 10.9.9.9, 203.0.113.7``. The peer is trusted. The walk reads 203.0.113.7 first, which is not trusted, and stops. The forged 10.9.9.9 is never read. The log line is:

.. code-block:: json

   {"time":"2026-11-24T10:15:02.418Z","client":"203.0.113.7","frontend":"web","protocol":"http/1.1","scheme":"http","method":"GET","host":"www.example.com","path":"/index.html","status":200,"bytes_in":112,"bytes_out":5310,"duration_ms":3.184,"ttfb_ms":2.907,"backend":"app","server":"app-2","verdict":"pass"}

Second round
~~~~~~~~~~~~

The first implementation left gaps that this section closes. Each paragraph is the design. The sections above describe the result.

**The TLS version and cipher suite.** The handler of the protocol runtime took the fingerprint of the client certificate as its fourth argument. It now takes a small value, ``Secured``, with the fingerprint, the version and the cipher suite of the handshake. ``Offer`` carries the same two names. The log gains ``tls_version`` (``1.2``, ``1.3``) and ``tls_cipher`` (the IANA name, such as ``TLS13_AES_128_GCM_SHA256``) after ``scheme``. Both are ``-`` on a plain frontend. A QUIC connection is always TLS 1.3. Its cipher suite is ``-``: the QUIC library does not tell us the suite it negotiated.

**One meaning for the byte counts.** ``bytes_in`` and ``bytes_out`` are the bytes of the HTTP message as HTTP/1.1 carries it, without TLS. The parser keeps the length of the head as received. The runtime reports the response head and the trailers as text, and the request body bytes that it sent on. The table of byte counts has one row per protocol, and it names the one case that is not exact: the framing of a chunked HTTP/1.1 request body, which is removed in place before the request is judged.

**Flow lines.** A TCP connection and a UDP mapping write one line when they end. The worker and the relay threads of the load balancer offer a ``FlowEnd`` to a bounded channel with ``try_send``. A full channel drops the line and counts it in ``sibuna_edge_flow_log_dropped_total``. The loop of the edge takes the lines after each step and offers them to the queue of the access log, which is bounded too. So no thread of the data path waits. Without a log the load balancer builds no line at all. A topology without an HTTP frontend has the log too, and ``sibuna lb --access-log`` works with ``--proto tcp`` and ``--proto udp``. At the end of a shutdown the flows that are still open are closed, and their lines say ``shutdown``.

.. code-block:: text

   relay threads --try_send--+
                             v
   lb worker ---try_send--> [ 4,096 flow ends ] --edge loop--> [ log queue ] --> writer
                             | full: drop, count                | full: drop, count

.. list-table::
   :header-rows: 1
   :widths: 18 82

   * - Field
     - Meaning
   * - ``time``
     - When the flow ended, as UTC in RFC 3339 with milliseconds.
   * - ``client``
     - The client address: the source of a PROXY header, or the socket peer.
   * - ``frontend``
     - The name of the frontend.
   * - ``protocol``
     - ``tcp`` or ``udp``. A refused connection of an HTTP frontend is ``tcp``. A connection that the HTTP server refused has ``-`` for the frontend and the backend.
   * - ``backend``, ``server``
     - The pool and the address of the server, or ``-`` when no server was reached.
   * - ``bytes_in``, ``bytes_out``
     - Payload bytes from the client and to the client.
   * - ``duration_ms``
     - From the accepted connection, or the first datagram, to the end.
   * - ``end``
     - Why the flow ended. See below.

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - ``end``
     - Meaning
   * - ``client_closed``, ``server_closed``
     - Both directions ended in order. The name says which side closed first.
   * - ``reset``
     - A read or a write failed.
   * - ``idle_timeout``
     - Nothing moved for the session timeout of the frontend.
   * - ``connect_failed``
     - No server of the pool accepted the connection.
   * - ``no_server``
     - The pool had no eligible server, or a rule denied the connection.
   * - ``evicted``
     - A UDP mapping without an answer gave way to a new client.
   * - ``send_failed``
     - A datagram could not be sent to the server.
   * - ``shutdown``
     - The node stopped while the flow was open.
   * - ``refused_<reason>``
     - The connection was refused. The reason is a label of ``sibuna_edge_refused_total``.

**Refused connections.** A refusal is counted always and logged at most ten times per second for the whole node. A flood of refused connections therefore writes at most ten lines per second, about 2 KiB, and the counter still has every one. The limit is a count per wall-clock second, kept in one atomic word.

**Reasons for UDP drops.** ``sibuna_edge_refused_total`` gains ``udp_rate_limit`` (a datagram above ``udp_defense.threshold_pps``), ``udp_flow_limit`` (no slot for a new mapping) and ``udp_reply_limit`` (an answer larger than three times what the client sent). ``no_server`` counts a connection or datagram for which no server was eligible.

**Refusals of the runtime on every path.** The hook of the first round reached the decision, which exists only with the event-driven workers. The runtime now has a hook of its own, ``Ingress::report_refusals``, and uses it when there is no decision.

**A reload of ``listen`` and of the queue.** A reload that changes ``observability.listen`` binds the new address first. When the bind fails, the reload is refused and the old listener keeps serving. Otherwise the old listener closes after the reload. A reload that changes ``queue`` creates a new channel. Entries go to the new channel from then on. The writer empties the old channel, learns from its closing that no entry follows, and turns to the new one. So no line is lost or changes its order, and the reload does not wait for the disk. A topology without an HTTP frontend follows a reload of ``observability`` in the same way.

**Descriptors of idle server connections.** Each event-driven worker keeps idle server connections for reuse. A worker now keeps at most its share of ``http.max_connections``, and the need counts the bound of every worker and that of the protocol runtime. The section *The descriptor limit* has the formula.

**Rotation without a reload.** SIGHUP reopens the log and also reloads the topology file, which replaces the run-time changes of ``sibuna ctl``. A nightly rotation must not do that. The admin socket gains ``reopen log``, which only reopens the file. The packaged unit gets ``LogsDirectory=sibuna``, because the rest of the system is read-only for the daemon, and the packages install ``/etc/logrotate.d/sibuna-edge``, which calls the command.

**A client abort.** A load run showed server failures and bad requests where nothing had failed: the load tool reset its streams at its end. The section *Counters* has the rule that replaced the miscount.

Rationale and alternatives
--------------------------

**Formatting on the worker.** A worker could format the line and send text. That costs a few hundred nanoseconds on the request path for a line that may be dropped. We send the entry.

**A lock-free ring of our own.** The bounded channel of the standard library does not block on ``try_send`` and is maintained by others. We found no reason to write a queue.

**Blocking when the queue is full.** Some balancers offer it for audit logs. A slow disk would then stop traffic. We drop and count, and an operator who needs every line can size the queue and watch the counter.

**The common log format.** It has no place for the server, the times or the verdict, and every consumer would need a custom parser. JSON lines are read by every log pipeline.

**A hop count for forwarded addresses.** The daemon's ``--trusted-hops`` counts entries from the right. A content network has a varying number of hops, and a wrong count trusts a forged entry. Naming the networks is the usual rule and fails closed.

**Only a separate listener for health and metrics.** It is the cleanest control. Many deployments probe the data port, though, so we keep the routes there and close them by default.

**A stage thread for the PROXY header.** The first implementation read the header on a thread of the binary, for HTTP frontends only. The worker of the load balancer already owns a poller and already holds connections for the TLS hello of SID 0015, so the header moved there. TCP frontends gained the protocol, and the thread is gone.

**The TLS version in the log.** The first round left it out, because the handler interface of the protocol runtime did not carry it. The second round changed the interface: the handler takes one value with the certificate, the version and the suite, so the next addition does not change every caller again.

**Reading a PROXY header across several reads.** It would need a buffer in front of TLS, which takes its bytes from the socket. Peeking keeps the socket the only buffer.

Security and operational considerations
---------------------------------------

The log holds client addresses and paths. Its file is created with mode 0640 and belongs to the user of the process. Paths are escaped, so a request cannot forge a second line.

A trusted proxy is trusted completely: it can name any client. The list must hold only networks whose every host is a proxy of ours.

A connection that waits for its PROXY header holds a flow permit, so the waiting connections cannot exceed the flow table, and their own bound of 4,096 keeps a flood of silent connections from filling the table for five seconds each.

The metrics text grows with the topology: about 3 KiB per server and per frontend. It is built per request and not cached.

The frontend rate limit of SID 0015 (``rate_limit.conn_per_10s``) does not count a trusted proxy and counts the client of a PROXY header. A frontend behind a proxy that sends only ``X-Forwarded-For`` therefore has no connection rate for the clients of that proxy. The request limiter of the firewall is the limit there.

Backwards compatibility
-----------------------

In edge mode ``/__sibuna/health`` and ``/__sibuna/metrics`` now answer 404 to clients outside the loopback network. A probe from another host needs ``internal_allow`` or the separate listener. The daemon mode is unchanged.

The ingress interface gains fields, so code that builds an ``Offer`` or a ``Forward`` names them.

The log gained the field ``scheme`` after ``protocol``, and HTTP/1.1 over TLS is now ``"protocol":"http/1.1","scheme":"https"`` where the first implementation wrote ``"protocol":"https"``. A consumer that matched ``https`` in ``protocol`` reads ``scheme`` instead.

Acceptance criteria and implementation status
---------------------------------------------

Implemented on the branch ``sid-0020-observability``. Every criterion has a test that runs in ``cargo test --workspace``. The tests in ``edge_*.rs`` start the binary.

.. list-table::
   :header-rows: 1
   :widths: 46 54

   * - Criterion
     - Test
   * - A request on the event-driven path and on the thread path writes one line with every field. The query is absent. A request that does not parse is logged.
     - ``edge_observe.rs``: ``each_request_is_one_line_with_its_server_status_and_times``
   * - A failed server is a 502 line without ``ttfb_ms`` and one failure of that server.
     - ``edge_observe.rs``: ``a_failed_server_is_logged_as_502_without_a_first_byte_and_counted``
   * - The in-process path reports each forwarded exchange once, with status, body bytes, first byte and protocol, on a pooled HTTP/1.1 connection and on a shared HTTP/2 session.
     - ``crates/ingress/tests/inline.rs``, ``crates/ingress/tests/grpc.rs``, ``cmd/sibuna/tests/edge_observe_h2.rs``
   * - A full queue drops and counts. Written plus dropped is offered. The request path does not wait.
     - ``access::sink::tests::every_offered_entry_is_written_or_counted_as_dropped``
   * - A line is ASCII JSON, and a request cannot forge a second line.
     - ``access::sink::tests::a_request_cannot_forge_a_second_line``
   * - SIGHUP reopens the file after a rotation.
     - ``edge_observe.rs``: ``sighup_reopens_the_log_after_a_rotation``, and ``access::sink::tests::a_reopen_follows_a_rotated_file_and_splits_no_line``
   * - The series exist per frontend and per server, and survive a reload by name.
     - ``crates/lb/tests/observe.rs``, ``crates/lb/src/stats.rs``
   * - The internal routes answer the allow-list only, and never a forwarded request.
     - ``edge_observe.rs``: ``the_internal_routes_answer_the_allow_list_only``
   * - Readiness is 200, then 503 from the start of a drain, while a request in flight still ends and is logged.
     - ``edge_observe.rs``: ``the_separate_listener_reports_readiness_until_the_node_drains``, and ``edge::probe::tests``
   * - A trusted proxy names the client for the log and the request limiter. A forged left entry is ignored. Without the option the field is ignored.
     - ``edge_observe.rs``: ``a_trusted_proxy_names_the_client_for_the_log_and_the_limits``
   * - PROXY versions 1 and 2 name the client. No header, a malformed header and an untrusted peer close the connection.
     - ``edge_observe.rs``: ``a_proxy_frontend_takes_the_client_from_the_header_and_refuses_the_rest``, ``crates/lb/src/proxy_header.rs``
   * - A descriptor limit below the need prints the warning with its hint, and the process still starts.
     - ``edge_observe.rs``: ``a_descriptor_limit_below_the_need_is_reported_with_a_hint``, ``edge::fdlimit::tests``
   * - ``sibuna ctl SOCKET show stats`` prints the series of the edge.
     - ``edge_observe.rs``: ``the_admin_socket_prints_the_series_of_the_edge``
   * - A bad ``observability`` object is refused by ``sibuna check``.
     - ``edge_observe.rs``: ``a_check_of_the_file_reports_a_bad_observability_object``

   * - HTTP/3 through the binary: the log line (``h3``, status, body bytes, server), the client certificate digest and a forged field, the per-client bound for QUIC connections, and a gRPC call to an HTTP/2 pool.
     - ``edge_http3.rs``, four tests
   * - A PROXY header before the TLS handshake names the client of an HTTP/2 request. Without it the handshake is not read.
     - ``edge_observe_h2.rs``: ``a_proxy_header_before_tls_names_the_client_of_an_http2_request``
   * - A PROXY source inside ``trusted_proxies`` lets its forwarded field count. A source outside does not.
     - ``edge_observe.rs``: ``the_forwarded_field_is_read_only_when_the_proxy_header_names_a_trusted_source``
   * - A TCP frontend takes the client from the header. The client drives the connection rate, source stickiness and the header for the server. The proxy is not rate limited.
     - ``crates/lb/tests/proxy_frontend.rs``, four tests
   * - A request that the runtime refuses before the decision (417, and 503 at the request bound) is one line and one count by reason.
     - ``edge_observe_h2.rs``: ``a_request_that_the_runtime_refuses_is_logged_and_counted_by_reason``
   * - A 502 of the server itself has ``ttfb_ms`` and is no failure, on both paths. An interim head cut in two keeps the final status, on both paths and for every cut.
     - ``edge_observe.rs``: ``a_502_of_the_server_itself_is_a_response_and_not_a_failure``, ``an_interim_head_cut_in_two_does_not_hide_the_final_status``, and ``client_writer::tests::the_final_status_is_found_wherever_the_pieces_are_cut``
   * - A request in flight is in the active gauge of its server, on both paths. A server added at run time is counted, a removed one loses its series, and a request of a retired revision keeps the name of its server.
     - ``edge_observe.rs``: ``a_request_in_flight_is_in_the_active_gauge_of_its_server``, and ``crates/lb/tests/observe.rs``
   * - With ``global.drain_delay`` a shutdown answers 503 on readiness and still serves new requests, then stops.
     - ``edge_observe.rs``: ``a_drain_delay_keeps_serving_while_readiness_says_no``
   * - A reload moves the log to another file, turns it off and on, starts a log that did not exist, and replaces ``internal_allow``. It changes the queue length without losing or reordering a line. It opens a new ``listen`` address before it closes the old one, and an address that cannot be bound refuses the reload as a whole.
     - ``edge_observe.rs``: ``a_reload_moves_the_log_and_changes_who_reads_the_internal_routes``, ``a_reload_starts_a_log_changes_its_queue_and_moves_the_listener``; ``access::sink::tests::a_new_queue_length_keeps_every_line_in_its_order``
   * - Silent clients of the separate listener do not delay the next probe.
     - ``edge::probe::tests::the_listener_refuses_what_it_does_not_serve``
   * - ``sibuna lb --access-log`` sets the log, for HTTP, TCP and UDP.
     - ``edge::quick::tests``, ``crates/lb/src/quick.rs``, ``edge_flow_log.rs``: ``the_quick_start_logs_udp_mappings``
   * - The line has ``tls_version`` and ``tls_cipher`` on every path: HTTP/1.1 over TLS with and without the workers, HTTP/2, HTTP/3, and ``-`` without TLS.
     - ``edge_observe_h2.rs``: ``an_http11_request_over_tls_is_logged_with_the_version_and_the_suite``, ``an_http2_request_to_an_http11_pool_is_logged_with_its_server_and_times``; ``edge_http3.rs``: ``an_http3_request_is_logged_with_its_protocol_server_and_bytes``; ``edge_observe.rs``: ``each_request_is_one_line_with_its_server_status_and_times``
   * - The byte counts are those of the table, on each path.
     - ``edge_observe.rs``: ``the_byte_counts_of_http11_are_the_bytes_of_the_message`` (workers and threads); ``edge_observe_h2.rs``: ``the_byte_counts_of_http2_are_the_heads_as_text_and_the_body_data``; ``edge_http3.rs``: both tests; ``crates/ingress/tests/inline.rs``
   * - A TCP connection and a UDP mapping write one line at their end, with the client, the server, the bytes and the reason. A full channel drops the line and counts it. A topology without HTTP reloads its log.
     - ``crates/lb/tests/flow_log.rs`` (four tests), ``crates/lb/src/flowlog.rs``, ``edge_flow_log.rs`` (two tests), ``access::sink::tests::a_flow_line_has_its_fields_in_order``
   * - Refused connections are all counted and logged at most ten times per second.
     - ``crates/lb/tests/flow_log.rs``: ``refused_connections_are_all_counted_and_logged_at_a_bounded_rate``
   * - Without the workers, a request that the runtime refuses is logged and counted.
     - ``edge_observe_h2.rs``: ``the_thread_path_logs_and_counts_what_the_runtime_refuses``
   * - A client that resets its stream or closes while the server is silent is logged with 499 and counts neither as a server failure nor as a bad request.
     - ``edge_observe_h2.rs``: ``a_client_that_resets_its_stream_is_no_failure_of_the_server_and_no_bad_request``; ``edge_observe.rs``: ``a_client_that_closes_while_the_server_is_silent_is_no_failure_of_the_server``
   * - The descriptor need counts the bounded idle server connections.
     - ``edge::fdlimit::tests``, ``edge_observe.rs``: ``a_descriptor_limit_below_the_need_is_reported_with_a_hint``
   * - ``show stats`` prints every series, and ``reopen log`` reopens the file without a reload.
     - ``edge_observe.rs``: ``the_admin_socket_prints_the_series_of_the_edge``

``cmd/sibuna/tests/edge_observe_h2.rs`` drives HTTP/2 over TLS through the binary and reads the log: one request to an HTTP/1.1 pool, and six gRPC calls on the shared session of an HTTP/2 pool. ``crates/ingress/tests/grpc.rs`` and ``tests/inline.rs`` check the report on both send paths, including an exchange that trailers end.

Formal model
~~~~~~~~~~~~

``docs/sid/assets/edge-observability.lean`` models the two algorithms of this record and is checked with Lean 4 core.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Theorem
     - Statement
   * - ``step_keeps_the_bound``, ``run_keeps_the_bound``
     - The queue never holds more than its capacity.
   * - ``offer_adds_one``, ``write_adds_none``, ``run_accounts_for_every_offer``
     - Written, queued and dropped together are the number of offers. No entry is lost or counted twice.
   * - ``room_means_no_drop``
     - An offer to a queue with room is not dropped.
   * - ``forged_entries_are_never_read``, ``client_ignores_the_left``
     - When trusted proxies appended their entries after the client's address, the walk answers that address, whatever stands to its left.
   * - ``walk_answers``
     - A field with at least one entry always names a client.

The parser of the PROXY header is a bounded scan without state. Its unit tests cover it, and we did not model it.

Known gaps
~~~~~~~~~~

#. The chunk framing of an HTTP/1.1 request body is not counted in ``bytes_in``, and of a chunked body larger than one connection buffer only the buffered part is counted. The framing is removed in place before the request is judged, in code that the three request paths share. Counting it needs the raw size carried through the dispatch.
#. A request that the runtime refuses before the decision has 0 for both byte counts on ``h2`` and ``h3``.
#. ``tls_cipher`` is ``-`` for ``h3``. The QUIC library does not expose the negotiated suite.
#. On the thread path an HTTP/2 or HTTP/3 request is logged with protocol ``http/1.1``, because the thread sees the translation. Only the requests that the runtime refuses carry ``h2`` or ``h3`` there.
#. On the worker path and the thread path an orderly close of the client's sending side is not an abort: the answer is still written and logged with its status. Only a connection that breaks is logged with 499. No test breaks a connection with a reset there, because the standard library cannot send one.
#. A flow line is written at the end of a flow only. A long-lived TCP connection has no line while it is open.
#. The line of a connection that the HTTP server refused (``connection_limit``, ``client_limit``, ``task_limit``) has ``-`` for the frontend.
#. A frontend behind a proxy that sends only ``X-Forwarded-For`` has no connection rate per client. This is a decision, explained under *Trusted proxies*.
#. A reload cannot move ``observability.listen`` to another address with the same port, because the new address is bound while the old one is open. Two reloads do it.
#. The log is reopened within about one second of SIGHUP or of ``reopen log``, not at once. Lines written in between go to the old file.
#. The descriptor need does not count the sockets of the protocol adapters towards TLS, HTTP/2 and HTTP/3 servers (SID 0017), which have no configured bound.
#. The packaging scripts were changed to install the logrotate file. The packages were not built in this work.
#. A request on an edge takes one more lock of the routing table, to find its frontend.
#. A second SIGTERM does not cut ``global.drain_delay`` short.
#. ``tests/e2e.rs`` has a test, ``proxied_responses_keep_the_client_connection_open_for_the_next_request``, that fails about once in eight runs. It fails as often on ``main`` before this branch. It is not fixed here.

Open questions
--------------

None. Two earlier questions are decided. The access log stays off unless configured, and the quick start has ``--access-log``. A TCP frontend accepts the PROXY protocol.

Review history
--------------

- 2026-11-24. Initial draft, from the findings of a read-only production audit.
- 2026-11-24. Design review before the implementation. The look at a PROXY header grew from 232 to 536 bytes, because a version 2 header carries extensions. ``Completion`` lost its duration, which the binary measures from the dispatch. A trusted proxy became exempt from the per-client connection bound. The internal routes gained the rule on forwarding fields, for a proxy on the same host.
- 2026-11-24. Merge with SID 0018 and the later sections of SID 0017. The separate listener is now the module ``probe``, because ``admin`` names the admin socket. The report covers the direct sends to HTTP/2 and HTTP/3 servers, and trailers end an exchange. A TLS connection takes its place under the client bound once, by the address of the PROXY header when it has one, and a trusted proxy is exempt. The admin socket gained ``show stats``. A test through the binary found that a server behind an adapter had no name in the log, because a reservation names the adapter; the lookup now uses that address.
- 2026-11-24. Implementation review. The separate listener closed over unread request bytes, and the reset could destroy its response; it now reads what arrived before it closes. It answers 501 to other methods, because the response writer has no 405. The warning of the descriptor limit is printed before the ready line. The acceptance table and the known gaps were written from the code and the tests.

- 2026-11-24. Production readiness. HTTP/3 is tested through the binary, with no defect found. The PROXY header moved from a stage thread of the binary into the worker of the load balancer, and TCP frontends read it. The connection rate stopped counting trusted proxies and counts the client of a PROXY header. Refusals before the decision are counted by reason, and refused requests are logged. The status scan passes over interim heads wherever the pieces are cut, on both HTTP/1.1 paths. A server's own 502 or 504 is told from ours by the result of the relay. The log gained ``scheme``, and ``https`` left ``protocol``. Servers gained an active gauge, a removed server loses its series at once, and a retired revision keeps its server names. ``global.drain_delay`` was added. A reload changes the log output and ``internal_allow``. The separate listener serves eight clients at once. The quick start gained ``--access-log``. The state moved to accepted: every acceptance criterion has a passing test, and the remaining gaps are listed with their reasons.

- 2026-11-25. Second round. The log gained ``tls_version`` and ``tls_cipher``, flow lines for TCP and UDP, and one meaning for the byte counts. A reload follows ``listen`` and the queue length. The thread path logs the refusals of the runtime. Refused connections are logged at a bounded rate and UDP drops have reasons. The workers bound their idle server connections and the need counts them. The review of the design changed three things. The queue change no longer sends the new channel through the old one, which could have made a reload wait for a full queue. The listener is bound before the log file is opened, so a refused reload leaves no empty file. The idle bound became a share of ``http.max_connections``, because 1,024 per worker would have asked for descriptors that are never used.
- 2026-11-25. A load run showed server failures and bad requests when clients reset their streams. A client abort is now 499 in the log, has its own counters, and is no failure of a server. ``reopen log`` and the logrotate file were added, because a rotation by SIGHUP also reloads the topology.

References
----------

- SID 0002, SID 0015, SID 0016 and SID 0017.
- The PROXY protocol, versions 1 and 2, ``doc/proxy-protocol.txt`` of HAProxy.
- RFC 7239, Forwarded HTTP Extension, section 8 on trusting forwarded addresses.
- Prometheus text exposition format, version 0.0.4.

.. rubric:: Lifecycle event

::

   2026-11-24: discussion -> accepted. Implemented with a passing test for every
   acceptance criterion; the remaining gaps are listed with their reasons
