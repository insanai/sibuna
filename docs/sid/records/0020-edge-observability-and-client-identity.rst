:sid-number: 0020
:sid-title: Edge Observability and Client Identity
:sid-state: discussion
:sid-status: Open for Discussion
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

We add one access log line per HTTP request, written by one thread from a bounded queue. We add counters and latency histograms per frontend and per server, the health state of each server, and the flow counters of the node. We add a readiness route that turns to 503 when the node drains. We close the health, readiness and metrics routes to everyone outside an allow-list, which is the loopback network by default, and we offer a separate listener for them. We let a frontend name the proxies it trusts, so that ``X-Forwarded-For`` from them names the client, and we let a frontend require the PROXY protocol, version 1 or 2. At startup we compare the descriptor limit of the process with what the topology can use, raise the soft limit when the hard limit allows it, and warn when it does not.

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

Out of scope: a log for TCP and UDP flows, log shipping, tracing, and the PROXY protocol on TCP frontends. The section *Known gaps* lists them.

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

The topology gains one object at its root and two options on an HTTP frontend. In JLV:

.. code-block:: text

   observability {
     access_log {
       output: "/var/log/sibuna/access.log"   // a path, "stdout" or "stderr"
       queue: 8192                             // entries; 64 to 1048576
     }
     internal_allow: ["127.0.0.0/8", "::1/128"]
     listen: "127.0.0.1:9180"
   }

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
   * - ``frontends.<name>.trusted_proxies``
     - ``[]``
     - HTTP frontends only. The networks of the proxies in front of this frontend, at most 64.
   * - ``frontends.<name>.proxy_protocol``
     - ``false``
     - HTTP frontends only. Every connection must begin with a PROXY header, version 1 or 2. It needs a non-empty ``trusted_proxies``.

A change of the ``observability`` object needs a restart, as other node-wide settings do. The frontend options follow a reload.

The access log
~~~~~~~~~~~~~~

A request path fills one entry and settles it when the response ends. Settling updates the counters and offers the entry to the queue with ``try_send``. The queue is the bounded channel of the standard library. One thread, ``edge-access-log``, takes entries, formats each as one JSON object and writes it through a buffer. It flushes when the queue is empty, and at least once per second.

The queue holds entries, not text, so that formatting runs on the writer thread. An entry owns one string for the client, host, method and path, and shares the names of the frontend, the backend and the server.

A full queue drops the entry. The drop is counted in ``sibuna_edge_access_log_dropped_total``. A write error drops the line, counts it in ``sibuna_edge_access_log_errors_total``, and reports the first error of each minute on standard error.

SIGHUP reopens a file destination, before the topology is read again and whether or not the new topology is accepted. A log rotation therefore renames the file and sends SIGHUP. The writer reopens the path between two lines, so no line is split.

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
     - ``http/1.1``, ``h2`` or ``h3``. A request that reached a worker through the TLS relay of SID 0015 is ``https``.
   * - ``method``
     - The request method, or ``-`` for a request that did not parse.
   * - ``host``
     - The ``Host`` field, at most 255 bytes.
   * - ``path``
     - The path in normal form, without the query, at most 1,024 bytes.
   * - ``status``
     - The status sent to the client. ``0`` when the exchange ended before a status.
   * - ``bytes_in``
     - The size of the request head as parsed plus the body length that the request declared. For a body without a length, the bytes buffered for the decision.
   * - ``bytes_out``
     - The response bytes written towards the client, head included, as HTTP/1.1. For ``h2`` and ``h3`` the body bytes.
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
     - After each request, from the response writer of the connection. The writer counts the bytes and reads the status from the first twelve bytes of the final head.
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
     - Requests a server was chosen for that ended without its response.
   * - ``sibuna_edge_server_response_seconds{backend,server}``
     - A histogram of ``ttfb_ms``.
   * - ``sibuna_edge_server_up{backend,server}``
     - 1 when the last health check passed or the pool has none, else 0.
   * - ``sibuna_edge_flows_active``, ``sibuna_edge_flows_limit``, ``sibuna_edge_drops_total``
     - The flow table of the node.
   * - ``sibuna_edge_ready``
     - 1 until the node drains.
   * - ``sibuna_edge_access_log_written_total``, ``..._dropped_total``, ``..._errors_total``
     - The log.
   * - ``sibuna_edge_proxy_protocol_accepted_total``, ``..._rejected_total``
     - Connections of PROXY frontends.

The histograms have fixed bounds: 1, 2.5, 5, 10, 25, 50, 100, 250, 500 ms, 1, 2.5, 5, 10 and 30 s.

Readiness and access control
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``/__sibuna/ready`` answers 200 with ``{"status":"ready"}`` while the node serves, and 503 with ``{"status":"draining"}`` after a shutdown or drain began. ``/__sibuna/health`` stays a liveness answer.

In edge mode the three routes answer only when all of the following hold. Otherwise the answer is the 404 of an unknown route.

#. The socket peer is inside ``internal_allow``.
#. The client address the request is judged by is inside ``internal_allow``.
#. The request has no ``X-Forwarded-For``, ``X-Real-IP`` or ``Forwarded`` field.

The third rule exists for a proxy on the same host. Its requests arrive from the loopback address on behalf of anyone. A proxy that forwards adds one of these fields; a local probe does not.

The solver assets, the challenge routes and the honeypot stay public, because clients need them.

The separate listener is one thread. It serves one request per connection, reads at most 4,096 bytes of head within two seconds, and answers ``GET`` and ``HEAD`` for ``/health``, ``/ready`` and ``/metrics``, with or without the ``/__sibuna`` prefix. Another method is answered 501 and another path 404. It also runs without any HTTP frontend, where it is the only way to read the counters.

Trusted proxies
~~~~~~~~~~~~~~~

A frontend lists the networks of the proxies in front of it. When the socket peer of a request is inside the list, we read the ``X-Forwarded-For`` fields as one list and walk it from the right. The client is the first entry that is not a trusted proxy. When every entry is a trusted proxy, the client is the leftmost entry. When there is no field, or an entry on the walk is not an address, the client is the socket peer, and ``sibuna_forwarded_invalid_total`` counts a malformed entry.

Each proxy appends the address it received the request from. The entries a client can write are therefore to the left of the first untrusted address, and the walk never reads them.

The chosen address is the client for the ban table, the request limiter, policy rules, the challenge fingerprint and the log. The per-client connection bound of the firewall counts socket peers, so it does not apply to a connection from a trusted proxy.

The PROXY protocol
~~~~~~~~~~~~~~~~~~

A frontend with ``proxy_protocol: true`` sends each accepted connection through a stage before TLS or HTTP. The stage is one thread with one poller. It holds at most 4,096 connections, each for at most five seconds.

When a connection becomes readable, the stage looks at the first bytes without taking them (``MSG_PEEK``, at most 536 bytes) and parses them:

.. code-block:: text

   v1  "PROXY TCP4 <src> <dst> <sport> <dport>\r\n"   at most 107 bytes
       "PROXY TCP6 ..."   "PROXY UNKNOWN ...\r\n"
   v2  12 signature bytes, version and command, family and protocol,
       a 16-bit length, then addresses and extensions   at most 16 + 520 bytes

The parser is one function over a byte slice with three results: a header of ``n`` bytes with a source address, a header of ``n`` bytes without one (``UNKNOWN`` or ``LOCAL``), or a refusal. A complete header must be inside the first look. This is the rule of HAProxy's own receiver and of the protocol text, which requires a sender to write the header in one piece. The stage then reads exactly ``n`` bytes, so the first byte of TLS or HTTP is the next one.

A connection is closed and counted when its socket peer is not a trusted proxy, when the header is malformed, incomplete or longer than the bound, or when the five seconds pass. A v1 address must be canonical: no leading zeros, a port from 0 to 65535 without a sign. A v2 header must have version 2, a known command, and a length that covers its address block.

The source address replaces the socket peer for everything that follows: the connection bounds, the trusted-proxy walk, the allow-list of the internal routes and the log. A header without a source keeps the socket peer.

The bound of 536 bytes is the 16 fixed bytes, the largest address block (216 bytes, for the Unix family, which we accept and ignore) and 304 bytes of extensions. A sender that adds longer extensions, such as a full TLS client certificate, is refused.

The descriptor limit
~~~~~~~~~~~~~~~~~~~~

A flow uses two descriptors: one to the client and one to the server. At startup we compute

.. math::

   need = 2 \cdot max\_flows + 2 \cdot http.max\_connections + 512

where the HTTP term is zero without an HTTP frontend, and 512 covers listeners, idle server connections, files and threads. When the soft limit is below the need, we raise it to the smaller of the need and the hard limit. When it is still below, we print a warning and continue:

.. code-block:: text

   -- DESCRIPTOR LIMIT TOO LOW ------------------------------------ edge.jlv

   This topology can use 18944 file descriptors, but the process may open 4096.

   global.max_flows = 8192, http.max_connections = 1024
   need = 2 * 8192 + 2 * 1024 + 512 = 18944

   Hint: Raise the limit (`LimitNOFILE=18944` in the systemd unit, or `ulimit -n 18944`),
   or lower `global.max_flows` and `http.max_connections`.

The two system calls live in a new FFI module of the reactor crate, beside the poller.

Worked example
~~~~~~~~~~~~~~

A content network at 198.51.100.0/24 reaches the frontend ``web``. A client at 203.0.113.7 sends ``X-Forwarded-For: 10.9.9.9`` of its own. The network appends the client's address. The request arrives from 198.51.100.4 with ``X-Forwarded-For: 10.9.9.9, 203.0.113.7``. The peer is trusted. The walk reads 203.0.113.7 first, which is not trusted, and stops. The forged 10.9.9.9 is never read. The log line is:

.. code-block:: json

   {"time":"2026-11-24T10:15:02.418Z","client":"203.0.113.7","frontend":"web","protocol":"http/1.1","method":"GET","host":"www.example.com","path":"/index.html","status":200,"bytes_in":112,"bytes_out":5310,"duration_ms":3.184,"ttfb_ms":2.907,"backend":"app","server":"app-2","verdict":"pass"}

Rationale and alternatives
--------------------------

**Formatting on the worker.** A worker could format the line and send text. That costs a few hundred nanoseconds on the request path for a line that may be dropped. We send the entry.

**A lock-free ring of our own.** The bounded channel of the standard library does not block on ``try_send`` and is maintained by others. We found no reason to write a queue.

**Blocking when the queue is full.** Some balancers offer it for audit logs. A slow disk would then stop traffic. We drop and count, and an operator who needs every line can size the queue and watch the counter.

**The common log format.** It has no place for the server, the times or the verdict, and every consumer would need a custom parser. JSON lines are read by every log pipeline.

**A hop count for forwarded addresses.** The daemon's ``--trusted-hops`` counts entries from the right. A content network has a varying number of hops, and a wrong count trusts a forged entry. Naming the networks is the usual rule and fails closed.

**Only a separate listener for health and metrics.** It is the cleanest control. Many deployments probe the data port, though, so we keep the routes there and close them by default.

**Reading a PROXY header across several reads.** It would need a buffer in front of TLS, which takes its bytes from the socket. Peeking keeps the socket the only buffer.

Security and operational considerations
---------------------------------------

The log holds client addresses and paths. Its file is created with mode 0640 and belongs to the user of the process. Paths are escaped, so a request cannot forge a second line.

A trusted proxy is trusted completely: it can name any client. The list must hold only networks whose every host is a proxy of ours.

The PROXY stage holds a flow permit for each waiting connection, so it cannot exceed the flow table, and its own bound of 4,096 keeps a flood of silent connections from filling the table for five seconds each.

The metrics text grows with the topology: about 3 KiB per server and per frontend. It is built per request and not cached.

The frontend rate limit of SID 0015 (``rate_limit.conn_per_10s``) counts connections by socket peer. Behind a trusted proxy it counts the proxy. An operator leaves it off on such a frontend, or uses the PROXY protocol, after which the peer is the client.

Backwards compatibility
-----------------------

In edge mode ``/__sibuna/health`` and ``/__sibuna/metrics`` now answer 404 to clients outside the loopback network. A probe from another host needs ``internal_allow`` or the separate listener. The daemon mode is unchanged.

The ingress interface gains fields, so code that builds an ``Offer`` or a ``Forward`` names them.

Acceptance criteria and implementation status
---------------------------------------------

Implemented on the branch ``sid-0020-observability``. Every criterion has a test that runs in ``cargo test --workspace``.

.. list-table::
   :header-rows: 1
   :widths: 46 54

   * - Criterion
     - Test
   * - A request on the event-driven path and on the thread path writes one line with every field. The query is absent. A request that does not parse is logged.
     - ``edge_observe.rs``: ``each_request_is_one_line_with_its_server_status_and_times``
   * - A failed server is a 502 line without ``ttfb_ms`` and one failure of that server.
     - ``edge_observe.rs``: ``a_failed_server_is_logged_as_502_without_a_first_byte_and_counted``
   * - The in-process path reports each forwarded exchange once, with status, body bytes, first byte and protocol.
     - ``crates/ingress/tests/inline.rs``
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
     - ``edge_observe.rs``: ``a_proxy_frontend_takes_the_client_from_the_header_and_refuses_the_rest``, ``crates/lb/src/proxy_header.rs``, ``edge::proxy_stage::tests``
   * - A descriptor limit below the need prints the warning with its hint, and the process still starts.
     - ``edge_observe.rs``: ``a_descriptor_limit_below_the_need_is_reported_with_a_hint``, ``edge::fdlimit::tests``
   * - A bad ``observability`` object is refused by ``sibuna check``.
     - ``edge_observe.rs``: ``a_check_of_the_file_reports_a_bad_observability_object``

The access log on the in-process path is tested at the interface of the ingress crate and not through the binary. See the first known gap.

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

#. No test drives HTTP/2 or HTTP/3 through the binary and reads the log file. The report is tested in the ingress crate, and the entry in the binary, but not both together.
#. ``bytes_in`` is an estimate: the parsed head plus the declared body. For a chunked body on the thread path it counts the buffered part only. ``bytes_out`` on the in-process path counts body bytes and not the head.
#. A request that the protocol runtime refuses before the decision, such as an HTTP/2 request that does not translate, is not logged. A connection that is refused admission (503) is not logged either.
#. On the thread path the writer cannot tell a server's own 502 or 504 from ours. Such a response has no ``ttfb_ms`` and counts as a failure of the server.
#. On the thread path an interim head (1xx) that is split across two writes loses the final status, which is then logged as 0.
#. HTTP/1.1 over TLS is labelled ``https``. Its requests use the socket pair, where the negotiated protocol is not known.
#. The frontend rate limit ``rate_limit.conn_per_10s`` counts the proxy behind a trusted proxy.
#. TCP frontends do not accept the PROXY protocol, and TCP and UDP flows have counters but no log line.
#. There is no gauge of active requests per server.
#. A request on an edge takes one more lock of the routing table, to find its frontend.
#. Readiness turns 503 when the drain begins, and the listeners stop in the same moment. There is no delay in which a load balancer in front could see the 503 first.
#. The separate listener is one thread. A client that sends nothing delays the next probe by up to two seconds.
#. The PROXY stage runs on every edge with an HTTP frontend, also when no frontend uses it. It wakes four times per second.
#. A PROXY header that names a source inside ``trusted_proxies`` makes that source a trusted proxy for the forwarded field. This is the intended chain, but it is not tested.
#. A change of the ``observability`` object needs a restart. SIGHUP reports the HTTP options as incompatible and keeps the old ones.
#. The log is reopened within about one second of SIGHUP, not at once. Lines written in between go to the old file.
#. The descriptor need is a rule of thumb. It does not count the idle server connections above 512 or the mesh.
#. ``tests/e2e.rs`` has a test, ``proxied_responses_keep_the_client_connection_open_for_the_next_request``, that fails about once in eight runs. It fails as often on ``main`` before this branch. It is not fixed here.

Open questions
--------------

#. Should the access log be on by default, to standard output, when the process runs under a service manager?
#. Should a TCP frontend accept the PROXY protocol, so that chained balancers keep the client address?

Review history
--------------

- 2026-11-24. Initial draft, from the findings of a read-only production audit.
- 2026-11-24. Design review before the implementation. The look at a PROXY header grew from 232 to 536 bytes, because a version 2 header carries extensions. ``Completion`` lost its duration, which the binary measures from the dispatch. A trusted proxy became exempt from the per-client connection bound. The internal routes gained the rule on forwarding fields, for a proxy on the same host.
- 2026-11-24. Implementation review. The separate listener closed over unread request bytes, and the reset could destroy its response; it now reads what arrived before it closes. It answers 501 to other methods, because the response writer has no 405. The warning of the descriptor limit is printed before the ready line. The acceptance table and the known gaps were written from the code and the tests.

References
----------

- SID 0002, SID 0015, SID 0016 and SID 0017.
- The PROXY protocol, versions 1 and 2, ``doc/proxy-protocol.txt`` of HAProxy.
- RFC 7239, Forwarded HTTP Extension, section 8 on trusting forwarded addresses.
- Prometheus text exposition format, version 0.0.4.
