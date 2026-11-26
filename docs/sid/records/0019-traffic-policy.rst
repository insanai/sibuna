:sid-number: 0019
:sid-title: Traffic Management and HTTP Policy for the Edge
:sid-state: accepted
:sid-status: Accepted
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-24
:sid-updated: 2026-11-24
:sid-discussion: No external discussion URL assigned
:sid-summary: Gives each HTTP pool its own timeouts, failover to another server, passive health, slow start, sticky sessions and round robin, and gives each frontend and route a small HTTP policy: redirect to https, HSTS, header edits and a body limit.
:sid-labels: ["architecture","load-balancer","network","http","operations"]

Traffic Management and HTTP Policy for the Edge
===============================================

Abstract
--------

The edge of SID 0015 balances HTTP requests over the servers of a pool. An audit before the first production use found that it lacks what an operator of HAProxy, nginx or Envoy takes for granted. A slow server answers 504 after the client idle timeout. A refused connect answers 502 although another server is healthy. A server that accepts connections and then stays silent is never taken out of rotation. There are no sticky sessions, no redirect to https and no limit on the size of a request body.

This record closes those gaps. Every new option has a default, so a topology that sets none of them keeps working and gets the safer behaviour: a connect bound of 5 seconds, a response bound of 60 seconds, up to two other servers on a failed connect, and ejection after three consecutive response timeouts.

Motivation and scope
--------------------

We list the gaps in the order of the harm they do.

#. **Timeouts.** The connect bound is a constant of 5 seconds. The wait for a response is the client idle timeout of the ``http`` object, 15 seconds by default. A report that takes 20 seconds cannot be served without raising the bound for every idle client.
#. **Failover.** A connect that is refused or times out answers 502 at once. No request byte was sent, so another server could have served the request.
#. **Passive health.** Only a failed connect marks a server. A server whose process hangs keeps its place until an active probe notices, and a pool without a probe never notices.
#. **Slow start.** A server that returns takes its full share at once, with cold caches.
#. **Sticky sessions.** An application that keeps session state in one server cannot be balanced.
#. **HTTP policy.** There is no redirect to https, no HSTS, no header edit, no body limit, and the server is not told the host and port that the client asked for.
#. **Round robin.** The simplest algorithm, and the one operators expect as a default elsewhere, is missing.

The record covers HTTP pools in edge mode. Slow start, source affinity and round robin live in the pool and so serve TCP and UDP pools too. The route prefix match of SID 0015 is not changed here.

There are three request paths: the event-driven workers of SID 0016, the in-process path of SID 0017 for HTTP/2 and HTTP/3, and the thread path (``http.event_loop: false``), which is the fallback for platforms without the workers. All three apply every rule of this record. The rule for moving a request is one function that the three paths share. The section "The three paths" names the few places where a path must differ, and "Known gaps" says what remains.

Specification
-------------

Invariants
~~~~~~~~~~

#. A topology that sets no option of this record is valid and serves as before, except for the defaults named in "Backwards compatibility".
#. A request is sent to another server only when sending it twice does no harm: no byte of it was sent, or we still hold all of it and either its method is idempotent (GET, HEAD, OPTIONS, PUT, DELETE) or the first server said that it did not act on it.
#. One request never tries the same server twice, and tries at most ``retries + 1`` servers.
#. A server is chosen by affinity only when it is eligible at that moment. Affinity never overrides health, a drain, a flow limit or an ejection.
#. The weight of a server in slow start never exceeds its configured weight, never decreases while it stays in service, and is never zero.
#. When every server of a pool is ejected by passive health and none is refused for another reason, the pool still serves. Passive health removes a server only while another can take its place.
#. A sticky cookie names a server by a keyed hash. A client that does not hold the key cannot construct the cookie of a server it was not given.
#. A header edit cannot change the framing of a message or a field that Sibuna writes itself.
#. Every wait has a bound, and every bound has a default.

The options
~~~~~~~~~~~

A pool (an entry of ``backends``) takes these members. All are optional.

.. list-table::
   :header-rows: 1
   :widths: 22 18 60

   * - Member
     - Default
     - Meaning
   * - ``connect_timeout``
     - ``"5s"``
     - The longest wait for a TCP connection to one server.
   * - ``response_timeout``
     - ``"60s"``
     - The longest silence of a server that owes us bytes: before the response head, and between two pieces of the body.
   * - ``retries``
     - ``2``
     - How many other servers one request may try. 0 to 8. Zero turns failover off.
   * - ``retry_body``
     - ``"64k"``
     - The largest request body that is kept so that the request can be sent again. 0 to ``"64k"``, the size of the request buffer. Zero keeps no body.
   * - ``passive_health``
     - on
     - ``"off"``, or an object with ``failures`` (3), ``ejection`` (``"10s"``) and ``http_5xx`` (false).
   * - ``slow_start``
     - off
     - A duration. A server that returns or is added ramps up to its weight over this time.
   * - ``sticky``
     - none
     - ``"cookie"``, ``"source"``, ``"off"``, or an object with ``kind`` and, for a cookie, ``cookie`` (the name, ``sibuna_srv``). A cookie needs an HTTP pool.
   * - ``balance.kind``
     - as before
     - Also ``"round_robin"``.

A frontend, and each of its routes, takes these members. A route without a member keeps the value of its frontend.

.. list-table::
   :header-rows: 1
   :widths: 22 18 60

   * - Member
     - Default
     - Meaning
   * - ``redirect_https``
     - false
     - ``true`` (status 308), ``301``, ``308``, or an object with ``status`` (308 or 301) and ``port`` (443). Only on a frontend without TLS.
   * - ``hsts``
     - false
     - ``true``, or an object with ``max_age`` in seconds (31536000), ``include_subdomains`` and ``preload``. Only on a frontend with TLS.
   * - ``request_headers``
     - none
     - An object with ``set`` (name to value) and ``remove`` (a list of names), applied to the request for the server. At most 32 names, and values of at most 1024 bytes.
   * - ``response_headers``
     - none
     - The same, applied to the response for the client.
   * - ``max_body``
     - none
     - A size in bytes, or text with ``k``, ``m`` or ``g`` (powers of 1024), or ``"off"``. A larger request body answers 413.

In JLV:

.. code-block:: text

   fn edge() -> Map<Value> {
       return {
           frontends: {
               plain: {
                   proto: "http",
                   binds: ["0.0.0.0:80"],
                   default_backend: "app",
                   redirect_https: true,
               },
               web: {
                   proto: "http",
                   binds: ["0.0.0.0:443"],
                   tls: { crt: "/etc/sibuna/certs/" },
                   default_backend: "app",
                   hsts: true,
                   max_body: "10m",
                   response_headers: {
                       set: { "X-Frame-Options": "DENY" },
                       remove: ["Server"],
                   },
               },
           },
           backends: {
               app: {
                   mode: "http",
                   response_timeout: "120s",
                   slow_start: "30s",
                   sticky: "cookie",
                   balance: { kind: "round_robin" },
                   servers: [
                       { name: "a", addr: "10.0.0.2:8080" },
                       { name: "b", addr: "10.0.0.3:8080" },
                   ],
               },
           },
       }
   }

The same document in JSON is accepted as before.

Timeouts
~~~~~~~~

An exchange waits for one party at a time, and the bound follows the party.

.. list-table::
   :header-rows: 1
   :widths: 40 25 35

   * - Wait
     - Bound
     - Ending
   * - The connect to a server
     - ``connect_timeout``
     - Failover, then 502
   * - The server takes the request or sends the response
     - ``response_timeout``
     - 504 before the response head, a closed connection after it
   * - The client sends its body or takes the response
     - ``http.idle_timeout``
     - As in SID 0016
   * - A tunnel
     - ``http.websocket_idle_timeout``
     - As in SID 0016

On a worker the server owes us bytes when the request body is complete and the client has taken every response byte we hold. Otherwise the client is the slow party and its own bound applies, so ``response_timeout`` cannot be used to hold a worker slot with a slow upload. On the in-process path the two server bounds replace the fixed 5 and 60 seconds of SID 0017. There the wait for the response head ends with 504 only when, for one whole ``response_timeout``, the head did not arrive and no byte of the request body moved. An upload that keeps moving is therefore not the silence of the server.

Failover
~~~~~~~~

.. typst-diagram:: ../diagrams/failover.typ
   :caption: One request and its attempts. A server is tried once, and the count of attempts is bounded.
   :alt: A request selects a server. A failed connect, or a failed safe buffered request, selects another server that was not tried while attempts remain. Otherwise the client receives 502.

The reservation of a request remembers the servers it tried. ``HttpRoutes::retry`` takes a failed reservation and returns a reservation on another server of the same pool, or nothing. It refuses when the attempts are spent, when the revision that routed the request no longer serves (a reload retires a revision and SID 0018 keeps it for ten seconds), and when no untried server is eligible. The failed server is marked as before, so later requests avoid it for two seconds.

A connect failure is a refused connection, an unreachable address or the connect timeout. For it the method of the request does not matter, because the server received nothing. After a byte was sent, a request is sent again only under the rule of the section "Moving a request that has a body". A pooled socket that the server closed is first replaced by a fresh connection to the same server, as before. If that fails too, the request moves on.

The decision is one function, ``sibuna_net::recover``. It takes what a path knows of a lost exchange: whether a response byte arrived, whether the connection was a pooled one, whether the request is kept, whether its method is idempotent, whether the server refused it, and whether it was already sent again on a fresh connection. It answers "reconnect to the same server", "move to another server" or "fail". The workers, the blocking relay of the thread path, the pooled HTTP/1.1 connections of the in-process path and the direct sends to HTTP/2 and HTTP/3 servers all ask it, so they cannot drift apart.

The three paths
~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 24 26 25 25

   * - Rule
     - Workers
     - In-process
     - Thread path
   * - ``connect_timeout``
     - The connect
     - The connect, or the opening of the shared session, without a cap
     - The connect
   * - ``response_timeout``
     - While the server owes bytes
     - No head and no moving upload for the bound, then silence between body pieces
     - Read timeouts of 250 ms on the server socket, summed to the bound, with a look at the client between two of them; the client idle deadline is lifted while the server owes bytes
   * - Failover
     - ``recover``
     - ``recover``, also for a session that fails after the send
     - ``recover``
   * - Passive health
     - Timeouts and statuses
     - Timeouts and statuses
     - Timeouts and statuses
   * - ``max_body``, declared
     - 413
     - 413
     - 413
   * - ``max_body``, unknown length
     - Counted with the chunk framing
     - Counted as data bytes
     - Counted with the chunk framing
   * - Over the limit after the head
     - Connection closed
     - Stream reset
     - Connection closed

The thread path gives a ``sibuna_net::Route`` to the blocking relay: the address of the current server, its bounds, the edit of the response, and the verbs ``unreachable``, ``advance`` and ``responded``. The relay asks ``recover`` and calls ``advance`` to move, which is ``HttpRoutes::retry``. A blocking read waits on one socket, so the relay cannot wait for the client and the server at once. It cuts the wait for the server into slices of 250 ms and asks the client socket for its pending error between two slices. A client that reset its connection is so noticed within a slice, the exchange ends, and the place on the server is free again. A client that closed in order is not treated as gone, on any path: it may have closed its sending side only and still read the answer. A chunked request body is counted in the bytes that the client sent, with the chunk framing, as a worker counts it.

On the in-process path a body of unknown length is counted as it streams to the server. HTTP/2 and HTTP/3 allow a response before the request ended, so before a response head we answer 413 and stop reading the body. After a response head there is nothing left to answer: the stream is reset, which the client sees as an aborted response.

A direct send to an HTTP/2 or HTTP/3 server that loses its session before a response head is first sent again on a fresh session to the same server, once, as a worker replaces a pooled socket. If that fails too, the server is marked and the request moves, under the same rule. The in-process path keeps a body that ended inside the 64 KiB it showed to the firewall, and sends it again from there. A body that was still streaming was handed to the session and cannot be sent again, so its request answers 502.

Passive health
~~~~~~~~~~~~~~

Each server has a count of consecutive failures. A response timeout is a failure. With ``http_5xx`` a response with status 500, 502, 503 or 504 is one as well; 501 and 505 describe the request, not the server. Any other complete response sets the count to zero. When the count reaches ``failures`` the server is ejected for ``ejection`` and the count starts again.

An ejected server takes no new request while another server of the pool can. If the only servers left are ejected ones, the pool uses them: a pool of one slow server must not answer 503 for ten seconds because three reports took too long. This is the panic rule of Envoy with a threshold of one server.

The existing rule for a failed connect stays: one failure removes the server for two seconds. It is not subject to the panic rule, because a refused connect costs the client nothing but a retry, and there is nothing to gain from repeating it.

Slow start
~~~~~~~~~~

With ``slow_start`` set to a ramp :math:`R`, a server that entered service :math:`t` ago has the effective weight

.. math::

   w(t) = \max\left(1, \left\lfloor \frac{256\, W\, t}{R} \right\rfloor\right) \text{ for } t < R, \qquad w(t) = 256\, W \text{ otherwise,}

where :math:`W` is its configured weight. Every scheduler compares servers by ratios of weights, so the common factor 256 changes nothing for servers at full weight and gives a server of weight 1 a ramp of 256 steps.

A server enters service when it is first seen in a pool that already had servers, and when it is eligible again after it was unhealthy or ejected. Servers that are first seen together, as at the start of the process, do not ramp. Every scheduler divides by the effective weight: round robin gives a ramping server its reduced share of turns, least connections compares connections and admitted requests per unit of weight, and the latency-aware scheduler divides its cost by the weight. A sticky server is used whatever its ramp, because its clients are already its own.

The ramp starts when a reservation first sees the server in service again, not when the health probe does. A pool without traffic therefore starts the ramp at its next request.

The default is off, as in HAProxy, nginx and Envoy. A ramp that is too short does nothing and one that is too long wastes a healthy server, and only the operator knows how long the application takes to warm up.

Moving a request that has a body
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A request can be sent again only while we still hold all of it. Every path buffers the first 64 KiB of a request for the firewall decision. A body that ended inside that buffer is held whole, at no further cost. ``retry_body`` says how much of it we are willing to send twice: a body of at most ``retry_body`` bytes that is held whole is *kept*. A longer body, and a body that is still streaming, is not kept. ``retry_body`` cannot exceed the buffer, so no path makes a second copy of a body.

Holding the request is necessary and not sufficient. Sending a request twice is safe in two cases only.

#. The method is idempotent by RFC 9110, section 9.2.2: ``GET``, ``HEAD``, ``OPTIONS``, ``PUT`` and ``DELETE``. Carrying such a request out twice has the effect of carrying it out once. ``TRACE`` is idempotent too. It has no body and is rare, and we leave it out.
#. The server provably did not act on the request. This is so when the connect failed, when a pooled HTTP/1.1 connection handed the request back without writing a byte of it, when an HTTP/2 server reset the stream with ``REFUSED_STREAM``, and when an HTTP/2 server sent a graceful ``GOAWAY`` with a last stream below the stream of the request (RFC 9113, sections 6.8 and 8.7). A ``GOAWAY`` with an error code ends the streams that the server worked on as well, so it proves nothing.

A missing reply is not such a proof. A ``POST`` whose connection was lost after a byte was sent is never sent again, whatever its size.

.. list-table:: What follows the loss of a server before a response byte
   :header-rows: 1
   :widths: 40 20 20 20

   * - Loss
     - Idempotent, kept
     - Not idempotent, kept
     - Not kept
   * - The connect failed, or the session could not be opened
     - Moves
     - Moves
     - Moves
   * - The request was handed back unsent, ``REFUSED_STREAM``, or a graceful ``GOAWAY`` below the stream (in-process path)
     - Same server once, then moves
     - Same server once, then moves
     - 502
   * - A pooled connection or a shared session was lost after the send
     - Same server once, then moves
     - 502
     - 502
   * - A fresh connection was lost after the send
     - Moves
     - 502
     - 502
   * - Silence for ``response_timeout``
     - 504
     - 504
     - 504
   * - Any loss after a response byte
     - Closed
     - Closed
     - Closed

A failed connect moves a request that is not kept as well, because the body has not left the client connection yet: it streams to the server that accepts the connect. A request that is "not kept" in the second row has a body that was already taken from its stream, so there is nothing left to send. A timeout does not move a request: the server may be working on it, and sending it elsewhere would do the work twice and take twice the time the client was promised.

``sibuna_net::recover`` reads four facts about the loss, ``unanswered``, ``kept``, ``idempotent`` and ``refused``, and two about the connection, ``pooled`` and ``retried``. It answers ``Fail`` unless ``unanswered`` and ``kept`` and (``idempotent`` or ``refused``). Otherwise it answers ``Reconnect`` for the first loss of a pooled connection and ``Move`` after that. The Lean model proves that a request that is not idempotent is sent again only with ``refused``.

Only the in-process path can have such a proof. The workers and the thread path speak HTTP/1.1 through blocking or raw sockets, where a lost connection says nothing, so for them ``refused`` is always false. For an HTTP/3 server we have no proof of refusal yet: the client library reports ``H3_REQUEST_REJECTED`` like any other stream error. HTTP/3 servers therefore get the idempotent rule only.

The choice of a server without a lock
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The routing table was one mutex, taken by every request for the choice of its server. Under contention the lock, not the choice, was the cost. Now a request reads an immutable snapshot.

.. typst-diagram:: ../diagrams/snapshot.typ
   :caption: Writers build a snapshot under the mutex and raise the generation. A reader compares one number and uses the snapshot its thread already has.
   :alt: A reload or a command changes the master table under a mutex, builds a snapshot from it, stores it and raises a generation counter. Each worker thread keeps its own reference to a snapshot together with the generation it was read at. A request compares that generation with the counter. When they are equal it uses the cached snapshot without any lock. When they differ the thread takes the mutex once and fetches the new snapshot.

A snapshot holds the frontends, the pools of the current revision and of the revision a reload retired, and the regime. It never changes after it is built. Everything that a request changes lives outside it, in the per-server state that a reload keeps: the count of active requests, the count of admitted requests, the round robin credit, the latency sample, the mark of a failed connect, the ejection and the ramp. These are atomics. The mark of a failed connect and the latency sample were a mutex each and are now one atomic number each. The slow start state stays behind a small mutex per server, but a server that is in service and past its ramp is recognised by one atomic flag, so the mutex is taken only around a return to service. The sticky token of a server was computed under a mutex and cached; it is now computed when the table changes and stored in the pool.

A writer (a reload, a run-time command, the change of the regime or of the sticky seed) changes the master table under the mutex, builds a new snapshot, and raises the generation. A run-time command copies the routes before it changes them, because the snapshot in use shares them. A reader that compares the generation just before the writer raises it uses the old snapshot, exactly as a request that arrived a moment earlier. The health flags are atomics that both snapshots share, so a probe needs no new snapshot.

There is no new crate and no ``unsafe``: the thread cache is a ``thread_local`` list of at most eight entries, one for each routing table the thread has used.

Two requests that choose at the same time may now both see the same least loaded server and both take it. With the mutex the second one saw the count of the first. The counts are exact again one request later, and limits are still enforced: a reservation counts itself first and then looks at the count. When it finds its server above ``max_flows`` it gives the place back and chooses again, at most eight times.

The ranking table of source stickiness
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Ranking every server for every request costs one hash and one logarithm per server. The ranking of a client depends only on its address, the names and the weights, so we compute it in advance for a fixed number of classes of clients.

A pool that is sticky by source has a table of 1021 slots. Slot :math:`i` holds the four nearest servers of the pool for the number :math:`i`, by the same weighted rendezvous ranking, nearest first, backups excluded. A client address is hashed to a slot. Its server is the first server of the slot that can serve now. When none of the four can, the pool falls back to ranking all servers for the slot number, so the answer is always the nearest eligible server of that slot.

The properties of the ranking carry over, per slot instead of per address: a server takes slots in proportion to its weight; when a server leaves, only its slots move, each to the next server of its own order; when it returns the slots return; every node computes the same table. The table depends on names and weights only, so a drain, an ejection or a health change does not rebuild it. A change of a weight, ``add server`` and ``del server`` rebuild it, 1021 rankings of the pool, when the next snapshot is built.

The price is granularity. Two addresses in one slot share their server and their second choice. With 1021 slots a server of weight 1 in a pool of total weight 1000 serves one slot, not a thousandth of the addresses exactly.

Sticky sessions
~~~~~~~~~~~~~~~

**By cookie.** The token of a server is the first 16 hexadecimal digits of a keyed BLAKE3 hash of the pool name and the server name. The key is derived from the challenge seed, so the nodes of a cluster that share ``http.secret_file`` accept each other's cookies. A request that carries the cookie with the token of an eligible server goes to that server. Any other request is balanced as usual, and its response carries

.. code-block:: text

   Set-Cookie: sibuna_srv=3f9a61c2d07be845; Path=/; HttpOnly; SameSite=Lax

with ``Secure`` on a frontend with TLS. The cookie has no lifetime: it ends with the browser session. The token reveals neither the name nor the address of the server, and a client cannot compute the token of another server to probe it.

**By source address.** The servers are ranked for the client address, without the port, by weighted rendezvous hashing in integer arithmetic. The first server of the ranking is used when it is eligible. When a server leaves, only its clients move, and they return when it returns. The hash is not keyed, so every node ranks alike.

A cookie that names a server that is down, drained, full, ejected or already tried falls back to the normal selection. Source stickiness ranks only the servers that can serve now. The clients of a server that is out thereby get their next server of the ranking, one each, and keep it until their own server returns. Only when no primary server can serve does the normal selection choose among the backups. A request that was moved by cookie stickiness to another server, or that failed over, receives the cookie of the server that answered. Source stickiness is a property of the pool, so TCP and UDP pools accept it too.

HTTP policy
~~~~~~~~~~~

The redirect and the body limit are decided after the ban table and the request limiter and before the firewall policy, so that a cleartext request is never challenged. The redirect goes to ``https://`` and the host of the request, with the configured port when it is not 443, and the path and query as they were sent. A request without a usable host answers 400.

A request that declares a body longer than ``max_body`` answers 413 before any byte goes to a server, and the connection closes because the body was not read. A chunked body that ends inside the request buffer of 64 KiB is measured exactly in the same way. A longer chunked body is admitted when the buffer is full, and a worker counts the rest as it arrives, with its chunk framing. When the count passes the limit the exchange ends: 413 when no response began, a closed connection otherwise.

A 413 closes the connection, because the body was not read. A client that is still writing would then receive a reset and might never read the answer. So after a 413 we stop sending, keep reading and discarding for at most 2 seconds and 1 MiB, and close then. A 413 is an answer of our own: it does not count in ``sibuna_upstream_errors_total``.

HSTS is one field line, written on every response on a TLS frontend: on the responses of a server, where it replaces a ``Strict-Transport-Security`` field of the server so that a client reads one policy, and on the answers of our own (a redirect, a challenge page, a refusal, 413, 502 and 504). A browser must learn the rule from whatever it is shown first. Our own answers carry neither the header edits nor the sticky cookie: the edits describe the application's responses, and a cookie would bind the client to a server that did not answer. The answer to an upgrade (101) belongs to the server and starts another protocol; no path edits it. A redirect keeps the connection open when the request has no body. The route of an answer of our own is the route of the path in normal form, the same route that chooses the server. Only an answer that is given before the path has a normal form, such as the 400 for a malformed path, takes the route of the path as it was written.

Header edits are prepared when the topology is parsed: a list of names to drop and one block of lines to append. ``set`` drops the name and appends the line. Names that carry framing or that Sibuna writes are refused at parse time: ``Host``, ``Content-Length``, ``Transfer-Encoding``, ``Connection``, ``Upgrade``, ``TE``, ``Trailer``, ``Keep-Alive``, the ``Proxy-`` fields, and on requests the ``X-Forwarded-``, ``X-Real-IP`` and ``X-Sibuna-`` fields.

The server is told what the client asked for: ``X-Forwarded-Host`` is the ``Host`` of the request and ``X-Forwarded-Port`` is the port of the listener. Both are written beside ``X-Forwarded-For`` and ``X-Forwarded-Proto``, and a value that the client sent under those names is dropped as before.

Round robin
~~~~~~~~~~~

``round_robin`` is the smooth weighted round robin of nginx. Each eligible server of the best tier gains its effective weight, the server with the most credit is chosen, and it pays the sum of the weights. Backups serve only when no primary is eligible.

Interfaces
~~~~~~~~~~

The lb crate gains plain data and a few verbs.

.. code-block:: rust

   pub struct Query<'a> {              // one request, for HttpRoutes::choose
       pub vip: SocketAddr,
       pub peer: SocketAddr,
       pub host: &'a [u8],
       pub path: &'a [u8],
       pub cookies: &'a [&'a [u8]],    // the values of the Cookie fields
       pub secure: bool,               // the frontend terminates TLS
       pub policy_revision: u64,
   }

   impl HttpRoutes {
       pub fn choose(&self, query: &Query<'_>) -> Option<HttpTarget>;
       pub fn retry(&self, failed: &HttpTarget) -> Option<HttpTarget>;
       pub fn policy(&self, vip: SocketAddr, host: &[u8], path: &[u8]) -> Option<Arc<RoutePolicy>>;
   }

   impl HttpTarget {
       pub fn connect_timeout(&self) -> Duration;
       pub fn response_timeout(&self) -> Duration;
       pub fn timed_out(&self);            // a response timeout
       pub fn answered(&self, status: u16); // a complete response
       pub fn route(&self) -> &RoutePolicy; // the policy of the matched route
       pub fn response_lines(&self) -> [&[u8]; 3]; // route fields, HSTS, cookie
   }

   pub struct HeadEdit<'a> {           // sibuna_net: one edit of a head
       pub remove: &'a [Box<str>],
       pub append: [&'a [u8]; 3],
   }

``HttpRoutes::select`` stays and calls ``choose``. ``sibuna_net::Audit`` gains ``request_edit``, ``response_edit``, ``forwarded_host`` and ``forwarded_port``, all with defaults that write nothing. ``ResponseRelay::feed_edited`` is ``feed`` with an edit of the final head.

All state of this record that belongs to a server (the failure count, the ejection, the ramp, the round robin credit and the cached cookie token) lives beside the load counters of SID 0015, which a reload keeps for every address. Two pools that name one address therefore share its ejection and its ramp. This is intended: the address is one process, and a process that stopped answering one pool has stopped answering.

A change of a weight at run time (``set server ... weight``) restarts no ramp. The ramp is a share of the weight in use, so a server in its ramp continues at the same share of the new weight. A new weight is the operator's statement of capacity, not a return to service.

What the operator sees
~~~~~~~~~~~~~~~~~~~~~~

``sibuna ctl SOCKET show servers`` has two columns for this record. ``ejected`` is the time passive health still keeps the server out, rounded up to seconds, or ``-``. ``ramp`` is the share of its weight that a server in slow start has now, in percent, or ``-``. A drain shows in ``state`` as before.

.. code-block:: text

   pool name address        state weight flows health ejected ramp changed
   app  a    10.0.0.11:8080 ready 1      0     up     7s      -    -
   app  b    10.0.0.12:8080 ready 1      3     up     -       40%  -
   app  c    10.0.0.13:8080 drain 1      0     up     -       -    state

Two series per server count the events: ``sibuna_edge_server_ejections_total`` and ``sibuna_edge_server_failovers_total``, the requests that left the server for another one. ``sibuna_origin_retries_total`` counts the moves of the node. The access log has one line per request, under the server that ended it. Its last field, ``retries``, is the number of servers the request left before that one: 0 for nearly every request.

Worked example
~~~~~~~~~~~~~~

A pool has servers ``a``, ``b`` and ``c`` with ``retries`` 2 and sticky cookies. Server ``a`` was stopped a moment ago and no probe has seen it yet. A browser sends ``POST /cart`` with the cookie of ``a``. The token matches ``a`` and ``a`` is eligible, so the request selects ``a``. The connect is refused. Nothing was sent, so the worker asks for another server. ``a`` is tried and marked, round robin gives ``b``, the connect succeeds and ``b`` answers. The response carries a new cookie with the token of ``b``. The next request of the browser goes to ``b``. When ``a`` returns it takes new clients, with a ramp if ``slow_start`` is set, and the browser stays on ``b``.

Rationale and alternatives
--------------------------

**A total request timeout.** Envoy bounds the whole exchange. A download of an hour is then cut. We bound silence instead, as HAProxy does with ``timeout server``.

**Failover on any error for any method.** nginx offers ``proxy_next_upstream non_idempotent``. A POST that reached a server may have been carried out, and sending it twice can charge a customer twice. We do not offer the switch.

**Ejection by success rate.** Envoy compares each server with the mean of its pool. It needs a request volume that small sites do not have, and its outcome is hard to predict. Consecutive failures are simple to state and to test.

**A cookie that names the server.** HAProxy writes the server name into the cookie by default. A client can then address each server in turn and learn the size of the pool. A keyed hash costs one hash per server at parse time and nothing per request beyond a comparison.

**A consistent-hash table for source affinity.** The Maglev table of SID 0015 would rank servers in constant time. It refers to servers by their position, and the positions change when SID 0018 adds or removes a server at run time. Rendezvous hashing has no table. It costs one hash per server, on at most 128 servers.

**Header edits as a rule language.** HAProxy and Envoy can set a header from a pattern or a variable. Fixed names and values cover security headers and markers, which is what operators asked for, and they can be checked completely when the file is parsed.

Security and operational considerations
---------------------------------------

Failover multiplies load on the servers that remain. The bound of ``retries`` and the two-second mark on a failed server keep a dead server from costing more than one connect per request for long. A request that fails over keeps the reservation of one server at a time, so flow limits hold.

Header values are checked when the file is parsed: visible ASCII, spaces and tabs, at most 1024 bytes, and no line break, so an edit cannot split a response. A request field that an edit sets or removes is also dropped when the client spells it with ``_`` for ``-``, because CGI and WSGI servers read both spellings as one variable. The list of refused names keeps an edit from altering framing.

The sticky token is compared in constant time with each server of the pool. The token of a server is computed once and kept beside its load counters. An unknown token is ignored, not an error, so a cookie left from an older topology does no harm. The token of a server changes when the seed changes, and every client is then balanced anew.

``max_body`` is a limit of the edge, checked before the firewall policy. It does not replace the buffer limit of the firewall, which bounds what is inspected.

Backwards compatibility
-----------------------

A topology of SID 0015 to SID 0017 parses unchanged. Four behaviours change without any option:

#. A server may now take up to 60 seconds to answer, where the client idle timeout (15 seconds by default) applied before.
#. A failed connect is tried on up to two other servers before the client sees 502.
#. Three consecutive response timeouts eject a server for ten seconds when another server can serve.
#. Servers receive ``X-Forwarded-Host`` and ``X-Forwarded-Port``.

Acceptance criteria and implementation status
---------------------------------------------

Implemented on the branch ``sid-0019-traffic-policy``. Unit tests stand beside the code. ``crates/lb/tests/traffic.rs`` tests the routing interface, ``crates/lb/tests/flows.rs`` real TCP and UDP flows, ``crates/ingress/tests/inline.rs`` and ``grpc.rs`` the in-process path, and ``cmd/sibuna/tests/edge_traffic.rs`` and ``edge_traffic_tls.rs`` the real binary. "Both paths" below means the event-driven workers and the thread path.

.. list-table::
   :header-rows: 1
   :widths: 22 14 64

   * - Criterion
     - Status
     - Evidence
   * - Timeouts of the pool
     - Done
     - Binary: a server that answers after 2.5 s is served although the client idle timeout is 1 s; a short ``response_timeout`` answers 504; a slow upload keeps the client bound; a connect that hangs ends at ``connect_timeout``. In-process: a silent server answers 504 at the pool bound.
   * - Failover
     - Done
     - Binary: a refused connect moves a POST to another server; at most ``retries`` other servers and none twice; after bytes were sent a GET moves and a POST answers 502. In-process: two refused connects, then the body reaches the third server once.
   * - Moving a request with a body
     - Done
     - Binary, workers and thread path (``edge_traffic.rs``) and HTTP/2 over TLS (``edge_traffic_tls.rs``): a PUT and a DELETE with a body reach the second server whole after the first read them and closed; a body above ``retry_body`` and any body with ``retry_body`` 0 answer 502; a POST answers 502 and no other server sees it. In-process (``grpc.rs``): a POST moves after ``REFUSED_STREAM``, once more to the same server and then to the next, and answers 502 after a lost session. ``crates/net`` tests ``recover`` over all 64 cases.
   * - The choice without a lock
     - Done
     - Routing (``traffic.rs``): eight threads choose 160,000 times on servers of 3 and 2 places and no reservation passes a limit; a drain, a weight and a removal reach a thread that read the table before. The measurements are in "Measured".
   * - The ranking table
     - Done
     - Routing: 4096 addresses keep their servers, in shares that follow weights 1, 2 and 4; when more servers leave than a slot keeps, every client has one that remains and returns home afterwards; a heavier weight gains clients and moves no other. The older tests of source stickiness pass unchanged, for HTTP, TCP and UDP.
   * - Passive health
     - Done
     - Binary, both paths: a silent server is ejected after its consecutive timeouts and the pool then answers at once; a pool of one server keeps serving; 503 responses count only with ``http_5xx``. Unit: forty thousand concurrent reports lose no count.
   * - Slow start
     - Done
     - Routing: a returning server and a server added by a reload ramp, servers that start together do not. Binary: a returning server takes at most 2 of 20 requests at the start of a 30 s ramp, and at least 10 without the option.
   * - Sticky sessions
     - Done
     - Binary, both paths: the cookie beside the cookie of the application, nine requests on one server, a forged token replaced; source stickiness over twelve connections. Workers: a sticky server that is ejected gives way and the cookie follows. In-process: the cookie is ``Secure``.
   * - HTTP policy
     - Done
     - Binary, both paths: redirect with 308 and 301, a route that opts out, a kept connection; header edits on both sides, with the client's ``_`` alias dropped; ``X-Forwarded-Host`` and ``X-Forwarded-Port``; 413 for a declared body and for a chunked body, buffered and streamed, with no upstream error counted; a client that still sends its refused body reads the 413. In-process: response fields set and removed; a body of unknown length is refused beyond the decision prefix. Unit: our own answers carry HSTS once, an interim head and a 101 are left alone.
   * - The three paths agree
     - Done
     - ``cmd/sibuna/tests/edge_traffic.rs`` runs every test of timeouts, failover, passive health, slow start and the body limit on the workers and on the thread path. ``crates/net`` tests ``recover``. In-process: an upload of 1.2 s outlives a response bound of 400 ms; a safe request moves when the session of its HTTP/2 server fails after the send; a session opens within a ``connect_timeout`` above five seconds. Both paths: a client that resets while the server is silent frees its place on the server within 1.5 s, where the server would answer after 3 s.
   * - TLS and HTTP/2 through the binary
     - Done
     - ``cmd/sibuna/tests/edge_traffic_tls.rs``, both paths: a request leaves a refused server; the sticky cookie is ``Secure`` and holds six requests on one server against round robin; the response edits and HSTS; the request edit reaches the server; a 413 of our own carries HSTS and no edit; the failover is counted. A 413 for ``/a/../open/length`` has the route of ``/open``, which turns HSTS off.
   * - Operator visibility
     - Done
     - Binary, both paths: ``show servers`` shows the time left of an ejection and the percent of a ramp; the ejection and failover series count; the log line of a moved request ends with ``"retries":1``.
   * - Integration with SID 0017, 0018 and 0020
     - Done
     - Binary, both paths: a drained server gives up its cookie and its source clients and gets them back; a redirect and a 413 are in the access log; behind a trusted proxy the forwarded client selects the server; a moved request passes over a drained server; a server added with ``add server`` takes at most 2 of 20 requests while it ramps; a moved request is one log line and one count under the server that answered, with one failure on the server it left. Routing: each client of an ejected server gets one other server and keeps it. Flows: source stickiness on a TCP pool and on a UDP pool.
   * - Round robin
     - Done
     - Routing: equal weights cycle, weights 5, 1, 1 give 50, 10, 10 in 70 turns without a run of five, backups last. Binary, both paths: nine requests visit three servers three times each.
   * - Configuration
     - Done
     - Every member has a default. ``sibuna check -f`` reports each malformed member with a hint.

Formal model
~~~~~~~~~~~~

``docs/sid/assets/traffic-policy.lean`` models the four rules that bound what a pool does. It is checked with Lean 4 core (``lean traffic-policy.lean``, version 4.19.0).

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Theorem
     - Statement
   * - ``failover_is_bounded``
     - Failover is a total function of its budget, and tries at most ``retries`` servers beyond the first.
   * - ``failover_tries_no_server_twice``
     - The servers tried are distinct, whatever the scheduler offers.
   * - ``no_retries_no_failover``
     - With ``retries`` 0 the request stays on its first server.
   * - ``ramp_weight_is_positive``, ``ramp_weight_is_bounded``
     - A ramping server has at least one unit of weight and at most its configured weight.
   * - ``ramp_weight_is_monotone``
     - The weight never decreases as time passes.
   * - ``ramp_weight_is_full_after_the_ramp``
     - After the ramp the weight is the configured weight.
   * - ``chosen_is_eligible``
     - Whatever is chosen is eligible, given that the scheduler chooses so. Stickiness never selects a server that cannot serve.
   * - ``eligible_sticky_server_is_chosen``, ``ineligible_sticky_server_gives_way``
     - A sticky server is used exactly when it is eligible. Otherwise the choice is the normal one.
   * - ``count_stays_below_the_limit``, ``success_clears_the_count``, ``ejects_exactly_at_the_limit``
     - Only ``failures`` consecutive failures eject a server.
   * - ``ejection_never_empties_a_pool``, ``ejected_servers_wait``
     - Passive health never leaves available servers without a candidate, and an ejected server waits while another is available.
   * - ``resend_needs_no_answer_and_a_kept_request``
     - A request is sent again only before a response byte and only while it is kept.
   * - ``a_request_that_is_not_idempotent_needs_a_refusal``
     - A request whose method is not idempotent is sent again only when the server refused it.
   * - ``a_server_is_tried_again_at_most_once``
     - The same server is tried again only for a pooled connection, and only once.
   * - ``first_eligible_is_eligible``, ``home_is_eligible``
     - The server that the ranking table gives a client is eligible, also when the slot has none and the whole pool is ranked.
   * - ``the_first_server_of_a_slot_serves_when_it_can``
     - A client has the nearest server of its slot whenever that server is eligible.

The model takes the scheduler as an arbitrary function. It does not model the round robin credits, the rendezvous ranking itself, or concurrency. Reservations are no longer sequential: the model states what one reservation does, and the test with eight threads shows that the limit of a server holds between them.

Integration with SID 0017, SID 0018, SID 0020 and SID 0021
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The branch was merged with the direct sends of SID 0017, the run-time changes of SID 0018 and the observability of SID 0020. These rules follow.

**Drained servers (SID 0018).** A drained server takes no new request: not by the scheduler, not by a sticky cookie, not by source stickiness and not by failover. Source stickiness leaves drained servers out of its ranking, so each client of a drained server has one other server until the drain ends. A cookie that names a drained server is replaced by the cookie of the server that answered, and is honoured again after the drain. A server whose drain ends has been out of service, so it ramps when the pool has a ``slow_start``.

**Servers added at run time (SID 0018).** ``add server`` joins a pool that has servers, so the new server ramps like one that a reload adds. Its sticky token is derived from its name, as for a server of the file.

**Retired revisions (SID 0018).** A request is chosen, and moved on a failure, under the routing revision it was decided under, for as long as that revision serves.

**Direct sends (SID 0017).** A request to an HTTP/2 or HTTP/3 server has the same bounds as one to an HTTP/1.1 server. ``connect_timeout`` bounds the opening of the shared session, whatever its value. A server whose session cannot be opened received nothing, so the request moves to another server of the pool. A session that fails before a response head is covered in "The three paths". ``response_timeout`` bounds the wait for the response head and the silence of the server between two pieces of the body. It thereby replaces the fixed 60 seconds of SID 0017 as the bound on a silent gRPC stream. Timeouts and statuses are reported to passive health, and the response edits and the sticky cookie apply.

**One line, one count (SID 0020).** A request that moved is logged once and counted once, under the server that ended it. Each server that it left counts one failure in ``sibuna_edge_server_failures_total``, one in ``sibuna_edge_server_failovers_total`` and no request. A redirect and a 413 are answers of our own: they are logged with their status and without a server.

**The client of source stickiness (SID 0020).** Behind ``trusted_proxies`` the client is the address that the proxy recorded, the same address that the access log and the limits use. Without the option it is the socket peer. TCP and UDP pools have no forwarded address and use the socket peer.

**The automatic redirect of SID 0021.** ``redirect_https`` is an explicit member of a cleartext frontend or route. It is self-contained: ``RoutePolicy::redirect_https`` holds it and ``traffic::intercept`` answers it, after the ban table and the request limiter and before the firewall. It knows nothing of managed names. The two redirects write the same answer for the same request, so a name that has both is redirected once, by whichever is asked first. Two points need care in SID 0021. An HTTP-01 challenge under ``/.well-known/acme-challenge/`` must be answered before ``traffic::intercept``, or the frontend needs a route for that prefix with ``redirect_https: false``; otherwise a frontend with ``redirect_https: true`` redirects the challenge. And ``redirect_https: false`` on a route is an explicit choice of the operator that the automatic redirect should respect.

Known gaps
~~~~~~~~~~

#. An HTTP/3 server cannot refuse a request in a way we read. The client library reports ``H3_REQUEST_REJECTED`` like any other stream error, so a request to an HTTP/3 server that is not idempotent never moves after the send.
#. The move of a request that a pooled HTTP/1.1 connection handed back unsent has no test. The connection must close between our check and our write, which a test cannot place. The rule that it feeds is tested.
#. A body moves only when it ended inside the request buffer of 64 KiB. A longer body is streamed and is gone when the server fails. Keeping it would mean a second buffer per request, up to the bound, and the record does not spend that memory.
#. A client that closes its connection in order while the server is silent is not noticed until we write to it. On no path can we tell this from a client that closed its sending side and waits for the answer. A reset is noticed: at once by the workers, within 250 ms on the thread path.
#. The choice of a server still writes to memory that the threads share: the reference counts of the pool policy, the route policy, the pool name and the server names, and the counters of the chosen server. Under eight threads that do nothing else it costs about a microsecond per call, against 4 microseconds with the lock. Removing these writes means a reservation that borrows from the snapshot, which changes the type that all three paths hold. We did not do it.
#. Two requests that choose at the same moment may take the same least loaded server. "The choice of a server without a lock" gives the reason.
#. A thread that serves no request keeps the snapshot it last read, and with it the pools of a topology that a reload replaced. This is memory only, one snapshot per idle thread, until the next request of that thread.
#. The ranking table changed the server of most client addresses against the ranking before it. Nodes that run the two versions side by side disagree on the home of a client until all are upgraded.
#. The measurements are micro-measurements on one development machine that ran other work. The record was not benchmarked under load on a cluster: this work was not allowed on the test hosts.

Measured
~~~~~~~~

A release build of the lb crate was timed on one machine with two million calls per thread.

.. list-table::
   :header-rows: 1
   :widths: 46 18 18 18

   * - Call
     - Threads
     - Before
     - After
   * - ``policy``, no policy in the topology
     - 1
     - 3.9 ns
     - 1.0 ns
   * - ``policy``, no policy in the topology
     - 8
     - 219 ns
     - 1.2 ns
   * - ``firewall_applies``, no switch in the topology
     - 8
     - 230 ns
     - 1.6 ns
   * - ``choose``, 4 servers
     - 1
     - 103 ns
     - 113 ns
   * - ``choose``, source sticky, 4 servers
     - 1
     - 259 ns
     - 199 ns
   * - ``choose``, source sticky, 128 servers
     - 1
     - 4340 ns
     - 3527 ns

"Before" took the table lock for each of the three questions of a request. "After" answers the first two from two flags that a reload stores, and hashes the name of a server once, not per request. The difference in the plain ``choose`` is noise between two runs.

The second table is the removal of the lock from the choice and the ranking table. It was measured in the same way, three runs each, on a machine that ran other work, so we give the range.

.. list-table::
   :header-rows: 1
   :widths: 46 18 18 18

   * - Call
     - Threads
     - With the lock
     - Without
   * - ``choose``, 4 servers
     - 1
     - 110 to 120 ns
     - 130 to 200 ns
   * - ``choose``, 4 servers
     - 8
     - 4100 to 4600 ns
     - 790 to 1600 ns
   * - ``policy``, a topology with ``max_body``
     - 8
     - 480 ns
     - 170 to 220 ns
   * - ``firewall_applies``, a topology with ``max_body``
     - 8
     - 14 ns
     - 1.4 ns
   * - ``choose``, source sticky, 4 servers
     - 1
     - 234 ns
     - 116 to 122 ns
   * - ``choose``, source sticky, 32 servers
     - 1
     - 954 ns
     - 122 to 129 ns
   * - ``choose``, source sticky, 128 servers
     - 1
     - 3443 ns
     - 148 to 188 ns

On one thread the choice costs a little more than before: the lookup of the thread's snapshot replaces an uncontended lock. On eight threads it costs a quarter. What remains there is the shared reference counts that "Known gaps" names: ``policy`` alone, which clones one shared policy and takes no lock, costs 200 ns per call on eight threads. Source stickiness no longer depends on the size of the pool.

Open questions
--------------

#. Should a sticky cookie take a lifetime, so that it survives a browser restart?
#. Should ``retries`` also bound the attempts of a TCP flow, which SID 0015 fixes at three?

Review history
--------------

- 2026-11-24. Initial draft, written from the audit of the edge before its first production use.
- 2026-11-24. Review of the design before the implementation. The response bound was first one bound for the whole exchange on a worker; it would have let a slow upload hold a slot for 60 seconds, so it now applies only while the server owes bytes. Passive health first ejected without regard to the rest of the pool; the panic rule was added so that a pool of one slow server keeps serving. The cookie first carried the server name; it is now a keyed hash. The redirect first offered 302 and 307; only the permanent statuses 308 and 301 remain, because a temporary redirect to HTTPS is a mistake.
- 2026-11-24. Review of the implementation. Found and fixed: the in-process path bounded one attempt by the sum of both timeouts and so tried a refused server for too long; the fixed-point logarithm of the rendezvous ranking overflowed; a chunked body was counted from the admission only, so the buffered part escaped ``max_body``; our HSTS field stood beside that of the server; a client could keep a request field that an edit removes by spelling it with ``_``. The slow-start text claimed that least connections ignores the ramp for sequential traffic; the code divides by the weight in the tie-break too, and the text now says so. The gaps that remain are listed in "Known gaps".
- 2026-11-24. Merge with ``main``, which had gained SID 0018, SID 0020 and the direct sends of SID 0017. The section on integration records the rules. Found and fixed in the merge: eligibility for slow start ignored a drain; source stickiness kept ranking a drained server and read the socket peer behind a trusted proxy; a moved request stayed in the log under the server it had left; the direct send had the fixed bounds of SID 0017 and no failover.
- 2026-11-24. Review before production use, of the gaps that the last review listed. Design first: the three paths must share the rule for moving a request, so it became ``sibuna_net::recover`` and the thread path gained ``sibuna_net::Route``; the section "The three paths" records it. Closed: the thread path has the pool timeouts, failover, passive health and the chunked body limit; the in-process path bounds a body of unknown length and no longer counts a moving upload as silence; a direct send moves a safe request after a lost session and honours ``connect_timeout`` above five seconds; our own answers carry HSTS; a 413 lets the client finish and is not an upstream error; ``show servers`` and two series show ejections, ramps and failovers; the clients of a server that is out keep one other server; passive health loses no concurrent report; the policy and firewall questions take no lock. Found on the way: a test expected 502 from a silent server on the thread path, which now answers 504 like the workers; tests of the lb crate bound a released port and could collide, and now use a loopback address of their own. Decided and recorded as intended: no edits and no cookie on our own answers, no edit of a 101, one ejection for one address in two pools, no new ramp on a weight change. What remains is in "Known gaps".
- 2026-11-25. The last gaps. Design first, in the three sections "Moving a request that has a body", "The choice of a server without a lock" and "The ranking table of source stickiness", with the two rules added to the Lean model. Implemented: ``retry_body`` and the rule of ``kept``, ``idempotent`` and ``refused`` on all three paths; the snapshot of the routing table; the ranking table; the watch on the client and the wire count of a chunked body on the thread path; the route of the normal path for HSTS on our own answers; the field ``retries`` of the access log. Review of the implementation found and fixed: a kept body that was sent again was counted twice against ``max_body`` on the in-process path, so a second attempt could answer 413; the design named ``TRACE`` among the methods and the code has no such method, so the text now leaves it out; the design let the snapshot hold the sticky key, which nothing reads once the tokens are stored in the pools. The crate ``h2`` is now named in the workspace. It was in the build through hyper, and we name it only to read the reason of a failed stream.

References
----------

- SID 0015, SID 0016, SID 0017 and SID 0018.
- HAProxy configuration manual: ``timeout connect``, ``timeout server``, ``retries``, ``option redispatch``, ``observe``, ``slowstart``, ``cookie``, ``balance``.
- nginx: ``proxy_next_upstream``, ``max_fails``, ``slow_start``, ``sticky cookie``, ``client_max_body_size``.
- Envoy: outlier detection and the panic threshold.
- RFC 6797, HTTP Strict Transport Security. RFC 9110, section 15.4.9 (308) and section 15.5.14 (413).
- D. Thaler and C. Ravishankar, "Using name-based mappings to increase hit rates", 1998 (rendezvous hashing).

.. rubric:: Lifecycle event

::

   2026-11-24: discussion -> accepted. Three reviews converged; every acceptance
   criterion is met on all three request paths and the remaining gaps are
   recorded
