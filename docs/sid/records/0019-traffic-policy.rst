:sid-number: 0019
:sid-title: Traffic Management and HTTP Policy for the Edge
:sid-state: discussion
:sid-status: Open for Discussion
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

There are three request paths, and they do not get the same work. The event-driven workers of SID 0016 are the main path and get everything. The in-process path of SID 0017 for HTTP/2 and HTTP/3 gets everything but the streaming body limit. The thread path (``http.event_loop: false``) is the fallback for platforms without the workers. It gets what the shared decision gives it and no more. The section "Known gaps" says what that leaves out.

Specification
-------------

Invariants
~~~~~~~~~~

#. A topology that sets no option of this record is valid and serves as before, except for the defaults named in "Backwards compatibility".
#. A request is sent to another server only when the first server cannot have acted on it: no byte of it was sent, or it is safe (GET, HEAD, OPTIONS) and was buffered whole.
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

On a worker the server owes us bytes when the request body is complete and the client has taken every response byte we hold. Otherwise the client is the slow party and its own bound applies, so ``response_timeout`` cannot be used to hold a worker slot with a slow upload. On the in-process path the two server bounds replace the fixed 5 and 60 seconds of SID 0017.

Failover
~~~~~~~~

.. graphviz::
   :caption: One request and its attempts. A server is tried once, and the count of attempts is bounded.
   :alt: A request selects a server. A failed connect, or a failed safe buffered request, selects another server that was not tried while attempts remain. Otherwise the client receives 502.

   digraph failover {
     graph [rankdir=LR, bgcolor="transparent", fontname="Helvetica", fontsize=9, nodesep=0.3, ranksep=0.45];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=8.5, fillcolor="#eff6ff", color="#1e40af", penwidth=1.0, margin="0.1,0.05"];
     edge [color="#64748b", fontname="Helvetica", fontsize=7.5, fontcolor="#475569", arrowsize=0.6];
     select [label="Select\nnot tried, eligible"];
     connect [label="Connect"];
     send [label="Send request"];
     done [label="Response"];
     fail [label="502", fillcolor="#fef3c7", color="#92400e"];
     select -> connect;
     connect -> send [label="connected"];
     send -> done;
     connect -> select [label="failed, attempts left"];
     send -> select [label="no response byte,\nsafe and buffered,\nattempts left"];
     select -> fail [label="none left"];
   }

The reservation of a request remembers the servers it tried. ``HttpRoutes::retry`` takes a failed reservation and returns a reservation on another server of the same pool, or nothing. It refuses when the attempts are spent, when the revision that routed the request no longer serves (a reload retires a revision and SID 0018 keeps it for ten seconds), and when no untried server is eligible. The failed server is marked as before, so later requests avoid it for two seconds.

A connect failure is a refused connection, an unreachable address or the connect timeout. For it the method of the request does not matter, because the server received nothing. After a byte was sent, only a request that SID 0016 calls retryable is sent again. A pooled socket that the server closed is first replaced by a fresh connection to the same server, as before. If that fails too, the request moves on.

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

Sticky sessions
~~~~~~~~~~~~~~~

**By cookie.** The token of a server is the first 16 hexadecimal digits of a keyed BLAKE3 hash of the pool name and the server name. The key is derived from the challenge seed, so the nodes of a cluster that share ``http.secret_file`` accept each other's cookies. A request that carries the cookie with the token of an eligible server goes to that server. Any other request is balanced as usual, and its response carries

.. code-block:: text

   Set-Cookie: sibuna_srv=3f9a61c2d07be845; Path=/; HttpOnly; SameSite=Lax

with ``Secure`` on a frontend with TLS. The cookie has no lifetime: it ends with the browser session. The token reveals neither the name nor the address of the server, and a client cannot compute the token of another server to probe it.

**By source address.** The servers are ranked for the client address, without the port, by weighted rendezvous hashing in integer arithmetic. The first server of the ranking is used when it is eligible. When a server leaves, only its clients move, and they return when it returns. The hash is not keyed, so every node ranks alike.

In both kinds a server that is down, drained, full, ejected or already tried falls back to the normal selection. A request that was moved by cookie stickiness to another server, or that failed over, receives the cookie of the server that answered. Source stickiness is a property of the pool, so TCP and UDP pools accept it too.

HTTP policy
~~~~~~~~~~~

The redirect and the body limit are decided after the ban table and the request limiter and before the firewall policy, so that a cleartext request is never challenged. The redirect goes to ``https://`` and the host of the request, with the configured port when it is not 443, and the path and query as they were sent. A request without a usable host answers 400.

A request that declares a body longer than ``max_body`` answers 413 before any byte goes to a server, and the connection closes because the body was not read. A chunked body that ends inside the request buffer of 64 KiB is measured exactly in the same way. A longer chunked body is admitted when the buffer is full, and a worker counts the rest as it arrives, with its chunk framing. When the count passes the limit the exchange ends: 413 when no response began, a closed connection otherwise.

HSTS is one field line, written on every response that a server gives on a TLS frontend. It replaces a ``Strict-Transport-Security`` field of the server, so that a client reads one policy. A redirect keeps the connection open when the request has no body.

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

All state of this record that belongs to a server (the failure count, the ejection, the ramp, the round robin credit and the cached cookie token) lives beside the load counters of SID 0015, which a reload keeps for every address.

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

Implemented on the branch ``sid-0019-traffic-policy``. Unit tests stand beside the code. ``crates/lb/tests/traffic.rs`` tests the routing interface, ``crates/ingress/tests/inline.rs`` the in-process path, and ``cmd/sibuna/tests/edge_traffic.rs`` the real binary. "Both paths" below means the event-driven workers and the thread path.

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
     - Binary: a refused connect moves a POST to another server; at most ``retries`` other servers and none twice; after bytes were sent only a safe buffered request moves. In-process: two refused connects, then the body reaches the third server once.
   * - Passive health
     - Done
     - Binary: a silent server is ejected after its consecutive timeouts and the pool then answers at once; a pool of one server keeps serving; 503 responses count only with ``http_5xx``.
   * - Slow start
     - Done
     - Routing: a returning server and a server added by a reload ramp, servers that start together do not. Binary: a returning server takes at most 2 of 20 requests at the start of a 30 s ramp, and at least 10 without the option.
   * - Sticky sessions
     - Done
     - Binary, both paths: the cookie beside the cookie of the application, nine requests on one server, a forged token replaced; source stickiness over twelve connections. Workers: a sticky server that is ejected gives way and the cookie follows. In-process: the cookie is ``Secure``.
   * - HTTP policy
     - Done, with gaps 1 to 4
     - Binary, both paths: redirect with 308 and 301, a route that opts out, a kept connection; header edits on both sides, with the client's ``_`` alias dropped; ``X-Forwarded-Host`` and ``X-Forwarded-Port``; 413 for a declared body. Workers: 413 for a chunked body, buffered and streamed. In-process: response fields set and removed.
   * - Integration with SID 0017, 0018 and 0020
     - Done, with gaps 7 and 13 to 15
     - Binary, both paths: a drained server gives up its cookie and its source clients and gets them back; a redirect and a 413 are in the access log; behind a trusted proxy the forwarded client selects the server. Workers: a moved request passes over a drained server; a server added with ``add server`` takes at most 2 of 20 requests while it ramps; a moved request is one log line and one count under the server that answered, with one failure on the server it left.
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

The model takes the scheduler as an arbitrary function. It does not model the round robin credits, the rendezvous ranking or concurrency: the routing table is one lock, so reservations are sequential.

Integration with SID 0017, SID 0018, SID 0020 and SID 0021
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The branch was merged with the direct sends of SID 0017, the run-time changes of SID 0018 and the observability of SID 0020. These rules follow.

**Drained servers (SID 0018).** A drained server takes no new request: not by the scheduler, not by a sticky cookie, not by source stickiness and not by failover. Source stickiness leaves drained servers out of its ranking, so each client of a drained server has one other server until the drain ends. A cookie that names a drained server is replaced by the cookie of the server that answered, and is honoured again after the drain. A server whose drain ends has been out of service, so it ramps when the pool has a ``slow_start``.

**Servers added at run time (SID 0018).** ``add server`` joins a pool that has servers, so the new server ramps like one that a reload adds. Its sticky token is derived from its name, as for a server of the file.

**Retired revisions (SID 0018).** A request is chosen, and moved on a failure, under the routing revision it was decided under, for as long as that revision serves.

**Direct sends (SID 0017).** A request to an HTTP/2 or HTTP/3 server has the same bounds as one to an HTTP/1.1 server. ``connect_timeout`` bounds the opening of the shared session. A server whose session cannot be opened received nothing, so the request moves to another server of the pool. ``response_timeout`` bounds the wait for the response head and the silence of the server between two pieces of the body. It thereby replaces the fixed 60 seconds of SID 0017 as the bound on a silent gRPC stream. Timeouts and statuses are reported to passive health, and the response edits and the sticky cookie apply.

**One line, one count (SID 0020).** A request that moved is logged once and counted once, under the server that ended it. Each server that it left counts one failure in ``sibuna_edge_server_failures_total`` and no request. A redirect and a 413 are answers of our own: they are logged with their status and without a server.

**The client of source stickiness (SID 0020).** Behind ``trusted_proxies`` the client is the address that the proxy recorded, the same address that the access log and the limits use. Without the option it is the socket peer. TCP and UDP pools have no forwarded address and use the socket peer.

**The automatic redirect of SID 0021.** ``redirect_https`` is an explicit member of a cleartext frontend or route. It is self-contained: ``RoutePolicy::redirect_https`` holds it and ``traffic::intercept`` answers it, after the ban table and the request limiter and before the firewall. It knows nothing of managed names. The two redirects write the same answer for the same request, so a name that has both is redirected once, by whichever is asked first. Two points need care in SID 0021. An HTTP-01 challenge under ``/.well-known/acme-challenge/`` must be answered before ``traffic::intercept``, or the frontend needs a route for that prefix with ``redirect_https: false``; otherwise a frontend with ``redirect_https: true`` redirects the challenge. And ``redirect_https: false`` on a route is an explicit choice of the operator that the automatic redirect should respect.

Known gaps
~~~~~~~~~~

#. The thread path (``http.event_loop: false``) has the choice of the server, sticky sessions, the redirect, the declared body limit and the header edits. It does not have the timeouts of the pool, failover to another server, the reports to passive health, or the limit on a chunked body that is longer than the request buffer.
#. The in-process path does not bound a body without a declared length beyond the prefix that the decision is shown. Its ``response_timeout`` also covers the time its server takes to read the request body.
#. Sibuna's own answers (challenge pages, refusals, 502 and 504) carry neither HSTS, nor the response edits, nor the sticky cookie. The response to an upgrade (101) is not edited either.
#. A request that is refused with 413 closes its connection without reading the body. A client that is still writing may see a reset before it reads the answer.
#. A 413 from a worker during a streamed body counts in ``upstream_errors``.
#. No test of the binary runs over TLS. ``Secure``, HSTS and the in-process edits are tested in the lb and ingress crates only.
#. Source stickiness on TCP and UDP pools follows from the shared reservation and has no test of its own. On a direct send to an HTTP/2 server one test through the binary sets ``response_timeout`` to 1 s: a gRPC call on which nobody speaks is cut after that time, and a conversation with a message every 400 ms outlives it. ``connect_timeout`` on a direct send has no test, and there it cannot exceed the 5 s that the egress allows for opening a session.
#. Passive health counts with relaxed atomics. Two workers that report at once may delay an ejection by one failure.
#. Two pools that name the same server address share its load counters, as in SID 0015, and therefore its ejection and its ramp.
#. The policy lookup, the firewall switch and the choice of a server each take the lock of the routing table. A topology without any policy pays the lock and nothing else.
#. Source stickiness ranks every server of the pool for each request: one hash and one integer logarithm per server, on at most 128 servers.
#. Nothing reports ejections and ramps to the operator. A failover shows in the worker counter ``origin_retries`` and in the failure counter of the server that was left. ``show servers`` of SID 0018 does not show an ejected or a ramping server.
#. On a direct send to an HTTP/2 or HTTP/3 server a request moves only when the shared session cannot be opened. A session that fails after the request was sent answers 502, also for a safe request.
#. Source stickiness gives the clients of a drained server one other server each. The clients of a server that is down or ejected are balanced as usual until it returns.
#. A run-time change of a weight restarts no ramp.
#. The branch was not benchmarked. The hot path of a topology without the new options gains one boxed allocation per request and one comparison per head.

Open questions
--------------

#. Should a sticky cookie take a lifetime, so that it survives a browser restart?
#. Should ``retries`` also bound the attempts of a TCP flow, which SID 0015 fixes at three?
#. Should Sibuna's own pages carry the HSTS field and the response edits?

Review history
--------------

- 2026-11-24. Initial draft, written from the audit of the edge before its first production use.
- 2026-11-24. Review of the design before the implementation. The response bound was first one bound for the whole exchange on a worker; it would have let a slow upload hold a slot for 60 seconds, so it now applies only while the server owes bytes. Passive health first ejected without regard to the rest of the pool; the panic rule was added so that a pool of one slow server keeps serving. The cookie first carried the server name; it is now a keyed hash. The redirect first offered 302 and 307; only the permanent statuses 308 and 301 remain, because a temporary redirect to HTTPS is a mistake.
- 2026-11-24. Review of the implementation. Found and fixed: the in-process path bounded one attempt by the sum of both timeouts and so tried a refused server for too long; the fixed-point logarithm of the rendezvous ranking overflowed; a chunked body was counted from the admission only, so the buffered part escaped ``max_body``; our HSTS field stood beside that of the server; a client could keep a request field that an edit removes by spelling it with ``_``. The slow-start text claimed that least connections ignores the ramp for sequential traffic; the code divides by the weight in the tie-break too, and the text now says so. The gaps that remain are listed in "Known gaps".
- 2026-11-24. Merge with ``main``, which had gained SID 0018, SID 0020 and the direct sends of SID 0017. The section on integration records the rules. Found and fixed in the merge: eligibility for slow start ignored a drain; source stickiness kept ranking a drained server and read the socket peer behind a trusted proxy; a moved request stayed in the log under the server it had left; the direct send had the fixed bounds of SID 0017 and no failover.

References
----------

- SID 0015, SID 0016, SID 0017 and SID 0018.
- HAProxy configuration manual: ``timeout connect``, ``timeout server``, ``retries``, ``option redispatch``, ``observe``, ``slowstart``, ``cookie``, ``balance``.
- nginx: ``proxy_next_upstream``, ``max_fails``, ``slow_start``, ``sticky cookie``, ``client_max_body_size``.
- Envoy: outlier detection and the panic threshold.
- RFC 6797, HTTP Strict Transport Security. RFC 9110, section 15.4.9 (308) and section 15.5.14 (413).
- D. Thaler and C. Ravishankar, "Using name-based mappings to increase hit rates", 1998 (rendezvous hashing).
