:sid-number: 0024
:sid-title: TLS on the Workers
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-25
:sid-updated: 2026-11-25
:sid-discussion: No external discussion URL assigned
:sid-summary: Ends the TLS of an HTTP/1.1 connection on the worker that serves its requests, so that no byte of such a connection crosses to another thread. The worker reads the first message of the client, keeps the connection when the client does not offer HTTP/2, and gives it to the protocol runtime with the bytes it read otherwise.
:sid-labels: ["architecture","load-balancer","tls","performance"]

TLS on the Workers
==================

Abstract
--------

An event-driven worker of SID 0016 serves an HTTP/1.1 connection from the first byte to the last on one thread. A connection with TLS did not have this property. The protocol runtime of SID 0017 ended its TLS and copied the clear bytes through a socket pair to a worker. We let the worker end the TLS itself. A connection whose client offers HTTP/2 still goes to the runtime.

Motivation and scope
--------------------

We measured Sibuna beside HAProxy with both writing the same headers (the book, "Like for like"). Over plain HTTP Sibuna carried the same load with less CPU for a request. Over HTTPS it carried 90 percent, although it used 40 of 48 CPU seconds. The time of each thread group showed the reason: the runtime threads ended TLS, the workers served the request, and every request and every response waited for the other thread. Sixteen threads also shared eight CPUs.

.. code-block:: text

   before:  client == TLS ==> runtime thread == socket pair ==> worker ==> server
   after:   client == TLS ==> worker ==> server

We specify which connections a worker keeps, how it reads and writes through TLS, and how a connection reaches the runtime. We do not change HTTP/2 or HTTP/3: they stay in the runtime, with its HTTP/2 library. We do not change the thread path that serves a node without workers. We do not add kernel TLS, CPU pinning or other tuning of the host, because a node must run unchanged in a container.

Specification
-------------

Invariants
~~~~~~~~~~

#. A TLS connection is served by exactly one of the two: a worker or the runtime. No byte is read twice and none is lost when a connection goes to the runtime.
#. The certificate, the protocol versions, the cipher suites and the client certificate check are those of the listener, whoever ends the TLS. Both use the same configuration object, and a reload reaches both.
#. A connection counts once under the node bound and once under the bound of its client, from the accept to its end, as before.
#. The worker does a bounded amount of work for a client that has not finished its handshake: at most 16 KiB of first message and at most 15 seconds.
#. Clear bytes that the TLS session holds are never left waiting for a socket event that will not come.

Which connections a worker keeps
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The listener gives every accepted TLS socket to a worker. The worker reads the first message of the client, the ClientHello, without answering. The message lists the application protocols that the client offers.

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - The client offers
     - Who serves the connection
   * - no protocol list, or a list without ``h2`` and without ``acme-tls/1``
     - the worker, as HTTP/1.1
   * - ``h2``
     - the runtime, which negotiates as before
   * - ``acme-tls/1``
     - the runtime, which answers the validation of SID 0021
   * - a server name whose certificate must first be obtained on demand
     - the runtime, which waits for the certificate
   * - a message that is not a ClientHello, or more than 16 KiB without a whole one
     - nobody: the worker closes the connection

The worker decides from the offer and not from the outcome, because the outcome is known only after the answer is sent, and a session that has answered cannot move. A client that offers ``h2`` gets ``h2`` whenever the listener serves it, so the offer tells the outcome.

To give a connection to the runtime, the worker removes the socket from its poller and passes the socket, the bytes it has read, the flow permit and the place under the bounds. The runtime reads those bytes first and the socket after them. The worker has written nothing, so the client sees one ordinary handshake.

Reading and writing through TLS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The TLS library is used without I/O of its own: the worker moves bytes between the socket and the session and between the session and its buffers. The request path above this point does not change. It reads clear bytes into the request buffer and appends clear bytes to the output of the connection.

*Reading.* The worker takes clear bytes from the session while the request buffer has room. When the session has none, the worker reads the socket once into the session and tries again. It stops when the buffer is full or the socket has nothing. If it stopped because the buffer was full, the connection is marked as holding clear bytes, and the worker reads again when it next works on the connection, with or without a socket event (invariant 5).

*Writing.* The worker gives output bytes to the session, which holds at most 64 KiB of encrypted bytes, and writes those to the socket. Output that the session did not take stays in the output of the connection, as bytes that a socket did not take do today. The worker asks for write events while the output or the session holds bytes. A connection closes only after the session has written everything, and the worker sends the TLS close message before it closes its side.

*The handshake.* The messages of the handshake pass through the same two steps. The time from the accept to the end of the handshake is bounded by 15 seconds, the bound of the runtime, or by the idle timeout when that is shorter. When the handshake ends, the worker records the TLS version, the cipher suite and the fingerprint of the client certificate for the access log and the rules, as the runtime does.

Tunnels, lingering closes (SID 0019) and deadlines work on clear bytes and need no change beyond these two steps.

A listener that obtains certificates on demand (SID 0021) adds one case. Its handshake may wait for a certificate, and a worker must not wait. The worker asks the listener whether the server name of the ClientHello must first obtain a certificate. If so, the connection goes to the runtime, which waits as before. A name whose certificate is there stays on the worker.

Counting
~~~~~~~~

The listener counts a TLS connection once when it accepts it, and the worker holds that place until the connection ends or goes to the runtime, which then holds it. Before this record a TLS connection with HTTP/1.1 counted twice under the node bound, once for the client socket and once for the socket pair. It now counts once, as a plain connection does.

``/__sibuna/metrics`` gains two counters: ``tls_kept`` for the connections a worker kept and ``tls_passed`` for those it gave to the runtime.

Rationale and alternatives
--------------------------

We considered peeking at the socket without reading, so that the runtime could take an untouched socket. A ClientHello with a post-quantum key share is larger than one network packet, so a peek can see half of it, and a level-triggered poller would then spin. Reading and passing the bytes on works for every size.

We considered deciding after the handshake and moving the session. The TLS library gives no way to move a session into the asynchronous wrapper of the runtime, and we will not write one.

We considered serving HTTP/2 on the workers too. That needs an HTTP/2 implementation of our own. We decided against it: the library in the runtime is correct and maintained, and the cost of writing and securing our own is larger than the gain.

We considered kernel TLS. It needs a kernel module and a capability that a container may not have.

Security and operational considerations
---------------------------------------

The handshake computes a signature, about a tenth of a millisecond, on the worker thread. A flood of handshakes therefore delays the requests of that worker. The same work delayed the runtime threads before, and the bounds on connections for each client apply before the handshake, as before.

The parser of the first message is that of the TLS library. We add no parser of our own.

A panic while a worker works on a connection closes that connection only (SID 0016). This now covers the TLS steps.

Backwards compatibility
-----------------------

No key of the configuration changes. A client sees the same certificate, protocols and suites. The HTTP/1.1 answers over TLS now come from the same code as over plain HTTP, which they already did through the socket pair. A node without workers (``http.event_loop: false``) is unchanged.

Acceptance criteria and implementation status
---------------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 6 54 40

   * - #
     - Criterion
     - Status
   * - 1
     - An HTTP/1.1 connection over TLS is served by a worker alone.
     - Met. ``cmd/sibuna/tests/edge_tls_workers.rs`` opens connections without a protocol list, with ``http/1.1`` and with TLS 1.2. ``tls_kept`` counts each, ``tls_passed`` stays 0, and the access log has the version and the suite of each request.
   * - 2
     - A client that offers ``h2`` is served over HTTP/2 as before, also when its first message arrives in pieces.
     - Met. The same file writes a ClientHello in three pieces with pauses and gets ``h2``, runs an HTTP/2 exchange, and reads ``tls_passed``. The unit tests of ``crates/ingress/src/sealed.rs`` feed a ClientHello byte by byte: the answer comes with the last byte, and a passed connection carries every byte.
   * - 3
     - Large requests and responses, pipelined requests and a WebSocket tunnel pass through TLS on a worker whole.
     - Met, on both paths. A 700 kB body, a 1 MiB response, 600 pipelined requests in one write (more than one buffer of clear bytes) and 2 MiB through a tunnel arrive whole.
   * - 4
     - A client that does not finish its handshake loses the connection within the bound.
     - Met. A silent client, a client with half a ClientHello and a client that sends plain HTTP are closed, and the node serves on. The test uses an idle timeout of one second. A second test sets the idle timeout to a minute: half a ClientHello loses its connection after 15 seconds, and a connection that finished its handshake stays.
   * - 5
     - A listener with certificates on demand passes only the handshakes that wait.
     - Met. ``cmd/sibuna/tests/edge_acme_demand.rs`` reads the counters: the first handshake for a name is passed to the runtime, and the second is kept by a worker.
   * - 6
     - HTTPS carries more requests on the benchmark host than before.
     - Met. With 256 connections on one host: 149,168 requests per second before and 174,901 after, where HAProxy with the same headers carries 153,080. The book has the table.

The model ``docs/sid/assets/tls-on-the-workers.lean`` proves the two facts the design rests on: a read leaves clear bytes behind only when it filled the buffer, and then says so (invariant 5), and the bytes that the runtime replays followed by the rest of the socket are the stream of the client (invariant 1).

Known gaps
----------

#. HTTP/2 is unchanged. It carries 67 to 74 percent of what HAProxy carries on the benchmark host, and only a cheaper HTTP/2 path would change that.
#. A client that offers ``h2`` and then speaks HTTP/1.1, because the listener chose it, is served by the runtime through the socket pair, as before. No listener is configured that way today.
#. TLS session resumption is that of the TLS library with its defaults. With a new connection for every request the node carried 5,890 HTTPS requests per second at 64 connections and 4,566 at 512, where HAProxy carried 4,967 and 4,693. The load generator was the limit in both cases: Sibuna used 10 to 12 CPU seconds of 64 and HAProxy 32. We did not find the rate at which the handshakes themselves fill the workers.
#. The node without workers, and Windows, keep the old path.
#. The 99th percentile at 2,048 HTTPS connections was 54 ms in the final run and 38 ms in an earlier run. We did not look for the reason of the spread.

Open questions
--------------

None.

Review history
--------------

- 2026-11-25. Initial draft, after the comparison with HAProxy.
- 2026-11-25. Implemented. The review of the code found three faults before the tests ran: a lingering close would have asked for write events without end, because the session flag stayed set while the worker only discards bytes; the draft named 10 seconds where the runtime uses 15; and a TLS connection with HTTP/1.1 had always counted twice under the node bound, which the new path corrects. Listeners with certificates on demand were left to the runtime.
- 2026-11-25. A listener with certificates on demand now keeps the connections whose certificate is there. The handshake bound got a test of its own, and the rate of new connections was measured.

References
----------

- SID 0016, Event-Driven HTTP Workers.
- SID 0017, In-Process Exchanges.
- SID 0021, Automatic HTTPS.
