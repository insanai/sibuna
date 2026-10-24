Part V: Zero-Allocation Engineering in Rust
===========================================

We follow a connection from accept to response through one fixed buffer, and examine the concurrent data structures that let many connection threads share state without heap allocation on the request path. Where memory safety would otherwise need machinery of its own (reader counts, arenas, descriptor tables, teardown chains), we show how Rust ownership provides it instead.

The Connection Loop
-------------------

.. admonition:: Objectives

   By the end of this chapter, we should be able to explain how one 64 KiB buffer serves an entire keep-alive connection, how the head and body are located without copying, why every connection gets its own bounded thread, how the proxy learns the origin's framing so a proxied client connection can stay open, and which of these guarantees the borrow checker proves for us.

One Thread per Connection, Bounded
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Accept workers (``--workers``, one per CPU by default, at most 64) share the listening socket. Each accepted connection is handed to a thread of its own with a one-megabyte stack, and the accept loop goes straight back to ``accept``. A thread that finishes its connection parks and takes the next one, because creating and ending a thread for every connection stalled the other threads (Part VIII, SID 0002). The alternative, serving a connection to completion on the accept thread, was the first design: it measured well on a single client and badly on sixty-four, because sixty of them waited for a worker to finish its 256-request quota, and the tail latency grew with every waiting client. With a thread per connection, the p99 at 64 connections stays under one millisecond in every whole-product workload, from 305 us to 857 us (``benchmarks/results/product-latest.md``; Part VIII).

The number of connection threads is bounded by ``--max-connections`` (1,024 by default, at most 8,192). Past the bound the accept loop answers ``503 Service Unavailable`` on the new socket and closes it without spawning anything, and counts the event in ``sibuna_overloaded_total``.

.. admonition:: Implementation: ``accept_loop``

   Accepts connections, checks each against the connection bound, and launches it on a thread of its own from the task pool. In ``cmd/sibuna/src/server.rs`` (crate ``sibuna``).

.. code-block:: rust

   fn accept_loop(server: &Arc<Server>, listener: &TcpListener) {
       while !server.is_stopping() {
           let stream = match listener.accept() {
               Ok((stream, _)) => stream,
               // ... out of descriptors or memory: back off 1 ms instead of spinning
           };
           let limit = server.max_connections.load(Ordering::Relaxed);
           if server.connections.fetch_add(1, Ordering::Relaxed) >= limit {
               server.connections.fetch_sub(1, Ordering::Relaxed);
               server.metrics.overloaded.bump();
               let text = "Service Unavailable: connection limit reached";
               reject(server, &stream, text);
               continue;
           }
           set_no_delay(&stream);
           let task_server = Arc::clone(server);
           let launched = server.tasks.launch(move || {
               let _counted = Counted(&task_server);
               crate::connection::serve(&task_server, &stream);
           });
           // ... a launch failure gives the place back and counts an overload
       }
   }

``Counted`` is a guard whose ``Drop`` gives the connection's place in the bound back however the thread ends, by return or by panic. The ``503`` path drains what the client has already sent before it shuts down its side of the socket: closing a socket over unread bytes answers with a reset, and the reset would discard the ``503``.

Threads come from a ``TaskPool`` (``cmd/sibuna/src/tasks.rs``), a fixed table of joinable slots. A finished thread keeps its stack until it is joined, so a slot is joined when it is taken again, and a new task takes the *lowest* finished slot rather than advancing a cursor. A cursor would reach a finished slot again only after a full lap of the table, leaving thousands of finished threads resident, and memory would grow with the connections served instead of the connections open. A second guard, ``Finished``, marks the slot free when the task ends, so a panicking connection frees its slot too.

Memory is bounded the same way. A connection thread holds its 64 KiB read buffer and 16 KiB write buffer on its stack, and a 40 KiB proxy workspace on the heap, allocated once when the connection starts. The worst case is therefore a known number rather than a function of how many sockets a client can open. The idle reaper (below) closes connections that stop sending, so a slow client cannot pin a thread past ``--idle-timeout``.

One Buffer per Connection
~~~~~~~~~~~~~~~~~~~~~~~~~

Every dynamic allocation on a request path is a denial-of-service lever: fragmentation over days, allocator lock contention across threads, and amplification by attackers who craft requests that maximise allocation. Sibuna's rule is absolute: classification, verification, and proxy hand-off run with zero heap allocation. The connection handler owns a 64 KiB read buffer and a 16 KiB write buffer for the life of the socket; everything else is a slice into them.

.. admonition:: Implementation: ``connection::serve``

   Registers the connection with the idle reaper, sets up the buffers, the proxy workspace and the engine cache once, and serves up to 4,096 requests. In ``cmd/sibuna/src/connection.rs`` (crate ``sibuna``).

.. code-block:: rust

   pub fn serve(server: &Server, stream: &TcpStream) {
       let Some(lease) = server.idle.register(stream) else { return };
       // ...
       let mut read_buffer = [0u8; MAX_REQUEST_BYTES]; // 64 KiB
       let mut write_buffer = [0u8; WRITE_BUFFER]; // 16 KiB
       let mut reader = Reader::new(stream, &mut read_buffer[..]);
       let mut peer = PeerText::default();
       peer.format(stream.peer_addr().ok());
       let mut link = Link {
           server,
           stream,
           writer: Writer::new(stream, &mut write_buffer[..]),
           workspace: Workspace::new(),
           cache: EngineCache::new(),
           activity: lease.activity(),
           last: false,
       };
       for served in 0..MAX_REQUESTS_PER_CONNECTION {
           link.last = served + 1 == MAX_REQUESTS_PER_CONNECTION;
           if !serve_one(&mut reader, &mut link, peer.as_bytes()) {
               break;
           }
           lease.touch();
       }
   }

``read_head`` fills the buffer until the blank line appears, searching only the bytes that arrived since the last search, and refuses heads over 16 KiB with ``431``. ``parse_request`` (crate ``sibuna-http``) produces a ``Request<'a>`` whose method, path, query, headers, and cookies are slices of the buffer. The declared body is filled up to what fits and sliced after the head. Then ``reader.consume(head_len + body_len)`` advances the reader, so the next keep-alive request starts cleanly; the reader moves the unread bytes to the front only when it needs room. A chunked body is decoded in place behind the head (SID 0009): each step's framing is cut out of the buffer, so the decoded prefix stays contiguous for inspection. Internal routes are length-delimited and keep the connection open. Proxied requests keep it open too, provided the origin's response is framed and the body was fully buffered; the next sections show how the proxy decides.

.. figure:: /assets/figures/read-buffer.svg
   :alt: The 64 KiB read buffer of one connection: a served part, then the unread window of request head (at most 16 KiB), body prefix and pending bytes, then free space. Method, path, query, headers and cookies are slices of the head, request.body is a slice of the body prefix, and ctx.pending holds the pending bytes, which the proxy sends to the origin first. After the response, reader.consume(head_len + body_len) moves the start of the window to the pending bytes.

   The connection's read buffer while one request is served. Every field of the request is a slice of it.

.. code-block:: rust

   fn serve_one<W: Write>(
       reader: &mut Reader<'_, &TcpStream>,
       link: &mut Link<'_, W>,
       peer: &[u8],
   ) -> bool {
       let head_len = match read_head(reader) {
           Head::Complete(length) => length,
           Head::TooLarge => { /* 431 "Request head exceeds 16 KB" */ return false; }
           Head::Closed | Head::Failed => return false,
       };
       let framing = {
           let bytes = reader.buffered();
           let head = bytes.get(..head_len).unwrap_or_default();
           let request = match parse_request(head) {
               Ok(request) => request,
               Err(error) => return reject_head(link, error),
           };
           let declared = request.content_length().unwrap_or(0);
           // ... Expect: 100-continue
           if declared == 0 && !request.chunked {
               let upload = Upload::declared(&request);
               let pending = bytes.get(head_len..).unwrap_or_default();
               let keep = dispatch(link, request, pending, upload, 0, peer);
               reader.consume(head_len);
               return keep;
           }
           (declared, request.chunked)
       };
       serve_with_body(reader, link, peer, head_len, framing)
   }

.. admonition:: What the borrow checker proves

   The request slices stay valid only until the next fill of the buffer. Sibuna states that rule as a type, not as a comment: the request is a ``Request<'a>``, and ``'a`` is a shared borrow of the reader's buffer. Filling or consuming the buffer needs ``&mut reader``, which the compiler refuses while a ``Request`` borrowed from it is still in use. In ``serve_one`` the request is moved into ``dispatch``, and only after that call returns may ``reader.consume`` run; writing them the other way round does not compile.

   The same rule explains two choices that look odd at first. First, ``serve_with_body`` parses the head a second time. The first parse must end its borrow before the body is buffered, because buffering a chunked body moves bytes inside the buffer; the second parse borrows the settled buffer. Parsing is deterministic and takes about 133 ns for a browser request with a cookie (``zero_copy_request_and_cookie``, 132.5 ns, in ``benchmarks/results/primitives-latest.md``), so the second parse costs little and yields the same verdict. Second, the proxy borrows the parsed request and the pending bytes and must not refill the connection buffer, so it reads further client bytes into an upload buffer of its own. Because it cannot hand back what it read, the client connection is kept only when the body was fully buffered.

The Proxy Head Rewrite
~~~~~~~~~~~~~~~~~~~~~~

The head is not forwarded verbatim. ``write_request_head`` (``crates/net/src/request.rs``, crate ``sibuna-net``) re-emits the request line and each header into the origin writer, dropping hop-by-hop fields (``Connection``, ``Keep-Alive``, ``Proxy-Connection``, ``Transfer-Encoding``, ``TE``, ``Trailer``, ``Upgrade``, the proxy authorization fields), any incoming forwarding or audit field (``X-Forwarded-For``, ``X-Real-IP``, ``Forwarded``, ``X-Forwarded-Proto``, ``X-Forwarded-Host``, ``X-Forwarded-Port``, ``X-Sibuna-Status``, ``X-Sibuna-Rule``), ``Expect``, ``Content-Length``, and every field the request's ``Connection`` header nominates. It then appends the audit set. Body framing is generated, never copied:

.. code-block:: rust

   for header in request.headers() {
       if is_hop_by_hop(header.name) || nominated(request, header.name) {
           continue;
       }
       out.write_all(header.name)?;
       out.write_all(b": ")?;
       out.write_all(header.value)?;
       out.write_all(b"\r\n")?;
   }
   match upload {
       Upload::None => {}
       Upload::Length(length) => {
           out.write_all(b"Content-Length: ")?;
           write_decimal(out, *length)?;
           out.write_all(b"\r\n")?;
       }
       Upload::Chunked(_) => out.write_all(b"Transfer-Encoding: chunked\r\n")?,
   }

A ``Content-Length`` is re-emitted. A chunked body that ended within the connection buffer is decoded in place and sent with its length. A longer one is announced as ``Transfer-Encoding: chunked`` and re-chunked one read at a time (SID 0009): each read lands in the proxy's 16 KiB upload buffer, is decoded in place there, and goes out as one canonical chunk, so the origin never sees the client's chunk sizes, extensions or trailers. The audit set:

.. code-block:: http

   Connection: keep-alive
   X-Forwarded-For: <client>
   X-Forwarded-Proto: <scheme>
   X-Real-IP: <client>
   X-Sibuna-Status: PASS
   X-Sibuna-Rule: session | robots-txt | ip/cidr-trie | ...

Bodies larger than the buffer are relayed in 16 KiB pieces from the client to the origin writer (``relay_body``) before the response is streamed back. The unit test ``proxy_head_rewrite_drops_hop_by_hop_headers_and_injects_audit_fields`` in ``crates/net/src/request.rs`` asserts that the rewrite drops a spoofed ``X-Forwarded-For`` and injects the audit fields.

The proxy's three buffers, the origin read buffer (one response head, 16 KiB), the origin write buffer (8 KiB) and the upload buffer (16 KiB), live in a ``Workspace`` that the connection allocates once and reuses for every request. The workspace makes their lifetime the connection's, not the exchange's, and the origin reader and writer borrow them for one exchange at a time.

Relaying the Origin Response
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The first proxy streamed the origin's bytes until the origin closed and then closed the client: correct framing with no parsing, at the price of a new TCP connection per proxied request. Under a load generator that price was visible as tens of thousands of sockets in ``TIME_WAIT`` and, on loopback, exhausted ephemeral ports. The proxy now reads the origin's head (at most 16 KiB) and classifies the body by RFC 9112's rules:

.. admonition:: Implementation: ``parse_response_head``

   Returns the status, one of four framings (no body for HEAD, 1xx, 204 and 304; a ``Content-Length``; chunked transfer coding; or close-delimited) and whether the origin keeps the connection. In ``crates/net/src/response.rs`` (crate ``sibuna-net``).

.. code-block:: rust

   pub enum Framing { None, Length(u64), Chunked, UntilClose }

   pub fn parse_response_head(
       head: &[u8],
       head_request: bool,
   ) -> Option<ResponseHead> {
       let status = status_code(head)?;
       let mut fields = FramingFields {
           keep_alive: head.get(7) == Some(&b'1'),
           ..Default::default()
       };
       for line in crlf_lines(head).skip(1) {
           if line.is_empty() {
               break;
           }
           fields.read_line(line)?; // Transfer-Encoding, Content-Length, Connection
       }
       let mut framing = fields.length.map_or(Framing::UntilClose, Framing::Length);
       if head_request || status / 100 == 1 || status == 204 || status == 304 {
           framing = Framing::None;
       } else if fields.encoded {
           framing =
               if fields.chunked { Framing::Chunked } else { Framing::UntilClose };
       }
       let mut keep_alive = fields.keep_alive;
       if framing == Framing::UntilClose || fields.closing {
           keep_alive = false;
       }
       if fields.nominates_framing {
           return None;
       }
       Some(ResponseHead { status, framing, keep_alive })
   }

The parser refuses what the proxy must not relay: a bad status line, a field name that is not a token, a control byte in a value, conflicting lengths, a repeated or non-final ``chunked`` coding, and a ``Connection`` field that nominates ``Content-Length`` or ``Transfer-Encoding``. Its work is linear in the head, and it never panics.

The head is re-emitted to the client with the origin's ``Connection`` headers replaced by Sibuna's own decision, and the body is relayed exactly: ``copy_exact`` for a length, chunk by chunk (size line, data, trailers) for chunked coding, ``copy_remaining`` for the legacy case. Only the legacy case closes the client. Every relay is built on one copy step: forward whatever the source already holds, and only when it holds nothing, flush the destination and then read once. A stream of small writes is therefore delivered as it is produced, while a bulk transfer still moves a full buffer per read and write.

.. code-block:: rust

   let keep = client_keep_alive && parsed.framing != Framing::UntilClose;
   write_client_head(client, head, keep).map_err(client_head_error)?;
   origin.consume(head_length);
   match parsed.framing {
       Framing::None => {}
       Framing::Length(length) => copy_exact(origin, client, length, progress)?,
       Framing::Chunked => relay_chunked(origin, client, progress)?,
       Framing::UntilClose => copy_remaining(origin, client, progress)?,
   }
   client.flush().map_err(|_| ProxyError::ClientFailed)?;
   Ok(Relayed { client_keep: keep, origin_reusable: parsed.keep_alive })

Parsing an eight-field origin head takes 322 ns, and a keep-alive ``GET`` with a 1 KiB response proxied over loopback takes 29.8 us (measured in October 2026; ``crates/net/src/lib.rs`` documents the measurement).

The Origin Pool
~~~~~~~~~~~~~~~

Parsing the framing also tells the proxy whether the *origin* socket can be used again: an HTTP/1.1 response without ``Connection: close`` (or an HTTP/1.0 one with ``keep-alive``) whose body was fully consumed leaves the socket at a clean request boundary. Such sockets go into a fixed pool of 256 idle origin connections, and the next proxied request takes one instead of connecting. Without the pool, every proxied request opens a new origin connection, and every closed connection holds its local port in ``TIME_WAIT``; under load a proxy on loopback soon runs out of ephemeral ports, and its throughput collapses.

A pool under one lock would make every proxied request contend for that lock. So the pool (``crates/net/src/pool.rs``) is striped: 16 stripes of 16 sockets, each stripe a ``Mutex<Vec<Arc<TcpStream>>>`` on a cache line of its own. A thread is assigned a home stripe round robin on first use, gives to and takes from it first, and looks into the other stripes, without waiting on a held lock, before it connects afresh.

.. code-block:: rust

   pub fn take(&self) -> Option<Arc<TcpStream>> {
       if self.is_stopping() {
           return None;
       }
       let home = home_stripe();
       if let Some(socket) =
           self.stripe(home).and_then(|stripe| lock(&stripe.sockets).pop())
       {
           return Some(socket);
       }
       (1..STRIPES).find_map(|offset| {
           let stripe = self.stripe((home + offset) % STRIPES)?;
           try_lock(&stripe.sockets)?.pop()
       })
   }

A pooled socket may have been closed by the origin while idle. The proxy notices in one of two ways, a failed write or an end-of-stream before the first response byte, and in both cases nothing has reached the client yet, so it closes the socket and retries once on a fresh connection, never on another pooled one: after an idle period every pooled socket may be stale, and the first version of this retry, which took a second pooled socket, answered ``502`` to the first request after every quiet spell. The retry is allowed only for a safe method (``GET``, ``HEAD``, ``OPTIONS``) whose body was fully buffered. A missing reply is no evidence that the origin did not commit a mutation, and a body that was relayed in pieces cannot be sent again; in both cases the client gets ``502``.

.. code-block:: rust

   let safe = matches!(request.method, Method::Get | Method::Head | Method::Options);
   let buffered = exchange.upload.is_buffered(request.body.len());
   let retryable = safe && buffered;
   for attempt in 0..2 {
       // A retry always connects afresh: after an idle period every pooled
       // socket may be stale, and a second stale one would fail the request.
       let pooled = if attempt == 0 { pool.take() } else { None };
       // ... connect if nothing was pooled, attach to the activity, exchange
       match outcome {
           Ok(relayed) => {
               if relayed.origin_reusable {
                   pool.give(origin);
               }
               return Ok(relayed.client_keep && buffered);
           }
           Err(error) => {
               drop(origin);
               let stale = was_pooled
                   && retryable
                   && matches!(
                       error,
                       ProxyError::UpstreamClosed | ProxyError::UpstreamWriteFailed
                   );
               // ... anything else is reported at once
           }
       }
   }

Unit tests relay fixed byte strings through the same functions and assert the output is byte-identical apart from the connection header (``crates/net/src/relay/tests.rs``). An end-to-end test of the daemon sends two proxied requests on one client socket and checks, through a sequence header the stub origin adds, that the second reused the pooled origin connection. A vector test in ``crates/net/tests/`` replays recorded proxy scenarios (a raw client request and a canned origin response) and compares every byte the origin and the client receive.

.. admonition:: Why the origin socket is an ``Arc``

   A socket descriptor is a small integer that the kernel reuses as soon as it is closed. Shutdown must interrupt an exchange in flight, yet it must never touch a descriptor that has meanwhile been reused for another connection. A table of active descriptors under a lock could guard against that, at the cost of a lock on every exchange. Sibuna needs no such table: the origin socket is an ``Arc<TcpStream>``. The pool holds one handle, the exchange holds one, and the connection's ``Activity`` holds a clone while the exchange runs. The descriptor closes when the last handle is dropped, so it cannot close, or be reused, while anyone can still reach it.

Idle Deadlines
~~~~~~~~~~~~~~

Every client connection registers its socket in an ``IdleTable`` (``crates/net/src/idle.rs``) and receives a ``Lease``. The lease's ``Activity`` holds the time bytes last moved on the connection. The daemon touches it after each request served; the proxy touches it on every origin read and per 16 KiB of upload, and attaches the origin socket of the exchange in flight. The reaper thread wakes every quarter of the shortest timeout (between 200 ms and one second) and shuts down every connection silent for longer than its timeout, together with the attached origin socket, so the thread blocked on either side sees end of stream and releases its slot.

Deadlines therefore measure silence, never the length of a response: a large download that keeps moving is never cut. Upload bytes come from the untrusted side and refresh the stamp only per 16 KiB, which asks a client for at least 16 KiB per idle period, the slow-body defence of minimum-rate request timeouts.

The table has one small lock per slot and no table-wide lock. It holds a ``try_clone`` of each client socket and an ``Arc`` of each attached origin socket, for the reason given above. A ``Lease`` unregisters its connection in ``Drop``, and a reaped slot stays owned by its lease until then, so an old connection can never release a slot that a new one took.

Upgraded Connections
~~~~~~~~~~~~~~~~~~~~

After a validated ``101``, a WebSocket upgrade is relayed both ways. Each direction runs on a thread of its own with one fixed buffer: the connection's own thread carries origin-to-client bytes, and a scoped thread with a 128 KiB stack carries client-to-origin bytes. One thread could serve both directions with ``poll(2)``, but the Rust standard library does not expose it; two threads with socket timeouts keep the relay free of ``unsafe``. An upgraded connection therefore holds two threads, so the number of connection threads can reach twice ``--max-connections`` when every connection is upgraded.

Both directions share one idle deadline (``--websocket-idle-timeout``, 300 seconds by default): bytes moving either way refresh one stamp. Each socket wait carries a timeout equal to the time left; a wait that times out re-reads the shared stamp and either waits again for the rest or ends the relay. When one direction reaches end of stream, the other socket's sending side is shut down (a half close); when a direction fails, both sockets are shut down so the other direction ends too. Before an upgrade is proxied, the connection releases its cached policy engine, so a connection that may live for hours does not keep an old engine alive.

Stopping
~~~~~~~~

``Running::stop``, and equally ``Drop`` for ``Running``, stops the daemon in a fixed order. It sets the stopping flag and wakes every accept worker by connecting to the listener, joins the workers, shuts down every registered client socket and its attached origin socket (``IdleTable::shutdown``), stops the origin pool, joins every connection thread, joins the reaper, and closes the pooled sockets.

SIGINT and SIGTERM reach that sequence through ordinary Rust. Before it spawns any thread, the daemon blocks both signals (every later thread inherits the mask) and dedicates one thread to ``sigwait``, which records the request and wakes the main thread at once. No code runs in a signal handler, and no thread polls a flag. The signal module (``cmd/sibuna/src/signals.rs``) holds the daemon's only ``unsafe`` code: the declarations of the few C library functions that ``std`` does not wrap.

.. admonition:: Release by ``Drop``

   Explicit cleanup calls must be written in reverse order of setup, and every early return must be read against them. In Sibuna each resource releases itself in ``Drop``: ``Daemon`` and ``Running`` stop the server, a ``Lease`` unregisters its connection, ``Counted`` returns a place in the connection bound, and ``Finished`` frees a task slot. The compiler inserts each release on every path out of the scope, including a panic unwinding through it, so no path can forget one.

What We Measured
~~~~~~~~~~~~~~~~

The table shows Shield in reverse-proxy mode on one Ryzen 9 5950X: the daemon pinned to four CPUs, ``wrk`` with two threads and 64 connections on eight other CPUs, five-second runs, the median of three. The rows are copied from ``benchmarks/results/product-latest.md``; Part VIII holds the full record.

.. list-table:: Shield in reverse-proxy mode, from ``benchmarks/results/product-latest.md``
   :header-rows: 1

   * - Workload
     - Status
     - req/s
     - p50 / p99 (us)
     - CPU per request (us)
   * - admitted with session, proxied
     - 200
     - 138,965
     - 438 / 857
     - 28.57
   * - challenged (interstitial)
     - 200
     - 195,188
     - 162 / 328
     - 13.73
   * - static allowed, proxied
     - 200
     - 145,673
     - 415 / 746
     - 27.27
   * - WAF denied (with session)
     - 403
     - 209,507
     - 151 / 306
     - 12.17

``wrk`` keeps 64 requests in flight, so on the CPU-bound proxied paths requests queue for the four CPUs, and the p99 there is the scheduler's tail rather than the cost of one request. An open-loop generator, which sends at a fixed rate and times each request from its intended send, measures latency at equal offered load instead. For admitted requests in reverse-proxy mode, the p99 is 65 us at 10,000 requests per second and 100 us at 100,000; at 150,000 offered the four CPUs saturate, 134,344 requests per second are achieved, and the queue grows to seconds (``benchmarks/results/latency-latest.md``). A warm keep-alive connection serves every decision without a heap allocation: ``cmd/sibuna/tests/steady_state.rs`` counts the allocations of the daemon, and ``crates/net/tests/steady_state.rs`` finds none over 500 proxied keep-alive requests.

.. admonition:: Exercise 5.1

   A client sends a 200 KB upload. Trace which bytes live in the 64 KiB buffer, which are relayed by ``relay_body`` through the upload buffer, and why the proxy must write the head to the origin *before* relaying.

Concurrent State Without Allocation
-----------------------------------

.. admonition:: Objectives

   Analyse the shard locks, the Robin Hood spent set, the GCRA limiter, the versioned ban table, the MPSC incident ring, and the read-copy-update publication of the policy engine with ``Arc`` and a generation-checked cache.

Every store in ``sibuna-store`` allocates its fixed capacity once, when it is built, and never allocates or blocks on a global lock afterwards. None needs a background sweeper: expired state is reclaimed in place.

Locks and Sharding
~~~~~~~~~~~~~~~~~~

The critical sections in Sibuna's tables are tens of instructions long, far shorter than a kernel futex round trip. Tables are split into 16 shards by key hash, so two operations contend with probability :math:`1/16`, and each shard sits on a cache line of its own, so neighbouring locks do not false-share.

The tables use ``std::sync::Mutex``: one compare-and-swap when uncontended, a short spin while the holder runs, then a futex wait. The alternative is a two-state atomic spin lock with a spin-loop hint in the wait loop. SID 0010 asked us to choose between the two by measurement. A spin lock saves about a nanosecond per uncontended operation, but it loses under contention:

.. list-table:: Shard lock throughput on a Ryzen 9 5950X (October 2026)
   :header-rows: 1

   * - Workload
     - ``Mutex``
     - Spin lock
   * - spent set, 16 threads
     - 10.8 M/s
     - 8.6 M/s
   * - spent set, 64 threads (more than the CPUs)
     - 11.2 M/s
     - 6.9 M/s
   * - GCRA on six hot addresses, 16 threads
     - 44.9 M/s
     - 19.3 M/s
   * - GCRA on six hot addresses, 64 threads
     - 37.4 M/s
     - 6.5 M/s

An edge server runs more connection threads than CPUs, and a spin lock whose holder is preempted makes every waiter burn its time slice, so we keep the mutex. A poisoned lock is entered rather than propagated: no operation panics while it holds a shard, and the shard stays structurally valid even if one did.

The Robin Hood Spent Set
~~~~~~~~~~~~~~~~~~~~~~~~

Only accepted proofs enter the spent set (Part III). It has 16 shards, each an open-addressed array of 4,096 slots of ``Option<Entry>``, where an entry is ``{ tag: [u8; 16], expires_at: u64, dist: u8 }``. Robin Hood insertion (Celis, 1986) displaces any occupant closer to its home than the incoming key, which keeps probe lengths tightly clustered; lookups stop as soon as they meet an entry nearer its home than they are to theirs.

.. admonition:: Implementation: ``Table::insert``

   Inserts a spent tag with its expiry, reclaiming expired slots on the way. In ``crates/store/src/spent.rs`` (crate ``sibuna-store``).

.. code-block:: rust

   fn insert(
       &mut self,
       tag: &Tag,
       expires_at: u64,
       now: u64,
   ) -> Result<(), SpendError> {
       if !self.can_insert(tag, now) {
           return Err(SpendError::Full);
       }
       let mut carry = Entry { tag: *tag, expires_at, dist: 0 };
       let mut idx = Self::home(tag);
       while carry.dist < MAX_PROBE {
           let slot = &mut self.entries[idx];
           let Some(e) = slot else {
               *slot = Some(carry);
               return Ok(());
           };
           // Overwriting an expired occupant is safe only when the new distance
           // is not smaller, so keys probing past this slot still pass the
           // early-termination test.
           if e.is_expired(now) && carry.dist >= e.dist {
               *e = carry;
               return Ok(());
           }
           if carry.dist > e.dist {
               std::mem::swap(&mut carry, e);
               // A displaced expired entry is simply dropped.
               if carry.is_expired(now) {
                   return Ok(());
               }
           }
           idx = (idx + 1) % SHARD_CAPACITY;
           carry.dist += 1;
       }
       Err(SpendError::Full)
   }

The expired-slot rule is the subtle part: an expired entry may be overwritten in place only by a key at least as far from its home, otherwise a later key that probes past the slot would stop early and be lost. Expired entries that get displaced are simply dropped. No sweeper thread is needed. Insertion first simulates the displacement path without changing anything (``can_insert``) and checks that bounded displacement can succeed without losing a live tag.

.. admonition:: Invariant

   A refused insertion never evicts a live tag. A tag that was spent and has not expired is therefore always found, and the refusal (``SpendError::Full``) can deny service but never enable a replay.

A slot is ``Option<Entry>``. An empty slot has no tag to read, so there is no ``occupied`` flag that a reader could forget to check, and ``match`` will not compile until both cases are handled. The error type is equally exact: the spent set can fail in two ways (``DoubleSpend`` and ``Full``), and ``SpendError`` names exactly those.

GCRA: Rate Limiting in One Integer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Generic Cell Rate Algorithm (ATM Forum, 1996) is the virtual-scheduling form of the leaky bucket. Per client it stores one *theoretical arrival time* (TAT). With emission interval :math:`T = \max(1, \lceil W / N \rceil)` for a positive limit :math:`N` per window :math:`W`, and burst tolerance :math:`\tau = (N - 1) T`:

.. math::

   \text{arrival at } t \text{ conforms} \iff \mathrm{TAT} \le t + \tau, \quad \text{then } \mathrm{TAT} \leftarrow \max(\mathrm{TAT}, t) + T.

.. admonition:: Theorem (token-bucket bound)

   After the first conforming arrival at :math:`t_1`, the :math:`k`-th conforming arrival satisfies :math:`t_k - t_1 \ge (k - 1) T - \tau`. Hence any interval of length :math:`L` contains at most :math:`N + \lfloor L / T \rfloor` conforming arrivals: a burst of :math:`N`, then one per :math:`T`. There is no fixed-window boundary artefact beyond the defined burst, and no per-request history.

.. figure:: /assets/figures/gcra.svg
   :alt: A chart of TAT against arrival time for T = 200 ms and tau = 800 ms. Five arrivals at t = 0 are admitted while TAT rises from 0 to 1000 ms; a sixth at t = 0 finds 1000 ms above the line t + tau and is refused. Afterwards an arrival halfway between multiples of 200 ms is refused, and one at each multiple of 200 ms finds TAT exactly on the line and is admitted.

   GCRA admission for a limit of 5 per second: a burst of five, then one every 200 ms. An arrival is admitted when the TAT it finds lies on or below the line :math:`t + \tau`.

.. admonition:: Worked example: five per second by hand

   Take :math:`N = 5` and :math:`W = 1000` ms, so :math:`T = 200` ms and :math:`\tau = 800` ms, and let a client that has been idle send six requests at :math:`t = 0`. The first finds an empty cell: :math:`\mathrm{TAT} = \max(0, 0) = 0 \le 800`, so it conforms and :math:`\mathrm{TAT} \leftarrow 200`. The next four conform the same way and leave :math:`\mathrm{TAT} = 1000`. The sixth finds :math:`1000 > 0 + 800` and is refused with ``Retry-After`` :math:`\mathrm{TAT} - \tau - t = 200` ms. At :math:`t = 199` a request still finds :math:`1000 > 999` and is refused; at :math:`t = 200` it finds :math:`1000 \le 1000`, conforms, and leaves :math:`\mathrm{TAT} = 1200`. The unit test ``gcra_admits_exactly_the_burst_then_drains_at_the_emission_rate`` in ``crates/store/src/limiter.rs`` checks exactly these numbers.

.. admonition:: Implementation: ``arrive``

   Applies one arrival to the cells of a locked shard and returns the decision, the retry delay and the remaining budget. In ``crates/store/src/limiter.rs`` (crate ``sibuna-store``).

.. code-block:: rust

   fn arrive(
       cells: &mut [Cell; SLOTS_PER_SHARD],
       key: u64,
       now_ms: u64,
       limits: Limits,
   ) -> Decision {
       let interval = limits.emission_interval();
       let tau = limits.burst_tolerance();
       let Some(cell) = locate(cells, key, now_ms, tau) else {
           return Decision {
               limited: true,
               capacity_exhausted: true,
               retry_after_ms: interval,
               remaining: 0,
           };
       };
       let tat = cell.tat_ms.max(now_ms);
       let horizon = now_ms.saturating_add(tau);
       if tat > horizon {
           return Decision {
               limited: true,
               capacity_exhausted: false,
               retry_after_ms: tat - tau - now_ms,
               remaining: 0,
           };
       }
       cell.tat_ms = tat.saturating_add(interval);
       // ... remaining = min(rate, floor((t + tau - TAT) / T) + 1)
   }

The shard's ``check`` takes the lock and calls ``arrive`` with the locked cells; the guard releases the lock when ``check`` returns. Cells are 16 bytes (a key and a TAT) in 16 shards of 512 slots with a 16-slot probe window, about 128 KiB in all. A cell whose TAT is older than :math:`t - \tau` has drained and is reclaimed on the spot. The ``Retry-After`` header is computed from the same arithmetic. Saturated probe windows refuse new clients rather than evicting active quota state, and the decision says so (``capacity_exhausted``), so a caller does not escalate a saturation refusal into a ban. A zero configured rate refuses requests. One limiter serves several rules: the cell key is a Wyhash of the client address seeded with the rule's scope, so the same client in different scopes has independent budgets.

The Versioned Ban Table
~~~~~~~~~~~~~~~~~~~~~~~

Bans use 4,096 slots with atomic version, key and expiry fields, open-addressed by a keyed hash of the banned address with an 8-slot probe window. A writer, serialised with the other writers by a mutex, brackets each update with version increments; readers take no lock, accept only a stable even version, and retry concurrent changes.

.. admonition:: Implementation: ``BanTable::ban`` and ``BanTable::read_slot``

   The writer's bracket and the reader's consistent snapshot. In ``crates/store/src/ban_table.rs`` (crate ``sibuna-store``).

.. code-block:: rust

   pub fn ban(&self, banned: &[u8], until: u64, now: u64) {
       let key = slot_key(banned);
       let _writers = self.lock_writers();
       let victim = &self.slots[self.victim(key, now)];
       // A key and an expiry are one logical value: bracket the replacement with
       // an odd version so readers cannot combine an old key with the next key's
       // expiry.
       victim.version.fetch_add(1, Ordering::SeqCst);
       victim.until.store(until, Ordering::SeqCst);
       victim.key.store(key, Ordering::SeqCst);
       victim.version.fetch_add(1, Ordering::SeqCst);
   }

   fn read_slot(&self, slot: &Slot) -> (u64, u64) {
       loop {
           let before = slot.version.load(Ordering::SeqCst);
           if before & 1 != 0 {
               std::hint::spin_loop();
               continue;
           }
           let key = slot.key.load(Ordering::SeqCst);
           let until = slot.until.load(Ordering::SeqCst);
           if before == slot.version.load(Ordering::SeqCst) {
               return (key, until);
           }
       }
   }

Sequential consistency prevents mixing an old identity with a replacement expiry: every access belongs to one total order, which keeps the argument simple. Readers take no mutex, but can wait for a writer and are not wait-free. These atomic operations have real cost, measured indirectly in the HTTP harness rather than assumed free. A full probe window overwrites a slot that has expired, or else the slot that expires first. ``clear`` lifts every ban but leaves the keys in place, because an emptied slot could hide a colliding key later in a probe chain.

The MPSC Incident Ring
~~~~~~~~~~~~~~~~~~~~~~

When the Shield surface denies a request or the honeypot fires, the incident is copied into a fixed record of about 1.3 KB (client address, User-Agent, method, path, category and payload, each cut at its capacity) and pushed onto a bounded multi-producer single-consumer ring (Vyukov's sequence-stamped design, 512 slots, ``BoundedQueue<IncidentRecord, 512>``). Producers are connection threads; the consumer is the storage thread. A full ring drops the newest record rather than blocking a response, an explicit loss policy rather than a durability guarantee. The drop counter makes that loss observable.

.. code-block:: rust

   /// Copies `incident` into the ring; a full ring drops it and counts the drop.
   pub(crate) fn record(&self, incident: &Incident<'_>) {
       if self.queue.push(IncidentRecord::from_incident(incident)).is_err() {
           self.metrics.incidents_dropped.bump();
       }
   }

After moving a record into a pending batch, the storage thread retains it, together with the prepared rows, until the commit is confirmed; it does not silently discard it on a database error, and a retry writes the identical batch.

Each slot carries a sequence number that tells producers whether the slot is free and the consumer whether it is full, so neither side takes a lock. A ring like this cannot be written in safe Rust: producers and the consumer touch different slots of one array at the same time, and only the sequence protocol, not the type system, proves which thread may touch which slot. The module ``crates/store/src/ring.rs`` therefore holds its values in ``UnsafeCell<MaybeUninit<T>>`` slots, and each ``unsafe`` block names the step of the protocol that justifies it:

.. code-block:: rust

   if diff == 0 {
       // Relaxed: the CAS only arbitrates which producer owns position `pos`.
       match self.tail.0.compare_exchange_weak(
           pos, pos.wrapping_add(1), Ordering::Relaxed, Ordering::Relaxed,
       ) {
           Ok(_) => {
               // SAFETY: the CAS gave this thread position `pos`, and
               // `sequence == pos` says the slot is empty; no other producer can
               // claim `pos` and the consumer does not read it before the Release
               // store below.
               unsafe { (*slot.value.get()).write(value) };
               // Release: publishes the written value to the consumer.
               slot.sequence.store(pos.wrapping_add(1), Ordering::Release);
               return Ok(());
           }
           Err(current) => pos = current,
       }
   } else if diff < 0 {
       return Err(value);
   }

Two conventions of the ring are types, not comments. On a full ring ``push`` returns ``Err(value)``, handing the record back so the caller decides whether to count or drop it; a bare ``false`` would lose it. The ring has a single consumer, and ``pop`` takes ``&mut self``, and shared code must claim the unique ``Consumer`` first, so a second consumer does not compile or is refused at run time.

Read-Copy-Update Engine Publication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The policy engine is rebuilt off the hot path when policies change. Requests must never observe a half-built engine, and an engine must never be freed while a request is still reading it. Sibuna publishes each engine as an ``Arc<Engine>`` in an ``EngineSlot``, and each connection reads it through an ``EngineCache``:

.. graphviz::
   :caption: Engine publication. The storage thread publishes a complete engine and advances the generation; each connection checks the generation with one acquire load and clones the published Arc only after a publication. An old engine is freed when the last cache holding it lets go.
   :alt: The storage thread builds Engine v2 off the request path and publishes it into the EngineSlot, which holds an RwLock around the current Arc and an atomic generation. Connection thread A has refreshed: its cache holds generation 2 and an Arc of Engine v2, and its next refresh is one acquire load with no clone. Connection thread B still holds generation 1 and an Arc of Engine v1; on its next refresh it sees the generation moved, takes the read lock and clones the Arc of v2. Engine v1 is freed when B lets go of it.

   digraph engine_publication {
     graph [rankdir=TB, bgcolor="transparent", newrank=true, nodesep=0.45, ranksep=0.55, pad=0.1];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=9.5, fontcolor="#172033", color="#1e40af", fillcolor="#eff6ff", penwidth=1.1, margin="0.12,0.06"];
     edge [color="#64748b", fontname="Helvetica", fontsize=8, fontcolor="#475569", arrowsize=0.6, penwidth=1.1];

     storage [label="Storage thread\nbuild Engine v2\noff the request path", color="#b45309", fillcolor="#fffbeb"];
     slot [label="EngineSlot\nRwLock<Arc<Engine>>\ngeneration: AtomicU64", color="#172033", fillcolor="#ffffff", penwidth=1.6];
     v2 [label="Engine v2\n(published)", color="#15803d", fillcolor="#f0fdf4"];
     a [label="Connection thread A\nEngineCache\ngeneration 2"];
     b [label="Connection thread B\nEngineCache\ngeneration 1"];
     v1 [label="Engine v1\nfreed when the last\ncache lets go", color="#94a3b8", fillcolor="#f8fafc", fontcolor="#475569", style="rounded,filled,dashed"];

     { rank=same; slot; v2; }
     { rank=same; a; b; v1; }

     storage -> slot [label=" publish: swap the Arc\n under the write lock,\n generation += 1 (Release)", color="#b45309", fontcolor="#92400e", penwidth=1.4];
     slot -> v2 [label="holds", color="#15803d", fontcolor="#15803d", penwidth=1.4, minlen=3];
     slot -> a [dir=back, label="refresh: load generation\n(Acquire); equal, no clone "];
     v2 -> a [dir=back, label=" Arc", color="#15803d", fontcolor="#15803d"];
     slot -> b [dir=back, label=" generation moved:\n read lock, clone Arc", style=dashed];
     b -> v1 [label="Arc until\nnext refresh", color="#94a3b8", minlen=2];
   }

.. admonition:: Implementation: ``EngineSlot::publish`` and ``EngineCache::refresh``

   Publication of a complete engine, and one connection's view of it. In ``cmd/sibuna/src/slot.rs`` (crate ``sibuna``).

.. code-block:: rust

   pub struct EngineSlot {
       current: RwLock<Arc<Engine>>,
       generation: AtomicU64,
   }

   pub fn publish(&self, engine: Engine) {
       let fresh = Arc::new(engine);
       let previous = {
           let mut current =
               self.current.write().unwrap_or_else(PoisonError::into_inner);
           std::mem::replace(&mut *current, fresh)
       };
       self.generation.fetch_add(1, Ordering::Release);
       // The old engine is dropped outside the lock (when this was its last holder).
       drop(previous);
   }

   pub struct EngineCache {
       generation: u64,
       engine: Option<Arc<Engine>>,
   }

   pub fn refresh(&mut self, slot: &EngineSlot) -> &Engine {
       let generation = slot.generation();
       if self.generation != generation {
           // A publication between the load above and this clone labels a newer
           // engine with an older generation; the next refresh simply loads again.
           self.generation = generation;
           self.engine = None;
       }
       self.engine.get_or_insert_with(|| slot.load())
   }

The generation is stored with release ordering after the engine is in place, and loaded with acquire ordering: a reader that sees a new generation also sees the engine stored before it. The race named in the comment is benign. If a publication lands between a reader's generation load and its clone, the reader caches the newer engine under the older generation number, and its next refresh notices the mismatch and loads again. A reader can be one engine late for one request; it can never see a half-built engine, because only complete engines are ever stored in the slot.

.. admonition:: Invariant

   Every engine a request reads is complete, and no engine is freed while any request or connection cache holds it. The first holds because an engine is built entirely before ``publish`` stores it; the second because every reader holds an ``Arc``, and the engine is dropped only with its last ``Arc``.

Why a cache and not simply a lock? SID 0010 asked us to measure the read cost with 16 threads and choose between ``RwLock<Arc<Engine>>`` and a lock-free alternative in safe Rust. Reading through the lock takes the lock word and the reference count, two cache lines that every core writes. The generation, by contrast, is written once per publication and otherwise only read, so each core keeps its copy:

.. list-table:: Cost of one engine read, Ryzen 9 5950X, 16 threads reading in a loop (October 2026)
   :header-rows: 1

   * - Reader
     - 1 thread
     - 16 threads
   * - ``RwLock`` read guard only
     - 4.2 ns
     - 752 ns
   * - ``RwLock`` read and ``Arc`` clone
     - 7.6 ns
     - 833 ns
   * - generation check with a cached ``Arc``
     - 0.8 ns
     - 1.8 ns

Under contention the cached read is more than 400 times cheaper than the lock, so the request path uses the cache and the ``RwLock`` only on the slow path of a refresh. The measurement is the ignored test ``read_cost_under_contention`` in ``cmd/sibuna/src/slot.rs``. Each use on the request path refreshes, so a request sees the engine current at that step. The engine itself is small: 209,052 bytes, about 204 KiB, of compact heap tables (``engine_bytes`` in ``benchmarks/results/primitives-latest.json``), with capacity for 128 rules, 128-byte rule names and 8,192 trie nodes.

.. admonition:: Why ``Arc`` and not reader counts

   The fixed-memory alternative keeps two engine slots, each with a reader count and its own allocation arena. A request pins a slot by incrementing its count and re-checking the slot pointer, and both atomics must be sequentially consistent to close the race in which a writer swaps between the reader's load and its increment. The builder swaps the pointer and then spins until the old slot's readers drain, before it resets that slot's arena and rebuilds into it. A reader that holds a slot across a rebuild therefore blocks the builder, and a slow origin would stall the next publication unless every request released its slot before proxy I/O began.

   ``Arc`` reference counting needs none of this. The storage thread builds a fresh ``Engine`` from each snapshot and publishes it; nothing is reused, so there is no spare slot, no arena reset, and no spin: ``publish`` never waits for readers. An old engine simply lives until its last holder lets go, and a slow origin can delay only that moment, never the next publication. The verdict copies the matched rule name into a 128-byte buffer to end a borrow: the decision borrows the engine through the connection's cache, and the response path needs the whole connection context mutably. An upgraded connection, which may live for hours, releases its cached engine before it is proxied.

.. admonition:: Exercise 5.2

   Using the GCRA theorem, compute the maximum number of requests a single client can get through in the first 3 seconds after being idle, for ``--rate-limit 100 --rate-window 10``. Compare with a fixed 10-second window counter and with a true sliding-window log.

.. admonition:: Explain the invariant

   Explain why an expired Robin Hood entry can be overwritten only by a key with a distance at least as large, using a three-slot example.
