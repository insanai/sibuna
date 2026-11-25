Part XII: Desk Reference and Diagnostics
========================================

Endpoints, metrics, error catalog, policy schema, and storage tables in one place, for the firewall daemon and for the edge load balancer (Part VIII, Part IX). The tables of the edge were read from the code, not from the SID records.

Endpoints
---------

.. admonition:: Objectives

   Know every route under ``/__sibuna/`` and what each returns.

.. list-table:: Reserved routes
   :header-rows: 1
   :widths: 34 10 56

   * - Endpoint
     - Method
     - Function
   * - ``/__sibuna/challenge``
     - GET
     - The interstitial page
   * - ``/__sibuna/challenge.json?need=&path=``
     - GET
     - Issues a stateless challenge: the requirement ticket from the challenged response decides it, otherwise the reported URL is evaluated in normal form (``414`` above 8 KiB, ``400`` for a path without a normal form). Returns ``{id, algorithm, difficulty, challenges, expires_at}``
   * - ``/__sibuna/verify``
     - POST
     - Accepts ``{"challenge_id", "nonce"}`` or ``{"challenge_id", "proof"}``; ``200`` with ``Set-Cookie``, ``400`` with a diagnostic, or ``413`` for a body larger than the connection buffer
   * - ``/__sibuna/wasm/sibuna-pow.wasm``
     - GET
     - The solver module, 14,744 bytes (``wasm_bytes`` in ``benchmarks/results/primitives-latest.json``), cacheable for one hour
   * - ``/__sibuna/worker.js``
     - GET
     - The Web Worker with WASM and JavaScript provers, cacheable for one hour
   * - ``/__sibuna/honeypot``
     - GET
     - Bans the caller for ``--ban-seconds`` and records an incident; ``403``. Only a top-level request bans (no ``Sec-Fetch-Dest`` or ``document``, and no cross-site ``Sec-Fetch-Site``); any other is answered ``404`` and counted
   * - ``/__sibuna/health``
     - GET
     - JSON liveness status with engine name, version, proxy mode and proof algorithm
   * - ``/__sibuna/metrics``
     - GET
     - Prometheus text format (version 0.0.4)

Any other path under ``/__sibuna/`` is answered ``404``. Issuance and verification spend the separate ``--challenge-rate-limit`` budget, and a banned address is refused with ``403`` on every route. Challenge responses carry ``X-Sibuna-Status: CHALLENGE``; admitted requests carry ``X-Sibuna-Status: PASS`` and ``X-Sibuna-Rule`` upstream (and ``X-Sibuna-Rule-Hash``, in hexadecimal, in forward-auth replies). A client that does not accept HTML receives ``401`` with ``{"error":"challenge_required","challenge":"/__sibuna/challenge.json?need=<ticket>"}``.

The separate opt-in management listener serves ``/console/``. Initialize its administrator locally with ``sibuna init-admin``, then replace the temporary password on first sign-in. ``/console/api/stats`` and ``/console/ws`` require an authenticated session (a kiosk session included). The WebSocket multiplexes statistics, events, nodes, policy, challenges and audit with bounded snapshots, deltas and gap recovery. Management peers connect to ``/console/peer``, and every API route lives under ``/console/api/``. Origin error counters are not observed in forward-auth mode. Part XI documents the console's workflows, HTTPS deployment and current SID 0007 limits.

Routes of the edge
~~~~~~~~~~~~~~~~~~

An edge started with ``--config-file`` or ``sibuna lb`` serves the routes of the firewall on the HTTP frontends whose surface is ``gate`` or ``shield``. It adds the routes below. ``cmd/sibuna/src/routes.rs``, ``cmd/sibuna/src/edge/probe.rs``, ``cmd/sibuna/src/acme.rs`` and ``crates/acme/src/server.rs`` hold them.

.. list-table:: HTTP routes of the edge
   :header-rows: 1
   :widths: 34 12 54

   * - Endpoint
     - Method
     - Function
   * - ``/__sibuna/ready`` on an HTTP frontend
     - GET
     - ``200`` with ``{"status":"ready"}``; ``503`` with ``{"status":"draining"}`` from the start of a shutdown (SID 0020)
   * - ``/__sibuna/health``, ``/__sibuna/metrics`` on an HTTP frontend
     - GET
     - As in the firewall. The metrics text adds the series of the edge (below)
   * - ``/health``, ``/ready``, ``/metrics`` on ``observability.listen``
     - GET
     - The same three answers on a separate listener, which also accepts the ``/__sibuna/`` spelling. It applies no address list: its address is its access control
   * - ``/.well-known/acme-challenge/TOKEN``
     - GET
     - The HTTP-01 answer of automatic HTTPS, before the firewall and before a redirect (SID 0021)
   * - ``URL/directory``, ``URL/new-nonce``
     - GET (``HEAD`` for the nonce)
     - The ACME server of the local authority, where ``URL`` is ``global.acme.internal.server.url``; off by default
   * - ``URL/new-account``, ``account``, ``new-order``, ``order``, ``authz``, ``chall``, ``finalize``, ``cert``
     - POST
     - Signed ACME requests of at most 32 KiB; HTTP-01 is the only challenge
   * - ``URL/crl``
     - GET
     - The revocation list of the present intermediate, in DER

The three routes of ``/__sibuna/`` answer a client inside ``observability.internal_allow`` (the loopback networks by default) whose request carries no ``X-Forwarded-For``, ``X-Real-IP`` or ``Forwarded`` field. Every other client receives the ``404`` of an unknown route. ``/__sibuna/ready`` exists on the edge only.

The admin socket
~~~~~~~~~~~~~~~~

``global.admin_socket`` (or ``sibuna lb --admin``) opens a Unix socket of mode 0600. ``sibuna ctl SOCKET COMMAND`` sends one line of at most 512 printable ASCII bytes and prints the answer. The socket accepts a burst of 20 commands and 10 per second after it. The console of the edge runs a listed subset of the same lines through the same parser. ``cmd/sibuna/src/edge/control.rs`` holds the grammar.

.. list-table:: Commands of the admin socket
   :header-rows: 1
   :widths: 40 46 14

   * - Command
     - Answer or effect
     - Console
   * - ``show servers``
     - One line per server: pool, name, address, state, weight, flows, health, ejection, ramp, change
     - yes
   * - ``show info``
     - ``key: value`` lines: version, process, source, reloads, watcher, flows, drops, run-time changes, and the counters of the spill cache (SID 0027)
     - no
   * - ``show stats``
     - The series of the edge in the Prometheus text format, as the metrics route prints them
     - no
   * - ``show certs``, ``show ca``
     - The names of automatic HTTPS with their state and staple; the root of the local authority as PEM (SID 0021)
     - yes
   * - ``revoke cert NAME|SERIAL``
     - Revokes a certificate of the local authority and writes the revocation list
     - no
   * - ``show hooks``
     - The plugins with their calls, verdicts, failures and open breakers (SID 0030)
     - no
   * - ``show cluster``
     - Each node of the mesh with the digest of its file, or with the revision it serves in persistent mode (SID 0023, SID 0028)
     - yes
   * - ``show affinity``
     - The sticky table and the shares of fleet-wide limits (SID 0025)
     - no
   * - ``show authority``
     - The revision of the database that this node serves (SID 0028)
     - no
   * - ``set server POOL/NAME state ready|drain [local]``
     - Admits a server, or stops new flows to it; ``maint`` is another word for ``drain``
     - yes
   * - ``set server POOL/NAME weight N [local]``
     - Sets the weight, 1 to 65,535
     - yes
   * - ``add server POOL/NAME IP:PORT [weight N] [local]``, ``del server POOL/NAME [local]``
     - Adds or removes a server of a pool
     - yes
   * - ``del ban ADDRESS [local]``
     - Lifts the ban of one client (SID 0022)
     - yes
   * - ``reload``
     - Loads the file as SIGHUP does and prints the result
     - no
   * - ``reload cluster``
     - Reloads this node, then sends the file to every peer (SID 0023)
     - yes
   * - ``reopen log``
     - Opens the access log file again
     - no
   * - ``help``
     - Lists the commands
     - no

With a mesh, a change to a server and a lifted ban reach every node unless the last word is ``local`` (SID 0022). A failure prints a diagnostic with a code of the families ``ADM`` or ``DBA`` below, and nothing has changed.

The console of the edge
~~~~~~~~~~~~~~~~~~~~~~~

With a ``console`` section the edge serves the console of SID 0031 on a listener of its own. Besides the routes of the firewall console, three routes concern the edge (``crates/console/src/routes.rs``, ``crates/console/src/api/edge.rs``).

.. list-table:: Console routes of the edge
   :header-rows: 1
   :widths: 30 10 60

   * - Endpoint
     - Method
     - Function
   * - ``/console/api/edge``
     - GET
     - The node, its refusals by reason, its frontends and its pools, at most 256 servers. Needs a session, or a token with the scope ``stats_read``
   * - ``/console/api/edge/fleet``
     - GET
     - One row for each member of the fleet, asked all at once, waiting at most five seconds
   * - ``/console/api/edge/command``
     - POST
     - ``{"line": "..."}``: one listed line of the admin socket. Needs the role operator or administrator, the ``Origin`` field, the CSRF token and the mutation allowance; a change is audited before and after it runs
   * - ``/console/peer``
     - GET
     - The stream of a peer console, from the ``allow_ips`` of its entry, with the peer key

A console without an edge answers ``404`` with ``CONSOLE404`` on the three ``edge`` routes.

Metrics
-------

Counters exposed as ``sibuna_<name>_total`` in Prometheus text format, in this order:

.. list-table:: Counters
   :header-rows: 1
   :widths: 34 66

   * - Counter
     - Incremented when
   * - ``incidents_persisted``, ``incident_batches``
     - Records and transactions whose commit the storage thread confirmed
   * - ``incidents_dropped``, ``incident_write_failures``
     - Queue pushes rejected because the ring was full, and failed commit attempts
   * - ``requests``
     - A parsed request reached dispatch (reserved routes included)
   * - ``allowed``, ``denied``, ``challenged``
     - A policy decision was made (admitted, refused, challenge issued or reissued)
   * - ``challenges_issued``
     - ``/__sibuna/challenge.json`` minted a challenge record
   * - ``solutions_accepted``, ``solutions_rejected``
     - ``/__sibuna/verify`` accepted or rejected a proof
   * - ``rate_limited``
     - GCRA refused a request (``429``): the request limit, the challenge budget or a rule's quota
   * - ``banned``
     - A banned address was refused, or the honeypot banned one
   * - ``bans_issued``
     - A ban was recorded (honeypot or a rule quota's ban)
   * - ``proxied``, ``upstream_errors``
     - A request was relayed to the origin, or the origin failed (``502``)
   * - ``parse_errors``
     - A malformed head, a repeated ``Host``, a target without a normal form (``400``), or an unsupported transfer coding (``501``) was refused
   * - ``overloaded``
     - A connection beyond ``--max-connections`` or ``--max-connections-per-ip`` was answered ``503``
   * - ``bans_refused``
     - A ban was not recorded because every slot its key may take held a ban in effect
   * - ``forwarded_invalid``
     - A trusted forwarded client address did not parse; the request was judged by the socket peer
   * - ``honeypot_refused``
     - A honeypot hit banned nobody because a page, not a person, requested it
   * - ``rate_evictions``
     - A limiter arrival evicted another active client's cell
   * - ``ja4_present``
     - With ``--ja4-header`` and trusted forwarding, the request carried exactly one header of that name with a JA4 fingerprint
   * - ``ja4_invalid``
     - With ``--ja4-header`` and trusted forwarding, the header was malformed or repeated; the request was judged without a fingerprint
   * - ``tunnels_opened``
     - An upgraded connection became a tunnel on an event-driven worker (SID 0016)
   * - ``origin_reused``, ``origin_connects``
     - An exchange of a worker reused an idle server socket, or opened a server connection
   * - ``origin_retries``
     - A request was sent again because an idle server socket had closed
   * - ``deadline_closes``, ``worker_faults``
     - A worker closed a connection because a deadline passed, or after a fault in its own code
   * - ``tls_kept``, ``tls_passed``
     - A worker ended a TLS connection itself, or gave it to the protocol runtime after its ClientHello (SID 0024)

The last eight counters are written by the event-driven workers of the edge (SID 0016, SID 0024). ``crates/core/src/metrics.rs`` holds the list.

Series of the edge
~~~~~~~~~~~~~~~~~~

The metrics text of an edge has the counters above and then these series. ``show stats`` on the admin socket prints the same text. A series of a family that is not configured is absent: forwarding, the mesh, the plugins and automatic HTTPS each add theirs only when they are on. The code that writes them is ``crates/lb/src/stats.rs``, ``crates/lb/src/forward/counters.rs``, ``cmd/sibuna/src/access.rs``, ``cmd/sibuna/src/plugins.rs`` and ``cmd/sibuna/src/acme.rs``.

.. list-table:: Series of the edge
   :header-rows: 1
   :widths: 40 10 18 32

   * - Series
     - Type
     - Labels
     - Meaning
   * - ``sibuna_edge_ready``
     - gauge
     -
     - 1 while readiness answers 200, 0 from the start of a shutdown
   * - ``sibuna_edge_flows_active``, ``sibuna_edge_flows_limit``
     - gauge
     -
     - The flows in the flow table, and ``global.max_flows``
   * - ``sibuna_edge_drops_total``
     - counter
     -
     - Datagrams that the edge worker discarded and admissions it refused
   * - ``sibuna_edge_proxy_protocol_accepted_total``, ``_rejected_total``
     - counter
     -
     - Connections whose PROXY header was accepted or refused
   * - ``sibuna_edge_flow_log_dropped_total``
     - counter
     -
     - Lines of TCP and UDP flows that did not fit the queue of the log
   * - ``sibuna_edge_refused_total``
     - counter
     - ``reason``
     - Refused connections, requests and datagrams. The reasons are ``rate_limit``, ``flow_limit``, ``draining``, ``connection_limit``, ``client_limit``, ``task_limit``, ``exchange_limit``, ``bad_request``, ``no_server``, ``udp_rate_limit``, ``udp_flow_limit``, ``udp_reply_limit``, ``client_closed``, ``hook``, ``inspect_denied`` and ``udp_not_quic``
   * - ``sibuna_edge_frontend_requests_total``
     - counter
     - ``frontend``, ``code``
     - HTTP requests by status class: ``1xx`` to ``5xx``, or ``none`` for an exchange that ended without a status
   * - ``sibuna_edge_frontend_bytes_in_total``, ``_bytes_out_total``, ``_flows_total``
     - counter
     - ``frontend``
     - Bytes from and to the clients, and flows of a frontend
   * - ``sibuna_edge_frontend_request_seconds``
     - histogram
     - ``frontend``
     - The duration of a request; buckets from 0.001 to 30 seconds (14 bounds)
   * - ``sibuna_edge_server_requests_total``
     - counter
     - ``backend``, ``server``, ``code``
     - Requests a server answered, by status class
   * - ``sibuna_edge_server_failures_total``, ``_failovers_total``, ``_ejections_total``
     - counter
     - ``backend``, ``server``
     - What a server did wrong, requests that left it for another server, and ejections by passive health (SID 0019)
   * - ``sibuna_edge_server_client_closed_total``
     - counter
     - ``backend``, ``server``
     - Clients that left before the server answered (logged as 499); not a failure of the server
   * - ``sibuna_edge_server_up``, ``sibuna_edge_server_active_requests``
     - gauge
     - ``backend``, ``server``
     - 1 while the server is in service, and its requests in flight
   * - ``sibuna_edge_server_response_seconds``
     - histogram
     - ``backend``, ``server``
     - The wait for the first byte of the server, with the buckets above
   * - ``sibuna_edge_access_log_written_total``, ``_dropped_total``, ``_errors_total``
     - counter
     -
     - Lines of the access log written, dropped because the queue was full, and failed writes
   * - ``sibuna_edge_access_log_queue_length``
     - gauge
     -
     - Entries waiting for the writer
   * - ``sibuna_edge_forward_active``, ``_peers_eligible``, ``_flows_out``
     - gauge
     -
     - Peer forwarding (SID 0026): 1 while this node forwards, the peers that can take a flow, and the flows forwarded now
   * - ``sibuna_edge_forward_streams_out_total``, ``_streams_in_total``
     - counter
     -
     - Connections handed to an owner, and taken from peers
   * - ``sibuna_edge_forward_datagrams_out_total``, ``_datagrams_in_total``, ``_datagrams_returned_total``
     - counter
     -
     - Datagrams sent to an owner, taken from peers, and replies passed back to a client
   * - ``sibuna_edge_forward_denied_total``
     - counter
     -
     - Connections closed because the owner's rate limit denied the client
   * - ``sibuna_edge_forward_local_total``
     - counter
     - ``reason``
     - Flows of another owner served here: ``declined``, ``connect_failed``, ``timeout``, ``peer_limit``
   * - ``sibuna_edge_forward_rejected_total``
     - counter
     - ``reason``
     - What the forwarding port refused: ``stranger``, ``bad_tag``, ``stale``, ``malformed``, ``unknown``
   * - ``sibuna_edge_mesh_bans_sent_total``, ``_received_total``, ``_applied_total``, ``_dropped_total``
     - counter
     -
     - Replicated bans (SID 0022): written into datagrams once for each peer and send, read from authentic datagrams, that added or extended a ban, and lost to a bound
   * - ``sibuna_edge_mesh_bans_known``
     - gauge
     -
     - The bans this node remembers now
   * - ``sibuna_edge_hook_calls_total``
     - counter
     - ``plugin``, ``tier``, ``result``
     - Calls of a plugin (SID 0030). ``tier`` is ``native``, ``wasm`` or ``agent``; ``result`` is ``admit``, ``deny``, ``challenge``, ``timeout``, ``overload``, ``trap`` or ``unavailable``
   * - ``sibuna_edge_hook_samples_dropped_total``, ``sibuna_edge_hook_fields_refused_total``
     - counter
     - ``plugin``
     - Telemetry samples dropped, and request fields that the plugin tried to add and that were refused
   * - ``sibuna_edge_hook_breakers_open``
     - gauge
     - ``plugin``
     - Open breakers of an agent plugin
   * - ``sibuna_edge_acme_certificates_managed``, ``_served``
     - gauge
     -
     - Names of automatic HTTPS, and those with a certificate in service (SID 0021)
   * - ``sibuna_edge_acme_failures_total``
     - counter
     -
     - Failed attempts to obtain or renew a certificate
   * - ``sibuna_edge_acme_nearest_expiry_seconds``
     - gauge
     -
     - Seconds until the first served certificate expires; absent while none is served

Some state of the edge has no series. The sticky table and the shares of fleet-wide limits are shown by ``show affinity`` only (SID 0025), the spill cache by ``show info`` (SID 0027), and the revision of the database by ``show authority`` (SID 0028). No series counts the commands, the lifted bans or the parked flows of the plugins.

A retry can increment ``incident_write_failures`` without losing records, because the pending batch is retained. Monitor increments over an interval; totals alone are not a queue depth.

Status Codes
------------

.. list-table:: Status codes of the data plane
   :header-rows: 1
   :widths: 12 88

   * - Code
     - When
   * - 200
     - Admitted (forward-auth), interstitial (HTML navigation needing a challenge), internal routes
   * - 302
     - Not used by the current protocol; verification answers ``200`` and the page reloads
   * - 400
     - Malformed request, a repeated ``Host`` field, a target without a normal form, invalid forwarded metadata, a malformed body, or a rejected solution with an Elm-style diagnostic
   * - 401
     - Challenge required for a client that does not accept HTML, or in forward-auth mode
   * - 403
     - Policy or WAF denial, banned address, honeypot
   * - 404
     - An unknown path under ``/__sibuna/``, or a honeypot hit that is not a top-level request
   * - 413
     - Solution body larger than the 64 KB connection buffer
   * - 414
     - A reported challenge URL over 8 KiB
   * - 417
     - Unsupported request expectation; ``100-continue`` is handled locally
   * - 429
     - GCRA limit exceeded; ``Retry-After`` in seconds
   * - 431
     - Request head over 16 KB
   * - 501
     - ``Transfer-Encoding`` with a coding other than chunked
   * - 502
     - Origin unreachable, or its response head was malformed or larger than 16 KB
   * - 503
     - Connection limit (``--max-connections`` or ``--max-connections-per-ip``) reached, or the node is draining; the socket is closed after the reply

An HTTP frontend of the edge answers with the codes above where its firewall decides, and adds these of its own (SID 0019, SID 0020, SID 0030).

.. list-table:: Status codes that the edge adds
   :header-rows: 1
   :widths: 12 88

   * - Code
     - When
   * - 301, 308
     - ``redirect_https`` on a cleartext frontend or route, or the automatic redirect of a managed name (308)
   * - 403
     - A request hook denied the request, or a WebSocket upgrade carried an ``Origin`` that the route does not list
   * - 404
     - ``/__sibuna/ready``, ``health`` or ``metrics`` asked from outside ``internal_allow`` or through a proxy
   * - 413
     - A request body above ``max_body``
   * - 499
     - Written to the access log only: the client closed or reset before any response; no client receives it
   * - 501
     - A WebSocket upgrade to a pool with ``http_version`` 2 or 3
   * - 502
     - No server could be reached, or a request that is not safe to repeat lost its server connection after it was sent
   * - 503
     - Readiness during a shutdown, an HTTP/2 or HTTP/3 request above the request bound, or a console stream over its quota
   * - 504
     - A server stayed silent longer than ``response_timeout``

Error Catalog
-------------

``INVALID COMMAND LINE`` stops startup for any option the daemon does not recognise, any value outside its documented range, and an invalid, missing or duplicate mode selection. The block names the option, the value given, the range expected and the error (``UnknownOption``, ``MissingValue``, ``InvalidValue``, ``InvalidMode``, ``MissingMode``, ``DuplicateMode``, ``RemovedOption`` for a Zaxonlite cluster option, ``ConflictingOptions`` for two storage options that exclude each other, ``MissingOption`` for a database URL without ``--cluster-node``), and ends with a hint. A database URL is shown as ``[redacted]``. Supply ``--mode reverse_proxy`` or ``--mode forward_auth`` once; ``-m`` is the equivalent short option. A rejected policy file prints a block titled for its error (for example ``INVALID POLICY ACTION``) with the file, the error name, the rule, the field and the value. A ``ja4`` pattern that no fingerprint could match prints ``INVALID POLICY JA4`` (``InvalidJa4``); a console management document with such a pattern is refused with the same error name. Console options are checked separately: ``CONSOLE002`` names a malformed or repeated console option, and ``CONSOLE001`` a console configuration that breaks a rule (``StorageRequired`` without storage).

.. admonition:: Implementation: ``ErrorKind::explain``

   Maps every domain error to a boundary line, an explanation, and a ``Hint:``. In ``crates/core/src/errors.rs`` (crate ``sibuna-core``).

.. list-table:: Challenge and session errors
   :header-rows: 1
   :widths: 28 36 36

   * - Error
     - Cause
     - Hint
   * - ``MalformedChallenge``
     - The identifier is not a well-formed challenge record
     - Fetch a fresh challenge and submit it unchanged
   * - ``InvalidChallengeTag``
     - The tag does not authenticate; not issued by this cluster or edited
     - Challenges cannot be forged; request a new one
   * - ``ChallengeExpired``
     - Older than the challenge TTL, or minted in the future
     - Request a new challenge
   * - ``FingerprintMismatch``
     - Submitted from a different address or User-Agent
     - Submit from the client that fetched it
   * - ``DifficultyNotMet``
     - Hashcash nonce lacks the required zero bits
     - Keep searching nonces
   * - ``InvalidProof``
     - The sequential-work proof does not open the committed labels
     - Run the prover to completion for the issued depth and openings
   * - ``WrongSolutionType``
     - A nonce for a PoSW challenge or a proof for Hashcash
     - Match the solution field to the algorithm
   * - ``DoubleSpendAttempt``
     - The challenge was already spent
     - Challenges are single use
   * - ``StoreFull``
     - The spent set is full
     - Lower the challenge TTL or raise ``--spent-tags``
   * - ``InvalidTokenSignature``
     - Cookie tag or signature fails
     - Re-authenticate through the interstitial
   * - ``TokenExpired``
     - Cookie past its expiry
     - Re-authenticate
   * - ``TokenBoundAddressMismatch``
     - Cookie presented from a different client identity
     - Cookies cannot be shared

The console's API answers a failure with ``{"error":"<CODE>","hint":"<sentence>"}``; the hint is the text the interface shows (``crates/console/src/http/reply.rs``).

.. list-table:: Console failure codes that concern operators
   :header-rows: 1
   :widths: 24 12 64

   * - Code
     - Status
     - Meaning
   * - ``CONSOLE002``
     - 400
     - The request is malformed, too large or not allowed in its form
   * - ``CONSOLE003``
     - 503 / 429
     - The storage job queue is full (32 jobs), or the password verifier is busy
   * - ``CONSOLEQUORUM``
     - 503
     - The database did not answer within the request's wait of 10 seconds; the outcome is unknown, and the data plane continues from the last applied policy
   * - ``CONSOLE004``
     - 503
     - The service cannot answer: not available in this build, stopping, or an internal failure
   * - ``CONSOLENODE``
     - 400 / 409 / 503
     - A node command was refused: it names another node (400), a stale boot or control revision (409), or it arrived while another command ran or a completion could not be recorded (503); inspect the operation receipt before retrying
   * - ``CONSOLEMUTATION``
     - 429
     - More than sixty management mutations in a minute from one session
   * - ``CONSOLEEDGE``
     - 400 / 503
     - A line on the page *Edge* is malformed or not on the list of the console (400), or the edge worker did not answer or the audit row could not be written (503)
   * - ``CONSOLEQUERY``
     - 429
     - A read of the page *Edge* past the query allowance of the session
   * - ``CONSOLE404``
     - 404
     - An ``edge`` route on a console that runs without an edge

Operator codes of the edge
~~~~~~~~~~~~~~~~~~~~~~~~~~

The edge renders a failure as a diagnostic with a title rule that carries the code, the explanation and a ``Hint:``. The tables list every code that the code tables hold, with its title as the daemon prints it. A code marked *log* is not a failure: it is the code of a line on standard error that reports an event.

.. code-block:: text

   -- REVISION CONFLICT (DBA002) ---------------------------------------------

   The commit expected revision 7, and the database is at revision 8.

   Hint: Somebody committed in between. Run `sibuna authority diff` again, look at the difference to the new head, and apply with its number after `--expect`.

.. list-table:: ``EDGE``: start, reload and notes of the edge (``cmd/sibuna/src/edge/failure.rs``, ``cmd/sibuna/src/edge.rs``)
   :header-rows: 1
   :widths: 14 30 56

   * - Code
     - Title
     - Meaning
   * - ``EDGE001``
     - ``CONFIGURATION FILE NOT FOUND``, ``ADDRESS IN USE``, ``ADDRESS NOT AVAILABLE``, ``PERMISSION DENIED``, ``SPILL CACHE NOT USABLE``, ``CERTIFICATE NOT LOADED``, ``INVALID CONFIGURATION``, ``FILE NOT READABLE``, ``EDGE NOT STARTED``
     - The edge did not start, or ``sibuna check`` refused the file. Automatic HTTPS adds ``NAME NOT PUBLIC``, ``NAME OUTSIDE CONSTRAINTS``, ``UPDATE NOT SIGNED``, ``WILDCARD NEEDS DNS`` and ``ON DEMAND NEEDS A GUARD``, and a failure of the database authority carries the title of its ``DBA`` code under ``EDGE001``
   * - ``EDGE002``
     - *log*
     - A reload was rejected; the serving routes stay, and the line says why
   * - ``EDGE010``
     - *log*
     - A command changed state: from the admin socket, from the mesh, or from the console; also a failed write of the access log
   * - ``EDGE011``
     - *log*
     - A configuration file was received from a peer (SID 0023)
   * - ``EDGE012``
     - *log*
     - The mesh address cannot serve ``show cluster``; the node serves without that answer
   * - ``EDGE013``
     - *log*
     - The kernel refused a listener option such as ``defer_accept``; the frontend serves without it (SID 0032)
   * - ``EDGE014``
     - *log*
     - A console peer is new or changed and is used after a restart (SID 0031)
   * - ``EDGE015``
     - *log*
     - The spill cache at start: created, reused, discarded, or in use by another process, with its size (SID 0027)

The code holds no ``EDGE003`` to ``EDGE009``.

.. list-table:: ``ADM``: the admin socket and the console commands (``cmd/sibuna/src/edge/control.rs``, ``crates/lb/src/runtime.rs``)
   :header-rows: 1
   :widths: 14 30 56

   * - Code
     - Title
     - Meaning
   * - ``ADM001``
     - ``MALFORMED COMMAND``
     - The line holds a byte outside printable ASCII, is longer than 512 bytes, or did not arrive within two seconds
   * - ``ADM002``
     - ``UNKNOWN COMMAND``
     - The words are not a command
   * - ``ADM003``
     - ``UNKNOWN POOL``
     - No pool has this name
   * - ``ADM004``
     - ``UNKNOWN SERVER``
     - The pool has no server of this name; the hint names a near one
   * - ``ADM005``
     - ``INVALID VALUE``
     - A weight, an address, a state, a server name or a client address is not valid
   * - ``ADM006``
     - ``DUPLICATE SERVER``
     - The pool already has a server with this name or this address
   * - ``ADM007``
     - ``CHANGE REFUSED``
     - The pool changes only by reload (a Maglev table or protocol adapters), is full, or would lose its last server
   * - ``ADM008``
     - ``RELOAD REJECTED``
     - The file does not check, or the daemon was started by ``sibuna lb`` and has no file
   * - ``ADM009``
     - ``TOO MANY COMMANDS``
     - More than a burst of 20 commands, or more than 10 per second after it
   * - ``ADM010``
     - ``NO ANSWER``
     - The edge worker did not answer within five seconds
   * - ``ADM011``
     - ``NO CLUSTER``
     - ``reload cluster`` or ``show cluster`` on an edge without a mesh or without a file
   * - ``ADM012``
     - ``CLUSTER RELOAD INCOMPLETE``
     - This node reloaded, and some peers did not take the file
   * - ``ADM013``
     - ``NOT REVOKED``
     - ``revoke cert`` named nothing that the local authority issued, or the build has no TLS

.. list-table:: ``ACME``: automatic HTTPS (``crates/acme/src/error.rs``, ``cmd/sibuna/src/acme.rs``)
   :header-rows: 1
   :widths: 14 30 56

   * - Code
     - Title
     - Meaning
   * - ``ACME000``
     - *log*
     - An event of a certificate: obtained, renewed, loaded, stapled, held or released on demand, or validated and issued by the ACME server
   * - ``ACME001``
     - ``STORAGE NOT WRITABLE``
     - The directory of ``global.acme.storage`` cannot be read or written
   * - ``ACME002``
     - ``AUTHORITY UNREACHABLE``
     - The ACME authority could not be reached, or no trust root could be loaded
   * - ``ACME003``
     - ``AUTHORITY REFUSED``
     - The authority answered with a problem; the daemon tries again later
   * - ``ACME004``
     - ``RATE LIMITED``
     - The authority limits our requests; the daemon waits as it was told
   * - ``ACME005``
     - ``VALIDATION FAILED``
     - The authority could not validate the name over HTTP-01, TLS-ALPN-01 or DNS-01
   * - ``ACME006``
     - ``UNEXPECTED ANSWER``
     - An answer broke the protocol or a bound
   * - ``ACME008``
     - ``CERTIFICATE REJECTED``
     - The issued certificate cannot be served
   * - ``ACME009``
     - ``DNS PROVIDER FAILED``
     - The DNS provider (hook, RFC 2136 or Cloudflare) could not write or remove the record, or its key or roots could not be read
   * - ``ACME010``
     - ``RECORD NOT VISIBLE``
     - The authoritative servers did not show the TXT record in time
   * - ``ACME011``
     - ``LOCAL AUTHORITY FAILED``
     - The local authority could not be created, read or used, or its root has other name constraints than the file lists
   * - ``ACME012``
     - ``ACCOUNT NOT BOUND``
     - The authority wants an external account binding, or refused ours
   * - ``ACME013``
     - ``NO OCSP RESPONSE``
     - The OCSP responder did not answer, or its answer cannot be stapled; the certificate is served without a staple
   * - ``ACME014``
     - *log*
     - The certificate thread stopped on a defect and starts again; the served certificates stay
   * - ``ACME015``
     - ``KEY TOOL FAILED``
     - The program ``openssl`` that makes RSA keys could not be run, or wrote no key
   * - ``ACME016``
     - ``REVOCATION LIST FAILED``
     - The revoked certificates or the revocation list of the local authority could not be read or written, or the list is full

The code holds no ``ACME007``.

.. list-table:: ``DBA``: the database authority (``crates/authority/src/error.rs``, ``cmd/sibuna/src/edge/authority/``)
   :header-rows: 1
   :widths: 14 30 56

   * - Code
     - Title
     - Meaning
   * - ``DBA001``
     - ``SOURCE REJECTED``
     - A source or a stored document does not evaluate or does not check
   * - ``DBA002``
     - ``REVISION CONFLICT``
     - The head is not the revision that the commit expected
   * - ``DBA003``
     - ``DATABASE UNAVAILABLE``
     - The database cannot be reached, or it refused the statement (also for a role that lacks a right)
   * - ``DBA004``
     - ``NO REVISION``
     - Nothing is published yet, or no revision has this number
   * - ``DBA005``
     - ``INVALID AUTHORITY``
     - The ``authority`` section or its file is wrong, or the build has no storage
   * - ``DBA006``
     - ``NO AUTHORITY``
     - ``show authority`` on an edge that serves its file
   * - ``DBA007``
     - ``MISSING COMMAND``
     - ``sibuna authority`` without a known command, or with a bad option
   * - ``DBA008``
     - ``REVISION DAMAGED``
     - A stored revision is not what its row says
   * - ``DBA009``
     - ``FILE IS LOCAL``
     - ``reload cluster`` on a node that follows a database
   * - ``DBA010``
     - *log*
     - A revision was applied
   * - ``DBA011``
     - *log*
     - A revision was refused; the node keeps the one it serves
   * - ``DBA012``
     - *log*
     - The database cannot be reached; the node keeps its revision and asks again every two seconds
   * - ``DBA013``
     - *log*
     - The database answers again
   * - ``DBA014``
     - *log*
     - The node started from its cache
   * - ``DBA015``
     - *log*
     - ``authority.binds`` names a frontend that the revision does not publish
   * - ``DBA016``
     - *log*
     - The cache is ignored or cannot be written, or the report to the database failed

.. list-table:: ``UPG``: replacing the binary (``crates/upgrade/src/error.rs``, ``cmd/sibuna/src/edge/upgrade.rs``)
   :header-rows: 1
   :widths: 14 30 56

   * - Code
     - Title
     - Meaning
   * - ``UPG001``
     - ``UPGRADE PEER REFUSED``
     - The replacement runs as another user than the running daemon
   * - ``UPG002``
     - ``UPGRADE VERSION NOT SHARED``
     - The two binaries share no version of the handoff protocol
   * - ``UPG003``
     - ``UPGRADE PROTOCOL ERROR``
     - A malformed, oversized or unexpected frame, or a descriptor that is not what the frame says
   * - ``UPG004``
     - ``UPGRADE TIMED OUT``
     - The running daemon did not answer in time; it keeps serving
   * - ``UPG005``
     - ``UPGRADE CONNECTION CLOSED``
     - The running daemon ended the handoff; its log says why
   * - ``UPG006``
     - ``UPGRADE NOT POSSIBLE NOW``
     - Another replacement is in progress, or the running daemon is stopping
   * - ``UPG007``
     - ``UPGRADE SOCKET NOT SUPPORTED``
     - The platform cannot pass descriptors (Linux only)
   * - ``UPG008``
     - ``UPGRADE SOCKET OF ANOTHER DAEMON``
     - The daemon at ``global.upgrade_socket`` listens on none of the addresses of this file
   * - ``UPG010``
     - *log*
     - The old process handed its listeners and UDP mappings to the replacement
   * - ``UPG011``
     - *log*
     - The replacement failed before the cutover; the old process serves on
   * - ``UPG012``
     - *log*
     - The old process refused an upgrade peer
   * - ``UPG013``
     - *log*
     - The replacement cannot be ended; UDP stays unread until it is gone
   * - ``UPG020``
     - *log*
     - The replacement took the listeners and UDP mappings

.. list-table:: ``SPILL``: the spill cache (``crates/spill/src/error.rs``)
   :header-rows: 1
   :widths: 14 30 56

   * - Code
     - Title
     - Meaning
   * - ``SPILL001``
     - ``SPILL CACHE SIZE OUT OF RANGE``
     - The size lies outside 64 KiB to 64 GiB
   * - ``SPILL002``
     - ``NOT A SPILL CACHE``
     - The file at the path exists and is not a cache; it is left alone
   * - ``SPILL003``
     - ``SPILL CACHE IN USE``
     - Another process holds the lock of the file; the daemon then runs with the sticky table in memory only
   * - ``SPILL004``
     - ``SPILL CACHE UNAVAILABLE``
     - The system refused an operation on the file

A ``SPILL`` failure other than ``SPILL003`` stops the start under ``EDGE001`` with the title ``SPILL CACHE NOT USABLE``, and the message carries the ``SPILL`` code.

.. list-table:: ``HOOK``: plugins (``crates/plugin/src/spec.rs``)
   :header-rows: 1
   :widths: 14 30 56

   * - Code
     - Title
     - Meaning
   * - ``HOOK001``
     - ``UNKNOWN PLUGIN``
     - A frontend lists a plugin that ``plugins`` does not define
   * - ``HOOK002``
     - ``INVALID PLUGIN SETTINGS``
     - A key of a plugin is missing, unknown or out of range
   * - ``HOOK003``
     - ``MODULE NOT READABLE``
     - The Wasm module cannot be read
   * - ``HOOK004``
     - ``MODULE NOT LOADED``
     - The module does not validate, or its memory does not fit ``memory_pages``
   * - ``HOOK005``
     - ``FORBIDDEN IMPORT``
     - The module imports something other than ``sibuna.add_header`` and ``sibuna.now_ms``
   * - ``HOOK006``
     - ``ABI MISMATCH``
     - The module lacks an export of the interface, or ``sibuna_abi`` does not return 1
   * - ``HOOK007``
     - ``UNKNOWN NATIVE HOOK``
     - The build has no native hook of this name
   * - ``HOOK008``
     - ``NATIVE HOOK REFUSED ITS SETTINGS``
     - A native hook refused the ``settings`` of the plugin
   * - ``HOOK009``
     - ``AGENTS NOT SUPPORTED``
     - An agent needs a Unix socket, which this platform lacks

A set of plugins that does not load at a reload leaves the serving set in place. Two more families concern the build and the console rather than the operator of the edge: ``HTML001`` to ``HTML008`` stop the build of a page template, and ``GEOIP001`` refuses a GeoIP snapshot in a build without the console. The console's query routes answer with families of their own (``TRAFFIC``, ``COMPARISON``, ``RANKHISTORY``, ``RULEHITS``, ``TIMELINE``, ``MINUTES``), whose hints the interface shows.

Policy Schema
-------------

.. code-block:: text

   {
     "default_action": "ALLOW" | "DENY" | "CHALLENGE",
     "waf": true | false,
     "inspection": { "path_traversal" | "sqli" | "xss" | "rce": "disabled" | "audit" | "enforce" },
     "thresholds": { "challenge_at": int, "deny_at": int, "bits_step": int },
     "ip_rules": { "<cidr>": "ALLOW" | "DENY" | "CHALLENGE", ... },
     "rules": [                                                    // up to 128
       {
         "name": "<kebab-case>",                                   // 1 to 128 printable bytes
         "path" | "path_regex": "<pattern>",                       // up to 512 bytes
         "user_agent" | "user_agent_regex": "<pattern>",
         "headers" | "headers_regex": { "<Header>": "<pattern>" }, // up to 4
         "remote_addresses" | "cidrs": ["<cidr>", ...],            // up to 8, IPv4 or IPv6
         "action": "ALLOW" | "DENY" | "CHALLENGE" | "WEIGH",
         "weight": int,                                            // WEIGH only, -1000..1000
         "challenge": { "difficulty": <work bits>, "algorithm": "hashcash" | "posw" },
         "limits": { "rate": int, "window_seconds": int, "ban_seconds": int },
         "ja4": "<fingerprint>" | "<prefix>*"                      // 36 bytes, or a prefix and *
       }
     ]
   }

``challenge_at`` and ``deny_at`` lie in -1000 to 1000 with ``deny_at`` at or above ``challenge_at``, and ``bits_step`` in 1 to 1000. A ``challenge`` block belongs only to ``CHALLENGE`` rules, with 1 to 64 work bits. ``limits`` gives a rule its own quota: ``rate`` 1 to 1,000,000 and ``window_seconds`` 1 to 86,400 are required, ``ban_seconds`` (at most 86,400) is optional, and ``WEIGH`` rules cannot carry limits. ``ja4`` is a whole JA4 fingerprint, which must be equal, or a prefix followed by ``*``, which the fingerprint must start with; ``*`` alone matches any fingerprint, and a request without one matches no ``ja4`` rule. A pattern that no fingerprint could match is refused with ``InvalidJa4`` (Part XI, JA4 Fingerprints From the Ingress). The reputation trie of ``ip_rules`` holds at most 8,192 nodes. Each rule may use one spelling of each criterion.

Pattern grammar: ``.*`` or ``*`` match anything; ``^...$`` anchors an exact path; a trailing ``*``, ``/*``, or ``.*`` is a prefix; a pattern starting with ``/`` is an exact path; anything else is a case-insensitive substring. Path patterns match the path in normal form (one slash between segments, no dot segments, unreserved characters unescaped, other escapes with upper-case hexadecimal digits), so a pattern holding ``;``, ``%2F``, ``%5C`` or ``\`` matches nothing, and path matching is case-sensitive (SID 0003).

Storage Tables
--------------

``policy_revision``, ``policies`` (with the nullable ``ja4_pattern`` criterion of at most 37 bytes), ``policy_inspection``, ``ip_reputation``, ``incident_receipts``, ``security_incidents`` (with the 256-byte embedding and the nullable 36-byte ``ja4`` fingerprint), the full-text index (``incidents_fts``, FTS5 over canonical tokens, on SQLite; the ``tsvector`` column ``search`` with a GIN index on PostgreSQL) and ``sibuna_schema``; the console adds 33 ``console_*`` tables. Stored action, algorithm and mode names are lowercase. Incident ids are ``node_id << 40 | sequence``, unique across a cluster without coordination; node ids run from 1 to 8,388,607.

The database authority of the edge (SID 0028) adds three tables as the component ``authority`` of ``sibuna_schema``, in the database of the firewall or in another: ``edge_head`` (one row with the number of the head), ``edge_revisions`` (one row per revision: ``origin`` ``apply`` or ``rollback``, ``restored``, the checked ``document`` of at most 256 KiB with its 64-digit ``digest``, the ``source`` with its name and digest, ``author``, ``note`` and ``committed_at``) and ``edge_nodes`` (one row per node: ``applied``, ``digest``, ``refused``, ``detail`` and ``seen_at``). On PostgreSQL an update of ``edge_head`` notifies the channel ``sibuna_edge``. The history is never pruned. ``crates/authority/src/sql.rs`` holds the schema.

Commands of the Binary
----------------------

One binary holds the firewall daemon, the edge and their tools. Part XI describes each command; this table says where.

.. list-table:: Commands of ``sibuna``
   :header-rows: 1
   :widths: 40 60

   * - Command
     - Purpose, and where Part XI describes it
   * - ``sibuna [options]``
     - The firewall daemon (*Command-Line Reference*)
   * - ``sibuna --config-file FILE``
     - The edge from a JSON or JLV topology; it takes no other option (*Edge Load Balancing*)
   * - ``sibuna check -f FILE``
     - Checks a topology offline, with its certificates and CA files, and exits
   * - ``sibuna lb --bind IP:PORT --server IP:PORT ...``
     - The edge from a few options, without a file; ``--print-config`` writes the file (*Starting with one command*)
   * - ``sibuna ctl SOCKET COMMAND``
     - One command of the admin socket (*Changing servers at run time*, and the table above)
   * - ``sibuna authority apply|diff|dump|history|rollback|status -c FILE ...``
     - Publishes and inspects the topology in a database (*A database for the topology*)
   * - ``sibuna init-admin``, ``sibuna console ...``
     - The accounts, tokens, policies and GeoIP data of the console (*Console Preview*)

Build Targets
-------------

.. list-table:: Build and repository commands
   :header-rows: 1
   :widths: 46 54

   * - Command
     - Result
   * - ``cargo build --release -p sibuna``
     - Daemon with SQLite storage, the console, JLV and automatic HTTPS (the default features ``sqlite``, ``console``, ``jlv`` and ``https``)
   * - ``cargo build --release -p sibuna --no-default-features``
     - In-memory daemon without storage or console and without any external crate
   * - ``cargo build --release -p sibuna --features postgres-tls``
     - Daemon that also connects to a shared PostgreSQL database, with verified TLS (the ``postgres`` feature alone connects without TLS)
   * - ``cargo test``
     - Unit tests, integration tests against a live daemon, storage and console tests (PostgreSQL ones when ``SIBUNA_TEST_DATABASE_URL`` is set)
   * - ``cargo clippy --all-targets``, ``cargo fmt --check``
     - Lints and formatting (``max_width = 99``)
   * - ``cargo xtask check``
     - The 70-line function, 1,408-line file and 99/108-column line limits; no tabs
   * - ``cargo xtask browser``
     - Checks in headless Chromium (``sibuna-browser``)
   * - ``cargo xtask bench <primitives|product|latency>``
     - Release-mode benchmarks; results in ``benchmarks/results/<command>-latest.json``
   * - ``cargo build -p sibuna-pow-wasm --target wasm32-unknown-unknown --profile wasm``
     - The browser module only (``-p sibuna-console-ui`` for the console interface)
   * - ``cargo run -p sibuna-geoip --bin geoip-snapshot -- ...``
     - Validate country data and write an embeddable GeoIP snapshot
   * - ``guidedog build`` / ``guidedog dsc``
     - This book / the SID records

The daemon's build script (``cmd/sibuna/build.rs``) builds both WebAssembly modules with the ``wasm`` profile into the workspace's target directory and fails the build when the console interface exceeds 768 KiB. ``SIBUNA_POW_WASM`` and ``SIBUNA_CONSOLE_WASM`` name prebuilt modules instead, for builds without the ``wasm32-unknown-unknown`` target. ``SIBUNA_GEOIP_DATA`` names a GeoIP snapshot to embed; it is decoded at build time, and a build without the console refuses it (``GEOIP001``).

.. admonition:: Exercise 12.1

   A client receives ``400`` with the title ``CLIENT FINGERPRINT MISMATCH`` after switching from Wi-Fi to cellular mid-solve. Explain the cause from the token and challenge formats, and propose the smallest change to the interstitial that recovers gracefully.

.. admonition:: Explain the invariant

   Without looking, list the endpoints a reverse proxy in front of Sibuna must route to the daemon rather than to the origin, and say why each is needed.
