Part X: Desk Reference and Diagnostics
======================================

Endpoints, metrics, error catalog, policy schema, and storage tables in one place.

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

The separate opt-in management listener serves ``/console/``. Initialize its administrator locally with ``sibuna init-admin``, then replace the temporary password on first sign-in. ``/console/api/stats`` and ``/console/ws`` require an authenticated session (a kiosk session included). The WebSocket multiplexes statistics, events, nodes, policy, challenges and audit with bounded snapshots, deltas and gap recovery. Management peers connect to ``/console/peer``, and every API route lives under ``/console/api/``. Origin error counters are not observed in forward-auth mode. Part IX documents the console's workflows, HTTPS deployment and current SID 0007 limits.

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

Error Catalog
-------------

``INVALID COMMAND LINE`` stops startup for any option the daemon does not recognise, any value outside its documented range, and an invalid, missing or duplicate mode selection. The block names the option, the value given, the range expected and the error (``UnknownOption``, ``MissingValue``, ``InvalidValue``, ``InvalidMode``, ``MissingMode``, ``DuplicateMode``, ``RemovedOption`` for a Zaxonlite cluster option, ``ConflictingOptions`` for two storage options that exclude each other, ``MissingOption`` for a database URL without ``--cluster-node``), and ends with a hint. A database URL is shown as ``[redacted]``. Supply ``--mode reverse_proxy`` or ``--mode forward_auth`` once; ``-m`` is the equivalent short option. A rejected policy file prints a block titled for its error (for example ``INVALID POLICY ACTION``) with the file, the error name, the rule, the field and the value. Console options are checked separately: ``CONSOLE002`` names a malformed or repeated console option, and ``CONSOLE001`` a console configuration that breaks a rule (``StorageRequired`` without storage).

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
         "limits": { "rate": int, "window_seconds": int, "ban_seconds": int }
       }
     ]
   }

``challenge_at`` and ``deny_at`` lie in -1000 to 1000 with ``deny_at`` at or above ``challenge_at``, and ``bits_step`` in 1 to 1000. A ``challenge`` block belongs only to ``CHALLENGE`` rules, with 1 to 64 work bits. ``limits`` gives a rule its own quota: ``rate`` 1 to 1,000,000 and ``window_seconds`` 1 to 86,400 are required, ``ban_seconds`` (at most 86,400) is optional, and ``WEIGH`` rules cannot carry limits. The reputation trie of ``ip_rules`` holds at most 8,192 nodes. Each rule may use one spelling of each criterion.

Pattern grammar: ``.*`` or ``*`` match anything; ``^...$`` anchors an exact path; a trailing ``*``, ``/*``, or ``.*`` is a prefix; a pattern starting with ``/`` is an exact path; anything else is a case-insensitive substring. Path patterns match the path in normal form (one slash between segments, no dot segments, unreserved characters unescaped, other escapes with upper-case hexadecimal digits), so a pattern holding ``;``, ``%2F``, ``%5C`` or ``\`` matches nothing, and path matching is case-sensitive (SID 0003).

Storage Tables
--------------

``policy_revision``, ``policies``, ``policy_inspection``, ``ip_reputation``, ``incident_receipts``, ``security_incidents`` (with the 256-byte embedding), the full-text index (``incidents_fts``, FTS5 over canonical tokens, on SQLite; the ``tsvector`` column ``search`` with a GIN index on PostgreSQL) and ``sibuna_schema``; the console adds 33 ``console_*`` tables. Stored action, algorithm and mode names are lowercase. Incident ids are ``node_id << 40 | sequence``, unique across a cluster without coordination; node ids run from 1 to 8,388,607.

Build Targets
-------------

.. list-table:: Build and repository commands
   :header-rows: 1
   :widths: 46 54

   * - Command
     - Result
   * - ``cargo build --release -p sibuna``
     - Daemon with SQLite storage and the console (the default features)
   * - ``cargo build --release -p sibuna --no-default-features``
     - In-memory daemon without storage or console and without any external crate
   * - ``cargo build --release -p sibuna --features postgres``
     - Daemon that also connects to a shared PostgreSQL database
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

.. admonition:: Exercise 10.1

   A client receives ``400`` with the title ``CLIENT FINGERPRINT MISMATCH`` after switching from Wi-Fi to cellular mid-solve. Explain the cause from the token and challenge formats, and propose the smallest change to the interstitial that recovers gracefully.

.. admonition:: Explain the invariant

   Without looking, list the endpoints a reverse proxy in front of Sibuna must route to the daemon rather than to the origin, and say why each is needed.
