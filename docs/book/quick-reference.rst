Part XI: Quick Reference Card
=============================

Keep beside a terminal: build, run, configure, route, observe, and diagnose. Part X holds the full tables; this card holds what an operator types.

Build
-----

.. code-block:: sh

   cargo build --release -p sibuna                          # daemon + SQLite + console
   cargo build --release -p sibuna --no-default-features    # in-memory, no external crate
   cargo build --release -p sibuna --features postgres      # shared PostgreSQL clusters
   rustup target add wasm32-unknown-unknown   # or set SIBUNA_POW_WASM / SIBUNA_CONSOLE_WASM
   cargo test            # unit, live daemon, storage and console tests
   cargo clippy --all-targets && cargo fmt --check
   cargo xtask check     # 70-line / 1,408-line / 99-column gate
   cargo xtask browser   # headless Chromium checks
   cargo xtask bench product   # whole products under wrk -> benchmarks/results/
   guidedog build        # this book (guidedog dsc: the SID records)

Run
---

.. code-block:: sh

   # Shield (default): PoW + WAF, proxy to :3000
   sibuna -p 8080 -u 3000 -s /etc/sibuna/secret
   # Gate: PoW only
   sibuna --gate -p 8080 -u 3000 -s /etc/sibuna/secret
   # Forward auth behind Nginx/Caddy (trusts X-Forwarded-For)
   sibuna -m forward_auth --host 127.0.0.1 -p 8080 -s /etc/sibuna/secret
   # Edge: persistent policies, reputation, forensics in <dir>/sibuna.db
   sibuna -D /var/lib/sibuna -s /etc/sibuna/secret
   # Cluster member: shared PostgreSQL, unique node id
   sibuna --database-url-file /etc/sibuna/database-url --cluster-node 1 -s /etc/sibuna/secret
   head -c 32 /dev/urandom | xxd -p -c 64 > /etc/sibuna/secret

Console (opt-in preview)
------------------------

.. code-block:: sh

   # Initialize while the daemon is stopped, then start the console
   sibuna init-admin admin --data-dir ./data
   sibuna --data-dir ./data --console 127.0.0.1:19446

Open ``http://127.0.0.1:19446/console/`` and replace the temporary password. Add ``--console-location 1.3521,103.8198`` to place the node on the globe. Remote access requires an HTTPS proxy, an explicit origin and trusted-proxy CIDRs; follow Part IX. SID 0007 is Committed. The console passes its browser workflows in headless Chromium (SID 0010, criterion 5); its formal performance isolation gate remains open (Part VIII).

Flags That Matter First
-----------------------

.. list-table::
   :header-rows: 1
   :widths: 38 16 46

   * - Flag
     - Default
     - Meaning
   * - ``-d, --difficulty``
     - 16
     - work bits (PoSW depth = bits - 3)
   * - ``-a, --algorithm``
     - posw
     - ``posw`` or ``hashcash``
   * - ``--posw-challenges``
     - 16
     - openings per proof
   * - ``--token-ttl``
     - 86400
     - session seconds
   * - ``--challenge-ttl``
     - 300
     - challenge seconds
   * - ``--token-scheme``
     - mac
     - ``mac`` or ``ed25519``
   * - ``--rate-limit / --rate-window``
     - 100 / 10
     - GCRA burst per window
   * - ``--ban-seconds``
     - 3600
     - honeypot ban
   * - ``-w, --workers``
     - CPUs
     - accept threads
   * - ``--max-connections``
     - 1024
     - then ``503``
   * - ``--max-connections-per-ip``
     - 64
     - per peer address (IPv6: per ``--ipv6-prefix``), then ``503``
   * - ``--trusted-hops``
     - 1
     - client = n-th ``X-Forwarded-For`` entry from the right
   * - ``--idle-timeout``
     - 15
     - reaper seconds
   * - ``-P, --policy-file``
     - none
     - JSON policy
   * - ``--trust-forwarded``
     - off
     - on in forward auth
   * - ``--secure-cookie``
     - off
     - add ``Secure``

Endpoints Under ``/__sibuna/``
------------------------------

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Route
     - Answer
   * - ``challenge``
     - interstitial HTML
   * - ``challenge.json?need=&path=``
     - ``{id, algorithm, difficulty, challenges, expires_at}``
   * - ``verify`` (POST)
     - ``{challenge_id, nonce | proof}`` -> ``200`` + ``Set-Cookie``, else ``400``
   * - ``wasm/sibuna-pow.wasm``
     - 15,181-byte solver
   * - ``worker.js``
     - worker with WASM and JS provers
   * - ``honeypot``
     - bans caller, ``403``; ``404`` for a subresource or cross-site fetch
   * - ``health``
     - ``{"status":"ok",...}``
   * - ``metrics``
     - Prometheus text

Route all of them to the daemon, never to the origin.

Status Codes
------------

.. list-table::
   :header-rows: 1
   :widths: 12 88

   * - Code
     - When
   * - 200
     - admitted (forward auth), interstitial, internal routes
   * - 400
     - malformed request or target, rejected solution (diagnostic body)
   * - 401
     - challenge required: non-HTML client or forward auth
   * - 403
     - policy or WAF denial, ban, honeypot
   * - 404
     - unknown ``/__sibuna/`` route, refused honeypot hit
   * - 413
     - solution body over the 64 KB buffer
   * - 414
     - reported challenge URL over 8 KiB
   * - 417
     - unsupported request expectation
   * - 429
     - GCRA limit, ``Retry-After`` seconds
   * - 431
     - head over 16 KB
   * - 501
     - transfer coding other than chunked
   * - 502
     - origin unreachable or malformed
   * - 503
     - connection limits reached, or node draining

Headers
-------

- *Upstream (proxy)*: ``X-Forwarded-For`` (socket peer, after the received chain when trusted), ``X-Forwarded-Proto``, ``X-Real-IP`` (the judged client), ``X-Sibuna-Status: PASS``, ``X-Sibuna-Rule: <rule>``; hop-by-hop and alternative forwarding fields dropped, underscore spellings too.
- *Forward-auth reply*: ``X-Sibuna-Status``, ``X-Sibuna-Rule``, ``X-Sibuna-Rule-Hash``.
- *Challenge reply*: ``X-Sibuna-Status: CHALLENGE``.
- *Cookie*: ``__sibuna_token=<75 chars, 139 with ed25519>; Path=/; Max-Age=<ttl>; HttpOnly; SameSite=Lax[; Secure]``

Policy File Skeleton
--------------------

.. code-block:: json

   { "default_action": "CHALLENGE", "waf": true,
     "thresholds": {"challenge_at": 10, "deny_at": 40, "bits_step": 5},
     "ip_rules": {"10.0.0.0/8": "ALLOW", "2001:db8::/32": "DENY"},
     "rules": [
       {"name": "api", "path": "/api/*", "headers": {"X-Api-Key": ".*"}, "action": "ALLOW"},
       {"name": "checkout", "path": "/checkout/*", "action": "CHALLENGE",
        "challenge": {"difficulty": 20, "algorithm": "posw"}},
       {"name": "login", "path": "^/login$", "action": "CHALLENGE",
        "limits": {"rate": 10, "window_seconds": 60, "ban_seconds": 600}},
       {"name": "headless", "user_agent": "Headless", "action": "WEIGH", "weight": 30} ] }

Patterns: ``*`` or ``.*`` any; ``^...$`` exact; trailing ``*`` prefix; leading ``/`` exact path; else case-insensitive substring. Paths are matched in normal form. Order: WAF -> trie deny/allow -> rules -> score -> bypass -> trie challenge -> bots -> default.

Storage (Edge) in SQL
---------------------

.. code-block:: sql

   INSERT INTO policies (id, name, priority, path_pattern, action, difficulty, algorithm,
     header_matchers, cidr_matchers, weight, enabled, created_at, updated_at)
     VALUES ('p1', 'protect', 10, '/checkout/*', 'challenge', 20, 'posw', '{}', '[]', 0, 1,
     unixepoch(), unixepoch());
   INSERT INTO ip_reputation (ip_or_cidr, reputation_score, banned_until, trigger_rule, hits, last_seen)
     VALUES ('198.51.100.7', -100, unixepoch() + 86400, 'analyst', 1, unixepoch());
   SELECT s.client_ip, s.violation_category, s.path, s.campaign_id
     FROM incidents_fts f JOIN security_incidents s ON s.id = f.rowid
     WHERE incidents_fts MATCH 'union' ORDER BY rank LIMIT 20;

SQLite (``sqlite3 <dir>/sibuna.db``); actions are lowercase. Score :math:`\le -50` -> deny prefix; :math:`\ge 50` -> allow. Cluster: same secret on every node, one PostgreSQL database, ``--features postgres``, ``--database-url-file <file> --cluster-node N`` with a unique N from 1 to 8,388,607; no member list, leader or cluster TLS (SID 0011).

Diagnostics
-----------

.. list-table::
   :header-rows: 1
   :widths: 44 56

   * - Title
     - Meaning
   * - ``MALFORMED CHALLENGE``
     - id edited or truncated; fetch a new one
   * - ``INVALID CHALLENGE TAG``
     - not minted by this seed or node
   * - ``CHALLENGE EXPIRED``
     - older than TTL or clock skew > 60 s
   * - ``CLIENT FINGERPRINT MISMATCH``
     - address or User-Agent changed
   * - ``DIFFICULTY NOT MET``
     - nonce lacks zero bits
   * - ``INVALID PROOF OF SEQUENTIAL WORK``
     - openings do not reach the root
   * - ``WRONG SOLUTION TYPE``
     - nonce for PoSW or proof for Hashcash
   * - ``DOUBLE SPEND PREVENTED``
     - challenge already used
   * - ``STORE FULL``
     - spent set saturated; lower TTL or raise ``--spent-tags``
   * - ``NETWORK BINDING MISMATCH``
     - cookie copied to another client
   * - ``INVALID COMMAND LINE``
     - unknown option, bad value, or a removed Zaxonlite option

Metrics to alert on: ``denied``, ``rate_limited``, ``overloaded``, ``upstream_errors``, ``incidents_dropped``, ``incident_write_failures``, ``bans_refused``, ``forwarded_invalid`` (all ``sibuna_*_total``).

Numbers to Remember
-------------------

Challenge id 70 chars (36-byte payload + 16-byte tag); token 75 chars (40 + 16), 139 with Ed25519; proof bytes :math:`32(1 + t(n+1))`; PoSW depth = bits - 3, range 4 to 24; request buffer 64 KB; head limit 16 KB; body inspected 8 KB; spent set 1,048,576 tags (``--spent-tags``); rate cells 262,144 per table (``--rate-table-cells``); bans 65,536 slots (``--ban-table-slots``); 64 connections per client address; incident ring 512; batch 32; campaign distance 0.35 over the 16,384 most recent embeddings; keep-alive 4,096 requests per connection; origin pool 256 sockets; storage job queue 32.

Ingress Routing
---------------

Use the Nginx or Caddy recipe in Part IX, Forward Auth Behind an Ingress. Route ``/__sibuna/*`` directly; authorize application requests with the original URI, method and trusted client address. Replace incoming Sibuna audit headers with the authorization result. Nginx needs explicit challenge, 429 and unavailable-auth handling.

``reverse_proxy`` carries admitted HTTP/1.1 bodies and WebSockets; ``forward_auth`` grants admission and the ingress carries them. Omitted auth bodies and origin responses cannot be inspected or counted by Sibuna. TLS terminates at the ingress; native HTTP/2 is deferred. Uploads use Content-Length or chunked coding; inspection sees at most an 8 KiB prefix, with file bytes opaque.
