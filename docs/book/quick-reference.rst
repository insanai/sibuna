Part XI: Quick Reference Card
=============================

Keep beside a terminal: build, run, configure, route, observe, and diagnose. Part X holds the full tables; this card holds what an operator types.

Build
-----

.. code-block:: sh

   cargo build --release -p sibuna                          # daemon + SQLite + console
   cargo build --release -p sibuna --no-default-features    # in-memory, no external crate
   cargo build --release -p sibuna --features postgres-tls  # shared PostgreSQL clusters
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
   # JA4 from a trusted ingress (Cloudflare's header; nginx module: x-ja4; ATS: ja4)
   sibuna --ja4-header cf-ja4 --trust-forwarded -p 8080 -u 3000 -s /etc/sibuna/secret
   # Cluster member: shared PostgreSQL, unique node id
   sibuna --database-url-file /etc/sibuna/database-url --cluster-node 1 -s /etc/sibuna/secret
   head -c 32 /dev/urandom | xxd -p -c 64 > /etc/sibuna/secret

Edge load balancer
------------------

.. code-block:: sh

   sibuna lb --bind :8080 --server 10.0.0.1:80 --server 10.0.0.2:80   # no file needed
   sibuna lb --bind :8080 --server 10.0.0.1:80 --print-config > edge.jlv
   sibuna lb --tls auto --domain example.org --server 10.0.0.1:80     # automatic HTTPS (ACME)
   sibuna check -f edge.jlv           # or edge.json: validate topology, certificates, CA files
   sibuna --config-file edge.jlv      # serve TCP, UDP and HTTP frontends
   kill -HUP "$(pidof sibuna)"        # reload routes, policy and certificates in place
   sibuna ctl /run/sibuna/edge.sock show servers                      # needs global.admin_socket
   /opt/sibuna/new/sibuna --config-file edge.jlv   # with global.upgrade_socket: replaces the running daemon, no connection lost (Linux)
   sibuna lb --tls auto --domain localhost --server 10.0.0.1:80       # the same from the local authority
   sibuna lb --tls auto --domain staging.example.org --acme-issuer internal --server 10.0.0.1:80   # a public name from the local authority
   sibuna lb --tls auto --domain example.org --acme-on-demand-ask http://127.0.0.1:9000/ok --server 10.0.0.1:80   # more names on demand
   sibuna ctl /run/sibuna/edge.sock show certs                        # certificates of tls.auto and on demand, and their OCSP staples
   sibuna ctl /run/sibuna/edge.sock show ca > sibuna-root.crt         # the root to install in clients
   sibuna ctl /run/sibuna/edge.sock show hooks                        # plugins: calls, verdicts, failures, open breakers (SID 0030)
   sibuna ctl /run/sibuna/edge.sock set server app/10.0.0.1:80 state drain   # or ready
   sibuna ctl /run/sibuna/edge.sock set server app/10.0.0.1:80 weight 5
   sibuna ctl /run/sibuna/edge.sock del ban 203.0.113.9                       # on every node of a mesh
   sibuna ctl /run/sibuna/edge.sock reload cluster                            # this node, then its peers
   sibuna ctl /run/sibuna/edge.sock show affinity                             # the sticky table and the shares of fleet-wide limits
   sibuna ctl /run/sibuna/edge.sock add server app/blue 10.0.0.3:80
   sibuna ctl /run/sibuna/edge.sock del server app/blue
   sibuna ctl /run/sibuna/edge.sock reload                            # as SIGHUP, with the result
   sibuna authority diff -c /etc/sibuna/node.json -f edge.jlv         # what apply would change in the database
   sibuna authority apply -c /etc/sibuna/node.json -f edge.jlv --expect 7   # publish revision 8, or a conflict
   sibuna authority history -c /etc/sibuna/node.json                  # the revisions, newest first
   sibuna authority rollback -c /etc/sibuna/node.json 6               # a new revision with the document of 6
   sibuna authority dump -c /etc/sibuna/node.json --revision 6        # evaluated data; --source for the source
   sibuna authority status -c /etc/sibuna/node.json                   # the head and what every node applied
   sibuna ctl /run/sibuna/edge.sock show authority                    # the revision that this node serves
   cat fullchain.pem privkey.pem > /etc/sibuna/certs/site.pem   # one HAProxy-style bundle

.. code-block:: json

   {
     "http": {"surface": "shield", "rate_limit": 100, "rate_window": "10s", "idle_timeout": "15s"},
     "frontends": {
       "web": {"proto": "http", "binds": ["0.0.0.0:443"],
               "tls": {"crt": "/etc/sibuna/certs/", "http3": true},
               "routes": [{"host": "api.example.org", "backend": "api", "firewall": false}],
               "default_backend": "site"},
       "raw": {"proto": "tcp", "binds": ["0.0.0.0:2222"], "default_backend": "ssh",
               "rate_limit": {"conn_per_10s": 60}},
       "dns": {"proto": "udp", "binds": ["192.0.2.10:53"], "default_backend": "ns",
               "udp_defense": {"mode": "rate_limit", "threshold_pps": 200}}
     },
     "backends": {
       "site": {"mode": "http", "servers": [{"name": "s1", "addr": "10.0.0.11:3000"}]},
       "api": {"mode": "http", "http_version": "2", "tls": {"sni": "api.internal"},
               "health_check": {"kind": "http", "path": "/healthz"},
               "servers": [{"name": "a1", "addr": "10.0.0.21:8443"}]},
       "ssh": {"mode": "tcp", "servers": [{"name": "g1", "addr": "10.0.0.8:22"}]},
       "ns": {"mode": "udp", "servers": [{"name": "n1", "addr": "10.0.0.53:53"}]}
     }
   }

``"http": {"surface": "off"}`` gives a load balancer with no firewall. TCP and UDP frontends never use the firewall.

Admission options of a frontend (SID 0032): ``"defer_accept": "5s"`` and ``"backlog": 4096`` on ``tcp`` and ``http``; ``"inspect_bytes"`` and ``"inspect_fallback": {"absent": {"action": "deny"}}`` beside ``tcp_inspect``; ``"udp_inspect": "quic"`` on ``udp``. All are off by default.

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
   * - ``--ja4-header``
     - off
     - header with the ingress's JA4 fingerprint; read only when trusted
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
       {"name": "old-tls", "ja4": "t12*", "action": "CHALLENGE"},
       {"name": "headless", "user_agent": "Headless", "action": "WEIGH", "weight": 30} ] }

JA4: a whole fingerprint, or a prefix and ``*``; no fingerprint, no match. Patterns: ``*`` or ``.*`` any; ``^...$`` exact; trailing ``*`` prefix; leading ``/`` exact path; else case-insensitive substring. Paths are matched in normal form. Order: WAF -> trie deny/allow -> rules -> score -> bypass -> trie challenge -> bots -> default.

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

SQLite (``sqlite3 <dir>/sibuna.db``); actions are lowercase. Score :math:`\le -50` -> deny prefix; :math:`\ge 50` -> allow. Cluster: same secret on every node, one PostgreSQL database, ``--features postgres-tls``, ``--database-url-file <file> --cluster-node N`` with a unique N from 1 to 8,388,607; no member list, leader or cluster TLS (SID 0011).

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

A plugin that does not load is refused with ``HOOK001`` to ``HOOK009``; the operations chapter lists them. To alert on hooks: ``sibuna_edge_hook_calls_total`` with ``result`` ``timeout``, ``trap`` or ``unavailable``, and ``sibuna_edge_hook_breakers_open``.

Metrics to alert on: ``denied``, ``rate_limited``, ``overloaded``, ``upstream_errors``, ``incidents_dropped``, ``incident_write_failures``, ``bans_refused``, ``forwarded_invalid`` (all ``sibuna_*_total``).

Numbers to Remember
-------------------

Challenge id 70 chars (36-byte payload + 16-byte tag); token 75 chars (40 + 16), 139 with Ed25519; proof bytes :math:`32(1 + t(n+1))`; PoSW depth = bits - 3, range 4 to 24; request buffer 64 KB; head limit 16 KB; body inspected 8 KB; spent set 1,048,576 tags (``--spent-tags``); rate cells 262,144 per table (``--rate-table-cells``); bans 65,536 slots (``--ban-table-slots``); 64 connections per client address; incident ring 512; batch 32; campaign distance 0.35 over the 16,384 most recent embeddings; keep-alive 4,096 requests per connection; origin pool 256 sockets; storage job queue 32.

Ingress Routing
---------------

Use the Nginx or Caddy recipe in Part IX, Forward Auth Behind an Ingress. Route ``/__sibuna/*`` directly; authorize application requests with the original URI, method and trusted client address. Replace incoming Sibuna audit headers with the authorization result. Nginx needs explicit challenge, 429 and unavailable-auth handling.

``reverse_proxy`` carries admitted HTTP/1.1 bodies and WebSockets; ``forward_auth`` grants admission and the ingress carries them. Omitted auth bodies and origin responses cannot be inspected or counted by Sibuna. TLS terminates at the ingress; native HTTP/2 is deferred. Uploads use Content-Length or chunked coding; inspection sees at most an 8 KiB prefix, with file bytes opaque.
