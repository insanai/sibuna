Part IX: Operations and Deployment
==================================

We cover the two surfaces, every command-line flag, forward-auth recipes, policy files, persistent storage in SQLite or PostgreSQL, clustering over one shared database, and packaging.

Surfaces and Configuration
--------------------------

.. admonition:: Objectives

   By the end of this chapter, we should be able to run Sibuna as a reverse proxy or a forward-auth validator, choose a surface, set the proof-of-work tier and difficulty, and manage the master secret.

Choosing a Surface
~~~~~~~~~~~~~~~~~~

- *Gate* (``--gate``, alias ``--no-waf``): proof-of-work admission, sessions, declarative rules, reputation, GCRA limits, bans.
- *Shield* (default, ``--shield``, alias ``--waf``): Gate plus the semantic firewall.
- *Distributed deployment* (an option for either surface): ``--data-dir`` keeps policies, reputation and forensics in a local SQLite file; ``--database-url`` with ``--cluster-node`` connects several nodes to one PostgreSQL database (SID 0011).

Command-Line Reference
~~~~~~~~~~~~~~~~~~~~~~

The table lists every option of ``sibuna --help``. Ranges are those the parser enforces.

.. list-table:: Daemon options
   :header-rows: 1
   :widths: 30 16 54

   * - Flag
     - Default
     - Meaning
   * - ``--port, -p``
     - ``8080``
     - Listening port, 1 to 65535
   * - ``--host, -h``
     - ``0.0.0.0``
     - Listening address, an IP address literal
   * - ``--upstream-host``
     - ``127.0.0.1``
     - Origin host (reverse proxy mode)
   * - ``--upstream-port, -u``
     - ``3000``
     - Origin port
   * - ``--mode, -m``
     - ``reverse_proxy``
     - ``reverse_proxy`` or ``forward_auth`` (also ``proxy`` and ``auth``), given once
   * - ``--workers, -w``
     - one per CPU
     - Accept threads sharing the listening socket, 0 (one per CPU) to 64; each accepted connection then gets its own thread
   * - ``--max-connections``
     - ``1024``
     - Connections served concurrently, 1 to 8192; further ones are answered ``503``
   * - ``--max-connections-per-ip``
     - ``64``
     - Connections one socket peer address may hold, 0 (no bound) to 8192; an IPv6 peer counts with its ``--ipv6-prefix`` network, and forwarded headers play no part; further ones are answered ``503``
   * - ``--idle-timeout``
     - ``15``
     - Longest silence in seconds, 0 to 86400. A request head must arrive within it. An origin response refreshes it on every read, so a slow stream lives while bytes flow and a silent origin is cut on both sockets. A proxied upload must deliver 16 KiB per period (a minimum rate against slow-body attacks). The client socket carries a write timeout of the same length, so a client that accepts no byte for that long loses the connection
   * - ``--websocket-idle-timeout``
     - ``300``
     - Idle deadline of an upgraded connection in seconds, 0 to 86400
   * - ``--trust-forwarded``
     - off; on in forward-auth
     - Honour ``X-Forwarded-For`` / ``X-Real-IP`` from the peer
   * - ``--no-trust-forwarded``
     - off
     - Never honour them, even in forward-auth mode
   * - ``--trusted-hops``
     - ``1``
     - With forwarded identity trusted, the client is the ``X-Forwarded-For`` entry this many positions from the right, 1 to 8
   * - ``--ipv6-prefix``
     - ``64``
     - IPv6 prefix length, 32 to 128, that rate limits, bans and the per-client connection bound apply to
   * - ``--algorithm, -a``
     - ``posw``
     - ``posw`` or ``hashcash``
   * - ``--difficulty, -d``
     - ``16``
     - Work bits, 1 to 64: Hashcash zero bits, or PoSW depth plus three
   * - ``--posw-challenges``
     - ``16``
     - Openings per sequential-work proof, 1 to 32
   * - ``--token-scheme``
     - ``mac``
     - ``mac`` (keyed BLAKE3) or ``ed25519``
   * - ``--token-ttl``
     - ``86400``
     - Session lifetime, seconds (1 to 31,536,000)
   * - ``--challenge-ttl``
     - ``300``
     - Challenge lifetime, seconds (1 to 86,400)
   * - ``--secret-file, -s``
     - random
     - 64 hex characters or 32 raw bytes; ``SIBUNA_SECRET`` (64 hex characters) is also accepted
   * - ``--cookie-name``
     - ``__sibuna_token``
     - Session cookie name, 1 to 64 token characters
   * - ``--secure-cookie``
     - off
     - Add the ``Secure`` attribute
   * - ``--gate`` / ``--shield``
     - shield
     - Surface selection
   * - ``--rate-limit``
     - ``100``
     - Requests per window per client (GCRA burst)
   * - ``--rate-window``
     - ``10``
     - Window in seconds, 1 to 86400
   * - ``--challenge-rate-limit``
     - ``30``
     - Challenge issuances and verifications per window per client, separate from the request budget
   * - ``--ban-seconds``
     - ``3600``
     - Honeypot ban duration, 0 to 31,536,000
   * - ``--policy-file, -P``
     - none
     - Declarative JSON policy
   * - ``--rate-table-cells``
     - ``262144``
     - Cells per rate limiter table, 16 bytes each, 4,096 to 16,777,216, rounded up to a power of two
   * - ``--ban-table-slots``
     - ``65536``
     - Ban table slots, 24 bytes each, 1,024 to 16,777,216, rounded up to a power of two
   * - ``--spent-tags``
     - ``1048576``
     - Solved challenges remembered against replay, 24 bytes each, 65,536 to 16,777,216
   * - ``--data-dir, -D``
     - none
     - One node: persist to the SQLite file ``<path>/sibuna.db``
   * - ``--database-url``
     - none
     - A cluster: the shared PostgreSQL database (``postgres://`` or ``postgresql://``)
   * - ``--database-url-file``
     - none
     - Read the database URL from an owner-only file
   * - ``--cluster-node``
     - none
     - This node's id; binds challenge keys and the top bits of incident identifiers; required with a database URL
   * - ``--storage-poll-ms``
     - ``500``
     - Storage tick interval, 1 to 60,000 ms
   * - ``--verbose, -v``
     - off
     - Verbose logging
   * - ``--help`` / ``--version``
     -
     - Print the help (console options first, when the console is compiled in) or the version, and exit

``--data-dir`` and a database URL exclude each other, and ``--database-url`` and ``--database-url-file`` exclude each other. A database URL without ``--cluster-node`` is refused. The Zaxonlite cluster options ``--cluster-listen``, ``--cluster-peer``, ``--cluster-secret-file`` and ``--cluster-tls-cert``, ``--cluster-tls-key`` and ``--cluster-tls-ca`` are gone; giving one stops startup with ``RemovedOption`` and a hint that names SID 0011. The console's options are listed in the next chapter.

.. admonition:: The master secret

   Without ``--secret-file`` or ``SIBUNA_SECRET`` the daemon draws a random seed, and the banner prints "random (set --secret-file)". Tokens and challenges then die with the process, and a cluster whose nodes hold different seeds will reject each other's cookies. Generate one with ``head -c 32 /dev/urandom | xxd -p -c 64 > /etc/sibuna/secret`` and mode 0600.

Console Preview
---------------

The console is compiled into the daemon by the default ``console`` feature, but starts only with ``--console``. It needs storage: ``--console`` without ``--data-dir`` or ``--database-url`` is refused with ``CONSOLE001`` (``StorageRequired``). Use ``cargo build --release -p sibuna --no-default-features --features sqlite`` to compile it out; a build with ``--no-default-features`` alone has neither storage nor console. Bootstrap locally while the daemon is stopped:

.. code-block:: sh

   sibuna init-admin admin --data-dir ./data
   sibuna --data-dir ./data --console 127.0.0.1:19446

``sibuna console init-admin`` is the same command. Open ``http://127.0.0.1:19446/console/`` and replace the generated temporary password, which must be changed at the first sign-in and expires after one hour. The signed-in navigation provides the animated country globe, request and challenge statistics, incident investigation, policy and inspection editors, users, scoped API tokens, audit and serving-node controls. The authentication shell loads no globe geometry or telemetry. The interface is a WebAssembly module built from ``cmd/console-ui`` (crate ``sibuna-console-ui``) by the daemon's build script; it and the committed stylesheet ship with ordinary builds.

.. list-table:: Console options
   :header-rows: 1
   :widths: 36 64

   * - Flag
     - Meaning
   * - ``--console <ip:port>``
     - Start the console on this listener (IPv6 in brackets, nonzero port); requires ``--data-dir`` or ``--database-url``
   * - ``--console-key-file <path>``
     - 64 hex characters, owner-only permissions; protects stored second-factor and webhook secrets
   * - ``--console-origin <https-origin>``
     - The canonical HTTPS origin behind a proxy
   * - ``--console-behind-proxy``
     - A TLS-terminating proxy delivers every request
   * - ``--console-trusted-proxy <cidr>``
     - A network whose connections may carry forwarded fields; repeatable, at most 16
   * - ``--console-advertise <origin>``
     - The link other consoles show for this one
   * - ``--console-location <latitude,longitude>``
     - This node's declared position on the globe
   * - ``--console-probe <node-id>=<http://ip:port>``
     - A peer data-plane listener to health-check; repeatable, at most eight
   * - ``--console-peer <node-id>=<https://origin>``
     - A management peer; repeatable, at most eight
   * - ``--console-peer-key-file <path>``
     - The peer key: owner-only, 64 hex characters, independent of the console key
   * - ``--console-peer-ca-file <path>``
     - Optional PEM trust anchors for peers, replacing the system roots
   * - ``--console-query-steps <n>``
     - SQLite steps per aggregate read, 100,000 to 50,000,000, default 4,000,000
   * - ``--console-capture-heads``
     - Store redacted request and origin response heads per incident; off by default
   * - ``--console-capture-header <name>``
     - Keep this header's value in stored heads; repeatable, at most 16; requires ``--console-capture-heads``
   * - ``--console-cookie-secure``
     - Give console cookies the ``Secure`` attribute without a proxy (accepted by the parser, not listed in ``--help``)

A console option without ``--console``, a repeated option or a malformed value stops startup with ``CONSOLE002`` and the option's error name. A configuration that breaks a rule of the console (for example an off-loopback listener without a trusted proxy) stops it with ``CONSOLE001``.

A Tour of the Console
~~~~~~~~~~~~~~~~~~~~~

The screenshots below come from a release build on one loopback node with SQLite storage and a policy of four ``ALLOW`` rules over a default challenge, after about four minutes of synthetic traffic: addresses from documentation ranges, SQL injection and cross-site scripting probes, three honeypot hits and seven challenges solved in headless Chromium. Every number is therefore illustrative. We took them with ``cargo xtask browser console --viewport-only``, which walks the console in Chromium at 1440 by 960 pixels and judges every page. Each page answers one question stated in its title and carries the product, the serving node, the page and the way back in the same place.

.. figure:: /assets/images/console-sign-in.png
   :alt: The console sign-in page: user name, password and authenticator code fields with a Sign in button, and below them a Kiosk code field with an Open wall display button.

   Sign-in. The public shell loads no globe geometry, GeoIP data or telemetry; the second form exchanges a wall-display code for a read-only statistics session.

.. figure:: /assets/images/console-traffic.png
   :alt: The Traffic overview page for the last 24 hours: tiles for requests, admitted, challenged, policy denied, banned, rate limited, other, and origin 4xx and 5xx, each with a yesterday comparison and a small sparkline.

   Statistics, Traffic, over the last 24 hours. The note under the period control states the coverage: only four of 1,440 expected minute records exist, so every "Yesterday" reads "Not available". Tiles show retained closed-minute counts with a live 60-second sparkline; decision colours (admitted green, challenged amber, denied red) are the same in every panel. Origin 4xx and 5xx read "Not recorded" for a retained period, because the minute records do not keep the proxy mode that gives an origin count its meaning; the live boot totals show them. Below the visible tiles are two level tiles, active ban entries and healthy nodes, the timeline, and sampled panels that rank request paths and referring hosts and count client operating systems, browsers and response status.

.. figure:: /assets/images/console-security.png
   :alt: The Security overview page: tiles for inspection, reputation, rate limiting, challenges, bans and honeypot, live trend panels, and a live event feed listing WAF findings.

   Statistics, Security. One tile per module over the selected period, live outcome trends, and the live event feed with its newest findings (here ``waf:sqli`` and ``waf:xss``). Values that are not recorded say so instead of showing zero: the Reputation tile reads "Not recorded". Further down the page are findings over sixty equal buckets, attack categories and attacked paths.

.. figure:: /assets/images/console-events.png
   :alt: The Events page with a filter form (module, category, country, client address, path, node, time range) above a list of recorded incidents tagged waf:xss and waf:sqli.

   Events. The filter form above the recorded incidents, newest first. Each incident opens inline with its evidence: the selected local response, byte lengths, campaign candidate, and explicit "not recorded" entries for the matched rule, score terms and JA4 fingerprint. With ``--console-capture-heads`` the redacted request head (and, for audited admissions through the reverse proxy, the origin response head) opens on request, rendered as UTF-8 or Latin-1, with the response condition stated (captured, local, forward-auth unobserved, origin unavailable) and a copy-as-cURL command; only listed header values are kept, and ``--console-capture-header <name>`` adds to that list. Otherwise heads read as not recorded. Deny and allow actions open the IP groups form with the address drafted.

.. figure:: /assets/images/console-challenges.png
   :alt: The Challenges page with a 24-hour retained window: seven challenges issued, submitted and accepted, none rejected, and a table of rejection causes, all zero.

   Challenges. A retained window (one hour, one day or seven days) sums durable per-minute records and states how many minutes were recorded and complete; here seven challenges were issued, submitted and accepted, and the rejection causes are all zero. Further down are live totals since this boot, the configured and most recently issued parameters, the accepted solve-time histogram partitioned by algorithm and parameter bin, adaptive-difficulty transitions and per-address records with deny and allow shortcuts, retained seven days.

.. figure:: /assets/images/console-policies.png
   :alt: The Policies page: the applied configuration (Shield, revision 3, four rules, PoSW at difficulty 16, node-local limits) and the first rule, public-static, with 339 recorded hits today.

   Policies. The applied engine names its surface, revisions, default algorithm and difficulty and its node-local limits, then lists rules in evaluation order with their hits today and the coverage of those counts. Further down are the inspection mode matrix, the request tester and IP groups. *Managed rules* opens the editor; saving an edit first shows a review of the changed fields, and confirming validates the whole candidate and creates a new revision.

.. figure:: /assets/images/console-nodes.png
   :alt: The Nodes page: node 1 accepting connections, with open connections, active local ban entries, policy revisions 3 of 3, uptime, resident memory, CPU and boot identifier, sparklines of memory and CPU, and Drain node, Resume admission and Clear local bans buttons.

   Nodes. The serving node's status and commands, with resident memory and CPU of the last second and their sixty-second sparklines; below them every announced member with its applied policy revision against the committed revision, its management address and its probe result (SID 0007, SID 0013).

.. figure:: /assets/images/console-geoip.png
   :alt: The GeoIP page with the provider ip-location-db user-country, no generation loaded yet, and the import form.

   GeoIP. Provider, licence, active generation digest, load time and the import form; here no generation has been loaded yet. A failed import never replaces the active generation.

.. figure:: /assets/images/console-settings.png
   :alt: The Settings page with an empty list of notification destinations and the form for a new webhook or syslog destination.

   Settings, with no notification destination yet and the form for a new one. Further down the page are denial-spike thresholds, retention with an explicit acknowledgement per window, response-page templates and About.

.. figure:: /assets/images/console-audit.png
   :alt: The Audit history page with a filter form and recorded activity rows: session.create, session.logout, kiosk.exchange and kiosk.grant, each with time, actor and role, subject and an Open button.

   Audit. Append-only history with actor and role, action, subject and a detail view with redacted before and after summaries; refused sign-ins are recorded too. Every management mutation and authentication row records the client address that presented the credential; rows the system writes on its own show it as not recorded. A policy record offers *Revert this change*, which restores the document recorded before that revision as a new, audited revision after a confirmation, and is refused if the rule set has moved on.

.. figure:: /assets/images/console-wall-display.png
   :alt: A wall display titled Node 1 Traffic, with Live, an expiry of 719 minutes, Pause, Theme and Exit kiosk controls, and the eleven traffic tiles without navigation.

   A wall display. A kiosk session shows the Traffic and Security views only, without navigation, and states when it expires.

The optional ``--console-location <latitude,longitude>`` declares this node's position, for example ``1.3521,103.8198`` for a deployment in Singapore. The globe initially centers there; Center Sibuna returns to that point after rotation. Country activity follows animated great-circle arcs toward the node, with rear-hemisphere and flat-map dateline clipping. Country positions are representative centroids, and arrows represent the observed sixty-second window rather than individual connections. An unset server position stays explicitly unknown. The configured marker remains visible through telemetry outages; stale traffic does not animate.

Policy previews build a private candidate including configured file rules. Saves compare the expected revision and require confirmation of a field comparison. Historical reverts compare against the current rule and create a new revision. Committed and locally applied revisions are distinct. Audit details retain bounded decision changes and the effective acting role. Matcher values are redacted and old records with missing context remain explicitly absent. Drain, resume and clear-local-bans require a command preview. A command that arrives while another one runs on the node is refused with ``503`` ``CONSOLENODE`` instead of queueing. Inspect the durable receipt after a lost response before retrying; a committed intent alone does not establish that the runtime effect finished.

For remote operation, use an HTTPS proxy and configure ``--console-origin``, ``--console-behind-proxy``, explicit ``--console-trusted-proxy`` CIDRs, and ``--console-key-file``. The key file contains 64 hexadecimal characters, has owner-only permissions and protects stored second-factor secrets; retain it across restarts separately from the challenge seed. The configured HTTPS origin and proxy allowlist are mandatory for off-loopback access. Sibuna terminates no inbound TLS on the console listener either; the console uses TLS only for its outbound connections, through rustls (SID 0012).

The native CLI accesses the running console through the same authorization and storage contracts. It reads credentials from private files, not command-line values:

.. code-block:: sh

   sibuna console geoip update --version 2026-09-09 \
       --origin http://127.0.0.1:19446 --username admin \
       --password-file ./admin-password

Use an owner-only password file, complete password setup first, and add ``--factor-file`` for an authenticator or recovery code when required; ``--token-file`` replaces the user name and password for account and GeoIP operations. The client speaks HTTP/1.1, requires HTTPS except for a literal loopback address, never follows redirects, and bounds each request to 20 seconds and each reply to 16 KiB. ``geoip status`` reads the active generation. Updates download the selected provider's published files over HTTPS (the public-domain ``user-country`` dataset by default, or DB-IP Lite with ``--provider dbip --version YYYY-MM``), verify the publisher's checksums (or the one given with ``--checksum``), validate bounded ranges through ``sibuna-geoip``, persist the new generation and activate it locally. Failed updates preserve the previous generation. A CLI timeout (``--timeout``, default 1200 seconds) stops waiting; it does not cancel submitted storage work. DB-IP Lite requires CC BY 4.0 attribution, shown only while its data is active. A build with ``SIBUNA_GEOIP_DATA=<snapshot>`` embeds a validated snapshot (written by the ``geoip-snapshot`` tool) until the first durable import; a build without the console refuses one with ``GEOIP001``. Unknown addresses, sample loss and stale data remain visible; importing country data does not create traffic or enrich already expired samples.

Cluster members announce themselves through the membership table of the shared database (``console_nodes``) at start, every minute, and within two seconds of a change of the applied policy or control revision, and appear on every console's Nodes page. There is no leader election: a SQLite node reports the role ``single`` and itself as leader, and a PostgreSQL node reports the role ``unknown`` and no leader, because PostgreSQL's failover is not visible to Sibuna (SID 0007). Configure ``--console-probe <node-id>=<http://ip:port>`` for the peers whose data-plane listeners this console should health-check and ``--console-advertise <origin>`` for the link other consoles show. Direct live telemetry uses ``--console-peer <node-id>=<https://origin>`` (repeatable, at most eight) and a dedicated ``--console-peer-key-file``. Peers require ``--console-behind-proxy``. Both endpoints must list each other and use trusted HTTPS ingress. The peer key is an owner-only file containing 64 hex characters, provisioned independently of the console key and the challenge seed. Peers talk over an authenticated TLS WebSocket, through rustls with the ``ring`` provider (SID 0012). ``--console-peer-ca-file`` optionally supplies PEM trust anchors for a private management PKI; otherwise the client uses the system roots. Host-name verification always applies and cannot be turned off: the host of each management origin, a DNS name or an IP address literal, must be named by the peer's certificate. A refused certificate marks the peer ``rejected`` and writes one ``peer.rejected`` audit row. Key rotation and a change of the CA file require a coordinated restart; a peer's certificate can be renewed without one. The Nodes API and its subscription report receipt age, clock skew, boot changes and sampling loss. Missing observations remain unavailable and disconnected values remain stale; received statistics never become another node's own contribution. The dashboard's *Live traffic scope* selects one node or combines the configured nodes. *Node coverage and locations* identifies missing, stale and clock-skewed sources, observation times and configured destinations. Country rankings show the uncertainty from omitted source rows. Arrows retain their receiving node, and missing node locations are not invented. The combined rate stays unobserved when any contributing source lacks a consecutive interval. Select one node to inspect its retained seconds and current-minute path rankings. Remote queries use the authenticated peer connection; a query answer must fit one 4 KiB WebSocket message, so the serving console halves the rows of a page that does not fit. Missing peers stay unavailable and history cursors cannot cross a node restart. Minute history keeps its own node selection and per-node rows. The navigation and mobile header identify the serving console node independently of the selected traffic source. Local commands remain per node.

Traffic tiles open on the last 24 hours of retained closed-minute records for the selected nodes. The period control also offers an hour, seven or ninety days, and live boot totals. Yesterday deviations require complete matching coverage from every selected node. The globe and sparklines still describe their separate live 60-second window. A retained scan refreshes one minute after completion, keeping its previous values and age visible until replacement; changing the source or period discards the old scope. Missing history never becomes zero.

*Compare retained traffic* displays two closed minute windows beside each other: the same window yesterday, the preceding period, or a second node. Duration and end-offset controls freeze both UTC ranges. Each action reads at most sixteen compact pages per side, with 96 stored records per page. This covers a 24-hour window without overlapping restarts in one batch; Continue retains the same boundaries for longer scans. Complete coverage, incomplete coverage and missing history remain explicit. Rate percentages require complete non-overlapping intervals in equal UTC windows, normalized by observed milliseconds; a zero reference with new traffic shows "New". The primary Traffic period remains independent. The minute format does not record historical proxy mode, so origin-response comparisons remain unavailable rather than interpreting forward-auth zeros as observed responses.

*Compare retained path rankings* selects two closed windows or nodes. Node 0 includes all retained nodes, including retired members. An action reads at most sixteen immutable archives, checks their identities and checksums, and merges every counter before selecting display rows. Archives seal after the 60-second late-sample window, so the newest closed minute may still be pending. Continue preserves the original windows and cursor. Bounds describe sampled path prefixes, not exact request totals. The page shows partial scans, truncation, retention boundaries and reported queue loss; missing archives cannot establish zero traffic or complete coverage.

Security opens on the last 24 hours and uses sixty equal time buckets over the selected period. Its aggregates run on the storage thread under a work bound. On SQLite the bound is ``--console-query-steps`` virtual-machine steps (100,000 to 50,000,000, default four million). Set it alongside ``--console``; invalid or repeated values are refused. On PostgreSQL the bound is a statement timeout of 2,000 ms set in the read's transaction (SID 0013); changing ``--console-query-steps`` does not change it. Exhausted queries ask for a narrower period. Step counts bound query work, not elapsed time. Charts share a scale; expand Trend values for the UTC interval starts and exact grouped counts. These are retained findings, so missing incident coverage cannot be interpreted as absence of attacks.

Wall displays use kiosk sessions. Under Account, an operator names the display and selects Create display code. The display pastes the one-time code into the sign-in form within ten minutes; its session is read-only, limited to statistics and expires within twelve hours. The account page erases the displayed code on navigation or when hidden. Hiding does not revoke an unused grant; the exchange deadline still applies. Codes never belong in URLs. Traffic and Security share the display: Security shows aggregate module trends and request outcomes without incident addresses or payload evidence. Automatic cycling is optional, off initially and suspended with reduced motion, stale data or Pause.

Notification destinations (signed webhooks and syslog for denial spikes, bans, unreachable members and leader changes) live under Settings; webhook secrets need ``--console-key-file``. The leader-change kind stays defined so that stored destinations keep their meaning, but no node raises it, because there is no leader election. Each destination has its own cooldown and three-attempt retry budget. Delivery audit records show outcomes; completed queue history is bounded to seven days and 4,096 events. Webhooks include a stable ``Idempotency-Key`` so receivers can suppress repeated effects after uncertain network completion. Webhooks are sent over HTTPS, or plain HTTP only to a literal loopback address, and the reply body is read up to 64 KiB. Syslog's UDP/TCP selection applies only to outbound notifications, independently of protected web traffic. Manual tests record intent and completion in Audit and refresh the destination outcome; an unconfirmed audit completion is shown explicitly before an operator retries.

Settings also controls retention: one to 90 days for minute history, one to seven for rankings, one to 30 for incidents and one to 365 for audit. The upper values are the defaults; rankings keep their 512 MiB quota. Saving a retention value requires confirmation because cleanup permanently removes older records in bounded batches. Increasing the value later does not restore deleted history. Stale edits are refused and successful changes appear in Audit.

Response pages (challenge, denied, rate limited, banned, overloaded) are editable under Settings as bounded HTML with fixed placeholders; drafts preview in a sandboxed tab and saved pages are served from the next policy snapshot.

Policy workflows on the Policies page: reorder managed rules, replay a draft against retained inspection findings, manage IP groups and country blocks pinned to the active GeoIP generation, and export or atomically import the managed set (also ``sibuna console policies export`` and ``sibuna console policies import --file <set.json>``). An import is one request carrying 1 to 128 documents of at most 4 KiB each and at most 256 KiB in all; the page's note names the command-line import for sets above about 96 KiB. Applied rules show recorded hits today, hourly sparklines and an accessible table. A hit is a successful declarative matcher evaluation: matching WEIGH rules and the first terminal match count; an earlier inspection or reputation decision may prevent evaluation. Private tests do not increment these counters. *Compare rule hits* freezes two closed periods for one recorded node. Revision history offers *Compare hits around this edit*, excluding the edit minute and using equal available periods up to the chosen duration. Optional applied-revision filters keep unrelated generations out of the comparison. Startup, cutover, missing writes and retention leave visible coverage gaps; percentages require complete coverage on both sides. Rule observations and hourly/daily summaries follow the minute-retention setting. An observed change around an edit is a comparison, not evidence that the edit caused the traffic change.

Importing a later GeoIP generation does not automatically refresh existing country-derived reputation rows. Preview the country action to compare added, retained and removed prefixes; page through the reviewed diff before applying it. The replacement removes obsolete rows owned by that country and preserves independently managed prefixes. A changed generation or policy revision requires a fresh preview, and overlapping independent edits are refused. The Events page contains retained WAF findings and honeypot incidents; it is not a complete access log. With GeoIP loaded, the storage thread records each incident's country and generation in the incident batch's transaction. This is attribution at persistence, not a reconstructed request-time location. Later imports leave recorded mappings unchanged. The country filter accepts an uppercase two-letter code, ``unknown`` for an address absent from the loaded generation, or ``not_recorded`` for an incident without mapping data. Source groups report mixed countries or coverage explicitly. The globe's *View events* action keeps the selected node and opens the country's retained incidents for the last hour. The Statistics page's *Security* view combines live rate-limit, challenge and ban rates with retained inspection and honeypot findings over one hour, one day, seven days or thirty days. Category, source and path links open the normal incident workflow with the same node and a fixed time boundary. Applying incident filters starts a new period. Findings include audit records and are distinct from blocked-request totals; absent reputation and rule-hit attribution is shown as not recorded. Event and audit filters keep labels with their controls, align the Apply action separately and adapt their columns to the available content width. One authenticated WebSocket survives navigation and carries statistics, incident summaries, node status, policy revisions, challenges and audit summaries. New incident and audit records wait behind *Load latest records* so the table stays in place while it is read. Policy updates show current committed and applied revisions without replacing an open draft. Flow counters update live; refresh a selected non-default challenge timing partition explicitly. Historical queries, detail reads and mutations remain HTTP requests.

Page fragments can be bookmarked; Back and Forward reopen authenticated pages. The sidebar also remembers theme and spacing choices in this browser, with System as the default theme. SID 0007 is Committed. The console passes its golden fixtures and its browser workflows in headless Chromium (``cargo xtask browser console``, SID 0010 criterion 5). Its end-to-end suite is ``cmd/sibuna/tests/console_*.rs``, whose PostgreSQL cluster scenarios run when ``SIBUNA_TEST_DATABASE_URL`` is set. SID 0010 records that with the console compiled in, disabled, storage only, or enabled and idle, the 16 product workloads stay within about 1% of the daemon built without it, which is within noise. The formal isolation gate of SID 0007, with eight active dashboards under load, has not been measured yet (Part VIII). The complete WebAssembly application has a 768 KiB uncompressed ceiling, which the daemon's build script enforces by failing the build, and a 640 KiB review threshold. The module measures 719,406 bytes (270,612 gzipped, October 2026), above the review threshold, which SID 0007 records for review. These project limits leave room for console workflows; they do not replace browser loading and responsiveness measurements. The module's linear memory grows on demand up to a declared maximum of 16 MiB.

Deployment Topologies
---------------------

.. admonition:: Objectives

   Deploy the autonomous reverse proxy and the forward-auth validator behind Nginx or Caddy.

Reverse Proxy
~~~~~~~~~~~~~

.. graphviz::
   :caption: Request routing on the Shield surface
   :alt: A request passes local bans and the rate limit, then inspection and policy. A DENY goes to Deny. An ALLOW goes to the origin or an auth success. A CHALLENGE checks the session MAC: a valid session goes to the origin, a missing or invalid one leads to a new puzzle.

   digraph shield_routing {
     graph [rankdir=LR, bgcolor="transparent", nodesep=0.5, ranksep=0.7];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10, fillcolor="#eff6ff", color="#1e40af", fontcolor="#172033"];
     edge [color="#64748b", fontname="Helvetica", fontsize=9, fontcolor="#64748b"];

     request [label="Request"];
     limits [label="Local bans\nand rate limit"];
     policy [label="Inspection\nand policy"];
     deny [label="Deny", fillcolor="#fef2f2", color="#b91c1c"];
     origin [label="Origin / auth\nsuccess", fillcolor="#f0fdf4", color="#15803d"];
     session [label="Session MAC\nif challenged", fillcolor="#fffbeb", color="#b45309"];
     puzzle [label="Issue puzzle", fillcolor="#fffbeb", color="#b45309"];

     request -> limits;
     limits -> policy [label="within limits"];
     policy -> deny [label="DENY"];
     policy -> session [label="CHALLENGE"];
     session -> origin [label="valid"];
     session -> puzzle [label="missing / invalid"];
     policy -> origin [label="ALLOW"];
   }

.. code-block:: sh

   sibuna --port 80 --upstream-host 127.0.0.1 --upstream-port 3000 \
          --secret-file /etc/sibuna/secret --difficulty 16 --algorithm posw

Admitted requests reach the origin with ``X-Forwarded-For``, ``X-Forwarded-Proto``, ``X-Real-IP``, ``X-Sibuna-Status`` and ``X-Sibuna-Rule`` headers. Hop-by-hop headers, the fields Sibuna writes itself and the alternative forwarding fields (``Forwarded``, ``X-Forwarded-Host``, ``X-Forwarded-Port``) are stripped, also when a client spells their names with underscores (``X_Forwarded_For``). ``X-Real-IP`` is the client the request was judged by. ``X-Forwarded-For`` is the socket peer alone, never a client-written entry; when forwarded identity is trusted, it is the received chain followed by the socket peer. Origins must therefore read the client from ``X-Real-IP`` or from the right of ``X-Forwarded-For``, never from its leftmost entry. The path the origin receives is the normal form that policy judged (SID 0009); a path without a normal form is answered ``400``.

HTTP/1.1 WebSocket upgrades pass through admission and policy checks before the origin's handshake is accepted. Subprotocol and extension negotiation remains end-to-end. Two threads relay bytes, one per direction, each with one fixed buffer, including prefetched bytes and half-closes; an upgraded connection therefore holds two threads, and the number of connection threads can reach twice ``--max-connections`` when every connection is upgraded. Upgraded sockets remain within the normal connection quota and shutdown registry, but use ``--websocket-idle-timeout`` (300 seconds by default) independently of the HTTP idle deadline. Traffic in either direction refreshes that bound, but a peer that accepts no byte for the whole period ends the relay, however busy the other direction is. Frames after the handshake are not WAF inspection inputs. HTTPS/WSS uses a TLS-terminating ingress in front of Sibuna's private HTTP/1.1 listener; Sibuna does not terminate browser TLS itself.

The ingress can negotiate HTTP/2 with browsers and forward HTTP/1.1 to Sibuna. Native HTTP/2 support in Sibuna is deferred to a later update; this arrangement does not provide end-to-end HTTP/2 semantics for applications such as native gRPC.

Content-Length request bodies stream through fixed buffers, preserving bytes and MIME headers. Multipart uploads retain boundaries, repeated field names, filenames and part types. The WAF examines at most the first 8 KiB of the body: multipart metadata and non-file fields remain text inspection inputs, while file payloads are opaque. A part whose ``filename`` is empty is an ordinary field. A body of a recognized binary top-level MIME type (images except SVG, audio, video, PDF, ZIP, gzip, 7z, protobuf and octet-stream) is opaque only when its prefix also looks binary, that is, when at least one byte in sixteen is a control byte other than tab, line feed, vertical tab, form feed and carriage return; otherwise it is inspected as text (SID 0004). JSON, XML, SVG, URL-encoded forms and unknown types retain text inspection. Ambiguous or malformed MIME metadata falls back to text inspection. Multipart parsing is bounded to 32 parts and 2 KiB of headers per part within that same prefix, and accepts the transport padding of RFC 2046 after a delimiter.

This is upload compatibility, not file validation or malware scanning. The backend must enforce accepted media types rather than trust a client's Content-Type declaration. Fields after the inspection prefix, including those after a large uploaded file, are not inspected. Compressed payloads are not decompressed for inspection. Uploads still pass admission, path, query and header checks and remain subject to connection deadlines. Chunked request bodies are decoded inside the connection buffer before inspection (SID 0009). A body that ends within the buffer reaches the backend with Content-Length. A longer one is re-chunked by Sibuna, one chunk per read, so the backend never sees the client's chunk sizes, extensions or trailers. A chunk line with a lone CR or LF, whitespace around the size, a malformed extension or more than 4 KiB is refused with 400. So is a trailer section over 16 KiB. ``Transfer-Encoding`` with another coding receives 501. Backends that cannot parse chunked requests still receive Content-Length for bodies under about 44 KiB. An origin connection that carried a request body is closed after its exchange and never returns to the pool. Clients waiting for ``100-continue`` receive it locally before sending the body; unsupported expectations receive 417. The Expect header is consumed before forwarding to the backend.

Forward Auth Behind an Ingress
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In ``--mode forward_auth`` the daemon answers the ingress's subrequest with ``200`` (plus the audit headers ``X-Sibuna-Status``, ``X-Sibuna-Rule`` and ``X-Sibuna-Rule-Hash``), ``401`` for a challenge, ``403`` for a denial, or ``429`` when rate limited. The ingress must forward the client address and original URL; forward-auth mode trusts them by default. Bind this listener privately so only the ingress can connect. ``X-Forwarded-Uri`` (Caddy) or ``X-Original-URI`` (Nginx), and ``X-Forwarded-Method``, restore the application request for policy evaluation; the original path is put in normal form, as a request line's path is. Duplicate or conflicting original-URL fields, and an original URI that is not origin-form, are rejected with ``400``. Internal daemon routes always use the actual request URI. Forward-auth does not inspect a body the ingress omits.

.. code-block:: nginx

   map $http_upgrade $sibuna_connection_upgrade {
       default upgrade;
       '' close;
   }
   server {
       listen 443 ssl;
       location / {
           auth_request /__sibuna_auth;
           auth_request_set $sibuna_auth_status $upstream_status;
           auth_request_set $sibuna_retry_after $upstream_http_retry_after;
           auth_request_set $sibuna_status $upstream_http_x_sibuna_status;
           auth_request_set $sibuna_rule $upstream_http_x_sibuna_rule;
           auth_request_set $sibuna_rule_hash $upstream_http_x_sibuna_rule_hash;
           error_page 401 = @sibuna_challenge;
           error_page 500 = @sibuna_auth_error;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection $sibuna_connection_upgrade;
           proxy_set_header Host $host;
           proxy_set_header X-Sibuna-Status $sibuna_status;
           proxy_set_header X-Sibuna-Rule $sibuna_rule;
           proxy_set_header X-Sibuna-Rule-Hash $sibuna_rule_hash;
           proxy_read_timeout 300s;
           proxy_pass http://127.0.0.1:3000;
       }
       location = /__sibuna_auth {
           internal;
           proxy_pass http://127.0.0.1:8080/;
           proxy_pass_request_body off;
           proxy_set_header Content-Length "";
           proxy_set_header X-Original-URI $request_uri;
           proxy_set_header X-Forwarded-Method $request_method;
           proxy_set_header X-Forwarded-Proto $scheme;
           proxy_set_header X-Forwarded-Uri "";
           proxy_set_header X-Forwarded-For $remote_addr;
           proxy_set_header User-Agent $http_user_agent;
           proxy_set_header Cookie $http_cookie;
       }
       location @sibuna_challenge {
           rewrite ^ /__sibuna/challenge break;
           proxy_pass http://127.0.0.1:8080;
           proxy_pass_request_body off;
           proxy_set_header Content-Length "";
           proxy_set_header X-Original-URI $request_uri;
           proxy_set_header X-Forwarded-Method $request_method;
           proxy_set_header X-Forwarded-For $remote_addr;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
       location @sibuna_auth_error {
           add_header Retry-After $sibuna_retry_after always;
           if ($sibuna_auth_status = 429) { return 429; }
           return 503;
       }
       location /__sibuna/ {
           proxy_pass http://127.0.0.1:8080;
           proxy_set_header X-Forwarded-For $remote_addr;
       }
   }

.. code-block:: text

   example.com {
       handle /__sibuna/* {
           reverse_proxy localhost:8080
       }
       handle {
           forward_auth localhost:8080 {
               uri /
               header_up X-Forwarded-For {remote_host}
               header_up -X-Original-URI
               copy_headers X-Sibuna-Status X-Sibuna-Rule X-Sibuna-Rule-Hash
           }
           reverse_proxy localhost:3000
       }
   }

The ``/__sibuna/*`` namespace (interstitial, challenge, verify, solver assets) must reach the daemon directly in both recipes. The nginx error page passes the original URI and method so the interstitial carries the requirement the authorization decided; without them the page still works, and issuance falls back to evaluating the URL the browser reports. Caddy supplies original URI/method metadata itself. The exclusive ``handle`` blocks ensure that challenge and verification routes do not enter the forward-auth precheck. Nginx requires the explicit Upgrade/Connection headers shown above for application WebSockets. The Nginx error handler renders the internal challenge route without making a second authorization decision or consuming the upload body. Its auth module accepts only 2xx, 401 and 403 directly, so the example translates a rate-limited auth error back to 429 with Retry-After; other authorization failures remain closed with 503. Nginx supplies its own 403 body, whereas Caddy forwards Sibuna's denial page. Both recipes replace incoming Sibuna audit headers with the actual authorization response. Configure normal TLS certificates and application upload/deadline limits at the ingress; the examples show the routing logic. The repository does not yet test these recipes against live ingresses; the forwarded-metadata rules they rely on are covered by unit tests in ``sibuna-http``.

Declarative Policy
------------------

.. admonition:: Objectives

   Write a policy file with rules, weights, thresholds, IP rules, and the WAF switch.

.. code-block:: json

   {
     "default_action": "CHALLENGE",
     "waf": true,
     "thresholds": { "challenge_at": 10, "deny_at": 40, "bits_step": 5 },
     "ip_rules": { "10.0.0.0/8": "ALLOW", "192.0.2.0/24": "DENY", "2001:db8::/32": "DENY" },
     "rules": [
       { "name": "deny-cf-workers", "headers": { "CF-Worker": ".*" }, "action": "DENY" },
       { "name": "deny-amazonbot", "user_agent": "Amazonbot", "action": "DENY" },
       { "name": "api-with-key", "path": "/api/*", "headers": { "X-Api-Key": ".*" },
       "action": "ALLOW" },
       { "name": "protect-checkout", "path": "/checkout/*", "action": "CHALLENGE",
         "challenge": { "difficulty": 20, "algorithm": "posw" } },
       { "name": "headless", "user_agent": "Headless", "action": "WEIGH", "weight": 30 },
       { "name": "internal-vpc", "remote_addresses": ["10.0.0.0/8", "fd00::/8"],
       "action": "ALLOW" }
     ]
   }

The loader fails closed: an unknown key, a misspelled action, a malformed address or an out-of-range number rejects the whole file, the diagnostic names the rule and field, and the daemon does not start. A command line with an unknown option or an out-of-range value is refused the same way. ``rules`` replaces the built-in table when present; ``ip_rules`` feeds the reputation trie, which scales to thousands of prefixes; ``waf: false`` selects the Gate surface from the file. Two further keys are part of the schema (Part X): ``inspection`` sets each WAF category to ``disabled``, ``audit`` or ``enforce``, and a rule's ``limits`` object gives it a quota of its own. Path patterns match the request path in normal form (SID 0003), so a pattern must be written in that form.

Persistent Storage and Clustering
---------------------------------

.. admonition:: Objectives

   Enable SQLite or PostgreSQL storage, add a dynamic policy and a ban with SQL, query incident forensics, understand campaign clustering, and run several nodes on one PostgreSQL database.

.. graphviz::
   :caption: The storage architecture: workers never block on the database
   :alt: Request threads push incidents into an MPSC ring of 512 slots. The storage thread pops them, writes batches through sqlx to the SQLite file or the PostgreSQL database holding policies, ip_reputation, security_incidents and the full-text index. When the policy revision changes it rebuilds the engine and publishes it as an Arc, which the request threads read. Other cluster nodes share the PostgreSQL database and hear NOTIFY sibuna_policy.

   digraph storage_architecture {
     graph [rankdir=LR, bgcolor="transparent", nodesep=0.5, ranksep=0.7];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10, fillcolor="#eff6ff", color="#1e40af", fontcolor="#172033"];
     edge [color="#64748b", fontname="Helvetica", fontsize=9, fontcolor="#64748b"];

     workers [label="Request threads\n(hot path)"];
     ring [label="MPSC ring\n512 incidents", fillcolor="#fffbeb", color="#b45309"];
     thread [label="Storage thread (tokio)\ndrain + poll"];
     db [label="sqlx: SQLite file\nor PostgreSQL", fillcolor="#f0fdf4", color="#15803d"];
     tables [label="policies, ip_reputation,\nsecurity_incidents,\nfull-text index", fillcolor="#f0fdf4", color="#15803d"];
     rebuild [label="Rebuild engine\noff the hot path"];
     publish [label="EngineSlot::publish\nArc swap", fillcolor="#fffbeb", color="#b45309"];
     others [label="Other cluster\nnodes"];

     { rank=same; workers; others; }
     { rank=same; ring; publish; }
     { rank=same; thread; rebuild; }
     { rank=same; db; tables; }

     workers -> ring [label="push"];
     ring -> thread [label="pop"];
     thread -> db [label="batched SQL"];
     db -> tables;
     tables -> rebuild [label="revision changed?"];
     rebuild -> publish;
     publish -> workers [label="new rules"];
     db -> others [dir=both, label="shared PostgreSQL,\nNOTIFY sibuna_policy"];
   }

``--data-dir /var/lib/sibuna`` opens the SQLite file ``/var/lib/sibuna/sibuna.db`` (WAL mode, ``synchronous=NORMAL``, a busy timeout) and starts the storage thread. ``--database-url`` (or ``--database-url-file``) connects to a PostgreSQL database instead. The storage thread owns a single-threaded tokio runtime and a small connection pool; it is the only place that runs SQL. On start, whenever the policy revision changes (a write to ``policies``, ``ip_reputation`` or ``policy_inspection``), and when a reputation entry expires, the thread rebuilds the engine from the policy file plus the database and publishes it; requests never wait on SQL. A rebuild reads the revision before and after loading, and discards its candidate if a writer committed in between.

Schema
~~~~~~

.. list-table:: Core tables
   :header-rows: 1
   :widths: 30 70

   * - Table
     - Purpose and key
   * - ``policy_revision``
     - The policy revision, one row; triggers on the three policy tables advance it.
   * - ``policies``
     - Ordered dynamic rules, keyed by ``id``.
   * - ``policy_inspection``
     - The stored WAF mode per category, one row.
   * - ``ip_reputation``
     - Scores, hit counts and expiry, keyed by address or prefix.
   * - ``incident_receipts``
     - Each node's durable incident receipt (the next sequence after its last committed batch), keyed by node.
   * - ``security_incidents``
     - One bounded event record with its 64-component embedding (256 bytes), keyed by ``node_id << 40 | sequence``.
   * - ``incidents_fts``
     - On SQLite: an FTS5 table over the canonical tokens of paths and payloads. On PostgreSQL the same tokens are the ``tsvector`` column ``search`` of ``security_incidents`` with a GIN index.
   * - ``sibuna_schema``
     - Every applied migration, keyed by component and version.

The core schema is ``crates/storage/src/schema.rs``, written once per dialect. With the console the component ``console`` adds 33 tables whose names start with ``console_`` (SID 0013; ``crates/console-storage/src/schema/``). Migrations are numbered per component and compiled into the binary; all pending migrations run in one transaction, and a node refuses a database whose version of a component is newer than it knows. An abbreviated printed schema is not an upgrade script. SQLite tables are ``STRICT``, and ``CHECK`` constraints mirror the Rust types, so the database refuses a row the daemon could not represent. Enumerated values are stored in lowercase: a direct write of ``'DENY'`` is refused.

Operating It
~~~~~~~~~~~~

Use the ``sqlite3`` shell on ``sibuna.db`` (WAL mode lets it read while the daemon runs), or ``psql`` on the cluster database:

.. code-block:: sql

   -- Add a dynamic rule; every node rebuilds on its next tick.
   INSERT INTO policies (id, name, priority, path_pattern, action, difficulty, algorithm,
     header_matchers, cidr_matchers, weight, enabled, created_at, updated_at)
   VALUES ('p-checkout', 'protect-checkout', 10, '/checkout/*', 'challenge', 20, 'posw',
     '{"X-Api": "v2"}', '["10.0.0.0/8"]', 0, 1, unixepoch(), unixepoch());

   -- Ban an address cluster-wide for a day.
   INSERT INTO ip_reputation (ip_or_cidr, reputation_score, banned_until,
     trigger_rule, hits, last_seen)
   VALUES ('198.51.100.7', -100, unixepoch() + 86400, 'analyst', 1, unixepoch());

   -- Forensics: full-text search over recorded payloads.
   SELECT s.id, s.client_ip, s.violation_category, s.path, s.campaign_id
   FROM incidents_fts f JOIN security_incidents s ON s.id = f.rowid
   WHERE incidents_fts MATCH 'union' ORDER BY rank LIMIT 20;

The statements are written for SQLite. On PostgreSQL, ``enabled`` is ``TRUE``, the time is ``CAST(extract(epoch FROM now()) AS BIGINT)`` instead of ``unixepoch()``, and the search reads ``WHERE search @@ CAST('union' AS tsquery)`` on ``security_incidents``. ``path`` and ``offending_payload`` hold the raw request bytes (``BLOB`` or ``BYTEA``). A direct write that breaks a constraint is refused by the database and never reaches a node. Under PostgreSQL the revision trigger also issues ``NOTIFY sibuna_policy``, so the other nodes tick at once; polling remains the guarantee.

Scores at or below :math:`-50` become ``deny`` prefixes in the trie, scores at or above :math:`50` become ``allow``, and ``banned_until`` bounds the ban. Honeypot hits insert a :math:`-100` record automatically, so with a shared PostgreSQL database a trap sprung on one node bans the address on all of them.

A Transaction Receipt Makes Retry Safe
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The storage thread collects at most 32 pending records and builds one SQL transaction. The transaction inserts incidents, updates the full-text index, and applies honeypot reputation changes. Each issuer (node) has a monotonically increasing receipt, its row of ``incident_receipts``. Every data-changing statement is guarded by that receipt; the transaction advances it last, and never backwards.

.. admonition:: Worked example: the acknowledgement disappears

   Suppose issuer 2 prepares sequences 101 through 132, ending at receipt 133. The database commits all records and receipt 133, then the connection fails before the acknowledgement arrives. The storage thread retains the prepared batch (identifiers, embeddings and campaigns) and retries it. The receipt already equals 133, so the guarded writes do nothing: neither incidents nor honeypot hit counts are doubled. If the original transaction rolled back, the old receipt remains and the retry applies all writes once.

A failed commit retains the pending batch in memory and increments ``incident_write_failures``. The tick still attempts policy polling. A full 512-record queue counts ``incidents_dropped``; it never blocks an HTTP response waiting for disk. The pending batch adds space for 32 records. Process death before commit can lose queued data: this is a bounded asynchronous forensic path, not a durable message queue at enqueue time.

.. admonition:: Exercise 9.1

   Move the receipt update outside the data transaction. Construct one crash schedule that duplicates a reputation effect and another that loses an incident.

Campaign Clustering
~~~~~~~~~~~~~~~~~~~

Each incident payload is embedded as a 64-dimensional unit vector by the hashing trick over byte trigrams (digits folded, case folded) and stored as 256 bytes in ``security_incidents.embedding``. The storage thread keeps the 16,384 most recent embeddings of all nodes in memory (4 MiB), refreshed from the database on each tick. Before insertion it finds the nearest of them, including earlier records in the same batch; if the cosine distance is at most :math:`0.35` the new incident joins that incident's ``campaign_id``, otherwise it starts a campaign named by its own identifier. Older incidents than the window are not compared. Similarity is a heuristic: the regression examples group related SQL payloads, but that is not a guarantee that every pair of attacks shares a campaign. No model runs and nothing is trained.

Clustering
~~~~~~~~~~

A cluster is a set of nodes that share one PostgreSQL database. Build with the ``postgres-tls`` feature (``cargo build --release -p sibuna --features postgres-tls``; it implies ``postgres``) and start each member with the database and a node id of its own:

.. code-block:: sh

   sibuna --database-url-file /etc/sibuna/database-url --cluster-node 1 \
          --secret-file /etc/sibuna/secret

Every member must use the same master secret and a unique ``--cluster-node`` from 1 to 8,388,607. The URL file holds one ``postgres://`` URL and must be readable by its owner only; the banner never prints the URL. Writes go to the PostgreSQL primary. Each node's storage thread sees the committed revision change (by ``NOTIFY`` or by polling) and rebuilds its engine.
Nodes reach the shared database across the network, so we encrypt and verify that connection. We give the server a certificate signed by our own certificate authority, and we name that authority in the URL: ``postgres://sibuna:...@db.internal:5432/sibuna?sslmode=verify-full&sslrootcert=/etc/sibuna/db-ca.pem``. On the server we accept TCP only through ``hostssl`` lines in ``pg_hba.conf``.

At startup the daemon prints one line about the database connection. With ``verify-full`` it says that the certificate and host name are verified. With any weaker mode it prints a warning and a hint. Without ``sslmode`` the mode is ``prefer``: the connection is encrypted only if the server offers TLS, and the server is not verified. A daemon built without ``postgres-tls`` refuses ``require``, ``verify-ca`` and ``verify-full`` and names the missing feature; it never falls back to plaintext. A refused certificate stops startup at once; the hint asks us to check ``sslrootcert`` and that the URL's host is a name in the server's certificate. ``sslrootcert`` adds our authority to the system trust store; it does not remove the system's authorities (SID 0011, SID 0012).

Sibuna does not replicate a database of its own and elects no leader. Replication, failover and backups are PostgreSQL's (streaming replication, Patroni or a managed service). The console's node view has no leader: it shows the role ``single`` for a SQLite node and ``unknown`` for a PostgreSQL node, and ``quorum`` means only that the node's last database round trip succeeded. If the database is unreachable, the last published engine keeps serving, incidents queue in the bounded ring and are dropped with a counter once it is full, and the storage thread retries with backoff; a node keeps its last policy until it reconnects. A Zaxonlite data directory (SID 0005) is not read; policies move with ``sibuna console policies export`` and ``sibuna console policies import``, and forensic history is not migrated.

Cluster Challenge Routing
~~~~~~~~~~~~~~~~~~~~~~~~~

Challenge keys are bound to ``--cluster-node``; keep challenge issuance and verification on the same member. Tokens use the shared seed and work on other members. Local rate quotas do not become global quotas, and process restarts clear spent sets. With three nodes on one local PostgreSQL, a policy row written directly reaches all three within one tick, a honeypot ban on one node reaches the others, and incident identifiers never collide (``crates/storage/tests/multi_node.rs``, SID 0011 criterion 2; it runs when ``SIBUNA_TEST_DATABASE_URL`` is set).

Packaging
---------

.. admonition:: Objectives

   Install and verify a release package, run Sibuna as a service, in a container or under Kubernetes, and build the binary ourselves.

Every release on GitHub carries the same executable for each platform, built from the release tag with the default features: SQLite storage and the console. PostgreSQL clusters need a build of our own (below).

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Platform
     - Release assets
   * - Linux x86-64, ARM64
     - ``sibuna-linux-amd64.tar.gz`` and ``sibuna-linux-arm64.tar.gz`` hold a static musl executable that runs on any distribution. ``sibuna_<version>-1_amd64.deb``, ``sibuna_<version>-1_arm64.deb``, ``sibuna-<version>-1.x86_64.rpm`` and ``sibuna-<version>-1.aarch64.rpm`` install it with a systemd service; ``sibuna-bin-<version>-1-x86_64.pkg.tar.zst`` does so on Arch Linux.
   * - macOS arm64, x86-64
     - ``sibuna-macos-arm64.tar.gz``, ``sibuna-macos-amd64.tar.gz``, for macOS 12 or later.
   * - Windows x86-64
     - ``sibuna-windows-amd64.zip`` holds ``sibuna.exe``, for Windows 10 or Server 2016 or later.
   * - FreeBSD 15.1, OpenBSD 7.9 (amd64)
     - ``sibuna-<version>-freebsd-15.1-amd64.pkg`` and ``sibuna-<version>.tgz``.
   * - Homebrew, Kubernetes, containers
     - ``sibuna.rb``, ``helm-sibuna-<version>.tgz``, and the image ``ghcr.io/insanai/sibuna:<version>`` for amd64 and arm64, whose digest is in ``IMAGE-DIGEST.txt``.
   * - Source
     - ``sibuna-<version>-source.tar.gz``.

Each archive and package carries ``LICENSE``, ``NOTICE``, ``LICENSES/`` (with ``THIRD-PARTY-RUST.txt``, the crates in the executable), ``README.md``, ``SECURITY.md`` and ``sibuna.build.json``. The manifest records the version, commit, Rust target, compiler version, features and the SHA-256 of the executable and of its two WebAssembly modules. The release workflow starts every executable on its own platform before it publishes anything, and it installs, reinstalls and removes the packages on Debian, Fedora, Arch Linux, FreeBSD and OpenBSD.

The assets are not signed. We check a download against ``SHA256SUMS`` from the same release before we install it:

.. code-block:: sh

   sha256sum --ignore-missing -c SHA256SUMS          # Linux
   shasum -a 256 --ignore-missing -c SHA256SUMS      # macOS, FreeBSD
   sha256 -C SHA256SUMS sibuna-1.0.0-beta.1.tgz      # OpenBSD

On macOS a browser download carries a quarantine attribute that stops an unsigned executable; ``xattr -d com.apple.quarantine sibuna`` removes it after the check.

The systemd service
~~~~~~~~~~~~~~~~~~~

The Debian, RPM and Arch packages install ``/usr/bin/sibuna``, the unit ``sibuna.service``, the account ``sibuna`` (through ``systemd-sysusers``), the helper ``/usr/lib/sibuna/seed.sh`` and the settings file ``/etc/sibuna/service.env``. Installation starts nothing. We set the origin, an IP literal, in the settings file and start the service:

.. code-block:: sh

   sudoedit /etc/sibuna/service.env      # SIBUNA_UPSTREAM_HOST, SIBUNA_UPSTREAM_PORT
   sudo systemctl enable --now sibuna
   curl -s http://127.0.0.1:8080/__sibuna/health

The service listens on ``127.0.0.1:8080`` until ``SIBUNA_HOST`` and ``SIBUNA_PORT`` say otherwise. ``SIBUNA_OPTIONS`` passes further options, split at spaces, for example ``--mode forward_auth`` or ``--console 127.0.0.1:19446``. Before each start, ``seed.sh`` creates the admission seed ``/var/lib/sibuna/admission.seed`` (64 hexadecimal digits, mode 0600, owned by ``sibuna``) if it does not exist; it never replaces one, because a new seed would end every session. The daemon keeps its SQLite database in ``/var/lib/sibuna``, a directory of mode 0700. The unit runs without capabilities, with a read-only system (``ProtectSystem=strict``), private ``/tmp`` and devices, and no new privileges.

An upgrade keeps the settings file, the seed and the state, and does not restart the service; we restart it after a backup. Removal stops and disables the service but keeps the account, the seed, the settings and the state, which we delete ourselves when we retire the host.

The FreeBSD and OpenBSD packages install only ``/usr/local/bin/sibuna`` and its documents (``pkg add``, or ``pkg_add -D unsigned`` for a package from outside the OpenBSD mirrors). They create no service, account or state: we run the daemon as an unprivileged user with a private seed and data directory.

Homebrew
~~~~~~~~

``sibuna.rb`` installs the release archive for the machine: macOS or Linux, arm64 or x86-64. It does not build from source, because Homebrew's Rust has no standard library for ``wasm32-unknown-unknown``, which the build of the two embedded WebAssembly modules needs; the archives hold the executables the release workflow already checked. Homebrew installs formulae from taps only, so we put the formula in a local tap:

.. code-block:: sh

   brew tap-new "$USER/local"
   cp sibuna.rb "$(brew --repository)/Library/Taps/$USER/homebrew-local/Formula/"
   brew install "$USER/local/sibuna"

The formula starts no service. Its caveats show how to create a seed; its test starts the daemon twice on the same data directory.

Containers and Kubernetes
~~~~~~~~~~~~~~~~~~~~~~~~~

The image ``ghcr.io/insanai/sibuna:<version>`` holds the static executable on a distroless base: CA certificates, user 65532, no shell and no package manager. The entry point is ``sibuna``, so the arguments are daemon options. The release workflow runs it read-only, without capabilities, with a seed mounted read-only and a volume for the state, and restarts it once:

.. code-block:: sh

   docker run -d --read-only --cap-drop=ALL --security-opt=no-new-privileges \
     -v "$PWD/admission.seed:/run/admission.seed:ro" -v sibuna-state:/var/lib/sibuna \
     -p 8080:8080 ghcr.io/insanai/sibuna:1.0.0-beta.1 \
     --host 0.0.0.0 --secret-file /run/admission.seed --data-dir /var/lib/sibuna/data \
     --upstream-host 10.0.0.5 --upstream-port 3000

The Helm chart ``helm-sibuna-<version>.tgz`` runs one Pod of that image. It requires a Secret that we create (``secret.existingSecret``, key ``admission.seed``), so no seed ever appears in values or templates. The Pod runs as UID 65532 with a read-only root filesystem under the Restricted pod security standard. One replica with ``Recreate`` upgrades keeps a single writer on the ReadWriteOnce volume, where Sibuna keeps its SQLite state in ``data/``; the claim is kept on uninstall. The probes call ``/__sibuna/health``. The Service is ClusterIP, the chart creates no ingress and no console, and its NetworkPolicy denies all traffic until ``networkPolicy.ingressFrom`` and ``networkPolicy.egressTo`` allow the clients and the origin. ``upstream.host`` must be an IP literal, and ``extraArgs`` passes further daemon options. The workflow installs, upgrades and uninstalls the chart in a kind cluster that enforces the Restricted standard.

.. code-block:: sh

   kubectl -n sibuna create secret generic sibuna-admission --from-file=admission.seed
   helm install gateway ./helm-sibuna-1.0.0-beta.1.tgz --namespace sibuna \
     --set secret.existingSecret=sibuna-admission \
     --set upstream.host=10.0.0.5 --set upstream.port=3000

Building from source
~~~~~~~~~~~~~~~~~~~~

Rust 1.94 or later builds the workspace; the releases use Rust 1.99.

- ``cargo build --release -p sibuna`` produces ``target/release/sibuna`` with the default features: SQLite storage and the console. sqlx bundles SQLite, and ``ring`` (rustls) needs a C compiler at build time; the binary links the system C runtime dynamically. The build script also builds the WebAssembly solver and console interface, which needs ``rustup target add wasm32-unknown-unknown``; ``SIBUNA_POW_WASM=<path>`` and ``SIBUNA_CONSOLE_WASM=<path>`` embed prebuilt modules instead.
- ``cargo build --release -p sibuna --no-default-features`` produces the in-memory firewall with no external crate at all; ``--data-dir`` and ``--database-url`` are then refused at start with ``StorageDisabled``, and ``sibuna console`` with ``CONSOLEBUILD``.
- ``cargo build --release -p sibuna --features postgres-tls`` adds PostgreSQL clusters with verified TLS to the database. It needs no OpenSSL.
- The static Linux executables of the releases come from ``cargo build --release --locked -p sibuna --target x86_64-unknown-linux-musl`` (or ``aarch64-unknown-linux-musl``) with ``musl-gcc`` as the C compiler (``CC_x86_64_unknown_linux_musl=musl-gcc``).

The release profile uses fat LTO and one codegen unit. The workflow builds the two WebAssembly modules once and passes them to every platform, so all executables of a release embed byte-identical modules. ``cargo xtask licenses`` regenerates ``LICENSES/THIRD-PARTY-RUST.txt`` after a dependency changes.

On Windows the daemon stops on Ctrl+C, Ctrl+Break and console close events; it does not run as a Windows service. Windows files have no mode bits, so Sibuna cannot refuse a key, credential or database URL file that others may read: we restrict those files with ACLs. The console's memory and CPU gauges are read from ``/proc`` and are unavailable on other systems.

.. admonition:: Exercise 9.2

   Write the policy file and the ``ip_reputation`` rows needed so that a staging network (``10.20.0.0/16``) bypasses challenges, ``/admin/*`` demands 20 work bits of sequential work, and a partner scraper identified by ``X-Partner-Key`` is admitted at 30 requests per 10 seconds.

   Hint: The daemon flags set the per-client limit every request meets first; a rule can carry a quota of its own in ``limits``.

.. admonition:: Explain the invariant

   Explain to an operator why adding a row to ``policies`` takes effect without a restart and without a request ever waiting, in terms of the storage thread and the engine slot.
