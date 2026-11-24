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

Edge mode
~~~~~~~~~

With ``--config-file`` the daemon runs as an edge load balancer. It forwards TCP and UDP, terminates TLS, HTTP/2 and HTTP/3, and applies the gate or shield to the HTTP names that need it. ``sibuna lb`` starts the same load balancer from a few options, without a file, and ``sibuna ctl`` changes its servers while it runs. The chapter *Edge Load Balancing* below describes the commands and the file.

Command-Line Reference
~~~~~~~~~~~~~~~~~~~~~~

The table lists every option of ``sibuna --help``. Ranges are those the parser enforces.

.. list-table:: Daemon options
   :header-rows: 1
   :widths: 30 16 54

   * - Flag
     - Default
     - Meaning
   * - ``--config-file``
     - unset
     - Start the TCP, UDP and HTTP edge listeners from a JSON or JLV file. We can validate the file offline with ``sibuna check -f``.
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
   * - ``--ja4-header``
     - off
     - The request header in which a trusted ingress sends the client's JA4 TLS fingerprint, such as ``cf-ja4``; 1 to 64 token characters, not ``X-Forwarded-*``, ``X-Real-IP``, ``X-Sibuna-*`` or ``Forwarded``. It is read only when forwarded identity is trusted (see "JA4 Fingerprints From the Ingress")
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

Edge Load Balancing
-------------------

.. admonition:: Objectives

   By the end of this chapter, we should be able to start a load balancer with one command, write an edge topology in JLV, forward TCP and UDP, terminate TLS with HAProxy-style PEM bundles or with certificates that Sibuna obtains itself, route HTTP by host name and path to HTTP/1.1, HTTP/2 and HTTP/3 servers, turn the firewall on or off per name, limit rates, check server health, drain and add servers while the daemon runs, and reload the file without dropping flows.

Starting with one command
~~~~~~~~~~~~~~~~~~~~~~~~~

We need no file to balance load. One command serves HTTP on port 8080 and spreads the requests over two servers.

.. code-block:: sh

   sibuna lb --bind :8080 --server 10.0.0.1:80 --server 10.0.0.2:80

``--bind`` and ``--server`` take numeric addresses and may repeat. ``:8080`` means every IPv4 address of the host. The firewall is off, so the command is a plain load balancer. The other options are few.

.. list-table:: Options of ``sibuna lb``
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Meaning
   * - ``--proto http|tcp|udp``
     - The protocol of the listener and the servers. The default is ``http``.
   * - ``--tls PEM``
     - Terminate TLS with a combined PEM file, or with every ``*.pem`` file of a directory.
   * - ``--tls auto``
     - Obtain and renew the certificate of each ``--domain`` (section *Automatic HTTPS*). Without ``--bind`` the listener is ``0.0.0.0:443``.
   * - ``--domain NAME``
     - A host name for ``--tls auto``. May repeat.
   * - ``--http IP:PORT|off``
     - With ``--tls auto``: the plain listener that answers the challenge and redirects to HTTPS. The default is port 80 on the address of each ``--bind``. ``off`` leaves it out.
   * - ``--acme-directory D``
     - ``letsencrypt`` (the default), ``letsencrypt-staging``, or a directory URL.
   * - ``--acme-email ADDRESS``
     - The contact address of the ACME account.
   * - ``--acme-storage DIR``
     - The directory of keys and certificates. The default is ``/var/lib/sibuna/acme``.
   * - ``--health PATH|tcp``
     - Probe each server with ``GET PATH``, or with a TCP connect.
   * - ``--firewall off|gate|shield``
     - The HTTP surface. The default is ``off``.
   * - ``--admin SOCKET``
     - Open the admin socket at this path for ``sibuna ctl``.
   * - ``--print-config``
     - Print the equivalent configuration and exit.
   * - ``--format jlv|json``
     - The printed format. The default is JLV.

A port below 1024 needs the capability ``CAP_NET_BIND_SERVICE``. The packaged unit ``sibuna-edge.service`` grants it and runs the file ``/etc/sibuna/edge.jlv``. The section *Changing servers at run time* describes the unit.

When the setup has proved itself we move it to a file. The same command with ``--print-config`` prints the module.

.. code-block:: sh

   sibuna lb --bind :8080 --server 10.0.0.1:80 --server 10.0.0.2:80 --print-config > edge.jlv
   sibuna check -f edge.jlv
   sibuna --config-file edge.jlv

.. code-block:: text

   // Written by `sibuna lb --print-config`. Check it with `sibuna check -f edge.jlv`.
   fn edge() -> Map<Value> {
       return {
           http: { surface: "off" },
           frontends: { web: { binds: ["0.0.0.0:8080"] } },
           backends: { app: { servers: ["10.0.0.1:80", "10.0.0.2:80"] } },
       }
   }

The quick start and the file are one mechanism. The command writes this document in memory and passes it through the checks of a file, so the printed module serves exactly what the command served. With three or more servers on one port the module lists the hosts once and generates the servers: ``servers: [for host in hosts: "${host}:80"]``. Every build prints JLV. A build without the ``jlv`` feature cannot load it and prints JSON by default.

This file is also the smallest one. A frontend without ``proto`` and a backend without ``mode`` speak HTTP. A frontend without ``default_backend`` takes the only backend of its protocol. A server written as a string is named by its address.

Frontends, backends and servers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The vocabulary follows HAProxy. A *frontend* binds one or more numeric socket addresses. A *backend* is a pool of *servers*. A frontend names a default backend of its own protocol. There are three protocols.

.. list-table:: Frontend protocols
   :header-rows: 1
   :widths: 12 44 44

   * - ``proto``
     - What Sibuna does
     - Firewall
   * - ``tcp``
     - Relays bytes to one server for the life of the connection. It can read a visible TLS ClientHello first.
     - None. Connection rate limits and SNI, ALPN or JA4 rules apply.
   * - ``udp``
     - Maps each client address to one server and relays datagrams both ways.
     - None. Packet rate limits and a response budget apply.
   * - ``http``
     - Parses each request, selects a backend by host name and path, and relays the exchange.
     - Gate or shield, or none, chosen per frontend and per route.

The semantic firewall inspects HTTP requests. It never runs on a TCP or UDP frontend, because those streams are opaque to Sibuna.

.. graphviz::
   :caption: The path of a flow through the edge. Only HTTP requests meet the firewall, and a route can skip it.
   :alt: TCP streams go from the worker to relay threads and TCP servers. UDP datagrams go from the worker to UDP servers. HTTP connections pass optional TLS termination, then the firewall or a bypass, then route selection, and reach HTTP/1.1 servers directly or HTTP/2, HTTP/3 and TLS servers through an adapter.

   digraph edge_paths {
     graph [rankdir=LR, bgcolor="transparent", fontname="Helvetica", fontsize=9, nodesep=0.25, ranksep=0.45];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=8.5, fillcolor="#eff6ff", color="#1e40af", penwidth=1.0, margin="0.1,0.05"];
     edge [color="#64748b", fontname="Helvetica", fontsize=7.5, fontcolor="#475569", arrowsize=0.6];

     worker [label="Edge worker\naccept, admission,\nUDP mappings"];
     relay [label="Relay threads\n(epoll)", fillcolor="#f0fdf4", color="#15803d"];
     tls [label="TLS, HTTP/2, HTTP/3\ntermination", fillcolor="#f5f3ff", color="#6d28d9"];
     fw [label="HTTP firewall\ngate or shield", fillcolor="#fffbeb", color="#b45309"];
     route [label="Route by host\nand path"];
     adapter [label="Origin adapter\nTLS, HTTP/2, HTTP/3", fillcolor="#f5f3ff", color="#6d28d9"];
     tcp [label="TCP servers", fillcolor="#ffffff"];
     udp [label="UDP servers", fillcolor="#ffffff"];
     h1 [label="HTTP/1.1 servers", fillcolor="#ffffff"];
     hx [label="TLS, HTTP/2 and\nHTTP/3 servers", fillcolor="#ffffff"];

     worker -> relay [label="tcp"];
     relay -> tcp;
     worker -> udp [label="udp"];
     worker -> tls [label="http + tls"];
     worker -> fw [label="http"];
     tls -> fw;
     fw -> route [label="admitted"];
     worker -> route [style=dashed, label="firewall: false"];
     route -> h1;
     route -> adapter;
     adapter -> hx;
   }

A first topology
~~~~~~~~~~~~~~~~

This module forwards one TCP port and one UDP port.

.. code-block:: text

   fn edge() -> Map<Value> {
       return {
           global: { max_flows: 8192 },
           frontends: {
               ssh: { proto: "tcp", binds: ["0.0.0.0:2222"], session_timeout: "1h" },
               dns: {
                   proto: "udp", binds: ["192.0.2.10:53"], session_timeout: "10s",
                   udp_defense: { mode: "rate_limit", threshold_pps: 200 },
               },
           },
           backends: {
               forge_ssh: { mode: "tcp", servers: [
                   { name: "a", addr: "10.20.0.8:22", weight: 2, max_flows: 100 },
                   { name: "b", addr: "10.20.0.9:22", weight: 1, max_flows: 50 },
               ] },
               nameservers: {
                   mode: "udp", balance: { kind: "bounded_maglev" },
                   servers: ["10.20.0.53:53"],
               },
           },
       }
   }

We save it as ``edge.jlv``, check it and start the listeners.

.. code-block:: sh

   sibuna check -f edge.jlv
   sibuna --config-file edge.jlv

The document that ``edge`` returns is the configuration. The same document written as JSON in a file that ends in ``.json`` is accepted too, and the JSON examples of this chapter show that form. A JSON object is also a JLV map, so each of them becomes a module when we put it after ``return``. We teach JLV, because a module can name a value once and generate the rest. The section *Writing the topology in JLV* shows how.

A failure to start is explained. The diagnostic has a title, the cause and a hint, and carries the code ``EDGE001``. An address in use, a port that needs a capability, a certificate that cannot be read, a missing file and an invalid key each have their own.

.. code-block:: text

   -- ADDRESS IN USE (EDGE001) ------------------------------------------------

   listener Http 0.0.0.0:8080: Address already in use (os error 98).

   Hint: Another process listens on this address. Find it with `ss -ltnp`, stop it, or change `binds`.

The checker rejects unknown keys, duplicate server identities, missing backends and invalid routes. It also loads every certificate and CA file. Startup binds every listener before it announces readiness. A UDP frontend binds a specific local IP, so replies leave from the address the client contacted. Durations are whole numbers with ``ms``, ``s``, ``m`` or ``h``, up to one day.

Global limits
~~~~~~~~~~~~~

.. list-table:: The ``global`` object
   :header-rows: 1
   :widths: 22 16 62

   * - Key
     - Default
     - Meaning
   * - ``max_flows``
     - ``8192``
     - Client connections and UDP mappings on the node, 1 to 1,000,000. Pending handshakes and TCP connects count. A full table refuses new flows.
   * - ``max_udp_flows``
     - half or all
     - The share of the table that UDP mappings may take. The default is half of ``max_flows`` beside TCP or HTTP frontends, and all of it on a UDP-only node.
   * - ``workers``
     - ``"auto"``
     - Relay threads for established TCP streams, 1 to 64. ``"auto"`` is one per CPU, up to eight.
   * - ``admin_socket``
     - none
     - The path of the admin socket for ``sibuna ctl``, at most 86 bytes. Without the key no socket is opened. Changing it takes a restart.
   * - ``watch``
     - none
     - Look at the file at this interval, ``1s`` to ``1h``, and reload it when it changed.
   * - ``shutdown_timeout``
     - ``"5s"``
     - How long a shutdown waits for established flows before it closes them, up to ``1h``. A reload may change it.
   * - ``reuse_port``
     - ``false``
     - Listeners share their address with other Sibuna processes of the same user, so a new process can start before the old one stops. Linux only. Changing it takes a restart.

One worker thread accepts connections, inspects handshakes and owns the UDP mappings. Established TCP streams move to the relay threads. On Linux every thread waits with epoll, so an idle flow costs no CPU time. We budget two file descriptors for each TCP stream and one for each UDP mapping. The operating system must allow the daemon that many descriptors (``LimitNOFILE`` under systemd).

UDP sources are not validated, so a flood of spoofed addresses could fill the table. The separate UDP ceiling keeps TCP and HTTP clients admitted. When the UDP share is full, a new client replaces the oldest mapping that no server has answered.

TLS certificates
~~~~~~~~~~~~~~~~

An HTTP frontend terminates TLS when it has a ``tls`` object. The ``crt`` key works as it does in HAProxy. Each entry is a PEM file that holds the certificate chain, leaf first, followed by its private key. An entry may also be a directory. We then load every ``*.pem`` file in it, in name order.

.. code-block:: json

   {
     "frontends": {
       "web": {
         "proto": "http", "binds": ["0.0.0.0:443"],
         "tls": {"crt": ["/etc/sibuna/certs/forge.example.org.pem", "/etc/sibuna/certs/"],
                 "http3": true},
         "default_backend": "site"
       }
     },
     "backends": {"site": {"mode": "http", "servers": [{"name": "s1", "addr": "10.20.0.8:8040"}]}}
   }

We can use the file that HAProxy uses, or build one from separate files.

.. code-block:: sh

   cat fullchain.pem privkey.pem > /etc/sibuna/certs/forge.example.org.pem
   chmod 600 /etc/sibuna/certs/forge.example.org.pem

The first certificate loaded is the default. The DNS names in each leaf certificate select among the others by the server name of the handshake. An exact name wins over a wildcard such as ``*.example.org``. A handshake that names no certificate receives the default one. With ``"strict_sni": true`` it is refused instead. We may still give ``cert_file`` and ``key_file`` as two separate files. Each file is limited to 256 KiB and a listener to 256 certificates. A key that does not match its certificate fails the check, and the message names the file.

A TLS listener offers ``h2`` and ``http/1.1`` by ALPN. HTTP/1.1 over TLS behaves like the plain listener: keep-alive and WebSocket upgrades work. With ``"http3": true`` we also bind the same port on UDP, and HTTP/2 responses advertise it with Alt-Svc. We can test the three protocols with ``curl --http1.1``, ``curl --http2`` and ``curl --http3-only``. Challenge cookies issued over TLS carry the Secure attribute.

A ``tls`` object takes three more members, all optional.

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Member
     - Default
     - Meaning
   * - ``min_version``
     - ``"1.2"``
     - The lowest TLS version offered. ``"1.3"`` refuses TLS 1.2 clients. HTTP/3 always uses TLS 1.3.
   * - ``client_ca``
     - none
     - A PEM file of CA certificates. A client must then present a certificate that one of them signed.
   * - ``client_auth``
     - ``"required"``
     - With ``client_ca``: ``"optional"`` also admits a client that presents no certificate. A certificate that is presented must still verify.

The cipher suites are those of the TLS library, all with forward secrecy and authenticated encryption, and are not configurable.

When a client presents a certificate that verifies, the servers receive its identity in the request field ``X-Client-Cert-SHA256``: the SHA-256 digest of the certificate, in 64 lower-case hexadecimal digits. This is the value that ``openssl x509 -in client.pem -outform DER | sha256sum`` prints. A server keeps a list of the digests it accepts, or maps each digest to an account. Sibuna removes every field of that name from the request of a client, also when it is spelled with ``_``, so a server may trust the field as Sibuna's statement. A request without the field came from a client without a certificate. We do not pass the certificate itself or its subject name yet.

To staple an OCSP response we put it as a DER file beside the certificate, with ``.ocsp`` added to the certificate's file name, as HAProxy does. We do not fetch or check the response: the tool that renews the certificate refreshes the file and sends SIGHUP.

The next section lets Sibuna obtain and renew certificates itself. An external ACME client such as certbot or acme.sh also fits. Its deploy hook writes the combined PEM file into the ``crt`` directory and sends SIGHUP. For the HTTP-01 challenge we route ``/.well-known/acme-challenge/`` to the client's own listener with ``"firewall": false``.

To rotate a certificate we replace the file and send SIGHUP. A new handshake uses the new certificate. An established session keeps the one it started with. A reload with a bad file changes nothing.

Automatic HTTPS
~~~~~~~~~~~~~~~

We need no certificate file for a public name. We list the name under ``auto`` and Sibuna obtains its certificate from Let's Encrypt, serves it, and renews it. This is the whole file for two names.

.. code-block:: text

   fn edge() -> Map<Value> {
       return {
           frontends: {
               web: { binds: ["0.0.0.0:443"], tls: { auto: ["example.org", "www.example.org"] } },
               plain: { binds: ["0.0.0.0:80"] },
           },
           backends: { app: { servers: ["10.0.0.1:80", "10.0.0.2:80"] } },
       }
   }

One command does the same without a file. It listens on port 443 and on port 80.

.. code-block:: sh

   sibuna lb --tls auto --domain example.org --domain www.example.org --server 10.0.0.1:80

The certificate authority speaks the ACME protocol (RFC 8555). It checks that we control each name, and it does so by connecting to us.

.. code-block:: text

   certificate authority                         Sibuna
        |  <----------- order for example.org ----  |   thread edge-acme
        |  ---- GET http://example.org/.well-known/acme-challenge/TOKEN --->  port 80
        |  <----------- TOKEN.THUMBPRINT ---------  |   answered before the firewall
        |  ------------ certificate ------------->  |   stored, then served on port 443

So three things must hold before the first start.

- Each name has a public DNS record that points at this host.
- Port 80 or port 443 of the host is reachable from the Internet. Port 80 serves the HTTP-01 challenge and port 443 serves the TLS-ALPN-01 challenge. One of the two is enough.
- The daemon's user can write the storage directory.

The work happens on a thread of its own. A listener never waits for the authority, and a failure never stops a listener. Until the first certificate arrives, a handshake for the name receives the default certificate of the listener, or fails when the listener has none. A new certificate serves the next handshake. We send no SIGHUP and restart nothing.

Every option has a default. We change one in ``global.acme``.

.. code-block:: text

   global: { acme: { directory: "letsencrypt-staging", email: "ops@example.org" } },

.. list-table:: Members of ``global.acme``
   :header-rows: 1
   :widths: 16 26 58

   * - Member
     - Default
     - Meaning
   * - ``directory``
     - ``"letsencrypt"``
     - The authority: ``"letsencrypt"``, ``"letsencrypt-staging"``, or the ``https`` URL of another ACME directory.
   * - ``email``
     - none
     - The contact address of the account. The authority may write to it before a certificate expires.
   * - ``storage``
     - ``"/var/lib/sibuna/acme"``
     - The directory of the account key, the certificates and their keys.
   * - ``challenge``
     - ``"auto"``
     - ``"http-01"``, ``"tls-alpn-01"``, or ``"auto"``. ``"auto"`` starts with HTTP-01 when the file has a plain HTTP frontend and with TLS-ALPN-01 otherwise. After a failed attempt it takes the other one.
   * - ``ca_file``
     - the system trust store
     - PEM roots for the connection to the authority. A private authority needs it.
   * - ``redirect``
     - ``true``
     - Redirect plain HTTP requests for the ``auto`` names to HTTPS.

By using an authority we accept its terms of service, as with any ACME client.

**The redirect.** A plain HTTP request whose ``Host`` is an ``auto`` name receives ``308 Permanent Redirect`` to ``https://`` with the same host, path and query. The port of the TLS frontend is added when it is not 443. Requests for other hosts are served as before. The challenge answer and the redirect are written before any firewall decision, so a ban or a challenge page cannot keep the authority out. Both appear in the access log like any other answer. ``redirect: false`` turns the redirect off. The challenge is still answered.

**Storage.** The directory holds one subdirectory per authority. Keys have mode 0600 and directories mode 0700.

.. code-block:: text

   /var/lib/sibuna/acme/
     acme-v02.api.letsencrypt.org-directory/
       account.key
       certs/example.org/cert.pem      the chain, leaf first
       certs/example.org/key.pem
       certs/example.org/retry         the failure count and the next attempt
       locks/example.org.lock

A restart loads the stored certificates and orders nothing while they are fresh. The packaged unit ``sibuna-edge.service`` creates ``/var/lib/sibuna`` for the service account. Several nodes may share the directory. The node that orders a name holds its lock file, and the others wait and then load the result. Every node answers the HTTP-01 challenge of every other node, because the answer depends only on the token and on the shared account key. With TLS-ALPN-01 the authority must reach the node that placed the order.

**Renewal and retry.** We renew a certificate when two thirds of its lifetime have passed. For a certificate of 90 days that is 30 days before it expires. After a failure we try again after 2 minutes, then 4, then 8, and so on, up to once a day. When the authority names a waiting time we wait at least that long. The delay survives a restart. The old certificate serves in the meantime. One order runs at a time, with a second between two orders, and the daemon places no order before its listeners serve.

**Staging first.** Let's Encrypt limits the certificates per name and week. While we test a setup we use ``directory: "letsencrypt-staging"``. Its certificates are not trusted by browsers and its limits are generous. We remove the line when the setup works. The production certificates are then ordered at once, because each authority has its own subdirectory.

**Names that are not public.** A public authority cannot validate ``localhost``, a name without a dot, or a name under ``.local``, ``.internal``, ``.lan``, ``.test``, ``.example`` and the like. With one of the two Let's Encrypt directories the check of the file refuses such a name and says so. We then serve the name with ``crt`` and a certificate of our own, or we name an authority of our own in ``directory``. An IP address and a wildcard name are refused under ``auto`` with every directory.

**Looking at the state.** The admin socket lists the certificates.

.. code-block:: sh

   sibuna ctl /run/sibuna/edge.sock show certs

.. code-block:: text

   name            issuer expires              renews               state error
   example.org     R11    2027-02-22T10:00:00Z 2027-01-23T10:00:00Z ready -
   www.example.org -      -                    2026-11-24T10:04:00Z retry VALIDATION FAILED (ACME005)

``state`` is ``pending`` before the first attempt, ``ordering`` during an order, ``waiting`` while another node holds the lock, ``retry`` after a failure, and ``ready`` otherwise. ``renews`` is the time of the next order. ``show stats`` and the metrics endpoint add four series: ``sibuna_edge_acme_certificates_managed``, ``sibuna_edge_acme_certificates_served``, ``sibuna_edge_acme_nearest_expiry_seconds`` and ``sibuna_edge_acme_failures_total``. An alert on the third one tells us when renewal has been failing for too long.

**Troubleshooting.** Each failure is written to standard error with a code, the reason of the authority and a hint.

.. code-block:: text

   -- VALIDATION FAILED (ACME005) ----------------------------------------------

   No new certificate for `www.example.org`. The authority could not validate the name with http-01: 203.0.113.9: Connection refused. The listeners keep serving. Next attempt at 2026-11-24T10:04:00Z.

   Hint: Point the DNS record of the name at this node, and let the authority reach port 80 (HTTP-01) or port 443 (TLS-ALPN-01) from the Internet.

.. list-table:: Failures of automatic HTTPS
   :header-rows: 1
   :widths: 14 30 56

   * - Code
     - Title
     - What to check
   * - ``ACME001``
     - storage not writable
     - The daemon's user must own ``global.acme.storage`` and be able to write it.
   * - ``ACME002``
     - authority unreachable
     - Outbound HTTPS to the directory, DNS on this host, and ``ca_file`` for a private authority.
   * - ``ACME003``
     - authority refused
     - The reason that the authority gave. It may refuse the name or the account.
   * - ``ACME004``
     - rate limited
     - Nothing. We wait as long as the authority asks. Use the staging directory for tests.
   * - ``ACME005``
     - validation failed
     - The DNS record of the name, and port 80 or 443 from the Internet to this host.
   * - ``ACME006``
     - unexpected answer
     - The directory URL. The authority answered outside the protocol or beyond our bounds.
   * - ``ACME008``
     - certificate rejected
     - The clock of this node. The certificate does not name the host, has expired, or does not fit the key.

A reload may add and remove ``auto`` names. A new name is ordered at once, and a removed name is no longer renewed or served. Changing ``global.acme``, or adding the first ``auto`` name to a daemon that has none, needs a restart. A certificate from ``crt`` and ``auto`` names may share a listener. For a name that both cover, the automatic certificate serves once it exists.

Sibuna has no authority of its own for internal names, issues no certificate at the first handshake of an unknown name, and does not solve the DNS-01 challenge, so it obtains no wildcard certificates. For these cases we keep using ``crt``.

HTTP routing by name and path
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An HTTP frontend selects a backend for each request, also for later requests on one keep-alive connection and for each stream of an HTTP/2 or HTTP/3 connection. The first matching route wins. A route gives a ``host``, a ``path_prefix``, or both. We compare host names without case or port and match a prefix of the normalized path that ends at a segment boundary: ``/public`` covers ``/public`` and ``/public/x``, and not ``/public-admin``. A prefix that ends in ``/`` is matched as written. Requests that match no route use ``default_backend``.

.. code-block:: json

   {
     "http": {"surface": "shield", "policy_file": "/etc/sibuna/policy.json",
              "idle_timeout": "1h", "websocket_idle_timeout": "1h"},
     "frontends": {
       "web": {
         "proto": "http", "binds": ["0.0.0.0:443"],
         "tls": {"crt": "/etc/sibuna/certs/"},
         "routes": [
           {"host": "forge.example.org", "backend": "forge", "firewall": false},
           {"host": "ci.example.org", "path_prefix": "/api/runner/", "backend": "ci", "firewall": false},
           {"host": "ci.example.org", "backend": "ci"}
         ],
         "default_backend": "site"
       }
     },
     "backends": {
       "forge": {"mode": "http", "health_check": {"kind": "http", "path": "/api/v1/health"},
                 "servers": [{"name": "f1", "addr": "10.20.0.8:8040"}, {"name": "f2", "addr": "10.20.0.9:8040"}]},
       "ci": {"mode": "http", "servers": [{"name": "c1", "addr": "10.20.0.10:8050"}]},
       "site": {"mode": "http", "servers": [{"name": "s1", "addr": "10.20.0.11:3000"}]}
     }
   }

Sibuna keeps the client's ``Host`` field and sets ``X-Forwarded-For``, ``X-Forwarded-Proto`` and ``X-Real-IP`` from the connection it terminated. It also sets ``X-Forwarded-Host`` to the ``Host`` of the request and ``X-Forwarded-Port`` to the port of the listener. A client cannot supply these fields. An application that reads ``X-Forwarded-For`` must list the Sibuna node as a trusted proxy.

Turning the firewall on and off
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A browser can solve a proof-of-work challenge. Git, curl, a CI runner and an API client cannot. We therefore choose where the firewall applies.

- ``"http": {"surface": "off"}`` makes the node a plain load balancer. Every well-formed request is routed. There is no challenge, no policy file and no default rate limit.
- ``"surface": "gate"`` or ``"shield"`` (the default) enables the firewall. A frontend then takes ``"firewall": false`` to exempt its requests, and each route takes ``"firewall": true`` or ``false`` to decide for its name or path. A route without the key follows its frontend.

A request on a route without the firewall skips the policy, the challenge and the semantic inspection. Sibuna still parses and validates the request, enforces the connection limits and timeouts, honours existing bans, and applies ``http.rate_limit`` when we set a number. The audit fields report the rule ``load-balancer`` for it.

Rate limiting
~~~~~~~~~~~~~

Each protocol has its own limiter. All of them count per source IPv4 address or IPv6 /64.

.. list-table:: Where rates are limited
   :header-rows: 1
   :widths: 30 34 36

   * - Setting
     - Applies to
     - Effect
   * - ``rate_limit: {"conn_per_10s": 200}`` on a ``tcp`` or ``http`` frontend
     - New connections, also QUIC connections on that address
     - Further connections are closed until the rate falls.
   * - ``udp_defense: {"mode": "rate_limit", "threshold_pps": 200}`` on a ``udp`` frontend
     - Datagrams per second
     - Further datagrams are dropped.
   * - ``http.rate_limit`` and ``http.rate_window``
     - Requests per window on every HTTP frontend
     - 429 with Retry-After. The default is 100 per 10 s. ``"off"`` disables it.
   * - A ``rate`` in a policy rule
     - Requests that match the rule
     - 429, and a ban when the rule asks for one. Only routes with the firewall evaluate it.
   * - ``http.max_connections_per_ip``
     - Concurrent connections of one client
     - Further connections are refused. The default is 64.

A UDP mapping may also send at most three times the bytes it received, with a bounded burst, so a spoofed source cannot use a server as an amplifier.

The ``http`` object
~~~~~~~~~~~~~~~~~~~

.. list-table:: HTTP firewall settings in edge mode
   :header-rows: 1
   :widths: 30 16 54

   * - Key
     - Default
     - Meaning
   * - ``surface``
     - ``shield``
     - ``off``, ``gate`` or ``shield``
   * - ``policy_file``
     - unset
     - A Sibuna policy. It needs ``gate`` or ``shield``.
   * - ``secret_file``
     - unset
     - The challenge seed shared by the nodes of a cluster
   * - ``rate_limit``
     - ``100``
     - Requests per window and client, 1 to 1,000,000, or ``"off"``. With ``surface`` ``off`` the default is ``"off"``.
   * - ``rate_window``
     - ``10s``
     - The length of the rate window
   * - ``max_connections``
     - ``1024``
     - Concurrent HTTP/1.1 connections and HTTP/2 or HTTP/3 exchanges, up to 1,000,000. Without the event-driven workers the bound is 8192.
   * - ``max_connections_per_ip``
     - ``64``
     - The same bound for one client address
   * - ``idle_timeout``
     - ``15s``
     - The longest silence on a connection or from a server. Raise it for long transfers.
   * - ``websocket_idle_timeout``
     - ``300s``
     - The longest silence on an upgraded connection
   * - ``event_loop``
     - ``true``
     - Serve HTTP on event-driven workers, one per processor (SID 0016). ``false`` serves each connection on a thread of its own. Platforms other than Linux always use threads.
   * - ``workers``
     - one per processor
     - The number of event-driven workers, from 1 to 64

A server that sends nothing within the timeout answers 504. A server that cannot be reached, or that fails inside an exchange, answers 502.

With the workers on, a request of an HTTP/2 or HTTP/3 client is decided on the thread that decoded it and goes to its server from there (SID 0017). The response head must arrive within the ``response_timeout`` of the pool, 60 s unless we set it, and the body must keep arriving. The same bounds and the same failover apply as for an HTTP/1.1 client: ``connect_timeout`` bounds the connection or the shared session to the server, and a request whose server cannot be reached moves to another server of the pool.

An idle HTTP/2 or HTTP/3 connection gives up its flow slot after ``idle_timeout``, and after 60 s at the earliest. HTTP/2 connections are also probed with PING every 20 s. An HTTP/2 client may open a WebSocket with extended CONNECT (RFC 8441), which Sibuna carries as an HTTP/1.1 upgrade. Other CONNECT tunnels are refused.

gRPC
~~~~

gRPC needs HTTP/2 from the client to the server, with trailers. We give it a TLS frontend and a backend with ``"http_version": "2"``. A request of an HTTP/2 or HTTP/3 client then reaches the HTTP/2 server on a shared session, with no HTTP/1.1 step between them. Unary, server-streaming, client-streaming and bidirectional calls all work, and all calls to one server share one connection.

.. code-block:: json

   {
     "http": {"surface": "shield", "rate_limit": "off"},
     "frontends": {
       "api": {
         "proto": "http", "binds": ["0.0.0.0:443"],
         "tls": {"crt": "/etc/sibuna/certs/"},
         "routes": [{"path_prefix": "/orders.Orders/", "backend": "orders", "firewall": false}],
         "default_backend": "site"
       }
     },
     "backends": {
       "orders": {"mode": "http", "http_version": "2",
                  "servers": [{"name": "o1", "addr": "10.20.0.31:50051"}]},
       "site": {"mode": "http", "servers": [{"name": "s1", "addr": "10.20.0.8:8040"}]}
     }
   }

Three settings matter for a gRPC service.

- A gRPC client cannot solve a browser challenge. We exempt the service with ``"firewall": false`` on its route, as above, or we allow its paths with a policy rule. The service then relies on its own authentication.
- The per-client request limiter counts every call, also on an exempt route. Its default of 100 requests per window is far too low for a service client. We raise ``rate_limit`` or turn it off.
- A stream on which the server is silent for the ``response_timeout`` of its pool is closed. The default is 60 s. Long-lived streams need application messages more often than that, or a pool of their own with a longer bound, such as ``response_timeout: "1h"``. The same member bounds the wait for the response head of a call.

The decision sees the request head and the message bytes that have arrived with it. It does not wait for more, because a call may wait for an answer before it sends its next message. gRPC over cleartext HTTP/2 from the client is not accepted: the frontend must terminate TLS. A server pool may speak cleartext HTTP/2 or HTTP/2 over TLS.

Servers that speak TLS, HTTP/2 or HTTP/3
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A backend speaks cleartext HTTP/1.1 unless we say otherwise. ``http_version`` selects ``"1.1"``, ``"2"`` or ``"3"``. A ``tls`` object makes the connection to the servers a TLS connection.

.. code-block:: json

   {
     "backends": {
       "api": {"mode": "http", "http_version": "2",
               "tls": {"ca_file": "/etc/sibuna/internal-ca.pem", "sni": "api.internal"},
               "servers": [{"name": "a1", "addr": "10.20.1.11:8443"}]},
       "media": {"mode": "http", "http_version": "3", "tls": {"sni": "media.internal"},
                 "servers": [{"name": "m1", "addr": "10.20.2.11:443"}]},
       "legacy": {"mode": "http", "tls": {"verify": false},
                  "servers": [{"name": "l1", "addr": "10.20.3.11:8443"}]},
       "grpcweb": {"mode": "http", "http_version": "2",
                   "servers": [{"name": "g1", "addr": "10.20.4.11:8080"}]}
     }
   }

.. list-table:: Server protocols
   :header-rows: 1
   :widths: 22 18 60

   * - ``http_version``
     - ``tls``
     - Connection to each server
   * - ``"1.1"`` (default)
     - absent
     - Cleartext HTTP/1.1 with keep-alive. No adapter is involved.
   * - ``"1.1"``
     - present
     - HTTP/1.1 inside TLS. WebSocket upgrades pass.
   * - ``"2"``
     - present
     - One HTTP/2 session per server, negotiated by ALPN. Each request is a stream.
   * - ``"2"``
     - absent
     - Cleartext HTTP/2 with prior knowledge (h2c)
   * - ``"3"``
     - required
     - One QUIC connection per server. Each request is a stream.

By default we verify the server certificate against the system roots, or against ``ca_file`` when it is set. The name checked is ``sni``, or the server's IP address without it. ``"verify": false`` accepts any certificate. We use it only on a network we trust.

The firewall always relays HTTP/1.1. For the other cases an adapter inside the daemon listens on a loopback port for each server and translates. HTTP/2 and HTTP/3 servers cannot receive an HTTP/1.1 upgrade, so a WebSocket request to them answers 501. A local process that connects to an adapter port reaches the server it could already reach directly.

Scheduling and health checks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A standalone pool defaults to weighted least connections. With ``"balance": {"kind": "round_robin"}`` each server takes its turn in proportion to its weight, whatever its open connections. With ``"p2c_pewma"`` we compare two eligible servers using their active flows, weights and observed latency. ``"bounded_maglev"`` hashes the client to a server and stays within a load factor. A server marked ``"backup": true`` becomes eligible when the primary servers are unavailable or full. ``max_flows`` on a server caps its concurrent flows. A failed connect suppresses that server for two seconds.

A TCP or HTTP pool can check its servers actively.

.. code-block:: json

   {"health_check": {"kind": "http", "path": "/healthz", "host": "ci.example.org",
                     "expect_status": 200, "timeout": "2s", "interval": "5s", "rise": 2, "fall": 3}}

``"kind": "tcp"`` passes when the connect completes. ``"kind": "http"`` sends ``GET`` and passes on a 2xx or 3xx status, or on ``expect_status`` alone. A server starts in service, as in HAProxy. It leaves after ``fall`` failed probes and returns after ``rise`` passed ones. A reload keeps the status of every address. Probes of a TLS, HTTP/2 or HTTP/3 pool travel through its adapter, so they test the same path as a request.

An HTTP pool also learns from live requests. This is *passive health*, and it is on by default. Three consecutive response timeouts eject a server for ten seconds. An ejected server takes no new request while another server of the pool can serve. If every server is ejected the pool uses them all, because a slow answer is better than none.

.. code-block:: text

   passive_health: { failures: 3, ejection: "10s", http_5xx: false }

``failures`` is the number of consecutive failures, from 1 to 100. ``ejection`` is how long the server stays out. With ``http_5xx: true`` a response with status 500, 502, 503 or 504 counts as a failure too. Any other complete response sets the count back to zero. ``passive_health: "off"`` keeps every server in rotation.

A server that returns after it was down or drained, or that a reload or ``add server`` adds to a pool, can start gently. With ``slow_start: "30s"`` its weight grows from almost nothing to its configured weight over thirty seconds. The default is off, as in HAProxy and nginx: only we know how long our application takes to warm up. Servers that start together with the edge do not ramp.

Timeouts and failover
~~~~~~~~~~~~~~~~~~~~~

Each HTTP pool bounds its own waits. The client has its bound, ``http.idle_timeout``, and the two do not replace each other.

.. list-table:: Timeouts of an HTTP pool
   :header-rows: 1
   :widths: 24 14 62

   * - Member
     - Default
     - Meaning
   * - ``connect_timeout``
     - ``"5s"``
     - The longest wait for a TCP connection to one server.
   * - ``response_timeout``
     - ``"60s"``
     - The longest silence of a server that owes us bytes: before the response head, and between two pieces of the body. The client then receives 504.
   * - ``retries``
     - ``2``
     - How many other servers one request may try, from 0 to 8.

.. code-block:: text

   backends: {
       reports: {
           mode: "http",
           connect_timeout: "2s",
           response_timeout: "5m",
           retries: 1,
           servers: [{ name: "r1", addr: "10.20.0.21:8080" }, { name: "r2", addr: "10.20.0.22:8080" }],
       },
   }

``response_timeout`` bounds silence, not the whole exchange. A download of an hour passes as long as the server keeps sending. A slow upload is the client's affair and stays under ``http.idle_timeout``.

When a server cannot be reached, the request moves to another server of the pool. The server received nothing, so this is safe for every method, also for ``POST``. After a byte of the request was sent, only a ``GET``, ``HEAD`` or ``OPTIONS`` request that fits the request buffer is sent again. A request never tries the same server twice, and never a drained one. ``retries: 0`` turns failover off, and the client then receives 502 at once.

A request that moved is one line of the access log and one request in the counters, under the server that answered it. Each server it left counts one in ``sibuna_edge_server_failures_total``. A redirect and a 413 of our own are logged without a server.

Sticky sessions
~~~~~~~~~~~~~~~

An application that keeps a session in the memory of one server needs every request of a client on that server. A pool offers two ways.

.. code-block:: text

   sticky: "cookie"
   sticky: { kind: "cookie", cookie: "srv" }
   sticky: "source"

With ``"cookie"`` the first response to a client carries a cookie, ``sibuna_srv`` unless we name it. The cookie is ``HttpOnly`` and ``SameSite=Lax``, and ``Secure`` on a frontend with TLS. Its value is a keyed hash, not the name of the server, so a client cannot aim at a server of its choice. The key comes from ``http.secret_file``. Nodes that share the file accept each other's cookies. Without the file the key is new at each start, and the clients are balanced once more.

With ``"source"`` the client address selects the server, without its port. No cookie is set, so this also serves clients that keep no cookies and TCP or UDP pools. When a server leaves, only its clients move, and they return when it returns. All clients behind one NAT address share a server.

In both cases a sticky server that is down, full, ejected or drained gives way: the request is balanced as usual, and with a cookie the client receives the cookie of the server that answered. While a server is drained, each of its ``"source"`` clients has one other server and returns when the drain ends.

Behind ``trusted_proxies`` the client address of ``"source"`` is the one the proxy recorded, as for the access log and the limits. Without that option it is the socket peer, so all requests of one proxy would share a server.

Redirects, headers and body limits
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A frontend carries a small HTTP policy. Each route can state its own, and a route keeps every member that it does not state.

.. list-table:: Policy members of a frontend or route
   :header-rows: 1
   :widths: 24 14 62

   * - Member
     - Default
     - Meaning
   * - ``redirect_https``
     - ``false``
     - ``true`` answers every cleartext request with 308 and the same host, path and query under ``https://``. ``301`` uses that status. ``{status: 308, port: 8443}`` names another port. Only on a frontend without ``tls``.
   * - ``hsts``
     - ``false``
     - ``true`` adds ``Strict-Transport-Security: max-age=31536000`` to the responses of the servers. ``{max_age: 600, include_subdomains: true, preload: false}`` sets the parts. Only on a frontend with ``tls``.
   * - ``request_headers``
     - none
     - ``{set: {...}, remove: [...]}`` for the request that goes to the server.
   * - ``response_headers``
     - none
     - The same for the response that goes to the client.
   * - ``max_body``
     - none
     - The largest request body: a number of bytes, or ``"64k"``, ``"10m"``, ``"1g"``. A larger request receives 413. ``"off"`` on a route lifts the limit of its frontend.

.. code-block:: text

   fn security() -> Map<Value> {
       return {
           set: { "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff" },
           remove: ["Server", "X-Powered-By"],
       }
   }

   fn edge() -> Map<Value> {
       return {
           frontends: {
               plain: {
                   proto: "http",
                   binds: ["0.0.0.0:80"],
                   default_backend: "app",
                   redirect_https: true,
                   routes: [{ path_prefix: "/.well-known/acme-challenge/", backend: "app",
                              redirect_https: false }],
               },
               web: {
                   proto: "http",
                   binds: ["0.0.0.0:443"],
                   tls: { crt: "/etc/sibuna/certs/" },
                   default_backend: "app",
                   hsts: { max_age: 31536000, include_subdomains: true },
                   max_body: "10m",
                   response_headers: security(),
                   request_headers: { set: { "X-Edge": "sibuna" } },
                   routes: [{ path_prefix: "/upload/", backend: "app", max_body: "1g" }],
               },
           },
           backends: {
               app: {
                   mode: "http",
                   sticky: "cookie",
                   balance: { kind: "round_robin" },
                   servers: [{ name: "a1", addr: "10.20.0.8:8080" }, { name: "a2", addr: "10.20.0.9:8080" }],
               },
           },
       }
   }

The redirect is decided before the firewall, so a cleartext request is never challenged first. The route for ``/.well-known/acme-challenge/`` above keeps certificate validation over port 80 working.

``set`` replaces a field: every field of that name is dropped and ours is added. ``remove`` drops a field. A value is fixed text of at most 1024 printable characters. The checker refuses the names that frame a message, such as ``Host``, ``Content-Length`` and ``Connection``, and on requests the forwarding fields that Sibuna writes itself. A request field that we set or remove is also dropped when the client spells it with ``_`` for ``-``.

The edits apply to exchanges with a server. Sibuna's own pages, such as a challenge or a 502, do not carry them.

In JSON the members have the same names: ``"redirect_https": true``, ``"max_body": "10m"``, ``"sticky": {"kind": "cookie", "cookie": "srv"}``.

WebSockets
~~~~~~~~~~

A WebSocket begins as an HTTP request, and Sibuna judges that request like any other: bans, limits, the policy and the semantic firewall apply to the handshake. The offer must be a well-formed version 13 handshake, and the server's 101 must carry the matching accept key. ``Sec-WebSocket-Protocol`` and ``Sec-WebSocket-Extensions`` pass unchanged, so subprotocols and compression are negotiated end to end. After the 101 Sibuna relays bytes and does not parse frames. A tunnel costs a record and two sockets, not a thread.

A frontend or a route may carry a ``websocket`` object. A route without one keeps the rule of its frontend.

.. code-block:: json

   {"routes": [{"path_prefix": "/api/live", "backend": "app",
                "websocket": {"origins": ["https://app.example.org"], "max_per_ip": 16}}]}

.. list-table:: WebSocket rule
   :header-rows: 1
   :widths: 20 80

   * - Key
     - Meaning
   * - ``origins``
     - The origins that may open a tunnel, each a scheme, a host and an optional port. An upgrade whose ``Origin`` field is absent or not listed answers 403. A browser sends a site's cookies with a handshake from any page, so an application that authenticates by cookie needs this check.
   * - ``max_per_ip``
     - The most concurrent tunnels of one client address under this rule. A client over it answers 429. A reload starts the count again for new tunnels.

Both checks apply whether or not the route uses the firewall. A browser cannot solve a challenge inside a WebSocket handshake. If a policy challenges the page, the page's session cookie admits the handshake. For a client that is not a browser we allow the tunnel's path in the policy.

Three timers matter. ``websocket_idle_timeout`` closes a tunnel on which neither side sent a byte for that long, so we set it above the application's ping interval. ``idle_timeout`` bounds the handshake. A shutdown closes tunnels after the drain period of five seconds, and Sibuna sends no close frame, because it does not speak the framing. Clients must reconnect, as they must after any network fault.

A tunnel stays on the server that accepted it. An application that keeps its live state in one process, such as a hub of connected clients, therefore needs a pool with one server, or a broker behind its servers.

TCP inspection and PROXY v2
~~~~~~~~~~~~~~~~~~~~~~~~~~~

A frontend may set ``"tcp_inspect": "tls_client_hello"``, define ``acls`` with exact ``sni`` or ``alpn`` matches or a ``ja4_prefix`` pattern such as ``t13d*``, and list ordered ``deny`` or ``use_backend`` rules. The worker closes malformed or incomplete handshakes after a bounded inspection of up to 32 KiB and a default deadline of two seconds. A complete hello with no matching rule uses the default pool. Enable ``"proxy_v2": {"enabled": true}`` on a TCP pool only when its servers accept a PROXY v2 address header before the stream. We can add ``"tlv_sni": true`` or ``"tlv_ja4": true`` inside ``proxy_v2`` to forward inspected metadata. SNI uses the AUTHORITY type (0x02). Sibuna uses the custom type 0xe0 for the 36 ASCII bytes of JA4. The origin must agree on this type.

Observing the edge
~~~~~~~~~~~~~~~~~~

An edge writes an access log, counts each request per frontend and per server, and answers a readiness probe. SID 0020 specifies all of it. We describe the file in JLV here. The JSON file has the same members.

.. code-block:: text

   fn edge() -> Map<Value> {
       return {
           observability: {
               access_log: { output: "/var/log/sibuna/access.log", queue: 8192 },
               internal_allow: ["127.0.0.0/8", "::1/128", "10.20.0.0/24"],
               listen: "10.20.0.5:9100",
           },
           frontends: {
               web: {
                   proto: "http",
                   binds: ["0.0.0.0:80"],
                   trusted_proxies: ["198.51.100.0/24"],
                   default_backend: "site",
               },
           },
           backends: {
               site: { mode: "http", servers: [{ name: "s1", addr: "10.20.0.11:3000" }] },
           },
       }
   }

.. list-table:: The ``observability`` object and the two frontend options
   :header-rows: 1
   :widths: 30 20 50

   * - Member
     - Default
     - Meaning
   * - ``access_log.output``
     - no log
     - A file path, ``"stdout"`` or ``"stderr"``. The file is created with mode 0640 and appended to.
   * - ``access_log.format``
     - ``"json"``
     - The only format: one JSON object per line.
   * - ``access_log.queue``
     - 8192
     - Entries that may wait for the writer, from 64 to 1048576.
   * - ``internal_allow``
     - ``["127.0.0.0/8", "::1/128"]``
     - The networks that may read ``/__sibuna/health``, ``/__sibuna/ready`` and ``/__sibuna/metrics`` on the HTTP frontends. At most 64. An empty list closes the three routes.
   * - ``listen``
     - none
     - An address of a separate listener for ``/health``, ``/ready`` and ``/metrics``.
   * - ``trusted_proxies`` on an ``http`` frontend
     - ``[]``
     - The networks of the proxies in front of this frontend. At most 64.
   * - ``proxy_protocol`` on an ``http`` frontend
     - ``false``
     - Every connection must begin with a PROXY header, version 1 or 2. Needs ``trusted_proxies``.

**The access log.** Each HTTP request writes one line when its response ends. The members are always these, in this order:

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Member
     - Value
   * - ``time``
     - When the request was dispatched, in UTC with milliseconds.
   * - ``client``
     - The address the request was judged by.
   * - ``frontend``
     - The name of the frontend, or ``-``.
   * - ``protocol``
     - ``http/1.1``, ``https``, ``h2`` or ``h3``.
   * - ``method``, ``host``, ``path``
     - As sent. The path is in normal form and has no query. A request that did not parse has ``-``.
   * - ``status``
     - The status sent to the client. 0 when the client left before a response.
   * - ``bytes_in``, ``bytes_out``
     - Request and response bytes. ``bytes_in`` is an estimate.
   * - ``duration_ms``
     - From the dispatch to the end of the response.
   * - ``ttfb_ms``
     - The wait for the first byte of the server, or ``null`` when no server answered.
   * - ``backend``, ``server``
     - The pool and the server the request was sent to, or ``-``.
   * - ``verdict``
     - ``pass``, ``deny``, ``challenge``, ``rate_limited``, ``banned``, ``internal`` or ``-``.

.. code-block:: json

   {"time":"2026-11-24T10:15:02.418Z","client":"203.0.113.7","frontend":"web","protocol":"http/1.1","method":"GET","host":"www.example.com","path":"/index.html","status":200,"bytes_in":112,"bytes_out":5310,"duration_ms":3.184,"ttfb_ms":2.907,"backend":"app","server":"app-2","verdict":"pass"}

A worker never waits for the log. It puts the entry in a bounded queue, and one thread formats and writes. When the queue is full the entry is dropped and ``sibuna_edge_access_log_dropped_total`` counts it. To rotate the file we rename it and send SIGHUP. Sibuna opens the path again within about a second. TCP and UDP flows are counted and not logged.

**Metrics.** The metrics text has the process counters and then the series of the edge: requests by status class, bytes and a duration histogram per frontend; requests, failures, a response time histogram and ``sibuna_edge_server_up`` per server; the flow table (``sibuna_edge_flows_active``, ``sibuna_edge_flows_limit``, ``sibuna_edge_drops_total``); and the counters of the log and of the PROXY protocol. Counters follow a name across a reload.

**Readiness.** ``/__sibuna/ready`` answers 200 with ``{"status":"ready"}``. From the start of a shutdown it answers 503 with ``{"status":"draining"}``. ``/__sibuna/health`` only says that the process runs. We point a load balancer in front of Sibuna at the readiness answer.

**Who may read them.** On an HTTP frontend the three routes answer only a client inside ``internal_allow`` whose request carries no ``X-Forwarded-For``, ``X-Real-IP`` or ``Forwarded`` field. Everyone else receives the 404 of an unknown route. The default is the loopback network, so a probe from another host needs its network in the list, or the separate listener. The listener at ``listen`` applies no list of its own. Its address is its access control, so we bind it to a management network.

**Clients behind a proxy.** Without ``trusted_proxies`` the client is the socket peer and ``X-Forwarded-For`` is ignored. With it, a request whose socket peer is inside the list is judged by the address its proxy recorded: we walk ``X-Forwarded-For`` from the right and take the first address that is not a trusted proxy. An entry the client wrote itself stands to the left of that address and is never read. The address is the client for bans, the request limiter, policy rules and the log. With ``proxy_protocol: true`` the frontend takes the client from the PROXY header instead. A connection from outside ``trusted_proxies``, or without a whole valid header in its first packet, is closed.

**The descriptor limit.** At startup Sibuna compares the limit on open files with what the topology can use: two per flow, two per HTTP connection, and 512. It raises the soft limit as far as the hard limit allows. When that is not enough it prints a warning with the numbers and a hint, and starts anyway:

.. code-block:: text

   -- DESCRIPTOR LIMIT TOO LOW ------------------------------------ edge.jlv

   This topology can use 18944 file descriptors, but the process may open 4096.

   global.max_flows = 8192, http.max_connections = 1024
   need = 2 * 8192 + 2 * 1024 + 512 = 18944

   Hint: Raise the limit (`LimitNOFILE=18944` in the systemd unit, or `ulimit -n 18944`),
   or lower `global.max_flows` and `http.max_connections`.

Writing the topology in JLV
~~~~~~~~~~~~~~~~~~~~~~~~~~~

JLV is the configuration language of jlavideploy and jlavici. A file that ends in ``.jlv`` is a JLV/2 module with a function ``edge`` that returns the same document as the JSON file. We write a pool once and generate its servers.

.. code-block:: text

   import { text } from jlv.std.foundation

   fn server(i: Int) -> Map<Value> {
       return { name: "forge-${i}", addr: "10.20.0.${i}:8040" }
   }

   fn web(name: Text, pool: Text, guarded: Bool) -> Map<Value> {
       return { host: name, backend: pool, firewall: guarded }
   }

   fn edge() -> Map<Value> {
       return {
           http: { surface: "shield", idle_timeout: "1h" },
           frontends: {
               web: {
                   proto: "http",
                   binds: ["0.0.0.0:443"],
                   tls: { crt: "/etc/sibuna/certs/" },
                   routes: [web("forge.example.org", "forge", false)],
                   default_backend: "site",
               },
           },
           backends: {
               forge: {
                   mode: text.lower("HTTP"),
                   health_check: { kind: "http", path: "/api/v1/health" },
                   servers: [for i in [8, 9]: server(i)],
               },
               site: { mode: "http", servers: [{ name: "s1", addr: "10.20.0.11:3000" }] },
           },
       }
   }

We check the module with ``sibuna check -f edge.jlv`` and run it with ``sibuna --config-file edge.jlv``. Sibuna compiles and evaluates the module at startup and at each reload, off the packet path. An error names the line and column. The pure ``jlv.std.foundation`` functions are available. One module is evaluated. It cannot import other files, read the environment or perform I/O. The source and the expanded document each have a 256 KiB limit, and evaluation has one million steps. Both formats pass through the same topology checks. A build without the ``jlv`` feature accepts JSON only.

Reload, drain and shutdown
~~~~~~~~~~~~~~~~~~~~~~~~~~

On Unix we replace the file and send SIGHUP. Sibuna prepares the whole revision first: the topology, the policy, the certificates and the server adapters. A valid revision updates routing for new flows. Established TCP streams, UDP mappings and running HTTP exchanges keep their server. A handshake still awaiting inspection is closed at the policy boundary. A rejected revision leaves the serving one untouched, and the log line ``EDGE002`` says why. To take one server out of rotation we drain it through the admin socket, as the next section shows. Changing listener addresses, the HTTP surface, the firewall limits, the ``observability`` object, the challenge seed or the mesh roster takes a restart. The frontend options ``trusted_proxies`` and ``proxy_protocol`` follow a reload. SIGHUP also reopens the access log. Shutdown stops admitting new flows, sends GOAWAY on HTTP/2 and HTTP/3, and gives active flows the time of ``global.shutdown_timeout`` to finish, five seconds by default. The last log line counts the flows that were closed by force.

A reload fails no request. The firewall decides a request under one policy and selects its server a moment later. When a reload falls between the two, the request is routed by the revision it was decided under. The daemon keeps the replaced revision for ten seconds for this purpose.

With ``global.watch`` the daemon reloads the file by itself. It looks at the modification time and the length of the file at the given interval, and loads the file when both differ from the last load and have been the same for two looks. The second condition waits for a writer to finish. A rejected file is logged once and not tried again until it changes. The watcher is off by default. After a reviewed edit, ``sibuna check -f`` followed by SIGHUP or ``sibuna ctl SOCKET reload`` shows us the result. The watcher suits a file that a deployment tool replaces by rename.

Replacing the binary without closing the port
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

With ``global.reuse_port`` ``true`` we upgrade Sibuna, or change a setting that needs a restart, without a moment in which the port is closed.

.. code-block:: sh

   /opt/sibuna/new/sibuna check -f /etc/sibuna/edge.jlv
   /opt/sibuna/new/sibuna --config-file /etc/sibuna/edge.jlv &   # binds the same addresses
   kill -TERM "$OLD_PID"                                         # drains, then stops

The new process binds the same addresses while the old one serves, and the kernel gives each new connection to one of them. On SIGTERM the old process stops accepting and waits up to ``shutdown_timeout`` for its established flows. The new process takes the admin socket when it starts, and the old process leaves that socket alone when it stops.

A connection that reaches the old process in the instant it closes its listener is reset, and the client connects again. In our test with a client that opens a new connection for every request, no request failed in 15 takeovers. An HTTP/3 connection does not survive the takeover: the kernel may hand its packets to the other process, which does not know the connection, and the client then connects again. Connections over TCP are not affected. Without ``reuse_port`` a second process on the same address is refused with ADDRESS IN USE, which protects against starting the service twice by mistake.

Changing servers at run time
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A deployment takes one server out of rotation, replaces it, and returns it. For this we need no edit of the file. The daemon opens a local admin socket when the file names one, and ``sibuna ctl`` sends it one command.

.. code-block:: text

   fn edge() -> Map<Value> {
       return {
           global: { admin_socket: "/run/sibuna/edge.sock" },
           frontends: { web: { binds: ["0.0.0.0:8080"] } },
           backends: { app: { servers: ["10.0.0.1:80", "10.0.0.2:80"] } },
       }
   }

.. code-block:: text

   $ sibuna ctl /run/sibuna/edge.sock set server app/10.0.0.1:80 state drain
   $ sibuna ctl /run/sibuna/edge.sock add server app/blue 10.0.0.3:80 weight 2
   $ sibuna ctl /run/sibuna/edge.sock show servers
   pool name        address     state weight flows health changed
   app  10.0.0.1:80 10.0.0.1:80 drain 1      4     -      state
   app  10.0.0.2:80 10.0.0.2:80 ready 1      9     -      -
   app  blue        10.0.0.3:80 ready 2      0     -      added

.. list-table:: Commands of ``sibuna ctl SOCKET``
   :header-rows: 1
   :widths: 46 54

   * - Command
     - Effect
   * - ``show servers``
     - One line per server. The column ``changed`` holds ``-`` for a server that is served as the file describes it, ``added`` for one that a command added, and ``state`` or ``weight`` for a changed field.
   * - ``show stats``
     - The series of the edge in the Prometheus text format: requests, bytes and times per frontend and per server, the flow table, the access log and the PROXY protocol.
   * - ``show certs``
     - One line per name of automatic HTTPS: the issuer, the expiry, the next renewal, the state and the last failure (section *Automatic HTTPS*).
   * - ``show info``
     - The version, the process, the file, the number of reloads, the watcher, the flows, the drops, the number of run-time changes, and the servers of the file that a command removed.
   * - ``set server POOL/NAME state ready|drain``
     - ``drain`` stops new flows to the server. Its health probes continue. ``ready`` admits it again. ``maint`` is accepted as another word for ``drain``.
   * - ``set server POOL/NAME weight N``
     - Sets the weight, 1 to 65,535.
   * - ``add server POOL/NAME IP:PORT [weight N]``
     - Adds a server. It takes the health check of its pool and starts in service. The name has 1 to 64 letters, digits and ``. _ : [ ] -``.
   * - ``del server POOL/NAME``
     - Removes a server. The last server of a pool stays. We drain it instead.
   * - ``reload``
     - Loads the file and applies it, as SIGHUP does, and prints the result or the reason for which the file was rejected.
   * - ``help``
     - Lists the commands.

A command applies to new flows only. An established TCP stream, a UDP mapping and a running HTTP exchange keep their server, as they do across a reload. ``sibuna ctl`` exits with status 0 on success. On failure it exits with status 1 and prints a diagnostic with a code from ``ADM001`` to ``ADM010`` and a hint, and nothing has changed.

The file stays the authority. Run-time changes live in memory, as an overlay on the last accepted revision, and the daemon never writes the file. The table says what happens to each change.

.. list-table:: Run-time changes and the file
   :header-rows: 1
   :widths: 28 30 20 22

   * - Change
     - Successful reload
     - Rejected reload
     - Restart
   * - ``state drain``
     - Kept, while the file still has a server of that pool, name and address
     - Kept
     - Lost
   * - ``weight``, ``add server``, ``del server``
     - Replaced by the file
     - Kept
     - Lost

A weight, an addition and a removal are topology, and the file can express them. The run-time form is a rehearsal. To keep the change we edit the module: a server added with ``add server app/blue 10.0.0.3:80`` becomes a new element of ``servers``, or a new host of the list that a comprehension reads. A drain is different. It says that somebody is working on a machine, and the file has no key for it. A reload must not return that machine to rotation, so a drain passes the reload. It ends when we say ``ready``, when the file drops the server or gives its name another address, or when the daemon restarts. The log line of a reload states what it did: ``Sibuna edge routes reloaded: 1 drain kept, 2 run-time changes replaced by the file``.

Two kinds of pool change their servers and weights only by reload. A pool with ``bounded_maglev``, and the default pool of a node with a ``mesh``, place clients by a table that every node builds from the file. A pool with ``http_version`` or ``tls`` reaches its servers through adapters that a reload prepares. ``drain`` works for every pool. A command acts on one node. On several nodes we send it to each.

The socket is a Unix socket with mode 0600, so only the user of the daemon can connect. Whoever can connect can direct traffic to an address of his choice. There is no TCP listener for administration. A connection carries one line of at most 512 bytes, and the daemon accepts a burst of 20 commands and 10 per second after it. Each command that changes state is logged with the code ``EDGE010``. A daemon that ``sibuna lb`` started has no file, so ``reload`` and SIGHUP are refused, and its run-time changes last until it stops.

Under systemd the Linux packages install the unit ``sibuna-edge.service`` beside ``sibuna.service`` and start neither. It runs ``sibuna --config-file /etc/sibuna/edge.jlv`` as the account ``sibuna`` with the one capability ``CAP_NET_BIND_SERVICE``, so it can bind ports 80 and 443. It raises the descriptor limit to 65,536, gives the daemon ``/run/sibuna`` for the admin socket, restarts it after a failure, and keeps the hardening of ``sibuna.service``. ``systemctl reload sibuna-edge`` checks the file and sends SIGHUP.

.. code-block:: sh

   sibuna lb --bind :443 --tls /etc/sibuna/certs/ --server 10.0.0.1:80 --server 10.0.0.2:80 \
       --admin /run/sibuna/edge.sock --print-config | sudo tee /etc/sibuna/edge.jlv
   sudo systemctl enable --now sibuna-edge
   sudo -u sibuna sibuna ctl /run/sibuna/edge.sock show servers

Several nodes
~~~~~~~~~~~~~

For several nodes we can add a top-level ``mesh`` object with a unicast ``listen`` address, a list of ``peers`` as numeric UDP socket addresses, and a ``key_file`` containing the same 32 random binary bytes on each node. We provision this key on the management network and restart nodes when rotating it. Peers exchange authenticated challenges every half second. Pools with no explicit scheduler choose two candidates while standalone and use a deterministic weighted Maglev table once a peer responds. The wide-area regime prefers eligible local servers over servers marked ``"remote": true``. At least three missed probe periods expire a peer. Each node makes its own health and admission decisions. Keeping established flows on their owning node across a routing change requires upstream flow steering.

Hosting jlavi, jlavideploy and jlavici
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The three sibling projects serve cleartext HTTP/1.1 and leave TLS to a proxy. One Sibuna node can serve all three names on port 443 and pass Git over SSH as TCP.

.. list-table:: What each project needs from the edge
   :header-rows: 1
   :widths: 16 20 64

   * - Project
     - Server
     - Needs
   * - jlavi
     - ``10.20.0.8:8040``
     - WebSocket on ``/live``, Git and large-file transfers of an hour, health at ``/api/v1/health``, ``trusted_proxies`` naming the Sibuna node, and TCP passthrough to ``sshd``. Several processes may share one pool.
   * - jlavideploy
     - ``10.20.0.9:7420``
     - WebSocket on ``/live``, long polls of 30 s, bodies up to 64 MiB, health at ``/healthz``. It reads no forwarded field.
   * - jlavici
     - ``10.20.0.10:8050``
     - Long polls of 25 s, chunk uploads of 16 MiB, large downloads, health at ``/healthz``. One coordinator only, so one server. The public URL must be the name the edge serves.

.. code-block:: json

   {
     "global": {"max_flows": 16384},
     "http": {"surface": "shield", "idle_timeout": "1h", "websocket_idle_timeout": "1h",
              "max_connections": 4096, "max_connections_per_ip": 256},
     "frontends": {
       "web": {
         "proto": "http", "binds": ["0.0.0.0:443"],
         "tls": {"crt": "/etc/sibuna/certs/", "http3": true},
         "firewall": false,
         "routes": [
           {"host": "forge.example.org", "backend": "jlavi"},
           {"host": "deploy.example.org", "backend": "jlavideploy"},
           {"host": "ci.example.org", "backend": "jlavici"}
         ],
         "default_backend": "jlavi"
       },
       "git_ssh": {"proto": "tcp", "binds": ["0.0.0.0:2222"], "default_backend": "jlavi_ssh",
                   "session_timeout": "1h", "rate_limit": {"conn_per_10s": 60}}
     },
     "backends": {
       "jlavi": {"mode": "http", "health_check": {"kind": "http", "path": "/api/v1/health"},
                 "servers": [{"name": "forge-1", "addr": "10.20.0.8:8040"}]},
       "jlavideploy": {"mode": "http", "health_check": {"kind": "http", "path": "/healthz"},
                       "servers": [{"name": "deploy-1", "addr": "10.20.0.9:7420"}]},
       "jlavici": {"mode": "http", "health_check": {"kind": "http", "path": "/healthz"},
                   "servers": [{"name": "ci-1", "addr": "10.20.0.10:8050"}]},
       "jlavi_ssh": {"mode": "tcp", "servers": [{"name": "forge-1", "addr": "10.20.0.8:22"}]}
     }
   }

The names carry no firewall here, because their clients are Git, curl and runners. To protect the browser pages of a project, we give its route ``"firewall": true`` and exempt the API paths with earlier routes. Each application sets its public URL to the HTTPS name. jlavi lists the Sibuna node in ``trusted_proxies``. A runner key that pins the certificate's public key stays valid as long as we keep the same private key when we renew.

Coming from HAProxy
~~~~~~~~~~~~~~~~~~~

.. list-table:: HAProxy directives and their edge equivalents
   :header-rows: 1
   :widths: 44 56

   * - HAProxy
     - Sibuna edge
   * - ``bind :443 ssl crt /etc/haproxy/certs/ alpn h2,http/1.1``
     - ``"binds": ["0.0.0.0:443"], "tls": {"crt": "/etc/sibuna/certs/"}``
   * - ``bind quic4@:443 ssl crt ... alpn h3``
     - ``"tls": {"crt": ..., "http3": true}``
   * - ``use_backend api if { hdr(host) -i api.example.org }``
     - ``"routes": [{"host": "api.example.org", "backend": "api"}]``
   * - ``use_backend api if { path_beg /v1/ }``
     - ``{"path_prefix": "/v1/", "backend": "api"}``
   * - ``mode tcp`` with ``req.ssl_sni``
     - ``"proto": "tcp", "tcp_inspect": "tls_client_hello"`` with ``acls`` and ``rules``
   * - ``balance leastconn``, ``weight``, ``maxconn``, ``backup``
     - ``least_connections`` (default), ``weight``, ``max_flows``, ``backup``
   * - ``balance roundrobin``
     - ``"balance": {"kind": "round_robin"}``
   * - ``balance source``
     - ``"sticky": "source"``
   * - ``cookie SRV insert indirect nocache httponly secure``
     - ``"sticky": {"kind": "cookie", "cookie": "SRV"}``. The value is a keyed hash, not the server name.
   * - ``timeout connect 5s``, ``timeout server 60s``
     - ``"connect_timeout": "5s"``, ``"response_timeout": "60s"`` on the backend (these are the defaults)
   * - ``retries 2`` with ``option redispatch``
     - ``"retries": 2`` (default). Each retry goes to another server.
   * - ``observe layer7``, ``error-limit 3``, ``on-error mark-down``
     - ``"passive_health": {"failures": 3, "ejection": "10s", "http_5xx": true}``
   * - ``server s1 ... slowstart 30s``
     - ``"slow_start": "30s"`` on the backend
   * - ``http-request redirect scheme https code 308 unless { ssl_fc }``
     - ``"redirect_https": true`` on the cleartext frontend
   * - ``http-response set-header Strict-Transport-Security max-age=31536000``
     - ``"hsts": true`` on the TLS frontend
   * - ``http-request set-header X-Edge sibuna``, ``http-request del-header X-Debug``
     - ``"request_headers": {"set": {"X-Edge": "sibuna"}, "remove": ["X-Debug"]}``
   * - ``http-response set-header``, ``http-response del-header Server``
     - ``"response_headers": {"set": {...}, "remove": ["Server"]}``
   * - ``http-request deny deny_status 413 if { req.body_size gt 10m }``
     - ``"max_body": "10m"``
   * - ``http-request set-header X-Forwarded-Host %[req.hdr(host)]``, ``X-Forwarded-Port %[dst_port]``
     - Always on for HTTP frontends
   * - ``option httpchk GET /health`` and ``check inter 2s rise 2 fall 3``
     - ``"health_check": {"kind": "http", "path": "/health", "interval": "2s", "rise": 2, "fall": 3}``
   * - ``server s1 10.0.0.1:8443 ssl verify required ca-file ca.pem sni str(api.internal) alpn h2``
     - ``"http_version": "2", "tls": {"ca_file": "ca.pem", "sni": "api.internal"}``
   * - ``server s1 ... send-proxy-v2``
     - ``"proxy_v2": {"enabled": true}`` on a TCP pool
   * - ``option forwardfor``
     - Always on for HTTP frontends
   * - ``timeout client``, ``timeout tunnel``
     - ``http.idle_timeout``, ``http.websocket_idle_timeout``, ``session_timeout`` on TCP and UDP frontends
   * - ``stick-table ... conn_rate``, ``http_req_rate``
     - ``rate_limit`` on a frontend, ``http.rate_limit``
   * - ``reload`` (new process)
     - SIGHUP or ``sibuna ctl SOCKET reload`` (same process, flows kept)
   * - ``stats socket /run/haproxy.sock mode 600 level admin``
     - ``"global": {"admin_socket": "/run/sibuna/edge.sock"}``
   * - ``echo "show servers state" | socat stdio /run/haproxy.sock``
     - ``sibuna ctl /run/sibuna/edge.sock show servers``
   * - ``set server app/s1 state drain``, ``state maint``, ``state ready``
     - ``set server app/s1 state drain``, ``state ready``
   * - ``set server app/s1 weight 10``
     - ``set server app/s1 weight 10``
   * - ``add server app/s3 10.0.0.3:80``, ``del server app/s3``
     - ``add server app/s3 10.0.0.3:80``, ``del server app/s3``
   * - ``server-state-file`` with ``load-server-state-from-file``
     - Not needed for drains, which pass a reload. Other run-time changes are made durable in the file.

Limits of this version
~~~~~~~~~~~~~~~~~~~~~~

On Linux the HTTP firewall serves connections on event-driven workers, one per processor, up to ``http.max_connections``. A connection that waits holds a small record and no buffer. On other platforms, and with ``event_loop`` ``false``, each HTTP/1.1 connection and each HTTP/2 or HTTP/3 exchange has a thread of its own, up to 8192 at a time. A WebSocket to a pool with ``http_version`` 2 or 3 answers 501. HTTP/3 clients cannot open WebSockets, and browsers fall back to HTTP/1.1 or HTTP/2 for them. Server addresses are numeric. The admin socket changes servers only: frontends, routes, certificates and policy change by reload. Run-time changes do not survive a restart. Request headers are limited to 16 KiB on HTTP/2 and HTTP/3. Response compression and caching are not provided. Header edits set fixed values: there are no patterns or variables. With ``event_loop`` ``false`` an HTTP/1.1 connection has the choice of the server, sticky sessions, the redirect, the header edits and the limit on a declared body, but not ``connect_timeout``, ``response_timeout``, failover to another server or passive health. A request body without a declared length is bounded by ``max_body`` on the event-driven workers only. SID 0019 lists the remaining gaps. SID 0015 lists the parts of the design that remain proposals: the shared-memory spill cache, database-backed topology, replicated bans, peer forwarding, binary handoff, plugins and the fleet console.


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

For remote operation, use an HTTPS proxy and configure ``--console-origin``, ``--console-behind-proxy``, explicit ``--console-trusted-proxy`` CIDRs, and ``--console-key-file``. The key file contains 64 hexadecimal characters, has owner-only permissions and protects stored second-factor secrets; retain it across restarts separately from the challenge seed. The configured HTTPS origin and proxy allowlist are mandatory for off-loopback access. The console listener uses plaintext HTTP; the console uses TLS only for its outbound connections, through rustls (SID 0012).

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

Page fragments can be bookmarked; Back and Forward reopen authenticated pages. The sidebar also remembers theme and spacing choices in this browser, with System as the default theme. SID 0007 is Committed. The console passes its golden fixtures and its browser workflows in headless Chromium (``cargo xtask browser console``, SID 0010 criterion 5). Its end-to-end suite is ``cmd/sibuna/tests/console_*.rs``, whose PostgreSQL cluster scenarios run when ``SIBUNA_TEST_DATABASE_URL`` is set. SID 0010 records that with the console compiled in, disabled, storage only, or enabled and idle, the 16 product workloads stay within about 1% of the daemon built without it, which is within noise. The formal isolation gate of SID 0007, with eight active dashboards under load, has not been measured yet (Part VIII). The complete WebAssembly application has a 768 KiB uncompressed ceiling, which the daemon's build script enforces by failing the build, and a 640 KiB review threshold. In 1.0.0-beta.3 the module measures 724,330 bytes (272,568 gzipped), above the review threshold, which SID 0007 records for review. These project limits leave room for console workflows; they do not replace browser loading and responsiveness measurements. The module's linear memory grows on demand up to a declared maximum of 16 MiB.

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
     graph [rankdir=TB, bgcolor="transparent", newrank=true, nodesep=0.35, ranksep=0.38, pad=0.1];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=9.5, fontcolor="#172033", color="#1e40af", fillcolor="#eff6ff", penwidth=1.1, width=1.4, height=0.42, margin="0.1,0.05"];
     edge [color="#64748b", fontname="Helvetica", fontsize=8.5, fontcolor="#475569", arrowsize=0.6, penwidth=1.1];

     request [label="Request", color="#172033", fillcolor="#ffffff"];
     limits [label="Local bans\nand rate limit", shape=hexagon, style=filled, margin="0.02,0.04"];
     policy [label="Inspection\nand policy", shape=hexagon, style=filled, margin="0.02,0.04"];
     session [label="Session MAC\nif challenged", shape=hexagon, style=filled, color="#b45309", fillcolor="#fffbeb", margin="0.02,0.04"];
     deny [label="Deny", color="#b91c1c", fillcolor="#fef2f2", penwidth=1.4];
     origin [label="Origin / auth\nsuccess", color="#15803d", fillcolor="#f0fdf4", penwidth=1.4];
     puzzle [label="Issue puzzle", color="#b45309", fillcolor="#fffbeb", penwidth=1.4];

     { rank=same; deny; session; }
     { rank=same; origin; puzzle; }
     deny -> session [style=invis, minlen=2];
     origin -> puzzle [style=invis];

     request -> limits;
     limits -> policy [label=" within limits"];
     policy -> deny [label="DENY ", color="#b91c1c", fontcolor="#b91c1c", fontname="Helvetica-Bold"];
     policy -> origin [label=" ALLOW", color="#15803d", fontcolor="#15803d", fontname="Helvetica-Bold"];
     policy -> session [label=" CHALLENGE", color="#b45309", fontcolor="#b45309", fontname="Helvetica-Bold"];
     session -> origin [label="valid ", color="#15803d", fontcolor="#15803d"];
     session -> puzzle [label=" missing / invalid", color="#b45309", fontcolor="#b45309"];
   }

.. code-block:: sh

   sibuna --port 80 --upstream-host 127.0.0.1 --upstream-port 3000 \
          --secret-file /etc/sibuna/secret --difficulty 16 --algorithm posw

Admitted requests reach the origin with ``X-Forwarded-For``, ``X-Forwarded-Proto``, ``X-Real-IP``, ``X-Sibuna-Status`` and ``X-Sibuna-Rule`` headers. Hop-by-hop headers, the fields Sibuna writes itself and the alternative forwarding fields (``Forwarded``, ``X-Forwarded-Host``, ``X-Forwarded-Port``) are stripped, also when a client spells their names with underscores (``X_Forwarded_For``). ``X-Real-IP`` is the client the request was judged by. ``X-Forwarded-For`` is the socket peer alone, never a client-written entry; when forwarded identity is trusted, it is the received chain followed by the socket peer. Origins must therefore read the client from ``X-Real-IP`` or from the right of ``X-Forwarded-For``, never from its leftmost entry. The path the origin receives is the normal form that policy judged (SID 0009); a path without a normal form is answered ``400``.

HTTP/1.1 WebSocket upgrades pass through admission and policy checks before the origin's handshake is accepted. Subprotocol and extension negotiation remains end-to-end. Two threads relay bytes, one per direction, each with one fixed buffer, including prefetched bytes and half-closes; an upgraded connection therefore holds two threads, and the number of connection threads can reach twice ``--max-connections`` when every connection is upgraded. Upgraded sockets remain within the normal connection quota and shutdown registry, but use ``--websocket-idle-timeout`` (300 seconds by default) independently of the HTTP idle deadline. Traffic in either direction refreshes that bound, but a peer that accepts no byte for the whole period ends the relay, however busy the other direction is. Frames after the handshake are not WAF inspection inputs. For WSS we use an external TLS ingress that forwards the HTTP/1.1 upgrade to Sibuna. The native HTTP/2 and HTTP/3 listeners handle ordinary HTTP exchanges.

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

JA4 Fingerprints From the Ingress
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A JA4 fingerprint summarises how a client opens a TLS connection. It is computed from the client's first handshake message, the ClientHello. The client's TLS library fixes that message before any HTTP byte is sent, so a client cannot change its fingerprint from inside its HTTP requests. Browsers, libraries and bots differ in it. This makes JA4 a stronger signal than a ``User-Agent`` value, which any client may write as it likes (SID 0014). JA4 was defined by FoxIO. A fingerprint has 36 characters in three parts joined by ``_``:

.. code-block:: text

   t13d1516h2_8daaf6152771_02713d6af862
   ^^^^^^^^^^ ^^^^^^^^^^^^ ^^^^^^^^^^^^
   a          b            c

   a  protocol (t TCP, q QUIC, d DTLS), TLS version (13 is TLS 1.3),
      d with SNI or i without, cipher count (two digits),
      extension count (two digits), ALPN code (h2 is HTTP/2)
   b  a 12-digit lowercase hexadecimal hash of the sorted cipher suites
   c  a 12-digit lowercase hexadecimal hash of the sorted extensions
      and signature algorithms

A TCP edge frontend can compute JA4 from a visible ClientHello during passthrough. When we run the HTTP firewall behind a TLS ingress, the ingress sees that handshake and Sibuna receives HTTP/1.1. We can configure the trusted ingress to compute JA4 and send the fingerprint to the firewall in a request header.

``--ja4-header <name>`` names that header. It is off by default and has no default name; we always name the header the ingress uses. Sibuna stores the name in lower case and matches it without regard to case. It refuses the names of fields it writes or strips itself (``X-Forwarded-*``, ``X-Real-IP``, ``X-Sibuna-*`` and ``Forwarded``, also with ``_`` for ``-``). When the option is set, the startup banner prints a line such as ``JA4: from cf-ja4 (trusted)``.

The header is read only when forwarded fields are trusted. This is the decision that governs ``X-Forwarded-For``: ``--trust-forwarded``, or forward-auth mode without ``--no-trust-forwarded``. From an untrusted peer the header is ignored. With trust, a request carries a fingerprint when exactly one field of that name is present and its value has the JA4 form. A malformed value, or a repeated field, gives the request no fingerprint. Two counters observe this: ``sibuna_ja4_present_total`` counts requests with a fingerprint, and ``sibuna_ja4_invalid_total`` counts requests whose header was malformed or repeated. A request from an untrusted peer bumps neither counter.

In reverse-proxy mode, the origin sees the header only when Sibuna trusts it. Without trust, Sibuna removes every field of that name from the request it sends to the origin, also when a client spells the name with ``_`` for ``-``. A client therefore cannot hand the origin a forged fingerprint under that name. With trust, the field passes unchanged in its exact spelling, and an alias with ``_`` is still removed. Without ``--ja4-header``, a field of that name is an ordinary field.

.. admonition:: The ingress must own the header

   A fingerprint is only as trustworthy as the ingress that wrote it. Sibuna cannot tell a value the ingress computed from a value the client sent. The ingress must therefore overwrite, or remove, any copy of the header that the client supplies, on every route that reaches Sibuna. Sibuna's listener must accept connections from the ingress alone, as for ``X-Forwarded-For``.

**Cloudflare.** The managed transform "Add bot protection headers" adds ``cf-ja4`` to the request sent to the origin, beside ``cf-bot-score``, ``cf-verified-bot`` and ``cf-ja3-hash``. It requires an Enterprise plan with Bot Management. An ingress between Cloudflare and Sibuna must pass the field on unchanged. We start Sibuna with:

.. code-block:: sh

   sibuna --ja4-header cf-ja4 --trust-forwarded -s /etc/sibuna/secret

The ingress in front of Sibuna must accept connections from Cloudflare's addresses alone; otherwise a client can bypass Cloudflare and send its own ``cf-ja4``.

**nginx.** FoxIO's ``ja4-nginx-module`` computes JA4 inside nginx and exposes it as ``$http_ssl_ja4``. It needs nginx 1.26 or later with the module's ClientHello capture patch, built with ``--with-http_ssl_module``. ``proxy_set_header`` replaces a client's field of the same name, so each location that reaches Sibuna sets the header itself:

.. code-block:: nginx

   # Reverse proxy: Sibuna runs with --ja4-header x-ja4 --trust-forwarded
   location / {
       proxy_set_header X-JA4 $http_ssl_ja4;
       proxy_set_header X-Forwarded-For $remote_addr;
       proxy_pass http://127.0.0.1:8080;
   }

   # Forward auth: Sibuna runs with --mode forward_auth --ja4-header x-ja4
   location = /__sibuna_auth {
       internal;
       proxy_pass http://127.0.0.1:8080/;
       proxy_set_header X-JA4 $http_ssl_ja4;
       # ... the other fields of the forward-auth recipe above
   }

In the forward-auth recipe, the same ``proxy_set_header X-JA4 $http_ssl_ja4;`` line belongs in ``@sibuna_challenge`` and in ``location /__sibuna/`` as well. A location that omits it passes the client's own ``X-JA4`` to Sibuna, which trusts it.

**Apache Traffic Server.** The ``ja4_fingerprint`` plugin is enabled by the line ``ja4_fingerprint.so`` in ``plugin.config``. It has no options. It adds a ``ja4`` field with the fingerprint, and an ``x-ja4-via`` field with the proxy's name, to the requests of each TLS connection. We start Sibuna with ``--ja4-header ja4 --trust-forwarded``. The plugin's documentation does not say whether it replaces a ``ja4`` field that the client sent. We must establish this for our version, or remove the client's field before the plugin adds its own, before we trust the value.

A rule matches a fingerprint with the ``ja4`` field (Part X, Policy Schema). The value is either a whole fingerprint, which must be equal, or a prefix followed by ``*``, which the fingerprint must start with. ``"*"`` alone matches any fingerprint. A request without a fingerprint never matches a ``ja4`` rule. The loader refuses a pattern that no fingerprint could match, such as ``T13D*`` in upper case, with ``INVALID POLICY JA4``. Matching compares bytes and allocates nothing.

.. code-block:: json

   { "rules": [
       { "name": "deny-known-scanner", "action": "DENY",
         "ja4": "t13i010400_0f2cb44170f4_5c4c70b73fa0" },
       { "name": "weigh-no-sni", "ja4": "t13i*", "action": "WEIGH", "weight": 15 },
       { "name": "weigh-headless", "user_agent": "Headless", "action": "WEIGH",
         "weight": 30 },
       { "name": "challenge-tls12-checkout", "path": "/checkout/*", "ja4": "t12*",
         "action": "CHALLENGE" }
   ] }

The first rule denies one fingerprint exactly; the value is an example, not a known scanner. The next two add weight to the request's score instead of deciding: a TLS 1.3 client that sent no server name, and a headless browser by its ``User-Agent``. When no later rule decides first, a request that shows both signals scores 45 and reaches the default deny threshold of 40, while a request that shows one is challenged. The last rule challenges, by prefix, every client that negotiated TLS 1.2 over TCP on the checkout path. It challenges rather than denies, because many legitimate older clients still use TLS 1.2. Rules should combine JA4 with other signals in this way. A JA4 value names a TLS library and its configuration, not a person or a device. Many clients share one library, and specialised libraries can imitate a browser's ClientHello. JA4 raises the cost of automation; it does not prove identity. For the same reason Sibuna keeps bans and reputation keyed by address and never by fingerprint.

Incidents (WAF denials, honeypot hits and audit findings) record the fingerprint of their request when it carried one, in the column ``security_incidents.ja4``. The console shows it in the incident evidence as "JA4 fingerprint", with the value or "Not recorded". The Events filters accept a fingerprint or a prefix. The managed-rule editor has a JA4 field, stored in ``policies.ja4_pattern``, and the policy test form takes a fingerprint.

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

The loader fails closed: an unknown key, a misspelled action, a malformed address or an out-of-range number rejects the whole file, the diagnostic names the rule and field, and the daemon does not start. A command line with an unknown option or an out-of-range value is refused the same way. ``rules`` replaces the built-in table when present; ``ip_rules`` feeds the reputation trie, which scales to thousands of prefixes; ``waf: false`` selects the Gate surface from the file. Two further keys are part of the schema (Part X): ``inspection`` sets each WAF category to ``disabled``, ``audit`` or ``enforce``, and a rule's ``limits`` object gives it a quota of its own. A rule's ``ja4`` field matches the JA4 fingerprint that a trusted ingress forwarded, exactly or by a prefix followed by ``*``; it needs ``--ja4-header`` (see "JA4 Fingerprints From the Ingress"). Path patterns match the request path in normal form (SID 0003), so a pattern must be written in that form.

Persistent Storage and Clustering
---------------------------------

.. admonition:: Objectives

   Enable SQLite or PostgreSQL storage, add a dynamic policy and a ban with SQL, query incident forensics, understand campaign clustering, and run several nodes on one PostgreSQL database.

.. graphviz::
   :caption: The storage architecture: workers never block on the database
   :alt: Request threads push incidents into an MPSC ring of 512 slots. The storage thread pops them, writes batches through sqlx to the SQLite file or the PostgreSQL database holding policies, ip_reputation, security_incidents and the full-text index. When the policy revision changes it rebuilds the engine and publishes it as an Arc, which the request threads read. Other cluster nodes share the PostgreSQL database and hear NOTIFY sibuna_policy.

   digraph storage_architecture {
     graph [rankdir=TB, bgcolor="transparent", newrank=true, nodesep=0.8, ranksep=0.42, pad=0.1];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=9, fontcolor="#172033", color="#1e40af", fillcolor="#eff6ff", penwidth=1.1, width=1.7, height=0.45, margin="0.1,0.05"];
     edge [color="#64748b", fontname="Helvetica", fontsize=8, fontcolor="#475569", arrowsize=0.6, penwidth=1.7];

     workers [label="Request threads\n(hot path)", color="#172033", fillcolor="#ffffff", penwidth=1.6, width=3.0];
     ring [label="MPSC ring\n512 incidents", color="#b45309", fillcolor="#fffbeb"];
     publish [label="EngineSlot::publish\nArc swap", color="#b45309", fillcolor="#fffbeb"];
     thread [label="Storage thread (tokio)\ndrain + poll"];
     rebuild [label="Rebuild engine\noff the hot path"];
     db [label="sqlx: SQLite file\nor PostgreSQL", shape=cylinder, style=filled, color="#15803d", fillcolor="#f0fdf4", height=0.62];
     tables [label="policies, ip_reputation,\nsecurity_incidents,\nfull-text index", color="#15803d", fillcolor="#f0fdf4"];
     others [label="Other cluster\nnodes", color="#64748b", fillcolor="#ffffff", style="rounded,filled,dashed", width=1.7];

     { rank=same; ring; publish; }
     { rank=same; thread; rebuild; }
     { rank=same; db; tables; }

     workers -> ring [label=" push"];
     ring -> thread [label=" pop"];
     thread -> db [label=" batched SQL"];
     db -> tables;
     rebuild -> tables [dir=back, label=" revision changed?"];
     publish -> rebuild [dir=back];
     workers -> publish [dir=back, label=" new rules"];
     db -> others [dir=both, style=dashed, label=" shared PostgreSQL,\n NOTIFY sibuna_policy"];
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
     - Ordered dynamic rules, keyed by ``id``. The nullable ``ja4_pattern`` holds a rule's JA4 criterion, at most 37 bytes.
   * - ``policy_inspection``
     - The stored WAF mode per category, one row.
   * - ``ip_reputation``
     - Scores, hit counts and expiry, keyed by address or prefix.
   * - ``incident_receipts``
     - Each node's durable incident receipt (the next sequence after its last committed batch), keyed by node.
   * - ``security_incidents``
     - One bounded event record with its 64-component embedding (256 bytes), keyed by ``node_id << 40 | sequence``. The nullable ``ja4`` holds the request's JA4 fingerprint, exactly 36 bytes.
   * - ``incidents_fts``
     - On SQLite: an FTS5 table over the canonical tokens of paths and payloads. On PostgreSQL the same tokens are the ``tsvector`` column ``search`` of ``security_incidents`` with a GIN index.
   * - ``sibuna_schema``
     - Every applied migration, keyed by component and version.

The core schema is ``crates/storage/src/schema.rs``, written once per dialect. With the console the component ``console`` adds 33 tables whose names start with ``console_`` (SID 0013; ``crates/console-storage/src/schema/``). Migrations are numbered per component and compiled into the binary. Core migration 2 adds the two JA4 columns; a database created before it is migrated on start. All pending migrations run in one transaction, and a node refuses a database whose version of a component is newer than it knows. An abbreviated printed schema is not an upgrade script. SQLite tables are ``STRICT``, and ``CHECK`` constraints mirror the Rust types, so the database refuses a row the daemon could not represent. Enumerated values are stored in lowercase: a direct write of ``'DENY'`` is refused.

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
   sha256 -C SHA256SUMS sibuna-1.0.0-beta.3.tgz      # OpenBSD

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
     -p 8080:8080 ghcr.io/insanai/sibuna:1.0.0-beta.3 \
     --host 0.0.0.0 --secret-file /run/admission.seed --data-dir /var/lib/sibuna/data \
     --upstream-host 10.0.0.5 --upstream-port 3000

The Helm chart ``helm-sibuna-<version>.tgz`` runs one Pod of that image. It requires a Secret that we create (``secret.existingSecret``, key ``admission.seed``), so no seed ever appears in values or templates. The Pod runs as UID 65532 with a read-only root filesystem under the Restricted pod security standard. One replica with ``Recreate`` upgrades keeps a single writer on the ReadWriteOnce volume, where Sibuna keeps its SQLite state in ``data/``; the claim is kept on uninstall. The probes call ``/__sibuna/health``. The Service is ClusterIP, the chart creates no ingress and no console, and its NetworkPolicy denies all traffic until ``networkPolicy.ingressFrom`` and ``networkPolicy.egressTo`` allow the clients and the origin. ``upstream.host`` must be an IP literal, and ``extraArgs`` passes further daemon options. The workflow installs, upgrades and uninstalls the chart in a kind cluster that enforces the Restricted standard.

.. code-block:: sh

   kubectl -n sibuna create secret generic sibuna-admission --from-file=admission.seed
   helm install gateway ./helm-sibuna-1.0.0-beta.3.tgz --namespace sibuna \
     --set secret.existingSecret=sibuna-admission \
     --set upstream.host=10.0.0.5 --set upstream.port=3000

Building from source
~~~~~~~~~~~~~~~~~~~~

We build and test with Rust 1.100. The default build includes the JLV compiler and requires Rust 1.100. We can build the JSON-only daemon with Rust 1.94 using ``cargo build -p sibuna --no-default-features``. We add ``--features sqlite,console`` to include SQLite and the console.

We install the release toolchain with ``rustup toolchain install 1.100.0 --profile minimal --target wasm32-unknown-unknown`` and select it with ``cargo +1.100.0`` in the commands below.

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
