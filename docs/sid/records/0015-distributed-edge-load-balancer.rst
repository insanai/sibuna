:sid-number: 0015
:sid-title: Sibuna Edge: TCP, UDP and HTTP Load Balancing
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-24
:sid-updated: 2026-11-25
:sid-discussion: No external discussion URL assigned
:sid-summary: Specifies TCP and UDP forwarding, TLS, HTTP/2 and HTTP/3 termination, HTTP/1.1, HTTP/2 and HTTP/3 origin pools, per-route firewall selection and distributed routing. Records implementation and qualification evidence.
:sid-labels: ["architecture","load-balancer","network","ddos","mathematics"]

Sibuna Edge: TCP, UDP and HTTP Load Balancing
=============================================

Abstract
--------

We route TCP streams, UDP datagrams and HTTP requests to named pools. An HTTP frontend can accept plaintext HTTP/1.1 or terminate TLS for HTTP/1.1 and HTTP/2, and QUIC for HTTP/3. We apply the gate or shield to the routes that ask for it and select an origin for each request. An origin pool can use HTTP/1.1 or HTTP/2, in cleartext or over TLS. HTTP/3 uses QUIC with TLS. The client and origin protocols are selected independently. We can drain a server while established TCP streams and in-flight HTTP exchanges finish.

The decision for discussion is whether to adopt worker-owned flows and an immutable routing configuration as the common basis for standalone, regional and multi-region deployments. We use that boundary for JSON and JLV/2 routing today. The mmap spill cache (SID 0027), peer forwarding (SID 0026) and plugin tiers (SID 0030) build on it. The Lean artifact covers selected properties of the design. Capacity, latency and continuity during upgrades require implementation evidence.

Motivation and scope
--------------------

The HTTP firewall uses a thread-per-connection runtime and one upstream address (SID 0002 and SID 0010). The edge listener serves multiple origin pools and can inspect a visible TLS ClientHello before selecting a TCP origin. SID 0014 remains the source of the trusted-header contract when an external ingress terminates TLS.

We keep the host network stack for routing, socket ownership and coexistence with other services. Routers and routing daemons remain responsible for anycast announcements and ECMP. We target large numbers of idle flows with a thread per assigned core and fixed worker budgets. Ten million connections is a capacity experiment. We include HTTP/2 and HTTP/3 termination in the edge. Kernel bypass remains optional.

Specification
-------------

Worker ownership and deployment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. typst-diagram:: ../diagrams/edge-pop.typ
   :caption: Example edge deployment at a point of presence (PoP).
   :alt: ECMP directs traffic to hosts. Each host has packet workers, an optional spill service and a separate management plane.

Each worker owns a poller, a flow table and a pool of 16 KiB buffers. The control plane validates configuration, builds routing tables, probes backends and publishes revisions. Workers take a consistent view at a batch boundary. Database access, configuration evaluation and access to file-backed pages belong off the worker thread.

We target 64 bytes for the primary flow slot. At ten million slots the array alone takes 640,000,000 bytes, about 610 MiB. The process also needs flow indexes, timers, buffers, routing snapshots and descriptors. Kernel socket memory and the two sockets per proxied TCP connection enter the host budget separately. We must check the layout on each target and measure the complete deployment under idle and active traffic.

For established proxied TCP streams the current ``global.max_flows`` ceiling is 1,000,000 per edge process. Ten million simultaneous TCP flows require at least ten such processes and 20 million edge socket descriptors in aggregate, plus listener and control descriptors. The generators and origins each need another ten million sockets and enough distinct address and port combinations. On the two test hosts the inherited hard descriptor limit was 1,048,576 per process. After the 512-descriptor reserve this allows at most 524,032 TCP flows per process even before other resource limits. The default ephemeral port range on these hosts offered 28,232 ports per address pair.

We measured two loopback TCP pilots on host 19 with 20 concurrent opens at a time. We established 10,000 streams in 1.64 seconds with 20,032 edge descriptors and 20,000 in 7.04 seconds with 40,032. The origin greeted every stream before we counted it. All streams passed an echo after a five-second hold, with zero admission drops in both runs. The two rates correspond to 27 and 59 minutes to open ten million streams if sustained. Capacity at ten million remains unmeasured. A full run also requires provisioning, a hold and a drain.

We can repeat the pilot from the repository root on Linux with Python 3.11 or later.

.. code-block:: sh

   cargo build --release --locked -p sibuna
   python3 benchmarks/tcp_flow_pilot.py target/release/sibuna --flows 20000

We also exercised the admission code at ten million simultaneous reservations. We instantiated ten independent node budgets and backend pools in one process. Each held one million pairs of node permits and backend tickets. Each refused an additional reservation at its limit. After dropping the tickets, all counts returned to zero and each pool admitted a new reservation. Two release runs took 0.95 and 1.05 seconds. The larger peak RSS was 551,424 KiB. This measures the cost of admission objects. Established network streams also need sockets, relay records and kernel memory.

The larger TCP pilot uses 32 frontend and origin address pairs per host. Each connection must receive an origin greeting before it counts toward the simultaneous hold. After the hold, each client sends a distinct value and checks the echo. The client, edge worker and origin run in one test process, which needs four descriptors per proxied stream. On host 19 one edge instance held 250,000 streams and 1,000,063 process descriptors. The cgroup grew from 142,286,848 to 5,113,987,072 bytes. At this observed cost, ten million streams in the same four-socket topology would require about 185 GiB across the test fleet. The two 12 GiB hosts cannot support that projection.

On host 20 the 250,000-stream attempt timed out while opening connections. New SSH connections also timed out temporarily. Its Linux connection-tracking limit was 262,144 entries. If both TCP legs are tracked, the attempted load needs about 500,000 entries. We did not capture the counter at failure. The harness now opens a loopback probe and checks the available connection-tracking entries before the ramp. The kernel documents the count and limit in its `connection tracking reference <https://docs.kernel.org/networking/nf_conntrack-sysctl.html>`_.

We next held 300,000 real TCP streams simultaneously on two independent edge instances. Each instance forwarded on its own loopback network. Host 19 established 250,000 streams in 6.15 seconds and host 20 established 50,000 in 1.80 seconds. A coordinator waited for both active counts, held them for five more seconds and then released both verifiers. All 300,000 distinct echoes passed. Both instances reported zero drops and released every flow slot. At the plateau the connection tracker on host 20 held 100,016 entries, up from six. Host 19 reported zero at both readings. This qualifies the tested 300,000-stream topology. Ten million simultaneously established TCP streams remain unmeasured.

We can repeat the two measurements with release builds. We set the TCP count to fit the host's memory, descriptor and connection-tracking limits.

.. code-block:: sh

   cargo test --release --locked -p sibuna-lb --lib ten_million_live_reservations -- --ignored --nocapture
   SIBUNA_TCP_FLOWS=50000 cargo test --release --locked -p sibuna-lb --test flows simultaneous_tcp_flows -- --ignored --nocapture

For a simultaneous hold on multiple hosts, each run can set ``SIBUNA_FLOW_RELEASE_FILE`` to an unused path in its own temporary directory. We wait for every run to print ``HELD`` before creating the files. Each worker checks its active count and drops again after the echoes, then checks that its flow count reaches zero on close.

A worker retains an unwritten suffix after a short write and pauses reads until it can make progress. With completion-based I/O it retains each submitted buffer until the completion arrives. A half-close flushes pending bytes before closing the opposite write side. Buffer exhaustion applies backpressure to TCP and counts dropped UDP datagrams. Flow admission fails once the shard reaches its limit.

Portable socket I/O
^^^^^^^^^^^^^^^^^^^

We propose epoll on Linux, kqueue on BSD and macOS, and IOCP on Windows. Linux workers may select io_uring, batched datagram calls, splice or reuseport steering after a capability check. We test ordering, cancellation, half-close and backpressure on each supported backend. Socket handles and buffer lifetimes stay behind the platform interface.

Configuration and authority
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Both static JSON and a JLV/2 program produce the same validated topology. The control plane checks bind conflicts, duplicate identities, protocol compatibility, references and resource budgets before it opens a listener or publishes a revision. A failed check identifies the source field, its location and the correction. For example, a TCP frontend whose default pool is missing must fail validation even if an earlier rule names a valid pool.

The JLV entry point is ``fn edge() -> Map<Value>`` under ``Role::Transform``. We expose the pure foundation library. We limit the source and expanded document to 256 KiB each, cap evaluation at one million steps and bound container length, nesting and call depth. The evaluator runs off the packet path. Sibuna ships the pinned JLV kernel under LGPL-3.0-or-later with the author's grant. Its sources and upstream revision are in ``vendor/jlv``. The daemon enables JLV by default and supports independent JSON-only builds.

The following design example includes proposed features. The operations chapter gives runnable JSON and JLV configurations. This design uses the same port for TCP and UDP. The API pool expects PROXY v2 before the TLS stream. Other TLS traffic goes to the default pool. The UDP pool accepts ordinary QUIC passthrough.

.. code-block:: text

   // /etc/sibuna/sibuna.jlv - Sibuna Edge Topology in JLV/2 (shared with jlavideploy & jlavici)

   let api_hosts: List<Map<Value>> = [
       { name: "api-1", addr: "10.20.1.11:8443", weight: 100, max_flows: 50_000, backup: false },
       { name: "api-2", addr: "10.20.1.12:8443", weight: 100, max_flows: 50_000, backup: false },
       { name: "api-3", addr: "10.20.1.13:8443", weight: 50,  max_flows: 25_000, backup: true  },
   ]

   fn quic_server(i: Int) -> Map<Value> {
       return { name: "h3-${i}", addr: "10.20.2.1${i}:443", weight: 100 }
   }

   fn edge() -> Map<Value> {
       return {
           global: {
               workers: "auto",              // 1 pinned worker per CPU core (excludes management_cpus)
               max_flows: 1_000_000,         // 64 MB FlowSlot table across workers
               admin_socket: "/run/sibuna/admin.sock",
               cluster_mode: "adaptive",     // standalone | lan_mesh | geo_anycast
           },
           console: {
               listen: "10.99.0.11:9443",    // isolated management VLAN / WireGuard listener
               management_cpus: [0],         // off-path core disjoint from packet workers
               behind_proxy: true,
               origin: "https://edge-console.internal",
               trusted_proxies: ["10.99.0.2/32"],
               allow_operators: ["10.99.10.0/24", "fd00:99:10::/48"],  // bastion / VPN CIDRs only
               peer_key_file: "/etc/sibuna/console-peer.key",
               peer_ca_file: "/etc/sibuna/management-ca.pem",
               peers: [
                   { node: 2, origin: "https://fra-edge-02.internal:9443", allow_ips: ["10.99.0.12/32"] },
                   { node: 3, origin: "https://fra-edge-03.internal:9443", allow_ips: ["10.99.0.13/32"] },
               ],
           },
           kv_stores: {
               edge_state: {
                   ram_budget: "256MiB",     // worker-owned RAM cache
                   mmap_path: "/var/lib/sibuna/edge_state.arena",
                   mmap_budget: "16GiB",     // L2 MAP_SHARED saturation spill ring
                   admission: "wtinylfu",    // frequency-based cache admission
               },
           },
           plugins: {
               bot_telemetry: {
                   kind: "wasm",
                   module: "/etc/sibuna/plugins/telemetry_enricher.wasm",
                   fuel_limit: 50_000,       // instruction budget per invocation
                   memory_pages: 4,          // 256 KiB pre-allocated linear memory
                   on_trap: "fail_open",
               },
           },
           frontends: {
               public_tls_tcp: {
                   binds: ["0.0.0.0:443", "[::]:443"],
                   proto: "tcp",
                   reuseport: true,
                   defer_accept: "5s",
                   inspect_delay: "2s",
                   tcp_inspect: "tls_client_hello",  // non-terminating SNI, ALPN & native JA4!
                   rate_limit: { conn_per_10s: 200, ipv6_prefix: 64, store: "edge_state" },
                   acls: {
                       is_api: { sni: "api.example.com" },
                       is_bad_ja4: { ja4_prefix: "t12d*" },
                   },
                   rules: [
                       { action: "deny", when: "is_bad_ja4" },
                       { action: "use_backend", backend: "api_tcp_origin", when: "is_api" },
                   ],
                   default_backend: "default_tls_origin",
               },
               public_quic_udp: {
                   binds: ["0.0.0.0:443"],
                   proto: "udp",
                   reuseport: true,
                   udp_defense: { mode: "rate_limit", threshold_pps: 50_000 },
                   session_timeout: "30s",
                   stick: { on: "4tuple", store: "edge_state" },
                   default_backend: "quic_h3_fleet",
               },
           },
           backends: {
               default_tls_origin: {
                   mode: "tcp",
                   servers: [{ name: "default", addr: "10.20.1.20:443", weight: 100 }],
               },
               api_tcp_origin: {
                   mode: "tcp",
                   balance: { kind: "bounded_maglev", load_factor_pct: 125, fallback: "pewma" },
                   proxy_v2: { enabled: true, tlv_ja4: true, tlv_sni: true },
                   health_check: { kind: "tcp", timeout: "500ms", interval: "2s", fall: 3, rise: 2 },
                   servers: api_hosts,
               },
               quic_h3_fleet: {
                   mode: "udp",
                   balance: { kind: "bounded_maglev", load_factor_pct: 125 },
                   // A protocol-aware health probe may be configured here.
                   servers: [
                       for i in [1, 2]: quic_server(i)
                   ],
               },
           },
       }
   }

HTTP admission and origin selection
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A TCP or UDP frontend selects an origin for the life of a flow. An HTTP frontend selects an origin for each admitted request, including later requests on one keep-alive connection and separate streams on one multiplexed connection. We evaluate ordered routes against the validated authority and normalized path. Both predicates must match when both are present. The first matching route selects a pool. The default pool handles the remaining requests. A reservation lasts until the origin exchange ends. If a reload intervenes between a policy decision and its backend reservation, we return 503 so that an old decision cannot authorize a new route.

With a TLS identity on a frontend, we negotiate HTTP/2 over TCP. We can enable HTTP/3 on the same numeric UDP port. We use rustls for TLS, Hyper for HTTP/2 and Quinn with h3 for HTTP/3. Each stream enters the existing HTTP firewall and reaches its selected origin as HTTP/1.1. The transport supplies the client address and the scheme used in forwarded headers. Client-supplied headers confer no trust. We validate the certificate and key before publishing a reload. Established TLS sessions keep the identity used at their handshake.

We allocate one node-wide flow slot per client connection or UDP mapping. UDP mappings take at most ``global.max_udp_flows`` of the table, because their sources are not validated. Multiplexed ingress limits concurrent streams to 32 per connection, and all HTTP exchanges on the node to ``http.max_connections``. An exchange over the limit receives 503. Each client connection keeps a lane of loopback connections to the synchronous firewall. A lane reuses a connection for the next bodiless request, so a busy HTTP/2 or HTTP/3 connection does not open a socket pair per exchange. One loopback listener serves all handoffs and gives a connection only to the task that registered its source address. An idle multiplexed connection is closed after ``http.idle_timeout`` and releases its flow slot. HTTP/1.1 over TLS is a byte pipe to the firewall, so keep-alive and WebSocket upgrade behave as on the plaintext frontend. CONNECT and extended CONNECT require a separate tunnel policy.

Certificates
^^^^^^^^^^^^

A TLS listener loads ``crt`` entries as HAProxy does. An entry is a PEM file with the chain and its private key, or a directory of such files. The first bundle is the default certificate. The DNS names of each leaf select the others by server name, exact names before wildcards. ``strict_sni`` refuses a handshake that names no certificate. The pair ``cert_file`` and ``key_file`` remains valid. We check that each key matches its certificate before a revision is published.

Firewall selection
^^^^^^^^^^^^^^^^^^

The firewall inspects HTTP only. A TCP or UDP frontend never invokes it. ``http.surface`` takes ``off``, ``gate`` or ``shield``. With ``off`` the node is a load balancer: it parses, limits and routes requests and issues no challenge. With the firewall on, a frontend or a route may set ``firewall`` to ``false``. Such a request skips the policy, the challenge and the semantic inspection. It keeps protocol validation, connection limits, bans and the request limiter. This serves clients that cannot solve a challenge, such as Git, package managers and CI runners, beside browser names on the same listener.

Rate limits
^^^^^^^^^^^

We limit at four places, each keyed by the source IPv4 address or IPv6 /64. A TCP or HTTP frontend limits new connections with ``rate_limit.conn_per_10s``. A UDP frontend limits datagrams with ``udp_defense.threshold_pps`` and bounds replies to three times the received bytes. The HTTP firewall limits requests with ``http.rate_limit`` per ``http.rate_window``, and ``"off"`` disables that limiter. A policy rule can carry its own rate for the requests it matches. ``http.max_connections_per_ip`` bounds concurrent connections of one client. Limits are node-local. A cluster shares bans and reputation through the database of SID 0011, and replicated edge limits remain proposed.

Origin protocols
^^^^^^^^^^^^^^^^

An HTTP pool sets ``http_version`` to ``1.1``, ``2`` or ``3`` and an optional ``tls`` object with ``verify``, ``ca_file`` and ``sni``. The firewall relays HTTP/1.1. For a cleartext HTTP/1.1 pool it connects to the server directly. For the other pools an adapter in the daemon listens on a loopback port per server. It tunnels HTTP/1.1 through TLS, or translates each exchange to a stream of one shared HTTP/2 session or QUIC connection. Health probes use the adapter, so they exercise the path of a request. A reload starts the adapters of the new revision first and closes unused ones after the revision serves. Server certificates are verified against the system roots or ``ca_file`` unless ``verify`` is ``false``.

Health
^^^^^^

A TCP or HTTP pool can probe its servers by TCP connect or by an HTTP ``GET``. A server starts in service, leaves after ``fall`` failures and returns after ``rise`` successes. A reload keeps the status of each address.

File and database authority
^^^^^^^^^^^^^^^^^^^^^^^^^^^

In file mode, the file is authoritative. A successful reload replaces temporary administrative weights. In persistent mode, the file owns host-local binds, worker placement, admin endpoints and disk paths. SQLite or PostgreSQL owns the published topology. SID 0028 implements publication of one checked topology document per revision, with an expected revision to detect conflicting writes. A concurrent edit returns a conflict. A dump exports evaluated data. Only the recorded source can reproduce the original program text.

Nodes read a complete committed revision and report their applied revision. A notification prompts a reread. A periodic revision check also recovers missed notifications. If validation fails or the database becomes unavailable, a running node retains its last valid snapshot.

Reload, drain and rollback
^^^^^^^^^^^^^^^^^^^^^^^^^^

For an in-process reload we prepare the entire candidate, including its routing tables, before publication. A bounded handoff of owned snapshot references to workers must protect the reader while old references are reclaimed. A generation number alone cannot provide that lifetime. Each accepted flow retains a stable backend identity. A draining backend leaves the candidate set for new flows. We bound retained generations and reject or defer a reload that would exceed the memory budget.

For a binary upgrade the old process accepts until the replacement has validated its configuration, acquired listeners and acknowledged readiness. On failure before cutover the old process continues service. On Unix we propose authenticated local descriptor passing with SCM_RIGHTS. Windows needs its own socket duplication and service-control path. The old process owns accepted TCP sockets until close or the drain deadline. At the deadline we count forced disconnects.

A UDP listener handle contains no user-space affinity mappings. Preserving a live UDP flow across binary replacement requires a single reader for each datagram and a handoff of its owner, upstream socket and return path, or compatible stateless backend routing. SID 0029 implements listener and live UDP mapping handoff on Linux. On other platforms we drain or expire stateful UDP mappings before cutover.

On Linux a simpler cutover is implemented. With ``global.reuse_port`` every listener sets ``SO_REUSEPORT``, the replacement binds the same addresses while the old process serves, and the old process drains on SIGTERM. No descriptor is passed and no supervisor is needed. The cost is one that descriptor passing would avoid: a connection in the accept queue of the old listener at the instant it closes is reset. In our test with a new connection for each request no request failed in 15 cutovers. A UDP mapping and a QUIC connection do not survive, as described above. The operations chapter gives the commands.

SID 0029 builds the two proposals above for Linux. With ``global.upgrade_socket`` the replacement connects to the old process, both check the credentials of the peer, and the listening sockets pass with SCM_RIGHTS. The old process serves until the replacement says that it is ready, then hands over its UDP mappings with their server sockets, with one reader at every instant, and takes the service back when the replacement fails before it acknowledges. SID 0029 departs from this section in two points: the replacement is started by the operator or the supervisor and not by the old process, and other Unix systems are not built. QUIC connections still do not survive.

.. typst-diagram:: ../diagrams/tcp-cutover.typ
   :caption: Proposed TCP listener cutover on Unix. The old workers drain accepted sockets.
   :alt: The supervisor waits for the replacement to acknowledge readiness before moving TCP admission.

Bounded memory and disk state
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We keep live sockets, pending writes and authoritative admission counters in worker-owned memory. Only reconstructible stick-table and affinity hints may enter the optional mmap cache. A lost hint can change the choice for a new flow. Dropping a hint must never detach an active flow from its origin or lift an enforced ban.

The proposed cache has 64 shards, four-way buckets and a fixed frequency sketch per shard. A full bucket admits a candidate only when its estimated frequency exceeds the victim's. A sketch collision or aging can change that comparison. We budget the sketch, indexes, scratch space and queues in addition to the slots.

Worker ownership permits ordinary reads and writes within a shard. If we introduce shared readers, each payload access must itself be race-free, writers must serialize, and the sequence protocol must account for ordering, bounded retries and generation wrap. Retrying after an unsynchronized payload copy cannot repair a Rust data race.

A storage worker owns the fixed-size file mapping. Packet workers may enqueue bounded lookup or demotion requests. They proceed on a cache miss and shed cache writes when the queue fills. The storage service validates the format version, length, key, expiry and checksum before reusing an entry. We discard incompatible or corrupt cache files and rebuild from authoritative state. Disk faults, slow writes and storage exhaustion must be tested independently of the slot bound.

.. graphviz:: ../diagrams/spill.dot
   :caption: A worker can finish a cache miss even when the disk service stalls.
   :alt: A worker uses its RAM shard directly. A bounded queue separates optional cache writes from the storage service.

Backend selection and cluster routing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A new flow first filters out unhealthy, draining and administratively disabled servers. In standalone mode the default scheduler uses weighted least connections. We can select power-of-two choices with a peak-weighted moving latency estimate. In a regional mesh we propose a 65,537-entry Maglev table built from a revision with stable server IDs, ordering and hash parameters. A primary lookup takes constant work. A full fallback scan costs up to one probe per eligible backend. Exhaustion returns an admission failure.

A hard node-local backend limit requires an atomic reservation or disjoint worker quotas whose sum fits the limit. We release a reservation on connect failure, timeout or close. Independent nodes can observe different health and load. A fleet-wide hard cap would require a quota allocation protocol.

.. graphviz:: ../diagrams/atdp-regimes.dot
   :caption: Routing regime as a function of active peers and sampled p95 RTT.
   :alt: With peers present, the regional and wide-area regimes retain their previous state between the thresholds.

With no reachable authenticated peers we select standalone. With peers present we enter the regional mesh below 1.5 ms and the wide-area regime above 3.0 ms. At either boundary and between them we retain the current mesh or wide-area regime. The first peer observed in this interval selects the regional mesh. Regime changes apply to new admissions.

In the mesh we propose at most one authenticated peer hop for datagrams whose previous owner is known. An already-forwarded datagram with an unknown owner is dropped. Ordinary accepted TCP sockets cannot intercept a segment that ECMP redirects to another host. TCP continuity across such a change requires flow-stable upstream steering or a separate packet-level forwarding facility.

Regional peers can merge expiring ban deadlines by taking a maximum. Eventual convergence requires eventual delivery, including reconciliation after packet loss. Ownership transfers, revocation, counters and garbage collection need separate rules before they can share this mechanism. Discovery supplies candidate addresses. Only configured, authenticated peers contribute routing state. We bind mesh messages to a sender, key epoch and replay window and retire departed peers.

In the wide-area regime we prefer healthy local origins. Routing by QUIC connection ID requires an agreed server-issued ID format, rotation and a policy for the initial client-chosen ID. Tuple affinity alone cannot survive arbitrary client migration. HTTP routing cookies require a frontend with access to HTTP. We keep opaque TLS streams on their selected TCP connection.

Admission and extension points
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each frontend applies the checks its protocol supports. The proposed stages are kernel listener admission, local address and ban checks, protocol-specific address validation, packet and byte rate limits, bounded handshake inspection, flow and cache admission, and HTTP gate or shield processing. We measure the cost of each stage on the target host. An application-level filter can shed work only after the traffic reaches the host.

For TCP passthrough we bound both the ClientHello prefix and the time allowed to assemble it. Rules can use visible SNI, advertised ALPN or a JA4 fingerprint. Each frontend must define a fallback for absent, encrypted or incomplete metadata. On an accepted TLS passthrough flow we replay the buffered bytes exactly once to the origin. JA4 describes a handshake and has no authority as a client credential. We accept inbound PROXY v2 metadata only on listeners restricted to trusted senders. Outbound TLVs require agreement with the origin on their code, format and length.

For ordinary UDP we use bounded mappings, idle expiry and per-prefix packet and byte budgets. We restrict replies to the selected upstream and account for response amplification. A generic UDP client cannot echo a private cookie. QUIC passthrough leaves Retry to the endpoint unless edge and origin explicitly share the token validation and original connection ID contract. We must test interoperability and the pre-validation amplification limit before enabling edge-generated Retry.

We propose three plugin tiers. Compiled native Rust hooks are trusted daemon code. A Wasm hook has a fixed page budget, metered instructions, bounded host calls and no ambient WASI access. Fuel limits work per invocation. Wall-clock latency needs measurement. An out-of-process agent uses a bounded queue, deadline and circuit breaker. At timeout, overload or trap the hook returns its configured outcome. An authorization hook must fail closed. A telemetry hook may discard its sample.

Implementation boundaries
~~~~~~~~~~~~~~~~~~~~~~~~~

We propose small crates with borrowed inputs and plain-data results. The worker depends on the poller, scheduler and bounded cache interface. The configuration compiler, health probes, storage client and console can allocate within their own budgets. Operating-system calls belong in the platform adapters. Resource owners release sockets, file mappings and buffer leases through Rust lifetimes and Drop.

.. graphviz:: ../diagrams/edge-crates.dot
   :caption: Proposed crate dependencies. Arrows point from each consumer to its dependency.
   :alt: The daemon composes the worker and management crates. JLV evaluation and SQL storage remain on the management path.

Operator console
~~~~~~~~~~~~~~~~

SID 0007 and SID 0013 provide the management listener, peer statistics and node commands. We propose adding a frontend and backend view with health, revision, drain state, active flows, latency, queue pressure and drops by cause. An operator must be able to tell whether a node is draining or rejecting new flows for lack of capacity. Weight changes use the same revision checks as file or database changes.

The proposed fleet view grows from nine to 64 members, including the local node. We retain a dedicated management listener, bound concurrent browser and peer streams and reserve capacity for ordinary HTTP requests. Direct peers can be screened by source address at accept. A node behind a trusted proxy needs a bounded HTTP parsing slot before it can check the forwarded identity and route. A successful peer upgrade requires an allowed address, a configured sender identity and a fresh authenticated transcript. Outbound connections verify the peer certificate and hostname. Removing a peer closes existing streams and refuses subsequent upgrades. Operator CIDRs supplement the existing user authentication.

The current build ceiling for console.wasm is 768 KiB. The proposal requests a review at 1 MiB and a ceiling of 1.25 MiB for the expanded view. We measure the built asset and data-plane throughput with the management listener under load before adopting the increase. The figures in the mockup are illustrative.

.. typst-diagram:: ../diagrams/edge-operator-view.typ
   :caption: Proposed operator view of mesh links, node pressure and backend drain state.
   :alt: Three sample nodes and two backend pools show proposed metrics and operator controls.

What the Lean model establishes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The companion file is ``docs/sid/assets/distributed-edge-load-balancer.lean``. From the repository root we check it with Lean 4.19.0.

.. code-block:: sh

   lean docs/sid/assets/distributed-edge-load-balancer.lean

- **Scheduling.** ``maglevProbe_lt_ring`` bounds an index for a nonempty table. ``admitBounded_respects_cap`` preserves a common cap for one sequential admission from a valid load vector. ``findAvailable_some_of_under_capacity`` establishes that the full scan finds a candidate when total load is below aggregate capacity. ``pewmaCost_mono`` establishes a nondecreasing cost.
- **Cache.** The sequence lemmas check equality and parity over natural numbers. ``kvRun_preserves_bounds`` bounds two occupancy counters over a finite trace. The admission lemma for a candidate of frequency one assumes the supplied victim estimate is at least one. Memory ordering, sketch accuracy, page faults, RSS and process survival require separate evidence.
- **Cluster.** The componentwise maximum on three fields is associative, commutative and idempotent. ``stepRegime_no_flap`` covers active peers and a current mesh or wide-area regime inside the closed deadband. ``cpf_loop_free`` rules out a second forward when the forwarded flag is set. Packet delivery and ownership discovery are outside the model.
- **Admission.** ``udp_spoof_allocates_zero_state`` preserves the active-session counter given a false validity input. Token authentication and network costs are outside that predicate. ``early_drop_strictly_saves_cpu`` compares two cost expressions assuming positive rejected traffic and a cheaper early check.

Rationale and alternatives
--------------------------

Keeping an external load balancer gives us operationally mature L4 routing today. Integrating routing lets us apply frontend policy, select a backend and report admission outcomes from one configuration. It also makes the daemon responsible for UDP expiry, TCP backpressure and origin health.

Kernel bypass could give us packet-level steering for established TCP flows. Cooperative socket I/O keeps the existing deployment model and leaves routing with the host. That choice limits what a proxy can recover after ECMP moves an established flow.

Kapteko's experiment measures how many separately addressable web servers a process can represent. We measure established client flows and the work of forwarding them to origins. We record listener count, live connections, active requests, process memory and kernel socket memory separately.

A transactional database is appropriate for durable configuration and audit records. A bounded mmap cache serves a different workload in which we can discard entries and recover on a miss. We can deploy the RAM tier alone until measurements justify disk spill.

Canonical JSON gives us a self-contained configuration path. Reusing JLV/2 adds generation and validation tools shared with jlavideploy and jlavici. It also adds a compiler to build, bound and distribute.

Compatibility and rollout
-------------------------

Invocations without an edge configuration must keep the current single-origin HTTP behavior, CLI defaults, trusted-header rules and storage contents. Edge mode is an explicit opt-in. Persistent mode requires additive, versioned migrations for frontend, backend, server and source-revision records on both SQLite and PostgreSQL. A downgrade plan must account for the installed schema before a binary rollback.

We propose bringing up one node and one canary frontend first. Check admission, routing and drain against the existing ingress before moving a VIP. Enable disk spill, programmable hooks and mesh routing independently. To roll back, route new traffic to the previous ingress and keep the canary available for its established flows until the drain deadline.

Implementation evidence
-----------------------

The Rust implementation serves opt-in TCP, UDP and HTTP frontends from JSON or JLV. It includes node-local caps, weighted least connections, power-of-two choices with peak EWMA, bounded-load Maglev, TCP and HTTP probing, SNI, ALPN and native TCP JA4 routing, PROXY v2 with optional authority and JA4 TLVs, UDP affinity, RTT-based mesh regime selection and in-process route reload. HTTP frontends load HAProxy-style PEM bundles, select certificates by server name, serve HTTP/1.1 and HTTP/2 over TLS and HTTP/3 over QUIC, and reach HTTP/1.1, HTTP/2 and HTTP/3 servers in cleartext or over TLS. The firewall can be switched off for the node, a frontend or a route. The operations chapter of the book documents the configuration accepted by this version.

The worker keeps every socket registered with epoll on Linux and with poll elsewhere. It hands established TCP streams to relay threads. A turn costs time in proportion to the ready sockets, and a deadline sweep runs every 100 ms. The flow table is configurable up to one million entries. Its default remains 8,192.

On Linux 7.0 x86-64 with Rust 1.100 and an increased descriptor limit, we exercised 8,192 simultaneous TCP streams and, in a separate run, 8,192 UDP mappings against a loopback echo server. Each flow exchanged data. At the configured ceiling the daemon refused the next flow and the first flow still exchanged data. In a four-process loopback mesh each node forwarded a UDP request and reply. After three nodes stopped, the surviving node reverted to standalone.

On two Linux 7.0 x86-64 machines we used curl with certificate verification to negotiate HTTP/2 and HTTP/3 in both directions. Each node forwarded requests to an HTTP/1.1 origin on the other machine. We checked the origin's HTTP version, client address, scheme and 2 MiB request bodies. A denied route returned 403 on all three HTTP versions. On a single HTTP/1.1 connection we reached the remote origin and then the local origin by changing the path. Both nodes also forwarded raw TCP and UDP. A reload with a mismatched key preserved the serving identity. A valid rotation changed the certificate presented by both HTTP/2 and HTTP/3. When one node stopped, its peer returned to standalone and continued serving HTTP/3. The restarted node rejoined the mesh.

On one machine we chained two daemons. The first, configured in JLV, routed three host names to pools with ``http_version`` 1.1, 2 and 3 over verified TLS. The second terminated TLS, HTTP/2 and HTTP/3 with a ``crt`` bundle and ran with ``surface`` ``off``. Requests, a 941-byte body and a 250 MB body passed on all three paths. A route with the firewall on answered 401 while its neighbours answered 200. Editing the JLV file and sending SIGHUP swapped which name was guarded. A module that failed topology checks and a module with a syntax error were rejected with a message, and the serving routes stayed.

Beside HAProxy 3.0.11 on one host, TCP forwarding reached 97% to 103% of HAProxy's throughput with less memory. Plaintext HTTP reached 97% at 16 connections and 59% to 77% at 256 and 2,048. TLS reached 53% to 70% and HTTP/2 37% to 39%. ``benchmarks/results/edge-haproxy-2026-11-24.md`` holds the record. The HTTP firewall served each connection or exchange on a thread, and this was the cause: it made 2.9 context switches per request at 256 connections. SID 0016 replaced the threads with event-driven workers. Plaintext HTTP then reached 94% to 117% of HAProxy, TLS 80% to 92% and HTTP/2 53% to 58%, and ``benchmarks/results/edge-workers-2026-11-24.md`` holds that record.

Kapteko's experiment shows that a kernel socket costs about 3.4 KiB before any buffer, and that state per idle unit decides how far one host scales. A forwarded TCP stream here holds two kernel sockets and one relay record. On the thread path an HTTP connection also held a thread and its stack, which measured about 145 KiB of resident memory per connection at 2,048 connections. On the workers of SID 0016 an idle HTTP connection holds about 0.4 KiB in the process and a WebSocket tunnel about 2 KiB, so both paths now scale with kernel socket memory. Kernel bypass would remove the socket cost. We do not plan it, because it would also remove the host network stack that the design keeps.

Cooperative platform-specific batching and the ten-million-flow experiment remain proposed work. The three plugin tiers are built for the edge (SID 0030): native hooks, Wasm hooks on an in-house metered interpreter, and agents on a Unix socket; a failure is configured with ``on_failure`` and not with ``on_trap``, a connection that waits for an agent is parked and decided by judge threads, a QUIC connection is judged when its ClientHello is read, and an agent call at the request stage still holds its thread. The operator console is built (SID 0031): the views of a node and of a fleet of 64 members, and the commands of the admin socket. The admission stages at the socket edge are complete for TLS passthrough, kernel listener admission and QUIC address validation (SID 0032); edge-generated Retry is specified there and not built. Bans, lifted bans and the run-time commands for servers are replicated (SID 0022). A learned sticky table is replicated, and ``max_flows`` can bound a server over all nodes by a quota protocol (SID 0025). A node forwards a new connection or a UDP client to the node that owns the client (SID 0026); an established TCP connection whose packets move to another node is not repaired. One file reloads a cluster from any node (SID 0023), which serves a small cluster without a database. A database is the authority for the published topology in persistent mode, with history and rollback (SID 0028). It stores one checked document for each revision and not rows, and the console does not edit it yet. Descriptor passing for the listener handoff and the handoff of live UDP mappings are built for Linux (SID 0029). The mmap spill cache is built as the disk tier of the learned sticky table (SID 0027). SID 0027 records the 50-million-key measurements, including the retention denominator and storage conditions. The following evidence is required to qualify the full design.

#. Compare legacy CLI behavior on the existing HTTP suite. Check that equivalent JSON and JLV produce the same topology. Reject missing references, stale database edits, incompatible listener changes and exhausted evaluation budgets while the last valid revision continues serving.
#. Exercise partial writes, half-closes, fragmented ClientHello, UDP expiry, lost replies and failed backend connects. Record open sockets and buffer leases before and after each test. Run the same cases through each advertised OS backend.
#. During reload and binary handoff, trace long-lived TCP streams, UDP mappings, failed readiness and expiry of the drain deadline. Count resets, lost or duplicate datagrams, forced closes and outstanding reservations. Publish the supported continuity contract for each protocol.
#. Measure memory at idle and under load, including kernel buffers, mappings, queues and retained snapshots. Exercise 50 million distinct candidate keys against 64 MiB of RAM cache and a 512 MiB arena. Seed and repeatedly access a known working set. Report its retention against the proposed 99.9% target alongside RSS, page faults, queue drops and tail latency with a slow or unavailable disk.
#. On four nodes vary RTT across both thresholds and at their endpoints. Partition and rejoin peers, lose and reorder deltas, change membership during live flows and rotate credentials. Check local caps, the one-hop limit, replay rejection and the published routing revision.
#. Check the Wasm page and fuel bounds, plugin timeout policy, console asset size and revocation of an active peer. Compare forwarding throughput on the same hardware and workload with the console idle and saturated. Report variation against the proposed maximum 1% throughput loss.
#. Run the workspace checks and exercise concurrent state access under Miri where supported. Report platform, kernel, hardware, memory budget and workload alongside any connection-count or nanosecond result.

Open questions
--------------

#. Which platforms can preserve UDP ownership during upgrades, and which require a drain? Which deployments can supply flow-stable TCP steering through an ECMP change?
#. Should Linux socket steering and mmap spill require explicit opt-in? What improvement over portable I/O and RAM-only caching warrants enabling either by default?
#. Which Wasm runtime satisfies the instruction, host-call and dependency budgets? What measurements would justify linking it into a worker? SID 0030 answers this with an in-house interpreter and records the measurements against wasmi.
#. Which mesh state needs anti-entropy, expiry or authoritative revocation? What consistency does each frontend require when its node is partitioned?

Review history
--------------

- 2026-11-24. Initial proposal for cooperative socket I/O, bounded state, JLV/2 configuration, adaptive cluster routing, plugin hooks and console changes.
- 2026-11-24. Implementation review added PEM bundles, HTTP/1.1 over TLS, TLS, HTTP/2 and HTTP/3 origins, HTTP probes, per-route firewall selection, the UDP share of the flow table, relay threads on epoll and a comparison with HAProxy.
- 2026-11-24. Pre-promotion review corrected flow memory accounting, narrowed upgrade and concurrency claims, checked the Lean file with version 4.19.0 and identified the implementation evidence required for deployment.

- 2026-11-25. On two Linux x86-64 hosts we tested the RC1 binary with certificate verification. Both frontends served HTTP/2 and HTTP/3 through an HTTP/1.1 origin. We changed the origin on one node and issued ``reload cluster``. Both frontends then reached the new origin over both client protocols and reported matching file digests.

References
----------

- Kapteko, `15 million web servers on one VM <https://kapteko.com/15-million-webservers/>`_ (2026).

- SID 0001 (process), SID 0002 (foundation), SID 0006 (formal models), SID 0007 (console), SID 0010 (Rust port), SID 0011 (storage), SID 0013 (console storage) and SID 0014 (trusted JA4).
- Jlavideploy JDD 0004 and JDD 0016 describe the JLV language. The jlavici workflow proposal illustrates the shared configuration model.
- Eisenbud et al., *Maglev: A Fast and Reliable Software Network Load Balancer* (NSDI 2016). Mirrokni, Thorup and Zadimoghaddam, *Consistent Hashing with Bounded Loads* (SODA 2018).
- Einziger, Friedman and Manes, *TinyLFU: A Highly Efficient Cache Admission Policy* (2017). Almeida, Shoker and Baquero, *Delta State Replicated Data Types* (2018).
- IETF, `QUIC connection IDs and address validation <https://www.rfc-editor.org/rfc/rfc9000.html>`_. See sections 5.1 and 8.1.
- The Rust Reference, `Behavior considered undefined <https://doc.rust-lang.org/reference/behavior-considered-undefined.html>`_.

.. rubric:: Lifecycle event

::

   2026-11-24: prediscussion -> discussion. Assigned a permanent number and
   opened for discussion.
