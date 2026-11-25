Configuring Sibuna with Jlavi
=============================

Jlavi is Sibuna's configuration language. We use it to describe the topology that Sibuna should serve. At startup or reload, Sibuna evaluates one JLV/2 module and validates its result with the same schema as a JSON configuration. Workers use the resulting routes for subsequent traffic.

We try each complete example in its own working directory. We stop the running example before starting another that uses the same port.

Read the language
-----------------

Source files use UTF-8. An identifier starts with an ASCII letter or underscore and can then contain digits. A newline ends a statement. Lists and records can span lines. Double quotes delimit text. A line comment starts with two slashes. A block comment runs from ``/*`` to ``*/`` and cannot nest.

We start with a function. Its parameters have types. The type after ``->`` describes its result. We can put this helper above the entry point in the same file.

.. code-block:: text

   fn address(host: Text, port: Int) -> Text {
       return "${host}:${port}"
   }

The call ``address("127.0.0.1", 9000)`` returns ``"127.0.0.1:9000"``. Inside a string, ``${...}`` inserts the value of the enclosed expression. A helper constructs data. Sibuna opens listeners only when it serves the resulting configuration.

Sibuna calls ``edge()`` with no arguments. Its result type is ``Map<Value>``. The keys are text. The values can have different types, so one map can hold a list of bind addresses beside a boolean switch. A list preserves order. For HTTP routes this matters because Sibuna uses the first matching route.

A colon separates a field name from its value. Commas separate fields and list elements. A trailing comma is allowed. Write a port as part of the quoted bind address, a connection limit as a decimal integer and a switch such as http3 as true or false.

Build a web pool
----------------

We can now describe the two timetable servers from :doc:`introduction` in a file. We save this module as ``edge.jlv``. A frontend listens on port 8080. Its ``default_backend`` names the timetable pool. The shield inspects HTTP requests, and the pool distributes admitted requests between two replicas.

.. code-block:: text

   fn edge() -> Map<Value> {
       let hosts = ["127.0.0.1", "127.0.0.2"]
       return {
           http: { surface: "shield" },
           frontends: { web: { binds: ["127.0.0.1:8080"], default_backend: "timetable" } },
           backends: { timetable: { servers: [for host in hosts: "${host}:9000"] } },
       }
   }

The binding ``let hosts`` gives the list a name for the rest of the function. Its value stays fixed. The expression ``[for host in hosts: "${host}:9000"]`` makes one server address per host in list order. We could write ``address(host, 9000)`` there if we included the helper above.

We check the module before opening the listener. To generate a module from a working ``sibuna lb`` command we add ``--print-config`` to that command.

.. code-block:: sh

   sibuna check -f edge.jlv
   sibuna --config-file edge.jlv

Name replicas with a helper
---------------------------

When replicas have names and weights, we can build each server record with the same function. We add the import at the top of the module and the helper before ``edge()``. The condition takes a boolean. The imported text library converts the name to lowercase.

.. code-block:: text

   import { text } from jlv.std.foundation

   fn replica(label: Text, address: Text, primary: Bool) -> Map<Value> {
       let name = text.lower(label)
       if primary {
           return { name: name, addr: address, weight: 2 }
       }
       return { name: name, addr: address, weight: 1 }
   }

In the first timetable pool we can replace the entire ``servers`` list with the expression below. Evaluating it produces two records that Sibuna can validate before it contacts either server.

.. code-block:: text

   [replica("East", "127.0.0.1:9000", true), replica("West", "127.0.0.2:9000", false)]

Serve and observe a protected application
-----------------------------------------

We save the following module as ``station.jlv``. We give the timetable a health check and twice as much weight on the first replica. A request must carry the station header to pass our request hook. The firewall checks it first. The separate connection hook asks a local agent about new connections on the staff frontend only.

.. code-block:: text

   fn edge() -> Map<Value> {
       return {
           global: {
               max_flows: 4096, workers: 2, admin_socket: "edge.sock",
               watch: "5s", shutdown_timeout: "10s",
           },
           http: {
               surface: "shield", policy_file: "policy.json", secret_file: "http.key",
               rate_limit: 120, rate_window: "10s",
           },
           plugins: {
               station: { kind: "native", hook: "require_header", settings: { name: "x-station" } },
               staff: { kind: "agent", socket: "staff.sock", deadline: "5ms", on_failure: "deny" },
           },
           hook_judges: { threads: 2, queue: 64 },
           frontends: {
               web: {
                   binds: ["127.0.0.1:8080"], default_backend: "timetable",
                   max_body: "64k", hooks: { request: ["station"] },
               },
               staff: {
                   binds: ["127.0.0.1:8081"], default_backend: "timetable",
                   hooks: { connection: ["staff"], request: ["station"] },
               },
           },
           backends: { timetable: {
               balance: { kind: "round_robin" },
               health_check: { kind: "http", path: "/healthz", expect_status: 200 },
               connect_timeout: "2s", response_timeout: "10s", retries: 1,
               servers: [
                   { name: "east", addr: "127.0.0.1:9000", weight: 2 },
                   { name: "west", addr: "127.0.0.2:9000", weight: 1 },
               ],
           } },
           observability: { access_log: { output: "stderr" }, listen: "127.0.0.1:9100" },
           console: { listen: "127.0.0.1:9443", data_dir: "console-data", node: 1 },
       }
   }

We set the node's flow limit in ``global`` and the HTTP request allowance in ``http``. The ``plugins`` map names the checks. Each frontend chooses which checks run. The two threads in ``hook_judges`` handle connection-stage agent calls, with room for 64 waiting connections. The console keeps its accounts and audit records in its own SQLite directory.

The value of ``http.policy_file`` names a JSON file. We save this policy as ``policy.json`` beside the module. It challenges requests by default and denies requests for the retired timetable. We run the commands from that directory so the relative paths resolve.

.. code-block:: json

   {
     "default_action": "CHALLENGE",
     "rules": [{ "name": "retired", "path": "/retired/*", "action": "DENY" }]
   }

.. code-block:: sh

   (umask 077 && openssl rand 32 > http.key)
   mkdir -p console-data
   sibuna init-admin admin --data-dir console-data
   sibuna check -f station.jlv
   sibuna --config-file station.jlv

We create the seed and administrator once. Each replica must answer ``GET /healthz`` and the staff agent must listen on ``staff.sock`` before it can admit staff connections. With Sibuna running, we can check readiness, inspect the pool and sign in at ``http://127.0.0.1:9443/console/``.

.. code-block:: sh

   curl http://127.0.0.1:9100/ready
   sibuna ctl edge.sock show servers
   sibuna ctl edge.sock show hooks

Route a browser and an RPC client
---------------------------------

This module uses a typed helper to name an origin. The public portal uses the shield. Calls under ``/orders.Orders/`` use an HTTP/2 pool and skip the browser firewall. The RPC service must authenticate its callers.

.. code-block:: text

   fn service(name: Text, address: Text) -> Map<Value> {
       return { name: name, addr: address }
   }

   fn edge() -> Map<Value> {
       return {
           global: { acme: { storage: "certificates", directory: "letsencrypt-staging" } },
           http: { surface: "shield" },
           frontends: { https: {
               binds: ["0.0.0.0:443"],
               tls: { auto: ["portal.example.org", "orders.internal"], http3: true },
               default_backend: "portal",
               routes: [{
                   host: "orders.internal", path_prefix: "/orders.Orders/",
                   backend: "orders", firewall: false,
               }],
           } },
           backends: {
               portal: { servers: ["10.0.0.10:8080"] },
               orders: { http_version: "2", servers: [service("rpc1", "10.0.0.11:50051")] },
           },
       }
   }

We replace the example names and addresses before deployment. For a public name the ACME authority must be able to validate our domain. For ``orders.internal`` Sibuna issues and renews the certificate locally. We install the local root certificate in each client's trust store.

Browsers can negotiate HTTP/2 over TCP or HTTP/3 over UDP on port 443. The portal pool uses the default HTTP/1.1 upstream. The orders pool selects HTTP/2 for gRPC trailers and streaming. For a public deployment we change the staging directory to ``"letsencrypt"`` after testing issuance. With an existing PEM bundle we replace ``auto`` with ``crt: "portal.pem"`` and supply the certificates and private keys for the names we serve.

Relay a TCP service
-------------------

Some clients speak a protocol of their own. We give the frontend and its pool the same protocol. This complete module relays a connection to one of two timetable feeds. The frontend limits new connections per source and the pool checks whether each feed accepts TCP connections.

.. code-block:: text

   fn edge() -> Map<Value> {
       return {
           frontends: { feed: {
               proto: "tcp", binds: ["127.0.0.1:7000"], default_backend: "feeds",
               rate_limit: { conn_per_10s: 200 },
           } },
           backends: { feeds: {
               mode: "tcp", health_check: { kind: "tcp" },
               servers: ["127.0.0.1:7001", "127.0.0.1:7002"],
           } },
       }
   }

Share a UDP topology
--------------------

Both nodes can use this module. In an empty directory we create mesh.key with 32 random bytes and copy it securely to the other node. Each node writes its own address and port from the nodes list into mesh.self. We run the check in that directory. The shared key authenticates peers, and accept_config lets them receive a cluster reload.

.. code-block:: text

   fn edge() -> Map<Value> {
       let peers = ["10.20.0.11", "10.20.0.12"]
       return {
           global: { admin_socket: "edge.sock", sticky_entries: 8192 },
           spill: { path: "dns.spill", size: "1m" },
           mesh: {
               nodes: [for peer in peers: "${peer}:7946"],
               self_file: "mesh.self",
               key_file: "mesh.key",
               accept_config: true, forward: {},
           },
           frontends: { dns: {
               proto: "udp", binds: ["127.0.0.1:15353"], default_backend: "resolvers",
               udp_defense: { mode: "rate_limit", threshold_pps: 200 },
           } },
           backends: { resolvers: {
               mode: "udp", sticky: "table", max_flows_scope: "fleet",
               servers: [
                   { name: "east", addr: "10.20.0.53:53", max_flows: 300 },
                   { name: "west", addr: "10.20.0.54:53", max_flows: 300 },
               ],
           } },
       }
   }

We run the first command on one node only. On the second node we use the same key and put 10.20.0.12:7946 in mesh.self. Each DNS listener serves clients on its own loopback interface.

.. code-block:: sh

   (umask 077 && openssl rand 32 > mesh.key)
   printf '%s\n' '10.20.0.11:7946' > mesh.self

The pool remembers a client's resolver. Each node keeps its own spill file for recovering choices after a restart. The mesh shares choices and the per-server flow allowance. We allow UDP port 7946 and the forwarding port 7947 (TCP and UDP) between peers. After starting both nodes we can compare their revisions with ``sibuna ctl edge.sock show cluster``.

Publish routes from a database
------------------------------

For a versioned topology we keep two modules. We use the first timetable example as ``edge.jlv``. Its ``frontends``, ``backends`` and ``http`` are the published revision. We save the following host settings as ``node.jlv``. The bind override lets this node serve the published web frontend on port 8180.

.. code-block:: text

   fn edge() -> Map<Value> {
       return {
           global: { admin_socket: "edge.sock" },
           authority: {
               sqlite: "authority.db", node: "station-1", poll: "5s",
               cache: "authority.cache", binds: { web: ["127.0.0.1:8180"] },
           },
       }
   }

.. code-block:: sh

   sibuna authority apply -c node.jlv -f edge.jlv --expect 0 --note "first timetable"
   sibuna authority history -c node.jlv
   sibuna --config-file node.jlv

This example uses a build with SQLite support. We use revision zero only for a new database. Before the next change we run ``sibuna authority diff -c node.jlv -f edge.jlv`` and apply against the revision we reviewed. SQLite serves one host. With PostgreSQL support we can serve a fleet. We replace ``sqlite`` with ``postgres_url_file`` pointing to a protected file containing the PostgreSQL connection URL. Each host supplies its own node name and bind overrides.

Evaluation and diagnostics
--------------------------

Sibuna exposes the pure ``jlv.std.foundation`` library. Helpers live in the same module. Deployment resources, filesystem operations and imports from neighbouring files are outside this interface. Source and resulting JSON each have a 256 KiB limit. Evaluation has a budget of one million steps.

If the compiler reports an unknown name, we check its spelling and type at the reported line and column. If validation reports an unknown backend, we check that the route names a pool in the returned map. A rejected reload keeps the previous routing configuration.

Where to configure each part
----------------------------

The following sections give the supported options, defaults and restart rules. A map in an operations example belongs at the same position in the value returned by ``edge()``. A quoted JSON field such as ``"max_flows": 4096`` can be written as ``max_flows: 4096`` in Jlavi.

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Jlavi field
     - Operations reference
   * - ``global``
     - :ref:`edge-global-limits`, :ref:`edge-reload-drain-and-shutdown`, :ref:`edge-replacing-the-binary-without-losing-a-connection`
   * - ``frontends``
     - :ref:`edge-http-routing-by-name-and-path`, :ref:`edge-redirects-headers-and-body-limits`, :ref:`edge-websockets`, :ref:`edge-admission-at-the-socket-edge`, :ref:`edge-tcp-inspection-and-proxy-v2`
   * - ``frontends.*.tls``
     - :ref:`edge-tls-certificates`, :ref:`edge-automatic-https`
   * - ``backends``
     - :ref:`edge-scheduling-and-health-checks`, :ref:`edge-timeouts-and-failover`, :ref:`edge-servers-that-speak-tls-http-2-or-http-3`, :ref:`edge-grpc`
   * - ``http``
     - :ref:`edge-turning-the-firewall-on-and-off`, :ref:`edge-rate-limiting`, :ref:`edge-the-http-object`, :ref:`edge-declarative-policy`
   * - ``mesh``
     - :ref:`edge-bans-across-a-cluster`, :ref:`edge-one-file-for-the-cluster`, :ref:`edge-one-node-for-each-client`
   * - ``spill``
     - :ref:`edge-sticky-sessions`, :ref:`edge-keeping-the-sticky-table-over-a-restart`, :ref:`edge-a-sticky-table-and-a-limit-for-the-whole-cluster`
   * - ``observability``
     - :ref:`edge-observing-the-edge`
   * - ``console``
     - :ref:`edge-the-operator-console-of-the-edge`
   * - ``plugins``, ``hook_judges``
     - :ref:`edge-hooks-a-decision-of-our-own-on-the-path`
   * - ``authority``
     - :ref:`edge-a-database-for-the-topology`

Standalone firewall deployments select reverse proxy or forward authentication with ``--mode``. Their incident and reputation storage is configured on the daemon command line. We use :ref:`edge-daemon-options` for those flags and :ref:`edge-packaging` for service installation.
