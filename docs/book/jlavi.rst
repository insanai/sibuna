Configuring Sibuna with Jlavi
=============================

A Jlavi file describes the topology that Sibuna should serve. At startup or reload, Sibuna evaluates one JLV/2 module and validates its result with the same schema as a JSON configuration. Workers use the resulting routes for subsequent traffic.

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

Check the module before opening the listener. For a starting point based on an existing command line, ``sibuna lb --print-config`` writes a complete JLV module to standard output.

.. code-block:: sh

   sibuna check -f edge.jlv
   sibuna --config-file edge.jlv

Read the language
-----------------

Source files use UTF-8. An identifier starts with an ASCII letter or underscore and can then contain digits. A newline ends a statement. Lists and records can span lines. Double quotes delimit text. A line comment starts with two slashes. A block comment runs from ``/*`` to ``*/`` and cannot nest.

The entry point takes no arguments. ``Map<Value>`` lets one record hold text, booleans, integers, lists and nested records. In the first module, let binds the list once. The for expression visits each host in order and inserts its text into the address at ``${host}``.

A colon separates a field name from its value. Commas separate fields and list elements. A trailing comma is allowed. Write a port as part of the quoted bind address, a connection limit as a decimal integer and a switch such as http3 as true or false.

Route a browser and an RPC client
---------------------------------

This second module uses a typed helper to name an origin. The public portal uses the shield. Calls under ``/orders.Orders/`` use an HTTP/2 pool and skip the browser firewall. The RPC service must authenticate its callers.

.. code-block:: text

   fn service(name: Text, address: Text) -> Map<Value> {
       return { name: name, addr: address }
   }

   fn edge() -> Map<Value> {
       return {
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

Share a UDP topology
--------------------

Both nodes can use this module. In an empty directory we create mesh.key with 32 random bytes and copy it securely to the other node. Each node writes its own address and port from the nodes list into mesh.self. We run the check in that directory. The shared key authenticates peers, and accept_config lets them receive a cluster reload.

.. code-block:: text

   fn edge() -> Map<Value> {
       let peers = ["10.20.0.11", "10.20.0.12"]
       return {
           mesh: {
               nodes: [for peer in peers: "${peer}:7946"],
               self_file: "mesh.self",
               key_file: "mesh.key",
               accept_config: true,
           },
           frontends: { dns: {
               proto: "udp", binds: ["127.0.0.1:5353"], default_backend: "resolvers",
           } },
           backends: { resolvers: { mode: "udp", servers: ["10.20.0.53:53"] } },
       }
   }

We run the first command on one node only. On the second node we use the same key and put 10.20.0.12:7946 in mesh.self. Each DNS listener serves clients on its own loopback interface.

.. code-block:: sh

   (umask 077 && openssl rand 32 > mesh.key)
   printf '%s\n' '10.20.0.11:7946' > mesh.self

Evaluation and diagnostics
--------------------------

Sibuna exposes the pure ``jlv.std.foundation`` library. Helpers live in the same module. Deployment resources, filesystem operations and imports from neighbouring files are outside this interface. Source and resulting JSON each have a 256 KiB limit. Evaluation has a budget of one million steps.

If the compiler reports an unknown name, we check its spelling and type at the reported line and column. If validation reports an unknown backend, we check that the route names a pool in the returned map. A rejected reload keeps the previous routing configuration.
