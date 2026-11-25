:sid-number: 0031
:sid-title: The Operator Console of the Edge
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-25
:sid-updated: 2026-11-25
:sid-discussion: No external discussion URL assigned
:sid-summary: Starts the console of SID 0007 beside the edge, adds a view of frontends, backends and the fleet, and lets an operator drain and weigh servers from it through the checks of the admin socket, on a bounded listener with a fleet of 64 members.
:sid-labels: ["architecture","load-balancer","console","cluster"]

The Operator Console of the Edge
================================

Abstract
--------

The console of SID 0007 serves the HTTP firewall. The edge of SID 0015 has an admin socket and no console. We start the same console beside the edge, from a ``console`` section of the topology file. We add one page with the frontends, the backends and the fleet. We let an operator run the commands of the admin socket from that page. The console adds no command: it hands the line to the code that the admin socket runs.

Motivation and scope
--------------------

An operator of several edge nodes asks three questions. Does this node take new flows, and if not, does it drain or is it full? Which servers are out, and why? Do all nodes serve the same file? The admin socket answers them on one node, as text, for a user with a shell on that node. The console answers them in a browser for a signed-in user, for all nodes.

We specify the ``console`` section, the data endpoints, the command path, the bounds of the listener, the screening of peers and the removal of a peer. We do not specify the database authority of SID 0028, a history of revisions, or the edit of routes in the browser. We do not change the firewall console: its routes, roles and limits stay.

Specification
-------------

Invariants
~~~~~~~~~~

#. The console adds no power. Every command it runs is on the list below, is a command of the admin socket, and runs through the parser and the worker of the admin socket.
#. Every request passes the checks of SID 0007: the session or token, the role, the ``Origin`` field and the CSRF token of a ``POST``, and the allowances for reads and mutations. A command needs the action ``control_node``, as the drain of the firewall console does.
#. The edge worker never waits for the console. A console thread asks, and the worker answers between two batches, as it answers the admin socket.
#. The listener holds at most its slots. Browser streams and peer streams have a quota each, and neither takes a slot of the reserve for ordinary requests.
#. A peer stream belongs to a configured member. A member that leaves the file loses its stream within two seconds and cannot open another.

The console section
~~~~~~~~~~~~~~~~~~~

.. code-block:: text

   console: {
       data_dir: "/var/lib/sibuna",
       node_file: "/etc/sibuna/console.node",
       behind_proxy: true,
       trusted_proxies: ["10.99.0.2/32"],
       allow_operators: ["10.99.10.0/24"],
       key_file: "/etc/sibuna/console.key",
       peer_key_file: "/etc/sibuna/console-peer.key",
       peer_ca_file: "/etc/sibuna/management-ca.pem",
       nodes: [
           { node: 1, listen: "10.99.0.11:9443", origin: "https://fra-edge-01.internal:9443", allow_ips: ["10.99.0.11/32"] },
           { node: 2, listen: "10.99.0.12:9443", origin: "https://fra-edge-02.internal:9443", allow_ips: ["10.99.0.12/32"] },
       ],
   },

``data_dir`` holds the SQLite file of the console: accounts, sessions and the audit log (SID 0013). The first account is made with ``sibuna console init-admin NAME --data-dir DIR`` while the daemon is stopped, as for the firewall.

``nodes`` names every member of the fleet, this node included, so the section is the same on all nodes and ``reload cluster`` of SID 0023 can carry it. A node finds itself by its number: ``node_file`` names a file that holds the number, or ``node`` gives it in place. The other entries are its peers. A fleet has at most 64 members. A single node writes ``listen`` and ``node`` and no list.

``listen``, ``data_dir``, ``behind_proxy``, the key files and the number of this node are read at the start. A reload that changes one of them is refused with the reason, and the routes stay. A reload may remove members. A reload that adds a member is accepted, and the new member is connected after a restart: the daemon logs ``EDGE014``.

The views
~~~~~~~~~

``GET /console/api/edge`` returns the view of this node. A signed-in user of any role may read it, and a token with the scope ``stats.read``.

.. code-block:: text

   { "node": { "node": 1, "version": "...", "uptime_seconds": 512, "state": "serving",
               "flows": 1204, "max_flows": 8192, "drops": 0, "reloads": 2,
               "runtime_changes": 1, "file_digest": "3fa9c1d2e4b50c77",
               "authority_revision": null, "regime": "regional",
               "refused": [ { "reason": "flow_limit", "count": 0 }, ... ] },
     "frontends": [ { "name": "web", "requests": 9120, "flows": 311, "bytes_in": 1, "bytes_out": 2,
                      "mean_ms": 3, "p95_ms": 10 } ],
     "pools": [ { "name": "app", "servers": [ { "name": "a", "address": "10.0.0.1:80",
                  "state": "ready", "weight": 2, "flows": 7, "health": "up", "backup": false,
                  "changed": "weight", "ejected_seconds": null, "ramp_percent": null,
                  "requests": 100, "failures": 0, "active": 1, "mean_ms": 2, "p95_ms": 5 } ] } ],
     "queues": { "access_log_dropped": 0, "flow_log_dropped": 0 } }

``state`` is ``serving``, ``draining`` or ``full``. A node drains from the signal to stop until it ends: it answers "not ready" and refuses new flows with the reason ``draining``. A node is full when its flow table holds ``max_flows`` flows: it refuses new flows with the reason ``flow_limit``. The two states have different words, different colours and different counters, so an operator does not take one for the other. ``refused`` holds every reason of SID 0020 with its count. The columns of a server are those of ``show servers``, and its counters are the series of the metrics endpoint.

``file_digest`` is the revision that a node reports today: the digest that ``show cluster`` prints. ``reloads`` counts the reloads since the start. ``authority_revision`` is the place of the revision of the database authority of SID 0028. It is ``null`` until that authority exists.

``GET /console/api/edge/fleet`` returns one row for each member: its number, the state of the link, and the summary of its node (the ``node`` object above) when the link is current. The console asks each peer over the authenticated stream of SID 0007 with a query of the kind ``edge``, all at once, and waits at most five seconds. A peer that does not answer has a row without a summary.

The commands
~~~~~~~~~~~~

``POST /console/api/edge/command`` takes ``{"line": "set server app/a state drain"}``. The line is a line of the admin socket. The console accepts these and refuses every other line with ``CONSOLEEDGE``:

.. code-block:: text

   set server POOL/NAME state ready|drain [local]
   set server POOL/NAME weight N [local]
   add server POOL/NAME IP:PORT [weight N] [local]
   del server POOL/NAME [local]
   del ban ADDRESS [local]
   reload cluster
   show servers | show cluster | show certs | show ca

The route needs the action ``control_node`` and spends the mutation allowance of the session, also for the four commands that only read. The console writes an audit row with the line before it runs it and a second row with the result. It then gives the line to the function that the admin thread calls. That function parses the line, loads the file for a reload, sends the command to the edge worker and waits five seconds. The worker applies it and, with a mesh, publishes it to the peers (SID 0022). The answer of the route is the answer of the socket: ``{"ok": true, "text": "..."}`` or ``{"ok": false, "code": "ADM005", "title": "...", "message": "...", "hint": "..."}``.

``reload``, ``reopen log``, ``show info`` and ``show stats`` are not offered. A plain ``reload`` of one node of a fleet makes the nodes differ, and the console is the tool for the fleet. The other three have their place in the view or on the host.

The listener
~~~~~~~~~~~~

The console keeps its own listener and its own threads. With a fleet of :math:`n` peers the quotas are 64 browser streams, :math:`\max(16, n)` peer streams and a reserve of 16 slots, in :math:`16 + 64 + \max(16, n)` slots: 96 for up to 16 peers, as today, and 143 for 63 peers. A stream over its quota is answered 503. The listener answers 503 when every slot is taken.

Connections are screened by source address at accept. Behind a proxy only the trusted proxies are served. Without a proxy, and with ``allow_operators``, only those networks are served. A screened connection is closed before it takes a slot or a thread. Behind a proxy, ``allow_operators`` is checked against the forwarded address of every request but the peer upgrade.

A peer upgrade passes four checks in this order: the request comes from a trusted proxy over HTTPS (SID 0007); the transcript names a configured member as its sender and this node as its target; the forwarded address lies in the ``allow_ips`` of that member; the proof is right under the peer key, the stamp is fresh and the transcript was never seen (SID 0007). Outbound connections verify the certificate and the host name of the peer (SID 0012).

Removing a peer
~~~~~~~~~~~~~~~

A reload with a file that no longer names a member removes it from the running console. The store refuses its next upgrade as it refuses an unknown sender. Its inbound stream closes at the next turn of its writer, within two seconds. The outbound worker ends its connection and stops. Its queued queries fail. Its row leaves the fleet view.

Rationale and alternatives
--------------------------

We start the console of SID 0007 and do not write a second one, because authentication, sessions, roles, the audit log, the bounded listener and the peer streams exist and are reviewed. The cost is a SQLite file on a node that had no storage.

We give the console the function of the admin thread and not a set of its own calls into the edge. A new check of the admin socket then holds for the console without a second change, and the list of commands is the only place where the two can differ.

We considered a general route that takes any line of the socket. It would offer ``reopen log`` and a single-node ``reload`` to a browser session, which no page needs. We considered sending commands to a peer through the console streams. The mesh carries them already, to every node, with a merge rule (SID 0022).

We considered putting the summary of a node into the statistics that peers stream every second. It would grow every snapshot of every console, and the fleet view is open rarely. A query on demand costs nothing while nobody looks.

We considered ``console`` options on the command line, as the firewall has them. A list of 64 members does not fit a command line, and a reload could not remove a member.

Security and operational considerations
---------------------------------------

A user with ``control_node`` can drain every server of every pool on every node of a mesh, as a user of the admin socket of one node can. The role is the gate. The audit log names the user, the address and the line.

The console listener is plain HTTP. Remote access needs a TLS proxy in front, and peers require it (SID 0007). The proxy must set ``X-Forwarded-For``: ``allow_ips`` and ``allow_operators`` are checked against its first entry, which only a trusted proxy may supply.

The console runs on its own threads and takes no lock of a request path. The view reads the atomic counters of SID 0020 and asks the worker for the table of servers at most four times a second. The measured cost on the data plane is in the acceptance table.

The peer key authenticates a member. A holder of the key at an address in ``allow_ips`` can read the statistics and the summary of a node. It cannot run a command: commands need a session.

Backwards compatibility
-----------------------

A file without ``console`` behaves as before. The firewall console keeps its options, routes and defaults. Its limit of eight peers becomes 63, and its quotas grow only with more than 16 peers. The peer query of the kind ``edge`` is answered ``unavailable`` by a node without an edge and refused as invalid by an older node. The ceiling of the console asset moves from 768 KiB to 1 MiB.

Acceptance criteria and implementation status
---------------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 6 44 50

   * - #
     - Criterion
     - Status
   * - 1
     - The view of a node agrees with ``show servers`` and with the metrics.
     - Pending.
   * - 2
     - A drain and a weight set in the console reach a second node.
     - Pending.
   * - 3
     - A request without a session, without the role or without the CSRF token is refused, and so is a line off the list.
     - Pending.
   * - 4
     - Streams over their quota are refused and ordinary requests are still served.
     - Pending.
   * - 5
     - A removed peer loses its stream and cannot open another.
     - Pending.
   * - 6
     - A peer upgrade from an address outside ``allow_ips`` is refused before its proof is checked.
     - Pending.
   * - 7
     - The console asset is under its ceiling.
     - Pending.
   * - 8
     - The data plane loses at most 1% of its throughput while the console is under load.
     - Pending.

Known gaps
----------

Pending.

Open questions
--------------

#. Should the console terminate TLS itself, so that a peer is screened by its own address at accept and no proxy is needed?
#. Should a member that joins be connected without a restart?

Review history
--------------

- 2026-11-25. Initial draft.

References
----------

- SID 0007, Console Management Interface. SID 0012, Console TLS. SID 0013, Console Storage.
- SID 0015, Distributed Edge Load Balancer. SID 0018, Quick Start and Admin Socket. SID 0020, Edge Observability.
- SID 0022, Replicated Bans on the Edge Mesh. SID 0023, One Configuration File for a Cluster.
- ``docs/sid/assets/edge-console.lean``.
