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

Everything in the section but the list of the other members is read at the start: the listener, ``data_dir``, the proxy settings, ``allow_operators``, the key files and the number of this node. A reload that changes one of them, or adds or drops the section, is refused with ``ADM008`` and the reason, and the routes stay. A reload may remove members. A reload that adds a member, or changes the entry of one, is accepted, and the entry is used after a restart: the daemon logs ``EDGE013``.

The views
~~~~~~~~~

``GET /console/api/edge`` returns the view of this node. A signed-in user of any role may read it, and a token with the scope ``stats_read``. The read spends the query allowance of the session. A console without an edge answers 404, and its session reply has no member ``edge``. The session reply of a node with an edge has ``"edge": true``, and the interface shows the page *Edge* only then.

.. code-block:: text

   { "node": { "node": 1, "version": "...", "uptime_seconds": 512, "state": "serving",
               "flows": 1204, "max_flows": 8192, "drops": 0, "reloads": 2,
               "runtime_changes": 1, "servers": 4, "servers_drained": 1, "servers_down": 0,
               "file_digest": "3fa9c1d2e4b50c77",
               "authority_revision": null, "regime": "regional",
               "refused": [ { "reason": "flow_limit", "count": 0 }, ... ] },
     "frontends": [ { "name": "web", "requests": 9120, "flows": 311, "bytes_in": 1, "bytes_out": 2,
                      "mean_micros": 3100, "p95_micros": 10000 } ],
     "pools": [ { "name": "app", "servers": [ { "name": "a", "address": "10.0.0.1:80",
                  "state": "ready", "weight": 2, "flows": 7, "health": "up", "backup": false,
                  "changed": "weight", "ejected_seconds": null, "ramp_percent": null,
                  "requests": 100, "failures": 0, "active": 1, "mean_micros": 2100,
                  "p95_micros": 5000 } ], "more": 0 } ],
     "queues": { "access_log_dropped": 0, "flow_log_dropped": 0 } }

``state`` is ``serving``, ``draining`` or ``full``. A node drains from the signal to stop until it ends: it answers "not ready" and refuses new flows with the reason ``draining``. A node is full when its flow table holds ``max_flows`` flows: it refuses new flows with the reason ``flow_limit``. The two states have different words, different colours and different counters, so an operator does not take one for the other. ``refused`` holds every reason of SID 0020 with its count. The columns of a server are those of ``show servers``, and its counters are the series of the metrics endpoint. A latency is a mean and the upper bound of the histogram bucket that holds the 95th percentile, both in microseconds. A view carries at most 256 servers over all pools and at most 128 pools and 128 frontends. ``more`` counts the servers of a pool that were left out, and ``show servers`` lists all.

The console thread does not read the table of the worker. It sets a flag and waits at most one second. The worker looks at the flag once in each turn, which is at most 25 ms long, and publishes its table. A view, or the failure to get one, serves every reader for 250 ms.

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

The route needs the action ``control_node`` and spends the mutation allowance of the session, also for the four commands that only read. No token reaches it. For a line that changes state the console writes an audit row with the line before it runs it (``node.command.intent``) and a second row with the result (``node.command.applied`` or ``node.command.rejected``). A line that only reads is not audited. The console then takes a token from a bucket of its own with the limit of the socket, 20 commands in a burst and 10 per second, and gives the line to the function that the admin thread calls. That function parses the line, loads the file for a reload, sends the command to the edge worker and waits five seconds. The worker applies it and, with a mesh, publishes it to the peers (SID 0022). The answer of the route is the answer of the socket: ``{"ok": true, "text": "..."}`` or ``{"ok": false, "code": "ADM005", "title": "...", "message": "...", "hint": "..."}``.

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

A file without ``console`` behaves as before. The firewall console keeps its options, routes and defaults. Its limit of eight peers becomes 63, and its quotas grow only with more than 16 peers. The peer query of the kind ``edge`` is answered ``unavailable`` by a node without an edge and refused as invalid by an older node. The ceiling of the console asset stays at 768 KiB: the module with the edge page measures 752,835 bytes, 28,505 more than before. The next page of this size will not fit. The review at 1 MiB and the ceiling of 1.25 MiB of SID 0015 stand.

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
     - Met. ``cmd/sibuna/tests/edge_console.rs``, ``the_view_agrees_with_show_servers_and_the_metrics``, starts the binary with an HTTP frontend and two servers, sends six requests and compares ``GET /console/api/edge`` with ``sibuna ctl SOCKET show servers`` cell for cell and with ``show stats``: the flow limit, the drops, the 13 refusal reasons, the requests and bytes of the frontend and the requests of each server. A drain from the console then shows in both.
   * - 2
     - A drain and a weight set in the console reach a second node.
     - Met. ``a_drain_and_a_weight_from_the_console_reach_the_second_node`` in the same file starts two binaries of one mesh. A drain and a weight posted to the console of the first appear in ``show servers`` and in the console of the second within five seconds. A change with ``local`` stays on the first. The digest in the view equals the one that ``show cluster`` prints.
   * - 3
     - A request without a session, without the role or without the CSRF token is refused, and so is a line off the list.
     - Met. Through the binary: ``a_request_without_a_session_a_token_or_a_listed_line_is_refused`` (401 without a session and with a forged cookie, 400 without the CSRF token, 403 for a bearer token, 400 ``CONSOLEEDGE`` for ``reload``, ``reopen log``, ``show info``, ``show stats``, ``help``; the edge counts no run-time change). Through the console with a recording edge: ``crates/console/tests/edge.rs`` (a viewer is refused with 403, another ``Origin`` with 400, no refused request reaches the edge, each change has an intent row and a result row, a read has none). The list itself: ``api::edge::tests``.
   * - 4
     - Streams over their quota are refused and ordinary requests are still served.
     - Met for browser streams. ``the_streams_are_bounded_and_the_reserve_and_the_data_plane_serve_on`` opens 64 streams on the binary, gets 503 for the next, opens 16 idle connections, and then still reads the view, runs a command and fetches through the load balancer. The quotas of a fleet are computed in ``config::budget::tests::a_fleet_grows_the_peer_quota_and_keeps_the_reserve`` (63 peers: 63 peer streams, 143 slots, a reserve of 16). No test holds 63 peer streams at once.
   * - 5
     - A removed peer loses its stream and cannot open another.
     - Met for the inbound stream. ``a_reload_that_removes_a_peer_closes_its_stream_and_refuses_it_after`` starts the binary with a fleet of three, opens the peer streams of two members with valid proofs, rewrites the file without one and runs ``reload``. The stream of the removed member ends with the close frame 1008 in under two seconds, its next upgrade is answered 403, and the stream of the other member stays open. ``crates/console/tests/peers.rs``, ``a_peer_outside_its_networks_is_refused_and_a_removed_peer_loses_its_stream``, shows the same on the console alone, and that the member leaves the reports. The end of the outbound connection to a removed peer has no test.
   * - 6
     - A peer upgrade from an address outside ``allow_ips`` is refused before its proof is checked.
     - Met. Both tests of criterion 5 send a valid, fresh proof of a member from an address outside its ``allow_ips`` and get 403 ``CONSOLEPEER``; the same proof shape from the right address is admitted. The order is in ``crates/console/src/api/peer.rs``: the address check stands before the call that verifies the proof. ``crates/serve/tests/listener.rs``, ``a_screened_source_is_closed_before_it_takes_a_slot``, and ``operator_networks_screen_every_request`` in ``crates/console/tests/edge.rs`` cover the screen at accept and ``allow_operators``.
   * - 7
     - The console asset is under its ceiling.
     - Met. The built module is 752,835 bytes under the ceiling of 786,432 bytes (768 KiB), which ``cmd/sibuna/build.rs`` enforces at every build. Before this record it was 724,330 bytes.
   * - 8
     - The data plane loses at most 1% of its throughput while the console is under load.
     - Not met as stated: the measurement cannot show 1% on this machine. Method: ``measure_the_data_plane_with_the_console_idle_and_under_load`` in ``cmd/sibuna/tests/edge_console.rs``, run with ``cargo test --release -p sibuna --test edge_console measure -- --ignored --nocapture``. The release binary serves an HTTP frontend on the loopback address in front of one keep-alive origin. Eight client connections send requests for three seconds, 24 times, in turn under three conditions: the console idle; its console under load (64 browser streams open, and four clients that read the view and the fleet and run ``show servers`` as fast as the console answers, about 8,400 requests a second); and the same load on the console of a second, unrelated daemon. Nothing is pinned, and other builds ran on the machine (32 processors, load average 15). Medians of eight runs, in requests a second, first run: 154,602 idle, 137,346 with its console under load (0.888), 142,835 with the other console under load (0.924). Second run: 143,189, 128,940 (0.901), 127,008 (0.887). The load costs the data plane 8 to 11 percent whether it falls on its own console or on the console of another process. So the loss is the price of the load generator and the console threads on shared processors, and the measurement shows no cost of the coupling beyond the spread of its runs, which is several percent. A machine with the console threads and the generator on processors of their own is needed to show 1%.

The model ``docs/sid/assets/edge-console.lean`` checks with Lean 4: a stream is admitted only under its quota and never into the reserve, a removed member is never admitted again, and every command of the console is a command of the socket.

Known gaps
----------

#. Criterion 8 is not established. See its row.
#. A member that joins, or whose entry changes, is used after a restart. Only removal is live.
#. The console does not terminate TLS. Peers need a TLS proxy in front of every console, the screen at accept sees the proxy, and the address of a peer is the first entry of ``X-Forwarded-For`` that this proxy sets.
#. The console of an edge shows the pages of the firewall console with empty data. The node commands of its *Nodes* page (drain, resume, clear bans) are accepted and do nothing on an edge: the edge has no drain flag of that kind. Servers are drained on the page *Edge*.
#. The database authority of SID 0028 does not exist in this tree. ``authority_revision`` is always ``null``.
#. No test runs a fleet of 64. The tests use two and three members, and the quotas of 63 peers are checked by arithmetic.
#. The end of the outbound connection to a removed peer, the answer ``ADM009`` of the bucket of the console, and the state ``full`` of a real node have no test. The interface is tested natively, with its harness, and was not opened in a browser. It has no golden fixture.
#. The fleet view holds one request thread for up to five seconds when a member is silent.
#. An answer of ``show servers`` or ``show ca`` above the input limit of the interface is shown as a failed request. The view is bounded at 256 servers for the same reason.
#. The console threads are not pinned to processors of their own. SID 0015 names ``management_cpus``, and this record does not build it.
#. A build without the ``console`` feature, or for a system without Unix sockets, refuses a file with a ``console`` section.

Open questions
--------------

#. Should the console terminate TLS itself, so that a peer is screened by its own address at accept and no proxy is needed?
#. Should a member that joins be connected without a restart?

Review history
--------------

- 2026-11-25. Initial draft.
- 2026-11-25. Review of the design by its author, against the code that exists and while the new code was written. Six faults, all corrected in the text above. (1) The draft let the peers of the firewall console grow from 8 to 63 and with them the nodes page and the ``nodes`` topic, whose protocol holds nine members. Those two now show the first eight peers, and the fleet view carries the 64. (2) The draft closed the stream of a removed peer at its periodic check, which runs every five seconds, and promised two. The writer of a stream now compares a removal counter in each turn of 100 ms. (3) The draft screened a peer by its source address at accept. Peers arrive through a TLS proxy, so the source is the proxy. The accept screen admits the proxy, and the address of the peer is checked in the request, before the proof. (4) The draft grew the quotas for every console. They grow only with more than 16 peers, so a firewall console reserves what it reserved. (5) The draft audited with new actions. The audit table binds its actions with a ``CHECK``, and a new action is a migration. The rows use the three actions of a node command, with the target ``edge``. (6) The draft raised the asset ceiling to 1 MiB before the asset was measured. It is measured, and the ceiling stays.
- 2026-11-25. Hostile review of the code by its author. Five faults found and corrected. (1) A console thread held the lock of the cached view while it waited one second for the worker. With a worker that does not answer, every reader waited behind the one before it. A failure is now cached for 250 ms as a view is. (2) The console called the function of the admin thread without the limit of 20 commands in a burst and 10 per second, which the socket applies before that function. Several sessions together could send more than the socket admits. The console now keeps a bucket of the same limit and answers ``ADM009``. (3) The first cut sent up to 1,024 servers in a view. The interface refuses an event above its input limit and bounds a page at 512 KiB. A view now carries 256. (4) The session reply did not say whether the node has an edge, so the interface could not hide the page on a firewall console, where the routes answer 404. The reply carries ``edge`` when true, and is unchanged otherwise. (5) The log line for a changed peer took the code ``EDGE014`` while ``EDGE013`` was free. Not corrected, and listed under known gaps: the node commands of the firewall page do nothing on an edge; the outbound link to a removed peer is not tested.

References
----------

- SID 0007, Console Management Interface. SID 0012, Console TLS. SID 0013, Console Storage.
- SID 0015, Distributed Edge Load Balancer. SID 0018, Quick Start and Admin Socket. SID 0020, Edge Observability.
- SID 0022, Replicated Bans on the Edge Mesh. SID 0023, One Configuration File for a Cluster.
- ``docs/sid/assets/edge-console.lean``.
