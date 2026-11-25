:sid-number: 0022
:sid-title: Replicated Bans on the Edge Mesh
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-24
:sid-updated: 2026-11-24
:sid-discussion: No external discussion URL assigned
:sid-summary: Carries each ban of a client from the node that issued it to the other nodes of the mesh, as an authenticated datagram whose merge is a maximum, so that a client banned on one node is banned on all.
:sid-labels: ["architecture","load-balancer","cluster","firewall"]

Replicated Bans on the Edge Mesh
================================

Abstract
--------

A cluster of edge nodes shares its addresses through DNS or ECMP. A client that one node bans reaches another node with its next connection, and that node knows nothing of the ban. We carry each ban over the mesh of SID 0015. A node that bans a client tells its peers the client and the time the ban ends. A peer keeps the later of the end it knows and the end it hears. This merge is a maximum, so a datagram may arrive twice, late or out of order without changing the result.

An operator observes one thing. With a ``mesh`` in the topology, a client that walks into the honeypot of one node receives 403 from every node within a second.

Motivation and scope
--------------------

SID 0015 lists replicated state among its proposals and asks which mesh state needs anti-entropy and expiry. We answer for the one state whose absence an attacker can use today. A ban is issued by the honeypot, by a rule quota, or by an administrator. It lives in the ban table of one process. With three nodes an attacker has three times the attempts before every node has banned it by itself, and a ban by an administrator holds on one node only.

We do not replicate the rate limiters. Their counters change with every request, and each node already bounds what it serves. We do not replicate the counters of rate limits. Sticky tables were left out here and are replicated by SID 0025. An earlier draft also left out the lifting of bans and run-time server changes; both are now replicated. Sticky cookies need no replication: every node derives the cookie from ``http.secret_file``, which the nodes of a cluster share.

Specification
-------------

Invariants
~~~~~~~~~~

#. A ban is the pair of a client key and the Unix second at which it ends. The state of a node is a map from keys to ends. To merge two states we take, for each key, the later end.
#. The merge is commutative, associative and idempotent. Any order, repetition or loss of datagrams that still delivers each ban once gives every node the same map.
#. A datagram can only add a ban or extend one. No datagram shortens or lifts a ban.
#. A datagram is accepted only from an address of the roster and only with a valid tag under the group key.
#. A received end is cut to 30 days from the receiver's clock. An end that has passed is ignored.
#. Every structure has a bound: the bans a node remembers, the bytes of a datagram, the datagrams sent in one period, and the queue between the firewall and the mesh thread.
#. A request never waits for the mesh. The firewall hands a ban to the mesh thread without blocking, and a full queue drops the hand-over and counts it.

The client key
~~~~~~~~~~~~~~

The firewall knows a client by its key: the canonical text of an IPv4 address, or of the network of an IPv6 address under ``ipv6_prefix``. Each node places the key in its ban table with a secret of its own, so the hash cannot cross the wire. We send the key itself, at most 64 bytes. The nodes of a cluster must agree on ``ipv6_prefix``, or a ban of one IPv6 network on one node names another network on its peer.

The datagram
~~~~~~~~~~~~

The mesh already sends probes of 44 bytes: ``S``, ``E``, a version, a kind, the boot nonce of the sender, a sequence number and a tag. A ban datagram has kind 3 and the same first 28 bytes. One count byte follows, then that many entries, then the 16-byte tag over everything before it. An entry is the end as eight bytes, the length of the key as one byte, and the key. A datagram has at most 1,200 bytes, so it fits one packet on every path.

.. typst-diagram:: ../diagrams/ban-datagram.typ
   :caption: Ban datagram fields in wire order.
   :alt: A 28-byte header precedes the count and variable-length ban entries. The last 16 bytes authenticate everything before them.

The tag is the keyed BLAKE3 hash of the bytes before it, cut to 16 bytes, under the key that the probes use. The kind byte is inside the hashed part, so a probe cannot be turned into a ban datagram.

We need no replay window. A replayed datagram states ends that the receiver already holds, and the maximum leaves them as they are. A datagram replayed after its bans have ended names ends in the past, which are ignored.

Sending
~~~~~~~

A node sends each ban it issues three times: at once, one second later, and four seconds after that. Three sends survive the loss of two packets. They do not survive a partition. So a node also sends everything it remembers to a peer that returns. A peer returns when its probes carry a new boot nonce, which means that it restarted with an empty table, or when it answers a probe after three periods of silence. The node then walks its map for that peer, at most eight datagrams in each period of 500 ms.

A node remembers bans that it learned as well as bans that it issued, and sends both to a returning peer. It never sends a learned ban on receipt. Forwarding on receipt is what makes gossip loop, and a full roster has no use for it: every node hears every issuer directly.

Receiving
~~~~~~~~~

The mesh thread checks the source address, the length, the version and the tag. It reads at most the entries that the count states and stops at the first entry that does not fit. For each entry it cuts the end to 30 days ahead, drops it when it has passed, and merges it into its map. When the merge moved the end, it bans the key in the ban table of the firewall until that end.

Memory
~~~~~~

The map holds at most 65,536 bans. An entry takes the key, the end and the state of its three sends. Every ten seconds the thread removes the bans that have ended. When the map is full and none has ended, a new ban is not remembered and is counted. The ban table of the firewall still holds it on the node that issued it.

Configuration
~~~~~~~~~~~~~

Replication needs no setting. It runs whenever the topology has a ``mesh`` and an HTTP frontend with the firewall. ``mesh.replicate_bans: false`` turns it off.

.. code-block:: text

   fn edge() -> Map<Value> {
       return {
           mesh: {
               listen: "10.0.0.1:7946",
               peers: ["10.0.0.2:7946", "10.0.0.3:7946"],
               key_file: "/etc/sibuna/mesh.key",
           },
           frontends: { web: { binds: ["0.0.0.0:80"] } },
           backends: { app: { servers: ["10.0.1.1:80", "10.0.1.2:80"] } },
       }
   }

Run-time commands
~~~~~~~~~~~~~~~~~

An operator changes servers at run time through the admin socket: ``set server POOL/NAME state drain``, ``set server POOL/NAME weight N``, ``add server`` and ``del server``. In a cluster each command would have to be given on every node, and a node that restarts would forget it. The mesh therefore carries the command as it carries a ban.

The state is a second map, from a key to a number. The number starts with the Unix millisecond of the command, and the merge keeps the larger number. The later command for a key therefore wins on every node, whatever the order of arrival.

.. list-table::
   :header-rows: 1
   :widths: 16 40 44

   * - Command
     - Key
     - Number
   * - add, del
     - ``a``, the address, a line feed, ``POOL/NAME``
     - the stamp, 16 bits of weight, 1 bit: present
   * - state
     - ``s``, ``POOL/NAME``
     - the stamp, 1 bit: drained
   * - weight
     - ``w``, ``POOL/NAME``
     - the stamp, 16 bits of weight

Of two commands for one key in one millisecond the larger content wins everywhere: the drain over the return, the addition over the removal. The datagram has the form of a ban datagram with kind 4. A key holds at most 192 bytes.

A command is sent three times as a ban is. A returning peer receives the last command of each kind for every server, the additions first, so that a server exists before its state and its weight are set. A node refuses a number whose time lies more than 60 seconds ahead of its own clock. Without that bound one node with a wrong clock could overrule every later command. The map holds at most 8,192 entries and nothing in it ends. When it is full, a command for a new key stays local.

A received command is applied by the edge worker as a local command is, at most 64 in a turn, and logged as ``EDGE010: mesh: set server ...``. A node that cannot apply a command ignores it: it does not have the server, or its pool does not allow the change. The last word ``local`` keeps a command on its node. ``mesh.replicate_commands: false`` turns the sharing off.

One rule of the edge stays. A pool that places clients by a Maglev table refuses weights and membership at run time, with or without a mesh, because every node must build the same table at the same moment. That is the default pool of a mesh. Its servers change by ``reload cluster`` (SID 0023). Drains work on every pool.

Lifting a ban
~~~~~~~~~~~~~

``del ban ADDRESS`` lifts the ban of one client. The merge of bans keeps the later end, so a lift cannot be a smaller end: the next datagram of a peer would bring the ban back. A lift is an entry of a third map, from the client key to the end up to which bans are lifted. That map also merges by the larger number, in a datagram of kind 5.

A ban is in effect when it ends after the lift of its client. The node of the operator sets the lift to the end of the ban it knows, and to at least 60 seconds ahead, which covers a ban that it has not heard yet. Every node that hears the lift tells its firewall to admit the client and forgets the ban. A ban that arrives later with an end that the lift covers is ignored, so a peer that was cut off cannot bring the ban back. A ban that ends after the lift is a new ban and holds. A lift is forgotten when its end has passed, as a ban is.

Lifts travel when bans do. ``del ban ADDRESS local`` lifts on one node only.

Observation
~~~~~~~~~~~

The metrics of the edge gain five series: ``sibuna_edge_mesh_bans_sent_total``, ``sibuna_edge_mesh_bans_received_total``, ``sibuna_edge_mesh_bans_applied_total``, ``sibuna_edge_mesh_bans_dropped_total`` and ``sibuna_edge_mesh_bans_known``. ``sibuna ctl SOCKET show stats`` prints them.

Rationale and alternatives
--------------------------

*A maximum, not a log.* A replicated log orders operations and needs acknowledgements, a window and recovery. A ban has one useful operation, and it is monotone. A map merged by maximum is the smallest state-based replicated data type that carries it, and its three laws are the whole proof of convergence.

*The end, not the remaining time.* A remaining time would be independent of the clocks of the nodes. It would also make a replayed datagram start the ban again. With the end in the datagram a replay is harmless, and the cost is that a ban lasts longer or shorter on a peer by the difference of the clocks. Nodes of a cluster keep their clocks within a second, and bans last minutes.

*Direct sends, not gossip.* The roster is fixed and has at most 63 peers. Every node can reach every other. Epidemic forwarding earns its cost in large, changing groups.

*No lifting (rejected in review).* An earlier draft left the lifting of bans out: a lift is not monotone, so it must win against a ban in flight, which needs a version for each key. An operator who lifts a ban on one node expects it lifted on all, so the section "Lifting a ban" replaces this choice.

*UDP on the probe socket.* The mesh socket exists, is authenticated and is bound to the roster. A TCP stream to each peer would add connection state and a reconnect policy for a payload of a few bytes.

Security and operational considerations
---------------------------------------

The group key authorises a ban of any client on every node. This is the power that the key already implies: a holder of the key is a node. The key file must be readable by the daemon alone.

An attacker without the key cannot ban. An attacker on the path can replay, which changes nothing, and can drop, which the three sends and the walk for a returning peer repair.

A node with a wrong clock sends ends that are too early or too late. The cut to 30 days bounds the damage of a clock far ahead. A clock far behind sends ends in the past, which peers ignore, so its bans stay local.

A flood of bans, from an attack that walks many addresses into the honeypot, is bounded at each step: the queue to the mesh thread holds 1,024 bans, the map 65,536, and a walk sends eight datagrams in a period. What overflows stays local and is counted.

Backwards compatibility
-----------------------

A node without this record ignores a datagram that is not 44 bytes long. A node with it probes as before. A cluster may be upgraded node by node.

Acceptance criteria and implementation status
---------------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 6 54 40

   * - #
     - Criterion
     - Status
   * - 1
     - A ban issued on one node is in effect on its peers within one second.
     - Met. ``cmd/sibuna/tests/edge_mesh_bans.rs`` starts three processes. A client walks into the honeypot of the first, and both peers answer 403 within one second.
   * - 2
     - A node that restarts learns the bans in effect from its peers.
     - Met. The same test stops the third node after every send of the ban and starts it again. It refuses the client within five seconds. A unit test does the same with mesh threads.
   * - 3
     - A forged, cut or altered datagram changes nothing.
     - Met. A unit test changes every single byte of a datagram, cuts it and uses another key: none is read. A datagram with the right key from an address outside the roster is ignored.
   * - 4
     - Duplicated and reordered datagrams give the same map.
     - Met. A unit test merges the same bans forwards, and backwards followed by forwards, and compares the maps. The Lean model proves the laws.
   * - 5
     - The map, the queue and the sends stay within their bounds.
     - Met in unit tests for the map and the size of a datagram. The queue and the sends of a walk are bounded by construction and have no test under load.

The commands and the lifts have their own rows.

.. list-table::
   :header-rows: 1
   :widths: 6 54 40

   * - #
     - Criterion
     - Status
   * - 6
     - A drain commanded on one node holds on its peers and on a node that restarts, the later command wins, and a local command stays local.
     - Met. ``cmd/sibuna/tests/edge_mesh_bans.rs`` drains a server on one of three processes, returns it on another with ``local``, restarts the third, and ends the drain from the third.
   * - 7
     - A weight, an added server and a removed server hold on every node and on a node that restarts.
     - Met. The same file sets a weight, adds a server with a weight on another node, changes it from a third, restarts a node and removes the server. Unit tests cover the entry of each command, the order of arrival, the bound on the clock and a full map.
   * - 8
     - A lifted ban is lifted on every node, does not return, and a new ban holds again.
     - Met. The same file lifts a ban on the second of three processes, restarts the third, bans again from another node and lifts locally. A unit test sends the lifted ban again and a later one.

Formal model
------------

``assets/replicated-bans.lean`` models the map as a function from keys to ends and the merge as the pointwise maximum. Lean 4.19.0 checks it without libraries.

- ``merge_comm``, ``merge_assoc``, ``merge_idem``: the three laws of the merge.
- ``merge_keeps``, ``merge_learns``: a merge shortens no ban and takes in every ban it hears.
- ``replay_is_harmless``, ``order_is_irrelevant``: a datagram heard twice, and two datagrams in either order.
- ``heard_keeps``, ``heard_contains``: after any list of datagrams a node holds every ban it had and every ban it heard.
- ``admit_is_bounded``, ``admit_never_extends``: a received end lies within the horizon and never beyond the end that was sent.
- ``effect_ignores_order``, ``lift_ends_ban``, ``lifted_ban_does_not_return``, ``newer_ban_holds``: the rule of lifts.
- ``later_command_wins``: of two stamped commands the later is the larger number, whatever they say.

The model does not cover the schedule of the three sends, the walk or the expiry. Unit tests cover those.

Known gaps
----------

#. A ban issued after a lift holds on every node only when it ends after the lifted ban would have ended. Two bans of the same length always do. A shorter ban issued soon after a lift holds on its own node only.
#. Bans that an administrator configures are not sent. They belong in the policy file of every node.
#. The nodes must agree on ``ipv6_prefix`` and keep their clocks close. Neither is checked.
#. A ban issued while a peer is cut off for less than three probe periods, with all three sends lost, reaches that peer only with its next walk, which a restart or a longer silence starts.
#. A walk copies the map once for the returning peer, up to 65,536 entries.
#. The test of three processes runs on one host over loopback. On three separate hosts we timed bans, lifts and ``reload cluster`` by hand (Part X of the book); no automated test runs there.
#. Replication runs in edge mode only. The daemon mode of the firewall has no mesh.
#. The map of commands never forgets a key. A cluster that gives commands for more than 8,192 keys over its life, counting removed servers, keeps later commands local until its nodes restart.
#. Two operators who add one server name with two addresses on two nodes at the same moment can leave the nodes with different addresses for it. The next command for that name settles it.
#. A reload returns a node to its file, as it does without a mesh. Commands given before the reload stay in force on the peers until they reload too. ``reload cluster`` reloads all nodes.
#. Pools that place clients by a Maglev table take no weights or members at run time.
#. Commands and lifts have no metrics of their own. Their effect shows in ``show servers`` and in the log.
#. A node whose clock is more than 60 seconds behind its peers has its commands overruled by their earlier ones. A node whose clock is more than 60 seconds ahead has its commands refused by its peers.
#. The Lean model covers the merge, the rule of lifts and the order of stamped commands. It does not model the bound on the clock, the schedule of sends or the walk.

Open questions
--------------

#. Should the lifting of a ban be replicated, with a version for each key?
#. Should a drain of SID 0018 travel the same way?

Review history
--------------

- 2026-11-24. Initial draft.
- 2026-11-24. Drain commands added on the same datagram and merge, after the question of what else a cluster must share. Configuration is not shared: every node reads its own file.
- 2026-11-24. Implementation and its review. The review found two faults. The mesh thread starts before the firewall, so a walk could arrive before the firewall could take bans: the bans were merged and never applied. The mesh now remembers them and applies them once the firewall has given its sink. The test of three processes then showed that a restarted node died: the daemon wrote the routing regime to a standard error that nobody read, and ``eprintln!`` ends a process there. The lines of the running edge are now written without that, and the test closes the pipe on purpose.
- 2026-11-25. Weights, added and removed servers, and lifted bans added. The drain map became the map of commands with a tagged key, and its configuration key became ``mesh.replicate_commands``. The review found that the default pool of a mesh refuses weights and members by design. We kept that rule and say so.

References
----------

- SID 0015, the mesh and its open question on replicated state. SID 0018, run-time changes are local to a node.
- Almeida, Shoker and Baquero, *Delta State Replicated Data Types* (2018).
- HAProxy Configuration Manual, section 3.5, "Peers", https://docs.haproxy.org/3.0/configuration.html#3.5

.. rubric:: Lifecycle event

::

   2026-11-24: prediscussion -> discussion. First draft by the author; open
   for discussion before implementation
