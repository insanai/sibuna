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

We do not replicate the rate limiters. Their counters change with every request, and each node already bounds what it serves. We do not replicate the lifting of bans, sticky tables or run-time server changes. Sticky cookies need no replication: every node derives the cookie from ``http.secret_file``, which the nodes of a cluster share.

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

.. code-block:: text

   0        4               20        28   29                          n-16      n
   +--------+---------------+---------+----+---------------------------+---------+
   | S E 1 3|  boot nonce   | sequence| k  | k x (end:8, len:1, key)   |   tag   |
   +--------+---------------+---------+----+---------------------------+---------+

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

Observation
~~~~~~~~~~~

The metrics of the edge gain five series: ``sibuna_edge_mesh_bans_sent_total``, ``sibuna_edge_mesh_bans_received_total``, ``sibuna_edge_mesh_bans_applied_total``, ``sibuna_edge_mesh_bans_dropped_total`` and ``sibuna_edge_mesh_bans_known``. ``sibuna ctl SOCKET show stats`` prints them.

Rationale and alternatives
--------------------------

*A maximum, not a log.* A replicated log orders operations and needs acknowledgements, a window and recovery. A ban has one useful operation, and it is monotone. A map merged by maximum is the smallest state-based replicated data type that carries it, and its three laws are the whole proof of convergence.

*The end, not the remaining time.* A remaining time would be independent of the clocks of the nodes. It would also make a replayed datagram start the ban again. With the end in the datagram a replay is harmless, and the cost is that a ban lasts longer or shorter on a peer by the difference of the clocks. Nodes of a cluster keep their clocks within a second, and bans last minutes.

*Direct sends, not gossip.* The roster is fixed and has at most 63 peers. Every node can reach every other. Epidemic forwarding earns its cost in large, changing groups.

*No lifting.* An operator who lifts a ban on one node would expect it lifted on all. A lift is not monotone: it must win against a ban in flight, which needs a version for each key. We leave it out and say so. An administrator lifts on each node, or waits for the end.

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

Formal model
------------

``assets/replicated-bans.lean`` models the map as a function from keys to ends and the merge as the pointwise maximum. Lean 4.19.0 checks it without libraries.

- ``merge_comm``, ``merge_assoc``, ``merge_idem``: the three laws of the merge.
- ``merge_keeps``, ``merge_learns``: a merge shortens no ban and takes in every ban it hears.
- ``replay_is_harmless``, ``order_is_irrelevant``: a datagram heard twice, and two datagrams in either order.
- ``heard_keeps``, ``heard_contains``: after any list of datagrams a node holds every ban it had and every ban it heard.
- ``admit_is_bounded``, ``admit_never_extends``: a received end lies within the horizon and never beyond the end that was sent.

The model does not cover the schedule of the three sends, the walk or the expiry. Unit tests cover those.

Known gaps
----------

#. Lifting a ban is local. An operator who clears the bans of one node clears that node only.
#. Bans that an administrator configures are not sent. They belong in the policy file of every node.
#. The nodes must agree on ``ipv6_prefix`` and keep their clocks close. Neither is checked.
#. A ban issued while a peer is cut off for less than three probe periods, with all three sends lost, reaches that peer only with its next walk, which a restart or a longer silence starts.
#. A walk copies the map once for the returning peer, up to 65,536 entries.
#. The test of three processes runs on one host over loopback. It has not run on separate hosts.
#. Replication runs in edge mode only. The daemon mode of the firewall has no mesh.

Open questions
--------------

#. Should the lifting of a ban be replicated, with a version for each key?
#. Should a drain of SID 0018 travel the same way?

Review history
--------------

- 2026-11-24. Initial draft.
- 2026-11-24. Implementation and its review. The review found two faults. The mesh thread starts before the firewall, so a walk could arrive before the firewall could take bans: the bans were merged and never applied. The mesh now remembers them and applies them once the firewall has given its sink. The test of three processes then showed that a restarted node died: the daemon wrote the routing regime to a standard error that nobody read, and ``eprintln!`` ends a process there. The lines of the running edge are now written without that, and the test closes the pipe on purpose.

References
----------

- SID 0015, the mesh and its open question on replicated state. SID 0018, run-time changes are local to a node.
- Almeida, Shoker and Baquero, *Delta State Replicated Data Types* (2018).
- HAProxy Configuration Manual, section 3.5, "Peers", https://docs.haproxy.org/3.0/configuration.html#3.5

.. rubric:: Lifecycle event

::

   2026-11-24: prediscussion -> discussion. First draft by the author; open
   for discussion before implementation
