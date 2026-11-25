:sid-number: 0025
:sid-title: Shared Affinity and Fleet-Wide Caps on the Edge Mesh
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-25
:sid-updated: 2026-11-25
:sid-discussion: No external discussion URL assigned
:sid-summary: Shares the learned server of a client between the nodes of a mesh, as a bounded table whose merge is a maximum, and bounds the flows of a server over all nodes with shares that move between nodes and never sum to more than the limit.
:sid-labels: ["architecture","load-balancer","cluster","affinity","quota"]

Shared Affinity and Fleet-Wide Caps on the Edge Mesh
====================================================

Abstract
--------

A cluster of edge nodes shares its addresses through DNS or ECMP, so two connections of one client can reach two nodes. Two things then differ from a single node. A client that a node placed on a server by a choice that the node remembers is placed afresh by the next node. A server whose ``max_flows`` is 100 receives up to 100 flows from every node.

We add a learned sticky table that the nodes replicate over the mesh of SID 0022, and a quota protocol that divides the limit of a server into shares. The sum of the shares never exceeds the limit, whatever the network loses, repeats or reorders, and whichever nodes stop. Both are opt-in. Without them a node behaves as before.

Motivation and scope
--------------------

SID 0015 lists replicated sticky tables as proposed work, and says that a fleet-wide hard cap would require a quota allocation protocol. Its fourth open question asks what consistency a frontend gets when its node is partitioned. We answer both for the mesh that exists: a fixed roster of at most 64 nodes, authenticated datagrams, and maps merged by a maximum.

We do not build peer forwarding (SID 0026) or the mmap spill cache (SID 0027). The table sits behind a small interface so that a spill cache can sit under it. We do not replicate rate limiters.

Specification
-------------

What stickiness needs from a cluster
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A pool keeps a client on a server in one of three ways. They differ in what a second node must know.

.. list-table::
   :header-rows: 1
   :widths: 14 40 46

   * - ``sticky``
     - How a node finds the server
     - What the nodes must share
   * - ``cookie``
     - The client presents a token. The token is a keyed hash of the pool and the server.
     - The key. Every node derives it from ``http.secret_file``. No table.
   * - ``source``
     - The node ranks the servers by a hash of the client address and takes the nearest eligible one.
     - The file. Nodes with the same servers and weights rank alike. No table.
   * - ``table``
     - The node balances the first flow of a client and remembers the choice.
     - The choice. This record replicates it.

The first two are computed, so no datagram can be lost. Their limit is what they compute from. Two nodes that disagree on the health of a server give a client of ``source`` two servers until they agree. A client of ``cookie`` keeps its server on every node while the server is eligible there.

The third kind is new. It serves two cases that a computation cannot. The first flow is placed by the balancer of the pool, so a table follows the load and a hash does not. The key can be a cookie that the application sets, such as a session identifier, which the edge cannot compute a server from.

The sticky table
~~~~~~~~~~~~~~~~

.. code-block:: text

   backends: {
       app: {
           sticky: { kind: "table", on: "cookie", cookie: "JSESSIONID", ttl: "30m" },
           servers: ["10.0.1.1:80", "10.0.1.2:80"],
       },
       db: { mode: "tcp", sticky: "table", servers: ["10.0.2.1:5432", "10.0.2.2:5432"] },
   }

``on`` is ``source``, the default, or ``cookie``, for HTTP pools. ``ttl`` is how long a choice is kept after its last use, from one second to 24 hours, by default 30 minutes. The short form ``"table"`` is the table on the source address.

Invariants of the table:

#. An entry maps a key of 16 bytes to a server and an end. The key is a keyed hash of the client address, or of the value of the cookie, under a key derived from the name of the pool. The server is a hash of its name. The end is the Unix millisecond at which the entry expires.
#. To merge two entries of one key we keep the larger pair of end and server, compared in that order. The merge is commutative, associative and idempotent.
#. A node writes an entry in two cases. It *learns*: a flow was placed on a server that the table did not name. The new end is the later of now plus ``ttl`` and one millisecond after the old end, so the new choice is larger than the old one on every node. It *refreshes*: a flow used the entry and less than three quarters of ``ttl`` remain. The new end is now plus ``ttl``.
#. A received entry is ignored when its end has passed, or lies more than 24 hours and 60 seconds ahead of the receiver's clock.
#. The table only advises the choice of a server for a new flow. A flow that is established holds a reservation on its server and never reads the table again. No entry, lost entry, or changed entry ends or moves an established flow.
#. A named server serves the client only while it is eligible: in the pool, healthy, not drained, with room. Otherwise the balancer chooses, and the node learns the new choice.
#. The table has a fixed number of slots, ``global.sticky_entries``, from 1,024 to 4,194,304 and by default 65,536. An entry takes 40 bytes. A full bucket gives up its entry with the earliest end. A lost entry costs a client its server for new flows and nothing else. A bucket has four slots, so a table gives up entries before it is full: filled to three quarters it had given up one client in nine. A table wants twice as many slots as clients. The size is read when the node starts.
#. The request path takes no lock. A lookup hashes once and reads at most four slots. A write claims one slot with one compare-and-swap and gives up when another thread holds it.

The table in memory
^^^^^^^^^^^^^^^^^^^

The table is an array of slots in buckets of four. A slot is five words: a sequence number, two words of key, the server and the end. All are atomic. A writer makes the sequence odd with a compare-and-swap, stores the entry and makes the sequence even again. A reader reads the sequence, the entry and the sequence again, and takes the entry when both readings are the same even number. It tries a slot at most 32 times and then treats it as empty. No thread waits for another, and no read sees half of an entry.

The workers and the mesh thread share one table. A worker reads it for each new flow of a pool with ``sticky: table`` and writes it when it learns or refreshes. The mesh thread writes what the peers send.

The interface
^^^^^^^^^^^^^

The pool and the mesh thread use the table through the trait ``AffinityStore``: ``find`` a key, ``keep`` an entry by the merge above, and ``scan`` the entries from a cursor. The table in memory is one implementation. The spill cache of SID 0027 can be a second that keeps the table in memory in front of it and takes the entries that a full bucket gives up.

The datagram
^^^^^^^^^^^^

.. code-block:: text

   0        4               20        28   29                               n-16      n
   +--------+---------------+---------+----+--------------------------------+---------+
   | S E 1 6|  boot nonce   | sequence| k  | k x (key:16, server:8, end:8)  |   tag   |
   +--------+---------------+---------+----+--------------------------------+---------+

The datagram has kind 6 and otherwise the form and the tag of SID 0022. It holds at most 36 entries in 1,200 bytes.

A worker hands the key of each entry that it wrote to the mesh thread through a bounded queue of 4,096 keys, without waiting. A full queue drops the key: the entry stays local until its next refresh. The mesh thread reads the entry of each key from the table and sends it three times, at once, after one second and after four more. A peer that returns, by a new boot nonce or after three silent periods, is sent the whole table by a cursor, at most 32 datagrams in a period of 500 ms. A table of 65,536 entries takes 29 seconds. The walk copies nothing.

A node never forwards what it received. Every node of the roster hears every writer directly.

Consistency under partition
^^^^^^^^^^^^^^^^^^^^^^^^^^^

A node that is cut off keeps serving from its table. It needs no peer to answer a request. The table is eventually consistent: it gives up agreement during a partition and keeps availability.

- A client whose entry both sides held before the partition keeps its server on both sides, as long as it is used and the server stays eligible on each side.
- A client that first appears during the partition is placed by each side it reaches. Its flows on each side keep their servers.
- When the partition ends, each side walks its table to the other. For each key both sides keep the larger entry, which is the choice made or used last. One side's choice changes for the next new flow of that client. Established flows stay.
- Three lost sends without a partition leave a peer without the entry until the next refresh, at most a quarter of ``ttl`` later for a client in use.

Fleet-wide caps
~~~~~~~~~~~~~~~

.. code-block:: text

   backends: {
       app: {
           max_flows_scope: "fleet",
           servers: [
               { name: "a", addr: "10.0.1.1:80", max_flows: 300 },
               { name: "b", addr: "10.0.1.2:80", max_flows: 300 },
           ],
       },
   }

``max_flows_scope`` is ``node``, the default, or ``fleet``. A pool sets it for its servers, and a server may set its own. With ``fleet`` the ``max_flows`` of the server bounds the flows of all nodes of the mesh together. A server with the scope ``fleet`` must state ``max_flows``.

Invariants of the quota:

#. Let :math:`L` be the limit, :math:`n` the nodes of the roster, :math:`s_i` the share of node :math:`i` and :math:`u_i` its flows on the server. At every moment :math:`u_i \le s_i` on every node that admits, and :math:`\sum_i s_i \le L`. Therefore :math:`\sum_i u_i \le L`.
#. The second inequality holds for every loss, repetition, delay and reordering of datagrams, for every partition, and for every set of nodes that stop or restart.
#. A node changes its share in two ways only. It gives a part that no flow uses to a peer, and its share falls at once. It hears what a peer gave to it, and its share rises.
#. A node admits a flow only while its flows are fewer than its share. The admission takes no lock.
#. No node takes a share from a silent peer. Silence does not tell a stopped node from one that is cut off and serves.

Base shares and the ledger
^^^^^^^^^^^^^^^^^^^^^^^^^^

The nodes of the roster are ordered by address. Node :math:`i` of :math:`n` has the base share :math:`b_i = \lfloor L/n \rfloor`, plus one when :math:`i < L \bmod n`. The bases sum to :math:`L`, and every node computes them from the file.

For each peer :math:`j`, node :math:`i` keeps two numbers that only grow: :math:`g_{ij}`, all that it ever gave to :math:`j`, and :math:`h_{ij}`, the largest :math:`g_{ji}` that it heard from :math:`j`. Its share is

.. math::

   s_i = b_i - \sum_j g_{ij} + \sum_j h_{ij} .

A node sends :math:`g_{ij}` to :math:`j` in every status datagram, twice a second. The receiver keeps the larger of what it holds and what it hears. This is the merge of SID 0022, and it gives the same indifference to loss and repetition: :math:`h_{ji} \le g_{ij}` always, since a receiver holds only numbers that the giver sent, and the giver lowered its share before it sent them. Summing the shares, each pair contributes :math:`h_{ji} - g_{ij} \le 0`. So :math:`\sum_i s_i \le L`. What a lost datagram holds back is counted on neither node until the next datagram arrives: it is stranded for half a second, never doubled.

Moving shares
^^^^^^^^^^^^^

Each node computes for each server its free share :math:`f = s - u` and a headroom :math:`r = \max(1, \lceil u/4 \rceil)`. It *wants* :math:`r - f` when that is positive. It reports a want of at least one, with a flag, when it refused a flow for lack of share since its last status. It has a *surplus* of :math:`f - r` when that is positive.

A node serves the wants that it heard once in each period, not when a datagram arrives. It gives a peer the smaller of the want and its surplus. To a peer that refuses flows it gives the smaller of the want and the larger of its surplus and half of its free share, rounded up. So a share that nobody uses moves to the node that refuses flows within two periods, and nodes that all use their shares give nothing. A want is served once: the next status of the peer states what it still wants.

A node also returns what it borrowed. When its free share exceeds twice the quarter of its flows, rounded up, and it holds a net gift of a peer, it gives the excess back to that peer, up to the net gift. An idle node therefore returns to its base, and the shares of an idle cluster return to the bases.

Three rules bound a gift.

#. It comes from the free share, so the giver's flows stay within its share.
#. A node lends only its base. Let :math:`o_{ij} = g_{ij} - h_{ij}` be the net amount that :math:`i` gave to :math:`j`. The positive :math:`o_{ij}` of one node never sum to more than :math:`b_i`. A node may pass a gift back to the peer it came from, and may not pass it on to a third. The restart below needs this rule.
#. A node gives only to a peer that it heard in the last three periods and that it is synchronised with, as defined below.

The second rule does not limit where the shares can go. Every node can lend its whole base to one peer, which then holds the whole limit. It limits the route: a share returns to its node before it goes to another.

Admission and the gift race
^^^^^^^^^^^^^^^^^^^^^^^^^^^

A worker admits a flow by adding one to the count of flows and then reading the share. When the count it added to was below the share it keeps the place. Otherwise it takes the one back and refuses. The mesh thread gives by lowering the share first and reading the count second. When the count exceeds the lowered share, flows entered meanwhile, and it raises the share again by the difference and gives less. Both use sequentially consistent operations. Either the worker's addition precedes the reading of the mesh thread, which then sees it, or it follows the lowering, and the worker then reads the lowered share. No flow is admitted on a share that was given away.

Restart
^^^^^^^

A node that restarts has no flows and has lost its ledger. Its peers still hold theirs, and they may serve flows on shares that it gave them. It must not start again from its base.

Each node has an *epoch*: the Unix millisecond of its start. A status datagram carries the epoch of its sender and the epoch of the receiver that the sender last heard. A receiver ignores a datagram whose sender epoch is below the largest that it knows for that peer. So when a node has heard the new epoch of a peer, no datagram of the old one counts any more.

A node that starts is *unsynchronised* with every peer, for every server. It becomes synchronised with peer :math:`j` when a datagram of :math:`j` echoes its own new epoch. It then takes over the ledger that :math:`j` kept: its :math:`g_{ij}` becomes the :math:`h_{ji}` of the datagram, and its :math:`h_{ij}` becomes the :math:`g_{ji}`. The echo proves that :math:`j` had heard the new epoch before it sent, so :math:`j` will raise its :math:`h_{ji}` no further on behalf of the old epoch, and the two ledgers agree.

A node that is unsynchronised with some peer does not know what it gave to that peer. By the second rule of gifts it gave at most its base to all peers together. So it counts nothing of its base, and only what the peers it is synchronised with have given to it in net:

.. math::

   s_i = \sum_{j\ \text{synced}} \max(0,\ h_{ij} - g_{ij}) .

This is never more than its true share. Such a node gives only what it borrowed, back to its lender. When it is synchronised with every peer it counts its full share again.

Two nodes that both restarted hold no ledger of their pair. Each finds the other unsynchronised and empty, and both begin the pair at zero. A gift between them from their earlier lives is forgotten. This is sound because of the second rule: a node never passed such a gift on to a third node, so forgetting it leaves the true share of each at zero or above. Without the rule it is unsound, and the model has the example: of four nodes with base 100, one borrows 100, lends 200 and restarts together with its lender. The lender gets its 100 back while the other two hold 200 each.

A change of the limit, of the address of the server or of the roster makes a new ledger, under a new key. The key is a hash of the protocol, the address, the limit and the roster.

The status datagram
^^^^^^^^^^^^^^^^^^^

.. code-block:: text

   0        4          20        28       36      44   45                          n-16   n
   +--------+----------+---------+--------+-------+----+---------------------------+------+
   | S E 1 7|boot nonce| sequence| epoch  | echo  | k  | k x (key:8, gave:8,       | tag  |
   |        |          |         |        |       |    |      got:8, want:4, f:1)  |      |
   +--------+----------+---------+--------+-------+----+---------------------------+------+

The datagram has kind 7. It is addressed to one peer: ``gave`` and ``got`` are the numbers of the pair. ``got`` tells the giver what has arrived. A datagram holds 39 records. A node sends its status to each peer in each period of 500 ms. A status without a record still carries the two epochs. A node keeps at most 1,024 ledgers over its life and forgets none. A server beyond that has a share of zero.

Two nodes share a ledger only when they agree on its key. So every node must name the server with the same protocol, address and limit, and the same nodes of the mesh. A node whose peer does not hold the ledger never synchronises with that peer for that server, and its share stays at what the other peers lend it. ``show affinity`` shows this in the column ``synced``.

The price
^^^^^^^^^

A cap that must hold under every partition cannot also be fully used under every partition. We state what is lost.

.. list-table::
   :header-rows: 1
   :widths: 30 44 26

   * - Event
     - Capacity that no node can use
     - For how long
   * - A datagram with a gift is lost.
     - The gift.
     - One period, 500 ms.
   * - A node is cut off from its peers.
     - Nothing is lost at once. Each side keeps its last share. The free share of one side cannot serve the demand of the other.
     - As long as the partition.
   * - A node stops.
     - Its last share: its base, plus what it was given, minus what it gave.
     - Until it restarts and hears each peer once: its start time plus one period.
   * - A node stops and never returns.
     - Its last share.
     - Until the operator removes it from ``mesh.nodes`` and restarts the nodes.
   * - A node restarts while a peer is silent.
     - Its base. It serves on what the peers that answer lend it.
     - Until the silent peer answers.
   * - All nodes start and one is missing.
     - Every share. No node knows what the missing node holds.
     - Until the missing node answers, or leaves the roster.

There is no timer that returns the share of a silent node. Such a timer needs the silent node to stop serving at the same deadline, and a node that is cut off from its peers still holds flows that it admitted. Returning its share would exceed the limit unless it closed those flows. We do not close flows for a quota.

Configuration and observation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Both run whenever the topology has a ``mesh`` and a pool that asks for them. ``mesh.replicate_sticky: false`` keeps the table local. ``mesh.replicate_shares: false`` stops the status datagrams: every node then keeps its base share and the cap still holds. Without a mesh the roster is this node alone: a table is local and a fleet cap is the cap of the node.

``sibuna ctl SOCKET show affinity`` prints the counters of the table and one line for each capped server.

.. code-block:: text

   sticky table: 65536 slots, 412 learned, 96 refreshed, 12 evicted, 0 not written
   sticky mesh: 1524 sent, 1012 received, 498 applied, 0 dropped
   server            limit   base  share   used  synced
   http 10.0.1.1:80    300    100    180    171  2/2
   http 10.0.1.2:80    300    100     40     12  2/2

Rationale and alternatives
--------------------------

*A table for one kind only.* A cookie token and a rendezvous rank are functions of shared inputs. Replicating their results would add state that can be wrong to mechanisms that cannot be.

*The end as the version.* A last-writer-wins entry needs a number that grows with each write. The end of the entry grows with each refresh, and a learn makes it grow by at least a millisecond. One number serves as version and as expiry, and the bound on its distance from the clock bounds the damage of a wrong clock.

*An atomic table, not a table for each worker.* A table for each worker needs no shared write. It also needs a message to every worker for each entry of a peer, and a client whose connections land on two workers would be learned twice. One table of atomics has neither cost. Its writes are rare: a learn for a new client and a refresh four times in a ``ttl``.

*Counters that only grow, not messages that move shares.* A message "take 5" must arrive exactly once. A repeated one doubles capacity and the limit is broken. A cumulative counter merged by a maximum arrives any number of times with the same effect. The cost is one pair of numbers for each peer and server.

*No central allocator.* A leader that hands out shares is one more thing that fails, and its election needs a majority that a mesh of two nodes does not have.

*A lease on shares.* We considered shares that expire unless renewed, so that the share of a dead node returns after a bound. A flow outlives a lease. The node whose lease expired would have to close the flows above what it keeps. We rejected closing established flows.

*A ledger on disk.* A node that wrote :math:`g_{ij}` to a file before each gift would know its ledger after a restart without its peers. This removes the last two rows of the table of prices. It adds a state file and a write on the path of a gift. We left it as the next step.

*Shares in proportion to load from the start.* The bases could follow the traffic of each node. The nodes would have to agree on the traffic, which is what the protocol exists to avoid. Equal bases need the file only, and the shares follow the traffic within a second.

Security and operational considerations
---------------------------------------

Both datagrams carry the tag of SID 0022 and are read only from an address of the roster. A holder of the mesh key can already ban every client. With this record it can also name a server for a client of a pool with ``sticky: table``, and it can claim to have given shares or withhold its own. It cannot raise the sum of the shares of the honest nodes above the limit by replaying their datagrams: a replay carries numbers that the receiver holds, or an epoch that it has left behind. A replayed status of the present epoch can repeat an old want. The receiver then gives free share that the sender no longer needs, at most once in a period and never above the rules of a gift, and the sender gives it back when it is idle. A replay also makes a stopped node look present, so a gift to it is stranded until it returns.

A client chooses its address and its cookie. It can fill the table with entries of its own, which evict others. An evicted client is balanced again. The keyed hash of the key keeps a client from choosing the bucket of another client, as long as the name of the pool is not its only secret: an attacker who knows the pool name can compute buckets. The damage is bounded to lost stickiness.

A node with a clock ahead writes entries that win over those of its peers for the same client until the clocks agree. Entries more than 24 hours and 60 seconds ahead are ignored. A node whose clock steps back across a restart has an epoch below its old one. Its peers ignore it, it stays unsynchronised, and ``show affinity`` shows ``0/2`` in the column ``synced``. Starting it again after the clock passed the old start repairs it.

The nodes must hold the same limit for a server. While a ``reload cluster`` travels, nodes with the old limit and nodes with the new one keep separate ledgers. For that time the flows are bounded by the sum of the two limits. A new ledger starts unsynchronised, so a change of the limit refuses new flows on that server until the nodes have exchanged one status, about a second. Flows under way stay. Two pools that name one server with two limits keep two ledgers, and each bounds its own flows.

Backwards compatibility
-----------------------

A node without this record ignores datagrams of kinds 6 and 7. A file without ``sticky: table`` and without ``max_flows_scope`` is served as before, and no table is allocated. A cluster may be upgraded node by node. A fleet cap must be turned on only when every node runs this record: an older node ignores the key and admits up to the whole limit.

Acceptance criteria and implementation status
---------------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 6 54 40

   * - #
     - Criterion
     - Status
   * - 1
     - A client that a node placed is placed on the same server by the other nodes within one second.
     - Met. ``cmd/sibuna/tests/edge_shared_affinity.rs`` starts three processes on loopback with a table on a cookie and a round-robin pool of three servers. Thirty users arrive, ten on each node. Every node held the choices of the other two 261 ms after the first request, and every user then reached the same server through every node.
   * - 2
     - A node that restarts learns the table from its peers.
     - Met. The same test kills the third node, places ten more users, waits past every send and starts the node again. It held all forty choices 258 ms after its start, from the walks of its peers, and chose for no user by itself.
   * - 3
     - A lost or evicted entry changes the choice of a new flow only. An established flow keeps its server.
     - Met at the routing interface. ``crates/lb/tests/affinity.rs`` puts a store behind the interface that forgets everything: the flow under way keeps its server and its place, and the next request is balanced. A full bucket and an ended entry are tested in ``crates/lb/src/affinity.rs``. Not shown with three processes.
   * - 4
     - The request path takes no lock, and a lookup costs less than a microsecond.
     - Met. A lookup and an admission use atomic operations only. A lookup, with the keyed hash of the client and the read of a bucket, took 172 ns in an optimised build on a table of 65,536 slots with 49,152 clients, as the mean of 400,000 lookups on one thread (``pool::learned::tests``). An unoptimised build took 3.1 microseconds. A worker hands a written key to the mesh thread with ``try_send`` on a bounded channel of the standard library, which does not wait.
   * - 5
     - The flows of all nodes on a capped server never exceed its limit.
     - Met. The process test caps one server at three flows over three nodes. The origin counts its requests under way: never more than three, while requests are held on one node and tried on all. ``quota::tests::the_cap_holds_under_loss_repetition_reordering_and_restarts`` runs random traces of two to five nodes and checks the sum after every step. The model proves the inequality.
   * - 6
     - Shares move to the node that has the demand.
     - Met. In the process test the node that receives three requests with a share of one held all three 450 ms after the first. When the flows ended, a node that had lent its share served again after 301 ms.
   * - 7
     - A node that is killed keeps its share from the others. A node that returns gets its ledger back.
     - Met. The process test kills a node whose share another node uses, and starts it again: it refuses every request for four seconds and shows a share of zero, until the borrower is idle. It then kills a node that holds its own share: the two that remain serve two flows of three for five seconds, and the third flow is served 1.25 s after the node starts again.
   * - 8
     - A forged, cut, altered or replayed datagram changes nothing.
     - Met in unit tests. ``mesh::hints::tests`` and ``mesh::shares::tests`` refuse a forged, a cut and an altered datagram of each kind, and a status that is old or of an old epoch changes nothing. Not shown with three processes.

We also ran the final build on two hosts as a mesh of two nodes with eight workers each, three origins, and clients on a third host. With a table keyed by a cookie, 300 clients reached the same server through either node, 300 of 300. A choice made on one node was known to the other in less than 50 milliseconds: with no pause between the first flow on one node and the next on the other, 25 of 40 clients met two servers; with 20 milliseconds 13 of 40; with 50 milliseconds none. All agreed two seconds later. After a restart of one node the 300 clients found their servers through it, 300 of 300. A server with ``max_flows: 20`` in fleet scope, whose answers we held for four seconds, never held more than 20 flows over both nodes: of 80 requests 20 were served and 60 refused. With all the demand on one node its share went from 10 to 13 after 1.5 seconds and to 17 after 3 seconds, and the two shares always added up to 20.

Formal model
------------

``assets/shared-affinity.lean`` holds the model. Lean 4 checks it without libraries, with ``lean docs/sid/assets/shared-affinity.lean``. It proves:

- The merge of two entries is commutative, associative and idempotent, and a repeated datagram changes nothing (``merge_comm``, ``merge_assoc``, ``merge_idem``, ``replay_is_harmless``).
- A learned choice is larger than the entry it replaces, and a refresh keeps the server (``learn_wins``, ``refresh_keeps``). An admitted end lies within the horizon (``admitted_is_bounded``).
- When every node holds at most what its peer gave, the shares sum to at most the limit (``shares_within_limit``). A gift and a hearing keep that condition (``give_keeps_sound``, ``hear_keeps_sound``), so it holds after every sequence of gifts and hearings, in any order and with any repetition (``cap_holds_on_every_trace``).
- A gift from the free share leaves the flows within the share (``gift_from_free_share``).
- Under the rule that a node lends only its base, the share that an unsynchronised node counts is at most its true share, and the full share is at least what it counted (``restarted_share_is_safe``, ``full_share_covers_counted``). Forgetting a pair that both nodes lost leaves a share of zero or more (``forgotten_pair_is_safe``). Without the rule the example of four nodes exceeds the limit.

The model does not cover the epochs, the order of the two atomic operations of an admission, or time. The first is tested by the random traces of ``quota::tests``, which restart nodes and deliver old datagrams. The second is tested by ``no_flow_enters_on_a_share_that_is_given_away_while_workers_race``.

Known gaps
----------

#. The share of a node that stops does not return after a bound. SID 0015 asked for that. It returns when the node starts again, or when the operator removes the node from the roster and restarts the others. The section on the price says why a timer cannot be sound without closing flows.
#. A cluster that starts with one node missing serves no flow on a capped server until that node answers. A node that restarts while a peer is silent serves only on what the other peers lend it.
#. The ledger is in memory only. A ledger on disk would remove the gap above and is not built.
#. The roster is fixed for the life of a process. A change of ``mesh`` needs a restart of every node, and for that time nodes with two rosters keep separate ledgers.
#. The table has no series in the metrics of SID 0020. ``show affinity`` is the only view.
#. The table is not written to disk and no spill cache sits under it. The interface for one exists, ``AffinityStore`` with ``ClusterState::use_store`` and ``Edge::bind_with``, and one test uses it. The daemon has no option that selects another store.
#. ``sticky: table`` on a cookie reads the ``Cookie`` field of the request only. It does not learn from the ``Set-Cookie`` of a response, so the first request of a session, which has no cookie yet, is balanced and not remembered.
#. A status datagram has no guard against a replay within one epoch. The section on security states what such a replay can do.
#. The process test runs on loopback without loss. Loss, repetition and reordering are tested in memory, not between processes. No test cuts the network between running processes: a killed node stands in for a partition.
#. Stickiness by a table was measured for a lookup, not as requests per second of a loaded node.

Open questions
--------------

#. Should the ledger be written to disk, so that a restart needs no peer?
#. Should an operator be able to declare a node dead, so that its peers count its share as returned?

Review history
--------------

- 2026-11-25. Initial draft.
- 2026-11-25. Review of the design before the code, with the model and a random simulation. Messages that move a share ("take 5") break the cap when repeated: replaced by counters that only grow. A node that restarts from its base double counts what it gave: added epochs and synchronisation. A random boot nonce cannot order two lives of a node: the epoch is the time of the start. A node that raises its own epoch is unsound when datagrams cross: removed. A lease that returns a silent share needs closed flows: rejected, and stated as the price. A re-learned choice could tie with the old one: the new end is at least one millisecond later. A reserve for each peer, and passing a loan on, exceed the limit when two nodes restart together, which the simulation found with four nodes: a node lends only its base, and an unsynchronised node counts only its loans.
- 2026-11-25. Review of the code. Serving a want when its datagram arrives lets a replay move shares many times in a period: wants are served once in a period. An idle node kept a quarter of what it borrowed: it returns all. The share is keyed by the address of the server, as its load is, so two pools of one server share it. A test of the seqlock asserted an order between readers that the table does not promise: the test now asserts whole entries only. The reader tries a held slot 32 times, not 4. A table filled to three quarters gives up one client in nine: stated with the size. Findings that stay are in the known gaps.
- 2026-11-25. Test on two hosts after the merge of all branches. The table, the restart of a node and the cap behaved as specified. The movement of shares is slower than "about a second" for a whole share, and the book now gives the measured steps. A client that uses two nodes within 50 milliseconds of its first flow can meet two servers.

References
----------

- SID 0015, the proposals for replicated sticky tables and the remark on a fleet-wide cap. SID 0019, sticky sessions by cookie and by source. SID 0022, the mesh datagram and the merge by a maximum. SID 0023, one file for a cluster.
- O'Neil, *The Escrow Transactional Method* (ACM TODS, 1986).
- Shapiro, Preguica, Baquero and Zawirski, *A Comprehensive Study of Convergent and Commutative Replicated Data Types* (INRIA RR-7506, 2011).
- Balegas et al., *Extending Eventually Consistent Cloud Databases for Enforcing Numeric Invariants* (SRDS 2015), the bounded counter.
- HAProxy Configuration Manual, section 3.5, "Peers", and ``stick-table``, https://docs.haproxy.org/3.0/configuration.html#3.5

.. rubric:: Lifecycle event

::

   2026-11-25: prediscussion -> discussion. First draft by the author; open
   for discussion before implementation
