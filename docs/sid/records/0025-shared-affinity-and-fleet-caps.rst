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
#. The table has a fixed number of slots, ``global.sticky_entries``, by default 65,536. A full bucket gives up its entry with the earliest end. A lost entry costs a client its server for new flows and nothing else.
#. The request path takes no lock. A lookup hashes once and reads at most four slots. A write claims one slot with one compare-and-swap and gives up when another thread holds it.

The table in memory
^^^^^^^^^^^^^^^^^^^

The table is an array of slots in buckets of four. A slot is five words: a sequence number, two words of key, the server and the end. All are atomic. A writer makes the sequence odd with a compare-and-swap, stores the entry and makes the sequence even again. A reader reads the sequence, the entry and the sequence again, and takes the entry when both readings are the same even number. It tries a slot at most four times and then treats it as empty. No thread waits for another, and no read sees half of an entry.

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

A node that hears a want from a peer gives the smaller of the want and its surplus. To a peer that refuses flows it gives the smaller of the want and the larger of its surplus and half of its free share, rounded up. So a share that nobody uses moves to the node that refuses flows within one period, and nodes that all use their shares give nothing.

Three rules bound a gift. It comes from the free share, so the giver's flows stay within its share. The net amount that a node has given to one peer, :math:`g_{ij} - h_{ij}`, never exceeds its base :math:`b_i`. A node gives only to a peer that it heard in the last three periods and that it is synchronised with, as defined below.

Admission and the gift race
^^^^^^^^^^^^^^^^^^^^^^^^^^^

A worker admits a flow by adding one to the count of flows and then reading the share. When the count it added to was below the share it keeps the place. Otherwise it takes the one back and refuses. The mesh thread gives by lowering the share first and reading the count second. When the count exceeds the lowered share, flows entered meanwhile, and it raises the share again by the difference and gives less. Both use sequentially consistent operations. Either the worker's addition precedes the reading of the mesh thread, which then sees it, or it follows the lowering, and the worker then reads the lowered share. No flow is admitted on a share that was given away.

Restart
^^^^^^^

A node that restarts has no flows and has lost its ledger. Its peers still hold theirs, and they may serve flows on shares that it gave them. It must not start again from its base.

Each node has an *epoch*: the Unix millisecond of its start. A status datagram carries the epoch of its sender and the epoch of the receiver that the sender last heard. A receiver ignores a datagram whose sender epoch is below the largest that it knows for that peer. So when a node has heard the new epoch of a peer, no datagram of the old one counts any more.

A node that starts is *unsynchronised* with every peer, for every server. It becomes synchronised with peer :math:`j` when a datagram of :math:`j` echoes its own new epoch. It then takes over the ledger that :math:`j` kept: its :math:`g_{ij}` becomes the :math:`h_{ji}` of the datagram, and its :math:`h_{ij}` becomes the :math:`g_{ji}`. The echo proves that :math:`j` had heard the new epoch before it sent, so :math:`j` will raise its :math:`h_{ji}` no further on behalf of the old epoch, and the two ledgers agree.

While node :math:`i` is unsynchronised with :math:`j` it does not know what it gave to :math:`j`. It knows that the net amount was at most :math:`b_i`. So it counts :math:`-b_i` for that peer:

.. math::

   s_i = b_i - \sum_{j\ \text{synced}} (g_{ij} - h_{ij}) - \sum_{j\ \text{unsynced}} b_i .

A negative result is a share of zero. Two nodes that both restarted find each other unsynchronised with empty ledgers and both begin at zero for the pair, which is sound because neither has a flow that depends on the other.

A change of the limit, of the address of the server or of the roster makes a new ledger, under a new key. The key is a hash of the protocol, the address, the limit and the roster.

The status datagram
^^^^^^^^^^^^^^^^^^^

.. code-block:: text

   0        4          20        28       36      44   45                          n-16   n
   +--------+----------+---------+--------+-------+----+---------------------------+------+
   | S E 1 7|boot nonce| sequence| epoch  | echo  | k  | k x (key:8, gave:8,       | tag  |
   |        |          |         |        |       |    |      got:8, want:4, f:1)  |      |
   +--------+----------+---------+--------+-------+----+---------------------------+------+

The datagram has kind 7. It is addressed to one peer: ``gave`` and ``got`` are the numbers of the pair. ``got`` tells the giver what has arrived. A datagram holds 39 records. A node sends one status to each peer in each period of 500 ms, and one at once to a peer that it just gave to. A node keeps at most 1,024 ledgers over its life. A server beyond that has a share of zero.

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
     - Its base, once for each silent peer. It serves on what the peers that answer give it.
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
   share            limit  base  share  used  synced
   http 10.0.1.1:80   300   100    180   171  2/2
   http 10.0.1.2:80   300   100     40    12  2/2

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

Both datagrams carry the tag of SID 0022 and are read only from an address of the roster. A holder of the mesh key can already ban every client. With this record it can also name a server for a client of a pool with ``sticky: table``, and it can claim to have given shares or withhold its own. It cannot raise the sum of the shares of the honest nodes above the limit by replaying their datagrams: a replay carries numbers that the receiver holds, or an epoch that it has left behind.

A client chooses its address and its cookie. It can fill the table with entries of its own, which evict others. An evicted client is balanced again. The keyed hash of the key keeps a client from choosing the bucket of another client, as long as the name of the pool is not its only secret: an attacker who knows the pool name can compute buckets. The damage is bounded to lost stickiness.

A node with a clock ahead writes entries that win over those of its peers for the same client until the clocks agree. Entries more than 24 hours and 60 seconds ahead are ignored. A node whose clock steps back across a restart has an epoch below its old one. Its peers ignore it, it stays unsynchronised, and ``show affinity`` shows ``0/2`` in the column ``synced``. Starting it again after the clock passed the old start repairs it.

The nodes must hold the same limit for a server. While a ``reload cluster`` travels, nodes with the old limit and nodes with the new one keep separate ledgers. For that time the flows are bounded by the sum of the two limits.

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
     - Open.
   * - 2
     - A node that restarts learns the table from its peers.
     - Open.
   * - 3
     - A lost or evicted entry changes the choice of a new flow only. An established flow keeps its server.
     - Open.
   * - 4
     - The request path takes no lock, and a lookup costs less than a microsecond.
     - Open.
   * - 5
     - The flows of all nodes on a capped server never exceed its limit.
     - Open.
   * - 6
     - Shares move to the node that has the demand.
     - Open.
   * - 7
     - A node that is killed keeps its share from the others. A node that returns gets its ledger back.
     - Open.
   * - 8
     - A forged, cut, altered or replayed datagram changes nothing.
     - Open.

Formal model
------------

``assets/shared-affinity.lean`` holds the model. Lean 4.19.0 checks it without libraries.

Known gaps
----------

Open.

Open questions
--------------

#. Should the ledger be written to disk, so that a restart needs no peer?
#. Should an operator be able to declare a node dead, so that its peers count its share as returned?

Review history
--------------

- 2026-11-25. Initial draft.

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
