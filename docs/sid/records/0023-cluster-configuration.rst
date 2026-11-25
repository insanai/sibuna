:sid-number: 0023
:sid-title: One Configuration File for a Cluster
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-25
:sid-updated: 2026-11-25
:sid-discussion: No external discussion URL assigned
:sid-summary: Lets every node of a mesh hold the same file, by naming all nodes in one list, and reloads the whole cluster from one node with one command that sends the checked file to the peers over an authenticated connection.
:sid-labels: ["architecture","load-balancer","cluster","configuration"]

One Configuration File for a Cluster
====================================

Abstract
--------

A cluster of edge nodes serves one topology. Today each node has a file of its own, and the operator copies every change to every node and reloads each. A node that was missed serves an old topology, and nothing says so. We make the file the same on all nodes, byte for byte, and we add one command, ``reload cluster``, that reloads the node it is given on and then sends the file to the peers. Each peer checks the file, puts it in the place of its own and reloads.

Motivation and scope
--------------------

SID 0015 proposes a database as the authority for the topology of a cluster, with a console to edit it. That is a large design, and a small cluster does not need it: its operator edits one file. What the operator lacks is a way to put that file on every node in one step, with an answer from each node.

We specify the shared form of the ``mesh`` section, the transfer of the file and its checks. We do not specify a database, a console, a history of revisions or a rollback. We do not send the files that the topology names by path: keys, certificates and block lists stay where the operator puts them.

Specification
-------------

Invariants
~~~~~~~~~~

#. A node serves only a file that it has checked itself. A file from a peer passes the same check as a file read by ``reload``.
#. A node takes a file only from a holder of the mesh key, only when it states ``mesh.accept_config``, and only when the file is newer than the last one it took.
#. A failed transfer changes nothing on the peer: its file and its routes stay.
#. The edge worker never waits for a peer. The admin thread sends the file, and a thread of its own receives it.

The shared mesh section
~~~~~~~~~~~~~~~~~~~~~~~

The form with ``listen`` and ``peers`` differs on every node. The form with ``nodes`` is the same on all.

.. code-block:: text

   mesh: {
       nodes: ["10.0.0.1:7946", "10.0.0.2:7946", "10.0.0.3:7946"],
       key_file: "/etc/sibuna/mesh.key",
       accept_config: true,
   },

A node finds itself in the list: it is the first address that belongs to this host. An address of another host cannot be bound, and that is the test. An address in use counts as local, because the running daemon holds it while it checks a new file. On a host where the test cannot decide, ``self_file`` names a file that holds the address of this node. The rest of the list are the peers. ``nodes`` replaces ``listen`` and ``peers``; the old form stays valid.

The rest of the file must suit every node too. The frontends bind the same addresses on all nodes, as a cluster behind DNS or ECMP does, and paths such as ``key_file`` and certificates are the same on all nodes.

The command
~~~~~~~~~~~

``sibuna ctl SOCKET reload cluster`` does three things in order. It checks the file of this node. It reloads this node. It sends the file to every peer at once and waits at most five seconds for each. The answer has the line of the reload and one line for each peer: ``ADDRESS reloaded``. When a peer does not take the file the command fails with ``ADM012 CLUSTER RELOAD INCOMPLETE``, and its message names every peer with its answer. A file that does not check stops the command before any peer is asked. On an edge without a mesh the command fails with ``ADM011``.

The transfer
~~~~~~~~~~~~

The sender connects by TCP to the mesh address of the peer. The port number is that of the mesh datagrams.

.. code-block:: text

   S E C 1 | stamp: 8 bytes | length: 4 bytes | file | tag: 32 bytes

The stamp is the Unix millisecond of the send. The tag is a keyed BLAKE3 hash of everything before it. The key is derived from the mesh key with the context ``sibuna/edge-mesh/config/v1``, so a datagram of the mesh cannot stand for a file and the reverse. A file holds at most 1 MiB.

The receiver takes these steps and stops at the first that fails.

#. The source address is the address of a node of the mesh.
#. The message is whole and its tag is right.
#. The stamp is later than the stamp of the last file taken, and within 60 seconds of the clock. An old message sent again is refused.
#. The file is written beside the file of the node, as ``NAME.incoming.EXT`` with mode 0600, and checked as a reload checks it.
#. The file names the same mesh: this node finds itself in it at its own address, with the same peers. A file in the old form names the sender as ``listen`` and is refused here, with a hint.
#. The file is renamed over the file of the node. The node loads it and leaves the revision for the edge worker, as the signal for a reload does.

The receiver answers ``ok`` or ``refused`` with the reason, in one line. The node logs ``EDGE011: configuration received from ADDRESS``.

Rationale and alternatives
--------------------------

We send the file and not a difference, because a file can be checked as a whole and a node that missed a change is repaired by the next one. We use TCP because a file does not fit a datagram and the mesh has no ordered stream. We let the receiver write its own file, so that a restart serves what the cluster serves.

We considered a database as SID 0015 proposes. It gives history and a single authority, and it adds a service that must be available for every change. We considered sending commands only, as SID 0022 does for servers. Commands cannot add a frontend or a route.

We considered receiving by default. A holder of the mesh key could then replace the topology of every node. That is more than the key allowed before, so a node must state ``accept_config``.

Security and operational considerations
---------------------------------------

A holder of the mesh key can ban any client and, on nodes that state ``accept_config``, replace the topology. The key file must be readable by the daemon alone. The file is not encrypted on its way. A topology holds the paths of secrets and not the secrets, but it shows addresses and routes to a reader of the network between the nodes.

The daemon must be able to write the directory of its file. A daemon that cannot refuses the transfer and keeps serving.

The answer ``reloaded`` means that the peer checked the file and gave it to its worker. The worker can still refuse a change that needs a restart, such as another admin socket. It logs the refusal and keeps its routes, and the file on disk is then ahead of what the node serves.

Backwards compatibility
-----------------------

Nothing changes for a file without ``nodes`` and without ``accept_config``. ``reload`` keeps its meaning.

Acceptance criteria and implementation status
---------------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 6 54 40

   * - #
     - Criterion
     - Status
   * - 1
     - One command puts one file on every node, and every node serves it.
     - Met. ``cmd/sibuna/tests/edge_cluster_reload.rs`` starts three processes with the same file, adds a server in the file of one and runs ``reload cluster``. All three serve it and hold the same bytes.
   * - 2
     - A file that does not check reaches no peer.
     - Met. The same test writes a broken file. The command fails and the peers keep their file.
   * - 3
     - A peer that refuses is named, and the others reload.
     - Met. A second test gives the third node another key. The command fails with ``ADM012``, names the node that reloaded and the node that refused.
   * - 4
     - An altered, cut, oversized, old or repeated message is refused.
     - Met in unit tests of the seal, the limit and the stamp.

Known gaps
----------

#. Files that the topology names by path are not sent. A new certificate or key must reach every node by other means before the reload.
#. A JLV file that imports other files is sent without them.
#. There is no history and no rollback. The operator keeps the earlier file.
#. A node that is down misses the file. It serves its old file when it returns, and nothing compares the files of the nodes. The operator runs the command again.
#. The stamp of the last file is kept in memory. After a restart a node accepts a message of the last 60 seconds again.
#. The receiver knows a node by the source address of the connection. A sender whose route leaves from another address than its mesh address is refused.
#. The test of three processes runs on one host. The nodes there share one listener with ``reuse_port`` and find themselves through ``self_file``.
#. The transfer is not encrypted.
#. The database authority, the console and the plugin tiers of SID 0015 are not built.

Open questions
--------------

#. Should the mesh carry a digest of the file of each node, so that ``show info`` can say when the nodes differ?
#. Should a returning node ask a peer for the file?

Review history
--------------

- 2026-11-25. Initial draft, written with the implementation. The review of the draft made receiving an explicit choice, added the check that the file names the same mesh, and bound the stamp to the clock so that a restart does not open the node to old messages for longer than a minute.

References
----------

- SID 0015, Distributed Edge Load Balancer.
- SID 0018, Quick Start and Admin Socket.
- SID 0022, Replicated Bans on the Edge Mesh.
