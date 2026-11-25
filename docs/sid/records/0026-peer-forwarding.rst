:sid-number: 0026
:sid-title: Peer Forwarding on the Edge Mesh
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-25
:sid-updated: 2026-11-25
:sid-discussion: No external discussion URL assigned
:sid-summary: Gives every client one owner among the live nodes of a mesh and lets a node that receives a flow of another node's client hand it to that node over an authenticated hop, at most once, so that a change of the routing in front of the cluster keeps a client on one node.
:sid-labels: ["architecture","load-balancer","cluster","network"]

Peer Forwarding on the Edge Mesh
================================

Abstract
--------

The router in front of a cluster chooses a node for each flow by a hash of its own. When a node joins or leaves, or when the router rehashes, a client lands on another node. That node has none of the state the first one kept for the client: its UDP mapping, its connection count, its rate budget, its sticky choice. We give every client one owner among the live nodes. A node that receives a new flow of a client it does not own hands the flow to the owner over the mesh network. The owner serves it under the true client address. A handed flow is never handed on, so no flow takes more than one extra hop. When the owner cannot take the flow, the node that received it serves it. The feature is off unless the file asks for it.

Motivation and scope
--------------------

SID 0015 names this mechanism "one-hop consistent peer forwarding" in its regional regime and leaves it as proposed work. It states the limit that we keep: an accepted TCP socket cannot take over a segment that the router sends to another host. We therefore do not repair an established TCP connection whose packets move to another node. We do make the cluster agree on where a client belongs, for every new TCP connection and for every UDP datagram.

We specify the owner of a client, the liveness of the forwarding path, the hand-over of TCP and HTTP connections, the encapsulation of UDP datagrams, the authentication of both with the mesh key, the bounds and the fallbacks. We do not specify forwarding for HTTP/3: the QUIC endpoint owns its socket and is outside this record. We do not specify packet-level forwarding of established TCP flows.

Specification
-------------

Invariants
~~~~~~~~~~

#. **One hop.** A flow that arrived from a peer is served by the node that received it. It is never forwarded again, whatever that node believes about the owner.
#. **No flow is lost to forwarding.** When the owner is down, refuses, or is at its bound, the receiving node serves the flow itself, as a node without forwarding does. The exception is a client that the owner denies by its rate limit: that client is refused.
#. **Agreement.** Two nodes that see the same peers alive name the same owner for a client.
#. **Least movement.** When a node leaves, only its clients change owner. When a node joins, the only clients that change owner are those that the new node now owns.
#. **Established flows stay.** A node serves a UDP client for which it holds a mapping, whoever the owner is. A forwarding node keeps sending a UDP client to the peer it chose while that peer answers. A TCP connection stays on the two sockets it has.
#. **Only peers forward.** A node takes a forwarded flow, and the client address it names, only from an address of the mesh roster and only under a tag made with the mesh key, for this node and for its current start.
#. **Nothing on the path of other flows.** A flow that needs no forwarding takes no lock. A UDP datagram of an existing local mapping costs nothing more than before. A new flow costs one computation of the owner.
#. **Bounded.** The flows forwarded to one peer, the connections that wait for a header, and the time of every wait have a limit.

Configuration
~~~~~~~~~~~~~

.. code-block:: text

   mesh: {
       nodes: ["10.0.0.1:7946", "10.0.0.2:7946", "10.0.0.3:7946"],
       key_file: "/etc/sibuna/mesh.key",
       forward: {
           port_offset: 1,
           max_flows_per_peer: 4096,
           connect_timeout: "250ms",
       },
   },

The object ``forward`` turns forwarding on. Every member has a default, so ``forward: {}`` is enough. Every node must state it: a node without it has no forwarding port, and its peers then serve its clients themselves.

- ``port_offset`` (1 to 1024, default 1). The forwarding port of a node is its mesh port plus this number, for TCP and for UDP, on the IP address of its mesh address. With the mesh on port 7946 the nodes forward on port 7947.
- ``max_flows_per_peer`` (1 to 1,000,000, default 4096). The most flows this node forwards to one peer at a time. A flow above the bound is served here.
- ``connect_timeout`` (10 ms to 5 s, default 250 ms). The longest wait for the owner to take a TCP connection: the connect and the answer to the header together.

A forwarding address must differ from every mesh address of the roster and from every other forwarding address. A change of ``forward`` needs a restart, as every change of the mesh does.

The owner of a client
~~~~~~~~~~~~~~~~~~~~~

The key of a client is its IPv4 address, or the first 64 bits of its IPv6 address. An IPv4-mapped IPv6 address counts as IPv4. The port and the frontend take no part: one client has one owner for all its flows. These are the keys of the rate limiters, so a limit that the owner counts is a limit for the cluster.

Each node :math:`n` of the roster has a seed :math:`s_n`: the first eight bytes of the keyed BLAKE3 hash of its mesh address, under a key derived from the mesh key with the context ``sibuna/edge-mesh/owner/v1``. The score of node :math:`n` for a client key :math:`k` is :math:`\mathrm{wyhash}(s_n, k)`. The owner is the eligible node with the largest score, and the node itself is always eligible. Equal scores go to the node that is earlier in the sorted roster. This is rendezvous hashing. It needs no table and no publication, and its work is one hash for each live node, at most 64.

The seeds depend on the mesh key. A client cannot compute which addresses share an owner, so it cannot aim a set of addresses at one node.

We chose this function over the Maglev table that SID 0015 sketches for origins. A table must be rebuilt and published to the worker at every change of liveness, and a rebuilt Maglev table moves a small share of the clients of nodes that did not change. Rendezvous hashing moves none of them.

Liveness of the forwarding path
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A peer is eligible when it can take a flow now. The mesh probes of SID 0015 do not show that: they are answered by another thread on another port. The edge worker therefore probes the forwarding port itself. Every 500 ms it sends each peer a ``PING`` with a fresh number. The peer answers ``PONG`` with that number, its own start number (its epoch) and a flag that says whether it drains. A peer is alive when it answered the outstanding number within the last 1.5 s and does not drain. A peer is eligible when it is alive and not held back. A peer is held back for one second after it refused a flow or failed a connect. A new flow goes only to an eligible peer. A UDP client that a peer already serves stays with it while the peer is alive, so one refused connection does not move the clients of that peer. A node that restarts draws a new epoch.

Forwarding runs only in the regional regime of SID 0015, where the measured round trip between the nodes is below the threshold. In the standalone and wide-area regimes every node serves what it receives.

TCP and HTTP connections
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: text

   client          node B (received)                 node A (owner)
     | SYN, accept   |                                  |
     |-------------->| local checks: drain, rate, slot  |
     |               | owner(client) = A, A eligible    |
     |               | connect A:forward port --------->| source in the roster?
     |               | header (76 bytes) -------------->| tag, epoch, frontend, drain,
     |               |                                  | slot, rate of the true client
     |               |<------------- status (17 bytes) -|
     | bytes         | relay both ways                  | serve as if accepted here,
     |<=============>|<================================>| client = address in the header

The receiving node applies its own checks first: it refuses when it drains, when the client exceeds the connection rate here, or when it has no flow slot. It then computes the owner. When the owner is itself, or no peer is eligible, the connection goes on as before. Otherwise the node connects to the forwarding port of the owner and writes one header. The connection leaves from the IP address of the node's mesh address, whatever the routing table would select, so the owner finds the source in its roster. On Linux the node binds the socket to that address before it connects. On other platforms the source is the address that the routing table selects, and forwarding works where that is the mesh address. The node reads nothing from the client yet, so the connection can still be served here.

.. code-block:: text

   offset  bytes  field
        0      4  "SEF1"
        4      1  kind: 1 = stream
        5      3  zero
        8      8  epoch of the receiver
       16      8  frontend: first 8 bytes of BLAKE3 of the frontend name
       24     16  client address (IPv4 as IPv4-mapped IPv6)
       40      2  client port
       42     16  destination address that the client reached
       58      2  destination port
       60     16  tag

The tag is the first 16 bytes of the keyed BLAKE3 hash of the two socket addresses of the forwarding connection, sender first, followed by bytes 0 to 59. The key is derived from the mesh key with the context ``sibuna/edge-mesh/forward/v1``. A header therefore holds for one connection between two nodes, and for one start of the receiver.

The owner answers 17 bytes: one status byte and a tag over the header's tag and the status, under the same key and addresses. Status 1 takes the connection. Status 2 declines it: the owner drains, has no such frontend, or has no flow slot; the receiving node serves the connection itself and holds the peer back for a second. Status 3 denies the client: the owner's connection rate limit for that client is exceeded, and the receiving node closes the connection. A failed connect, a wrong answer and a timeout count as status 2.

The owner takes these steps and stops at the first that fails. A failure before step 3 closes the connection without an answer.

#. The source address of the connection is the IP address of a node of the roster.
#. The header arrives whole within one second, its tag is right and its epoch is the epoch of this node.
#. The node does not drain, the frontend exists with the TCP or HTTP protocol, and a flow slot is free. Otherwise status 2.
#. The client named in the header is within the connection rate of the frontend, or the frontend trusts it. Otherwise status 3.
#. Status 1. The connection is admitted as one accepted from the client. For a TCP frontend the destination in the header is the address given to the pool and written in a PROXY v2 header to the server. For an HTTP frontend the client address replaces the socket peer, as the source of a PROXY header does (SID 0020), and the listener is the bind of that frontend on this node.

After status 1 the receiving node relays bytes between its two sockets until both directions end. It keeps the half-close of each side. TLS, the hello inspection, HTTP parsing, the firewall and the choice of a server all happen on the owner. The receiving node never looks at the bytes.

A frontend with ``proxy_protocol`` is not forwarded. Its sender is a proxy that already chose this node, and the client is known only after the header.

UDP datagrams
~~~~~~~~~~~~~

Each node has one UDP socket on its forwarding port. A forwarded datagram is the client's datagram between a header and a tag.

.. code-block:: text

   offset  bytes  field
        0      4  "SEF1"
        4      1  kind: 2 = forward, 3 = return, 4 = refuse, 5 = ping, 6 = pong
        5      3  zero (pong: byte 5 is 1 when the node drains)
        8      8  epoch of the receiver (ping: number of the ping; pong: the same number)
       16      8  frontend (ping: zero; pong: epoch of the answering node)
       24     18  client address and port
       42     18  destination address and port
       60      n  the datagram of the client (kinds 2 and 3)
     60+n     16  tag

The tag covers the forwarding address of the sender, the forwarding address of the receiver and every byte before the tag. A datagram for one node is therefore not valid for another, and not valid in the other direction.

A UDP worker handles a datagram from a client in this order.

#. The rate limit of the frontend, as before.
#. A local mapping for the client exists: the datagram goes to its server, as before. Nothing else is looked at.
#. A forwarding entry for the client exists and its peer is still alive: the datagram is sent to that peer as kind 2. An entry whose peer is no longer alive is removed.
#. Otherwise the owner is computed. The owner is this node, no peer is eligible, or the bound of the peer is reached: a local mapping is opened, as before. Otherwise a forwarding entry is made and the datagram is sent to the owner.

A forwarding entry holds the peer and the time of the last datagram. It ends after the session timeout of the frontend without traffic. It fixes the peer of an established client, so a node that joins does not take the client away while it talks.

The owner checks the source address against the forwarding addresses of the roster, then the tag, then the epoch. It then handles the datagram as one received from the client on its own listener of that frontend, with its own rate limit, mapping table and reply bound. The mapping remembers the peer that sent the last datagram. A reply of the server goes back to that peer as kind 3, and the peer sends it to the client from the listener that the client reached. So the client sees the answer come from the address it sent to, also where the nodes do not share one address. A datagram that the client later sends to the owner directly turns the replies to the direct path.

A node that receives kind 3 delivers it only when it holds a forwarding entry for that client towards that peer. A draining owner without a mapping for the client answers kind 4. The receiving node then removes the entry and holds the peer back, and the next datagram of the client is served here.

A client datagram longer than 65,431 bytes does not fit. It is dropped and counted in ``sibuna_edge_drops_total``.

Bounds
~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 40 20 40

   * - Bound
     - Value
     - At the bound
   * - Flows forwarded to one peer (TCP connections and UDP entries)
     - ``max_flows_per_peer``
     - The flow is served here.
   * - Connect to the owner and its answer
     - ``connect_timeout``
     - The connection is served here. The peer is held back 1 s.
   * - Connections of peers that wait for their header
     - 1,024, for 1 s each
     - The connection is closed. The sender serves the client.
   * - Flows taken from peers
     - ``global.max_flows``, shared with all flows
     - Status 2. The sender serves the client.
   * - Silence of a peer before its relayed connections are closed
     - 10 s
     - The connections end and free their slots.
   * - A UDP forwarding entry without traffic
     - session timeout of the frontend
     - The entry is removed.

A forwarded flow holds a flow slot on both nodes.

Cost
~~~~

A forwarded TCP or HTTP connection waits for one connect and one exchange of header and status on the mesh before its first byte moves: two round trips between the nodes. After that every byte passes one more relay and one more hop in each direction. A forwarded UDP datagram takes one more hop in each direction, and each node on the hop computes one keyed hash over the datagram. A flow that is not forwarded pays for the computation of the owner once, when it starts. The acceptance table gives the measured values.

Counters
~~~~~~~~

With forwarding on, ``show stats`` and the metrics listener add these series.

- ``sibuna_edge_forward_active``: 1 while this node forwards, which is while its mesh is in the regional regime.
- ``sibuna_edge_forward_peers_eligible``: peers that can take a flow now.
- ``sibuna_edge_forward_flows_out``: flows that this node forwards now.
- ``sibuna_edge_forward_streams_out_total``, ``sibuna_edge_forward_streams_in_total``: connections handed to a peer, and taken from peers.
- ``sibuna_edge_forward_datagrams_out_total``, ``sibuna_edge_forward_datagrams_in_total``, ``sibuna_edge_forward_datagrams_returned_total``: datagrams sent to an owner, taken from peers, and replies delivered for an owner.
- ``sibuna_edge_forward_local_total{reason}``: flows of another node's client that were served here. The reasons are ``declined``, ``connect_failed``, ``timeout`` and ``peer_limit``.
- ``sibuna_edge_forward_denied_total``: connections closed because the owner denied the client.
- ``sibuna_edge_forward_rejected_total{reason}``: what was refused on the forwarding port. The reasons are ``stranger`` (source not in the roster), ``bad_tag``, ``stale`` (another epoch), ``malformed`` and ``unknown`` (no such frontend or entry).

Rationale and alternatives
--------------------------

**Liveness from the mesh thread.** The first design took the liveness of a peer from the mesh probes. A peer can answer those while its worker is stuck or while it runs a version without the forwarding port. UDP sent to such a peer vanishes without an error. The worker now probes the port that the flows use.

**Sending the client bytes with the header.** This saves one round trip. The owner could then only close a connection that it does not take, and the client would see a reset at every drain of a node. We wait for the status and keep the fallback.

**A time stamp in the header.** It needs clocks that agree. The epoch of the receiver and the addresses of the connection bind a header as tightly, without a clock.

**PROXY protocol v2 for the client address.** It carries the addresses but no tag, no frontend and no epoch. We would have to add all three as extensions and still refuse the plain form. One fixed header of our own is simpler to check.

**One UDP socket for each forwarded client.** This is how a mapping to a server works, and the kernel would match the replies. It costs a descriptor for each forwarded client. One socket and a header on the way back cost none.

**Replies from the owner straight to the client.** Where every node holds the same address this saves a hop. Where the nodes have addresses of their own, the client would see an answer from an address it never sent to. We return through the node that the client reached. Direct return is left as an option for later.

**Forwarding again when the owner disagrees.** A second hop could reach the "right" owner when two nodes see different peers. It could also loop. We serve on the first node that a forward reaches.

**Dropping a forwarded datagram whose owner is unknown.** SID 0015 states this. We serve it instead: the node that got it is alive and has a pool, and a drop would lose the client for no gain.

**Replicating the state instead.** SID 0025 replicates sticky tables and quotas. Replication repairs the choice of a server after the fact. Forwarding keeps the flow on the node that has all of the state, including the UDP mapping itself, which cannot be replicated. The two complement each other.

Security and operational considerations
---------------------------------------

A holder of the mesh key can make any node serve a flow under any client address. It can already ban any client (SID 0022). The key file must be readable by the daemon alone.

The header and the datagrams are authenticated. The bytes of a relayed TCP connection are not, and nothing is encrypted by this layer. A reader of the network between the nodes sees what a reader of the network in front of them sees. An attacker who can alter packets between the nodes can alter a relayed connection, as it can alter the client's own packets. TLS that the owner terminates protects against both.

A header is bound to the addresses of its connection. A node that reaches its peers through an address translation cannot forward. The receiver knows a peer by its source IP address, as SID 0023 does.

A tag is checked only after the source address. A sender outside the roster costs one comparison for each node. A datagram that claims the address of a peer costs one hash over its bytes.

The forwarding network should carry the largest client datagram plus 76 bytes without fragmentation.

The status ``denied`` is the one case where the receiving node does not serve the client. Without it a client above its limit on the owner would be served by every other node.

During a disagreement about liveness, which lasts at most the 1.5 s of the detection, one client can be served by two nodes. Each serves correctly. Limits that count on one node are then split for that time. The same holds while the nodes disagree about the regime: a node whose mesh left the regional regime serves what it receives, and its peers still forward.

A forwarded datagram carries no number of its own. Someone who can copy packets between the nodes can send a forwarded datagram again while the owner keeps its epoch. The owner then sees the client's datagram twice, as it can on any network that duplicates datagrams.

When an owner stops without notice, its relayed TCP connections break, as the connections of any node that stops do. New connections are served by the node that receives them from the first failed connect on. UDP datagrams sent to it are lost until the peer is found silent, at most 1.5 s.

Backwards compatibility
-----------------------

A file without ``mesh.forward`` opens no port, sends no probe and takes no forwarded flow. The edge then behaves as before, and the only added work is one test of an option that is absent. A cluster can turn forwarding on node by node: a node whose peer has no forwarding port never finds it eligible.

Acceptance criteria and implementation status
---------------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 6 44 50

   * - #
     - Criterion
     - Status
   * - 1
     - A TCP connection that arrives at a node that does not own its client is served by the owner, and the server sees the address of the client.
     - Done. ``edge_forward::a_flow_at_the_wrong_node_reaches_the_owner_and_the_server_sees_the_client``: three processes, a connection to each; the server of the owner reads the client's address and port in its PROXY v2 header and echoes 100,000 bytes.
   * - 2
     - The same for a connection of an HTTP frontend.
     - Done. The same test: the server of the owner reads the client in ``X-Forwarded-For``. In one process, ``forward::tests::a_connection_reaches_the_owner_of_its_client_under_the_address_of_the_client``. HTTP over TLS and HTTP/2 through a forward are not tested.
   * - 3
     - The same for UDP, and the reply reaches the client from the address it sent to.
     - Done. The same test, and ``edge_forward::every_node_names_the_same_owner_for_a_client_and_the_clients_spread`` for twelve client addresses.
   * - 4
     - A change of membership during a flow does not break it.
     - Done for the flows that the design covers. ``edge_forward::established_flows_stay_when_the_owner_stops_returns_and_stops_again``: a relayed TCP connection and a forwarded UDP client keep their node while another node joins, takes the ownership of the client, and leaves again. A TCP connection whose packets the network moves to another node is not covered: see the known gaps.
   * - 5
     - With the owner down, the receiving node serves the flow.
     - Done. The same test kills the owner and connects at once: the connect fails and the receiving node serves. ``edge_forward::a_node_alone_serves_every_flow_itself`` for TCP, HTTP and UDP.
   * - 6
     - A forward from outside the roster, or under a wrong key, is refused.
     - Done. ``edge_forward::a_forward_from_outside_the_roster_or_under_another_key_is_refused`` with processes. ``forward::tests::a_forged_handover_is_refused_whatever_is_wrong_with_it`` covers a stranger with the right key, a wrong key, a replayed header, another epoch and a cut header. ``forward::tests::a_forged_datagram_is_refused_and_a_stranger_cannot_keep_a_peer_alive`` covers the datagrams.
   * - 7
     - A forwarded flow is never forwarded again.
     - Done. ``forward::tests::a_forwarded_connection_is_served_where_it_lands_and_never_forwarded_again``, and the theorems ``forwarded_is_served`` and ``one_hop`` of the model. The same property of a datagram rests on the code path and the model. No test sends a datagram to a node that does not own its client through a peer.
   * - 8
     - A cluster without ``forward`` behaves as before.
     - Done. ``edge_forward::a_cluster_without_the_forward_object_behaves_as_before``: no port is open and no series exists.
   * - 9
     - The added latency and the cost in throughput are measured.
     - Done, on loopback only. See the measurement below.

Measurement
~~~~~~~~~~~

``edge_forward::measure_the_cost_of_the_forwarding_hop`` starts two release processes on loopback, with one server behind each. One client thread talks to the owner of its address, first through the owner and then through the other node, one exchange at a time. The run is ``cargo test --release -p sibuna --test edge_forward -- --ignored --nocapture``. The machine has 32 hardware threads and ran other work at the time. The table gives the median of two runs each, and the 99th percentile in parentheses.

.. list-table::
   :header-rows: 1
   :widths: 40 20 20 20

   * - Exchange
     - Direct
     - Forwarded
     - Added (median)
   * - New TCP connection up to the first line of the server, 2,000 times
     - 171 and 162 us (227, 212)
     - 250 and 253 us (303, 317)
     - 79 and 91 us
   * - Echo of 64 bytes on an established TCP connection, 20,000 times
     - 33 and 38 us (41, 46)
     - 52 and 59 us (63, 75)
     - 19 and 21 us
   * - UDP question and answer of 64 bytes, 20,000 times
     - 31 and 34 us (41, 41)
     - 51 and 56 us (63, 83)
     - 20 and 22 us
   * - HTTP request on a new connection, 2,000 times
     - 204 and 185 us (264, 258)
     - 287 and 306 us (378, 392)
     - 83 and 121 us
   * - Echo of 1 GiB on one TCP connection
     - 1,661 and 1,737 MiB/s
     - 1,649 and 1,452 MiB/s
     - 1 and 16 percent less

These numbers bound the cost of the code, not of a network. On loopback a round trip between the nodes costs a few microseconds. On a real mesh a new connection adds two round trips between the nodes, and every later exchange adds one. The throughput of one connection is limited by the single test client and its echo server as much as by the relays, so the loss under many connections is not measured. Nothing was measured with many clients at once.

Known gaps
----------

#. An established TCP connection breaks when the network moves its packets to another node. That node holds no socket for the connection and answers with a reset. Forwarding keeps the owner of the client, so the next connection reaches the node with the client's state. It does not keep the connection. Repairing it needs the connection state on every node or a packet-level forward, and neither is built.
#. HTTP/3 is not forwarded. A QUIC connection is served by the node that receives its packets.
#. A frontend with ``proxy_protocol`` is not forwarded.
#. Forwarding stops while a node's mesh is outside the regional regime. On a busy machine the measured round trip can pass the threshold for a while, and the node then serves what it receives. ``sibuna_edge_forward_active`` shows it.
#. Under ``global.reuse_port`` the old and the new process share the forwarding port during a replacement. A probe answer can reach the process that did not ask. The peers and the node itself can then find each other not alive for up to the shutdown timeout, and serve locally for that time.
#. A relayed connection of an HTTP frontend has an idle limit of one hour on the receiving node. The owner applies the HTTP deadlines and closes first.
#. On platforms other than Linux the forwarding connection is not bound to the mesh address. Those builds compile and are not tested.
#. All tests and measurements ran on loopback. No test ran over a network with loss, delay or an ECMP router, and none with IPv6 nodes.
#. The tests do not cover the status 3 (denied) path, the bound ``max_flows_per_peer``, the refusal of a draining owner (kind 4), or the end of relayed connections after ten seconds of silence, with processes. The code paths exist and compile, and the status codes have unit tests of their encoding only.
#. The model covers the routing rule and the binding of a header. It does not model time, the hold-back or the UDP entries.

Open questions
--------------

#. Should the owner reply to a UDP client directly where all nodes hold one address?
#. Should a forwarding node keep a few connections to each peer open, to save the connect?

Review history
--------------

- 2026-11-25. Merge with SID 0032. On a frontend with ``udp_inspect: "quic"`` a datagram that may open no mapping is dropped before the owner is computed, so a node forwards nothing that its peer would refuse.
- 2026-11-25. Review of the code after the tests passed. It found these faults, and each is fixed. A hand-over connection left from the address that the routing table selects, which on a host with several addresses is not the address that the owner knows; the node binds the mesh address first. One refused TCP connection held a peer back and so removed the UDP entries of every client of that peer; an established client now stays while its peer is alive. A node whose mesh had not reached the regional regime showed the same gauges as one that forwards; the gauge ``sibuna_edge_forward_active`` separates them, and the tests wait for it. The tests bound listeners at 127.0.0.1, where connections of other tests hold ports; the nodes have loopback addresses of their own. The review also recorded what it did not fix: a forwarded datagram can be replayed within an epoch, the regime can split the nodes for a while, and a replacement process shares the forwarding port. These stand under the security considerations and the known gaps.
- 2026-11-25. Initial draft. The review of the draft before any code found seven faults and changed the design. The liveness of a peer came from the mesh thread, which does not show that the forwarding port works; the worker now probes the port itself. The client bytes travelled with the header, so an owner that drains could only reset the client; the node now waits for a status and can serve the connection itself. A time stamp bound the header, which needs agreeing clocks; the epoch of the receiver and the addresses of the connection replace it. The status was one bare byte, which a process that takes the port of a stopped daemon could send; it carries a tag now. Each forwarded UDP client had a socket of its own; one socket serves all. The owner replied to a UDP client directly, from an address the client did not send to; replies return through the receiving node. A client denied by the owner's rate limit was served by the receiving node; it is refused now.

References
----------

- SID 0015, Distributed Edge Load Balancer.
- SID 0020, Edge Observability and Client Identity.
- SID 0022, Replicated Bans on the Edge Mesh.
- SID 0023, One Configuration File for a Cluster.
- Thaler and Ravishankar, *Using Name-Based Mappings to Increase Hit Rates* (IEEE/ACM Transactions on Networking, 1998), for rendezvous hashing.
- Eisenbud et al., *Maglev: A Fast and Reliable Software Network Load Balancer* (NSDI 2016), for connection tracking before consistent hashing.
