:sid-number: 0034
:sid-title: Admission Under Attack
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-26
:sid-updated: 2026-11-26
:sid-discussion: No external discussion URL assigned
:sid-summary: Seven protections for TCP and UDP frontends against floods from many real addresses: concurrent caps per client address and per frontend, bans and automatic bans checked at accept and before a UDP mapping, cheap refusal by reset or tarpit, a pressure mode that admits known clients first, accept threads that spread refusal over the cores, a total packet budget per UDP frontend that serves confirmed mappings first, and counters, top refused sources and a pressure signal. A Lean model proves the caps under any interleaving, the hysteresis of pressure, the bound on new clients and the reserve of confirmed datagrams.
:sid-labels: ["architecture","load-balancer","network","ddos","admission","multi-core"]

Admission Under Attack
======================

Abstract
--------

Before this record a TCP frontend limited each client address by its connection rate, and the node limited all flows together. That stops a client that connects fast. It does not stop a client that connects slowly and holds thousands of streams, a flood on one port that takes the flow budget of every other port, or a client the HTTP firewall banned and that comes back over TCP. All accepts and refusals ran on one thread, so a flood of connections from many addresses was bounded by one core.

This record adds seven protections. They are ordered by value and each one is measured against the previous state. None needs privilege, kernel programs or a new crate.

#. Concurrent caps: ``max_flows_per_ip`` and ``max_flows`` on a frontend.
#. Bans at accept for TCP and UDP, and automatic bans with ``auto_ban``, shared over the mesh.
#. Cheap refusal: a refused connection is reset, closed, or held in a tarpit (``refuse``).
#. Pressure mode: above a level of the flow table, new addresses are admitted at a bounded rate and known addresses first (``global.pressure``).
#. Accept threads: refusal runs on several cores (``global.accept_threads``).
#. A packet budget per UDP frontend that keeps a reserve for confirmed mappings (``udp_defense.total_pps``).
#. Observation: refusal counters per reason, the top refused sources, and a signal when pressure switches.

Motivation and scope
--------------------

The table compares the TCP and UDP admission of Sibuna before this record with HAProxy 3.0 and Envoy 1.31.

.. list-table::
   :header-rows: 1
   :widths: 26 26 24 24

   * - Control
     - Sibuna before
     - HAProxy
     - Envoy
   * - Connection rate per address
     - ``rate_limit.conn_per_10s``
     - stick table ``conn_rate``
     - local rate limit filter
   * - Concurrent connections per address
     - HTTP only
     - stick table ``conn_cur``
     - connection limit filter (per listener)
   * - Cap per listener
     - none
     - ``maxconn`` per frontend
     - ``max_connections`` per listener
   * - Bans for TCP
     - none
     - ``tcp-request connection reject`` on a stick table flag
     - external authorisation
   * - Cheap refusal
     - close after accept
     - ``reject``, ``silent-drop``, ``tarpit``
     - close
   * - Accept on several cores
     - one thread
     - one accept queue per thread group
     - one listener per worker
   * - UDP total per listener
     - per address only
     - not applicable
     - per listener overload actions

The record covers the TCP and UDP frontends of the packet worker in ``sibuna-lb``, the accept of HTTP frontends, which the packet worker also does, one socket option in ``sibuna-reactor``, and the daemon wiring that shares bans between the HTTP firewall and the packet worker. It does not change the HTTP firewall's own decisions. Floods that fill the link, SYN floods at line rate and reflection attacks must be stopped before the node, by the provider's scrubbing, anycast or router filters. A process cannot drop a packet it never receives.

Specification
-------------

Invariants
~~~~~~~~~~

#. **Caps hold under any interleaving.** A flow permit is taken only when the node, its frontend and its client address on that frontend are each below their cap. Taking and releasing are atomic under one lock. In every reachable state each count is at most its cap, whatever the order in which the accept threads, the packet worker and the QUIC endpoints take and release permits.
#. **Refusal before work.** A refused connection costs one accept, a few table reads and one close. It reaches no hook, no inspection, no pool and no server.
#. **A ban in effect refuses.** A client address banned in the shared ban table is refused at accept on a TCP frontend and before a mapping opens on a UDP frontend, on every node that holds the ban. An HTTP frontend refuses a banned client at accept while pressure is on, and otherwise answers its requests with the ban page as before.
#. **Within limits, never banned.** An automatic ban follows only more than ``strikes`` refusals of one address in one ``window``.
#. **Pressure has hysteresis.** Pressure switches on at a load of at least ``on`` percent of ``global.max_flows`` and off at a load of at most ``off`` percent, with ``off < on``. A constant load switches it at most once.
#. **Known first.** Under pressure a known address is never refused for being new, and the new addresses admitted over ``n`` seconds are at most ``new_per_second`` times ``n + 1``.
#. **Reserve of confirmed datagrams.** In each second a UDP frontend with ``total_pps`` passes at least ``min(tokens, total_pps / 2)`` datagrams of confirmed mappings, whatever other datagrams arrive.
#. **Bounded memory.** Every new table has a fixed size or is bounded by ``global.max_flows``.

Admission order
~~~~~~~~~~~~~~~

An accept thread runs these checks on each accepted connection, in order. The first that fails refuses the connection.

#. The node drains: ``draining``.
#. The address is banned, on a TCP frontend, or on an HTTP frontend under pressure: ``banned``.
#. The frontend reads a PROXY header: the connection goes to the packet worker, which reads the header and then runs checks 2, 4, 5 and 6 with the address the header names.
#. The connection rate of the address: ``rate_limit`` (as before).
#. The node, the frontend and the address hold their caps: ``flow_limit``, ``frontend_limit``, ``client_flow_limit``.
#. Pressure is on, the address is not known, and the bucket of new addresses is empty: ``pressure``. The caps come first, so a connection that a cap refuses spends no token.

An admitted connection goes to the packet worker, which runs the connection hooks, the inspection and the choice of a server as before. A trusted proxy (``trusted_proxies`` of the frontend) is exempt from the address ban, address rate, address cap and new-address bucket, because it carries many clients. The node and frontend caps still apply to admitted flows.

A refusal with ``rate_limit`` or ``client_flow_limit`` is a strike against the address. Both need a completed TCP handshake, so the address is real.

1. Concurrent caps
~~~~~~~~~~~~~~~~~~

``max_flows`` on a frontend is the most flows of that frontend on the node, from 1 to ``global.max_flows``. ``max_flows_per_ip`` is the most flows of one client address on that frontend, from 1 to 1,000,000. IPv6 addresses count per /64, as the rate does. Both apply to TCP connections, UDP mappings, QUIC connections and HTTP connections that the packet worker accepts. A flow counts from its acceptance until its permit is released, when the stream, the mapping or the HTTP connection ends.

The counts live in the flow budget of the node, beside the node count. The table of address counts holds one entry per address with at least one flow, so it never holds more than ``global.max_flows`` entries. An entry is removed when its count reaches zero.

The caps are local to a node. A client that spreads its flows over the nodes of a mesh may hold ``max_flows_per_ip`` on each. Replicating counts would cost a message per flow and is not done.

2. Bans and automatic bans
~~~~~~~~~~~~~~~~~~~~~~~~~~

The packet worker and the HTTP firewall share one ban table. An edge without an HTTP frontend has one too. A client is known in it by the same key as in the firewall: its address in IPv4-mapped form, IPv6 cut to /64 by the edge and its HTTP firewall. The mesh replicates every ban as before (SID 0022), now also on an edge without an HTTP frontend.

``auto_ban`` on a TCP or HTTP frontend bans an address automatically:

.. code-block:: text

   auto_ban: { strikes: 50, window: "10s", ban: "10m" }

``strikes`` is from 1 to 1,000,000. ``window`` is from 1 second to 1 hour. ``ban`` is from 1 second to 24 hours. The strikes are counted by a GCRA limiter of 65,536 cells keyed by address, the same limiter type that counts the connection rate. When the limiter refuses a strike, the address is banned until now plus ``ban`` and the ban is sent to the peers. A refused ban (the probe window of the table holds only bans in effect) is counted and dropped.

3. Cheap refusal
~~~~~~~~~~~~~~~~

``refuse`` on a TCP or HTTP frontend says how a refused connection ends:

- ``"reset"`` (the default). The socket gets ``SO_LINGER`` with a zero time and is closed. The kernel sends a reset and keeps no ``TIME_WAIT`` state for it.
- ``"close"``. An orderly close, as before this record. A client that already sent bytes still sees a reset: the kernel resets a socket closed with unread data.
- ``"tarpit"``. The connection is held without reading for 10 seconds and then reset. A slow scanner waits instead of moving on. At most 1,024 connections are held per accept thread. When the tarpit is full, the oldest one is reset at once.

An HTTP frontend that refuses at accept writes nothing in any mode. The HTTP firewall still answers 503 for its own limits, as before.

4. Pressure mode
~~~~~~~~~~~~~~~~

.. code-block:: text

   global: { pressure: { on: 90, off: 75, new_per_second: 1000 } }

The load is the flows of the node over ``global.max_flows``, in percent. ``on`` and ``off`` are from 1 to 100 with ``off < on``. ``new_per_second`` is from 1 to 1,000,000. These are the defaults, so pressure mode is on for every node. A file can switch it off with ``pressure: "off"``.

The packet worker checks the load at every sweep, every 100 ms, and switches the mode. While pressure is on:

- A new address passes only with a token from a bucket of ``new_per_second`` tokens a second, with a burst of the same size.
- A known address passes as before.
- An HTTP frontend refuses a banned address at accept.

An address becomes known when one of its flows proves it: a TCP stream that carried bytes in both directions, a UDP mapping that got a reply, an HTTP/3 connection whose handshake finished after Retry, or an HTTP exchange that a server answered with a status below 400. A page of Sibuna's own, such as a challenge or a ban page, proves nobody. The table of known addresses has 65,536 slots of 8 bytes. A slot holds 47 bits of the keyed hash of the address combined with the high bits of the proof time, a presence bit and the minute it was last proved. An address stays known for 24 hours after its last proof. Two addresses that share a slot replace each other. An attacker cannot make an address known without completing flows from it, and those count against its caps.

5. Accept threads
~~~~~~~~~~~~~~~~~

``global.accept_threads`` is ``"auto"`` or a number from 1 to 64. ``"auto"`` is the number of available CPUs, at most 4. Each accept thread has its own poller and watches every TCP and HTTP listener. On Linux the registration is exclusive (``EPOLLEXCLUSIVE``), so one connection wakes one thread. Elsewhere every thread wakes and the losers find nothing to accept.

An accept thread runs the admission order above. A refusal ends on that thread. An admitted connection, with its permit, goes to the packet worker over a channel, and a wake-up follows. The permit bounds the connections in the channel by ``global.max_flows``. UDP listeners stay on the packet worker.

The packet worker owns the listeners. It publishes the table of TCP and HTTP listeners that the accept threads watch, with the admission settings of each. It publishes again when the table changes: at the start, after a reload, at a drain, when a lent listener is armed, and when the listeners are given up to a replacement (SID 0029). An accept thread swaps in a new table at its next wake-up, and the packet worker wakes them. A listener that runs out of descriptors is paused on that thread for 50 ms.

6. UDP totals
~~~~~~~~~~~~~

.. code-block:: text

   udp_defense: { mode: "rate_limit", threshold_pps: 1000, total_pps: 200000 }

``total_pps`` is the most datagrams a second that the frontend passes from clients, from 1 to 100,000,000. The budget is a token bucket of ``total_pps`` tokens a second with a burst of the same size. A datagram of a confirmed mapping takes a token when there is one. Any other datagram, including one that would open a mapping, takes a token only if it leaves at least half the burst, rounded down to whole datagrams. A flood from random addresses therefore never takes the last half, and the confirmed mappings keep it.

A mapping is confirmed when its client address is validated (QUIC, SID 0032), or when the server answered and the client then sent again. The second rule is weak: a sender that spoofs an address and guesses that the server answered can send a second datagram without seeing the reply. It is the strongest rule that works for any UDP protocol. A protocol with its own validation, such as QUIC, should use it.

7. Observation
~~~~~~~~~~~~~~

Five reasons join the refusal series of SID 0020: ``banned``, ``pressure``, ``frontend_limit``, ``client_flow_limit`` and ``udp_total_limit``. Strikes and automatic bans are counted as ``sibuna_edge_auto_bans_total`` and ``sibuna_edge_strikes_total``. ``sibuna_edge_pressure`` is 1 while pressure is on, and ``sibuna_edge_pressure_switches_total`` counts the switches. The daemon logs ``EDGE016`` when pressure switches on and when it switches off.

The node keeps the 16 addresses with the most refusals in the current minute in a Space-Saving sketch of 64 counters, with the most recent reason of each. The console's edge page shows them, the pressure state and the new reasons. The metrics endpoint does not export addresses, to keep its series bounded.

Rationale and alternatives
--------------------------

**Counts in the flow budget.** The budget is already the one place where every transport takes a permit. Putting the frontend and address counts there makes the caps hold across TCP, UDP and QUIC, and the Lean model has one lock to reason about. A separate table per frontend would need its own release path.

**Shared accept queue, not ``SO_REUSEPORT`` per thread.** With ``SO_REUSEPORT`` the kernel hashes each connection to one socket. A flood from few addresses then lands on few threads, and a slow thread holds its queue while others idle. One queue with exclusive wake-ups gives each connection to an idle thread. It also keeps one socket per listener, so the handoff of SID 0029 and the reuse of ``global.reuse_port`` are unchanged.

**Refusal on the accept threads, flows on the packet worker.** Moving the whole flow start to the accept threads would put the pools, the hooks and the sticky table under locks. Under attack most connections are refused, so spreading the refusal is what matters.

**Reset as the default.** An orderly close of a refused connection costs a FIN exchange and leaves ``TIME_WAIT`` state on the client side or ours. A reset costs one segment. A legitimate client sees "connection reset" instead of an empty response, which tells it as much.

**Known addresses, not the sticky table.** The sticky table belongs to pools, and a frontend may serve several. The known table is per node, independent of pools, and records only proof of a working flow.

**Pressure on by default.** It changes nothing below 90 percent of the flow table. Above that, the alternative is first come, first served, which a flood wins.

**No kernel programs.** XDP and eBPF could drop packets before the socket. They need privilege, which we do not ask for in containers. They may come later as an optional mode.

Security and operational considerations
---------------------------------------

The ban key and the known key are keyed hashes under secrets drawn at start. An outsider cannot compute which addresses collide.

A spoofed UDP flood cannot be banned usefully: the addresses are random. The total budget and the eviction of unanswered mappings handle it. A ban of a spoofed address would ban the real owner of that address. Automatic bans therefore count only strikes that need a completed TCP handshake, and the file refuses ``auto_ban`` on a UDP frontend. A ban that the HTTP firewall or the operator issued still applies to UDP.

Clients behind one carrier-grade NAT share an address. ``max_flows_per_ip`` and automatic bans treat them as one. The defaults are therefore off, and the operator sets them per frontend.

The tarpit holds descriptors. It is bounded per thread and counted in the descriptor check of the daemon (SID 0020).

Backwards compatibility
-----------------------

Two defaults change. A refused TCP or HTTP connection is reset instead of closed. Pressure mode is on above 90 percent of the flow table. ``refuse: "close"`` and ``pressure: "off"`` restore the old behaviour. Every other option is new and off. Refusal counters gain five reasons.

Acceptance criteria and implementation status
---------------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 6 44 50

   * - #
     - Criterion
     - Status
   * - 1
     - The caps hold under any interleaving of takes and releases.
     - Met. ``caps_hold`` and ``reachable_within`` in the Lean model. ``an_address_holds_its_cap_and_the_frontend_holds_its_own`` in ``crates/lb/tests/defense.rs``: a third flow of one address and a fourth flow of the frontend are reset, and an ended flow gives its places back.
   * - 2
     - A banned address is refused at accept and before a mapping, on every node.
     - Met on one node. ``a_banned_address_is_refused_at_accept_and_opens_no_udp_mapping``: a banned address is reset on TCP and its datagram reaches no server, while others pass. ``defense::tests::a_ban_holds_for_every_spelling_of_an_address_and_its_prefix``. The mesh carries the bans of ``Defense`` with the code of SID 0022, now also on an edge without an HTTP frontend; the replication itself is tested in SID 0022.
   * - 3
     - Strikes ban an address and the ban reaches the peers.
     - Met. ``strikes_beyond_the_rule_ban_the_address``: two rate refusals are within ``strikes: 2``, the third bans, the next connection is refused as ``banned``, and the metrics count 3 strikes and 1 ban. ``within_limits_not_banned`` in the Lean model.
   * - 4
     - A refused connection is reset by default and costs no server work.
     - Met. ``linger::tests::a_reset_reaches_the_peer_as_a_reset`` in ``sibuna-reactor``. ``a_frontend_refuses_by_close_or_by_tarpit_when_asked``: ``close`` ends in order, ``tarpit`` holds the client silent. Every refusal of ``defense.rs`` reaches no origin.
   * - 5
     - Pressure switches with hysteresis, admits known addresses and bounds new ones.
     - Met. ``under_pressure_a_known_address_passes_and_new_ones_wait_for_a_token``: half the table switches pressure on, one new address takes the token of the second, the next is refused as ``pressure``, a known address passes, and pressure switches off when the load falls. ``constant_load_settles``, ``hysteresis``, ``known_pass``, ``new_bounded`` in the Lean model. ``known::tests`` check the expiry across the wrap of the minute counter.
   * - 6
     - Accept and refusal scale over the accept threads.
     - Partly met. Refusal runs on every accept thread, and a drain and a handoff wait until no thread watches a listener they give up (``a_lent_tcp_listener_is_one_queue_for_both_edges``). The cost per refusal is close to HAProxy's. The scaling itself is not shown (gap 4, *Measurement*).
   * - 7
     - Confirmed UDP mappings keep their reserve under a flood.
     - Met. ``total::tests::a_flood_of_others_leaves_half_the_burst_to_confirmed_mappings``. ``flood_keeps_reserve`` and ``confirmed_keep_share`` in the Lean model.
   * - 8
     - The counters, the top sources and the pressure signal are visible.
     - Met. ``top::tests`` find a heavy source among 1,000 light ones within its error bound. The integration tests read ``top_sources`` and the metrics. The console protocol carries ``pressure`` and ``top_refused`` (``a_view_survives_the_wire``), and the edge page shows them.

Measurement
-----------

We ran a release build on one of three LAN hosts (16 cores each, LXC containers, Debian 13, Linux 7.0). The two others generated load with a small client written for the test. HAProxy 3.0.11 ran on the same host with equal settings. Every server was a local echo program.

.. list-table:: A flood of connections refused by ``rate_limit.conn_per_10s: 1``, 1,024 client threads, 15 s
   :header-rows: 1
   :widths: 34 22 22 22

   * - Proxy
     - Connections a second
     - CPU per refused connection
     - Served
   * - Sibuna, 1 accept thread
     - 17,050
     - 22 us
     - 4
   * - Sibuna, 4 accept threads
     - 17,100
     - 43 us
     - 4
   * - HAProxy, 1 thread
     - 17,290
     - 19 us
     - 2
   * - HAProxy, 4 threads
     - 17,240
     - 50 us
     - 2

Both proxies met the same ceiling of about 17,000 connections a second, which is the limit of the generators and the network of the containers, not of either proxy: one accept thread was busy 38 percent of the time. The cost of a refusal is close to HAProxy's. More threads cost more CPU per refusal at this rate, because each wakes for fewer connections. The scaling of accept threads beyond one core is therefore not shown by this run (gap 4).

.. list-table:: One address holds 9,000 connections against a table of 8,192; a second address connects 19 times a second
   :header-rows: 1
   :widths: 40 30 30

   * - Frontend
     - Connections of the holder
     - Connections of the other address
   * - No caps
     - 8,192 held
     - 0 of 97 served
   * - ``max_flows_per_ip: 500``
     - 500 held
     - 95 of 95 served, p99 3.8 ms

Under pressure (``max_flows`` 4,000, ``on`` 90, ``new_per_second`` 20), an address that had never finished a flow opened 3,800 connections: 3,632 passed before pressure switched on and 168 were refused after. A known address was served 93 times of 93 meanwhile. A third address that opened and finished 52,703 connections in 5 seconds passed all of them, because its first finished flow proved it. The daemon logged ``EDGE016`` when pressure switched on and when it switched off.

Known gaps
----------

#. Caps are per node. A mesh does not share counts.
#. Generic UDP confirmation is weak, as stated above.
#. Floods larger than the link are out of reach.
#. The scaling of accept threads over cores is not measured: the generators of the test reached 17,000 connections a second, which one accept thread serves at 38 percent of a core.
#. An address that finishes flows quickly becomes known, so pressure does not slow a client that completes every exchange. The connection rate and the caps bound such a client.
#. A QUIC connection refused by a cap or by pressure is not counted under its reason, only refused.

Open questions
--------------

#. Should the known table be replicated over the mesh, so a client known on one node is known on all?

Review history
--------------

- 2026-11-26. Review after the code and the measurement. The accept threads accepted a connection on a listener just given up to a replacement process; a release and a drain now wait until every thread watches the new table (``publish_and_settle``). A refused connection that had sent bytes is reset by the kernel even with ``refuse: "close"``; the text and the test say so. The check order puts the caps before pressure, so a refused connection spends no token. ``EDGE014`` was taken by the console; the code is ``EDGE016``. An HTTP client is proved only by a server's answer below 400, so a challenge page proves nobody. The PROXY header path now replaces the permit of the header wait with one under the client's own caps.
- 2026-11-26. Initial draft, written before the code, with the Lean model ``docs/sid/assets/admission-under-attack.lean``. The review of the draft found two faults: automatic bans on UDP would let a spoofer ban the owner of an address, so the file refuses them; and a PROXY frontend must run the ban check on the address in the header, not on the proxy.

References
----------

- SID 0015, Distributed Edge Load Balancer. SID 0020, Edge Observability and Client Identity. SID 0022, Replicated Bans. SID 0029, Upgrade Handoff. SID 0032, Staged Admission at the Socket Edge.
- HAProxy 3.0 configuration manual, sections 4.2 (``tcp-request connection``) and 7 (stick tables).
- Envoy 1.31, connection limit filter and overload manager.
- Linux ``epoll_ctl(2)``, ``EPOLLEXCLUSIVE``. ``socket(7)``, ``SO_LINGER``.
- Metwally, Agrawal and El Abbadi, *Efficient Computation of Frequent and Top-k Elements in Data Streams* (2005).
