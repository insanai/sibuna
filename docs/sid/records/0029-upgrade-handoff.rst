:sid-number: 0029
:sid-title: Replacing the Binary: Listener and UDP Flow Handoff
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-25
:sid-updated: 2026-11-25
:sid-discussion: No external discussion URL assigned
:sid-summary: Replaces a running edge by a new process without closing a listener. The old process passes its listening sockets and its live UDP mappings over an authenticated Unix socket, keeps serving until the replacement acknowledges, and takes the service back when the replacement fails before the cutover.
:sid-labels: ["architecture","load-balancer","upgrade","operations"]

Replacing the Binary: Listener and UDP Flow Handoff
===================================================

Abstract
--------

We replace the binary of a running edge without losing a connection that waits in a listener and without moving a UDP client to another server. The old process listens on a Unix socket, ``global.upgrade_socket``. The replacement checks its file, connects, and is given the listening sockets with ``SCM_RIGHTS``. It prepares everything it needs to serve and says so. Only then does the old process stop reading its UDP sockets, send the live UDP mappings with their server sockets, and wait for the acknowledgement. The old process then stops accepting and drains its TCP streams. A replacement that fails before the acknowledgement leaves the old process serving.

This record builds two proposals of SID 0015, section "Reload, drain and rollback": descriptor passing for the listener handoff, and the handoff of live UDP flows. It is built on Linux. Other platforms keep ``global.reuse_port`` or a restart.

Motivation and scope
--------------------

Today a binary is replaced with ``global.reuse_port``. The replacement binds the same addresses, and the old process drains on SIGTERM. Two things are lost. A listener of the old process has an accept queue of its own, and the kernel keeps giving it a share of the new connections until it closes. The old process refuses what it accepts while it drains, and the connections still in its queue are reset when it exits. We measured this: with one long stream holding the old process in its drain, the old process refused or reset new connections for the whole drain. A UDP mapping is user-space state, and the replacement has none of it, so every UDP client is given a server again.

Passing the descriptor removes the first loss, because the listener is never closed: both processes hold the same socket, with one accept queue. Passing the mappings removes the second.

We specify the socket, the protocol, its bounds and failure cases, what survives and what does not, and what a supervisor sees. We do not hand over accepted TCP streams, HTTP connections or QUIC connections. The old process keeps them until they end or until ``global.shutdown_timeout``, as SID 0015 states.

Specification
-------------

Invariants
~~~~~~~~~~

#. At every instant a live process accepts on each TCP listener, unless the replacement dies after it acknowledged the cutover. That case is a crash of the serving process, and the supervisor answers it as it answers any crash.
#. At every instant at most one process reads a UDP listener and the server sockets of its mappings. While nobody reads, the kernel holds the datagrams in the socket, and a live process that will read them holds the socket open.
#. A listener is never closed during the handoff. A failure before the acknowledgement returns the service to the old process, with every listener and every mapping it had.
#. Only a process of the same user takes or gives descriptors. Both ends check the credentials of the peer.
#. Every wait has a deadline, every message a size limit, and every count a bound. A peer that breaks a rule ends the handoff and changes nothing.
#. The edge worker never waits for the peer. A thread of its own speaks the protocol and asks the worker for short, bounded steps.

The setting
~~~~~~~~~~~

.. code-block:: text

   global: {
       upgrade_socket: "/run/sibuna/edge.upgrade",
   },

A daemon with this key listens on the path. A daemon that starts with this key first connects to the path. When a daemon answers there, the new process replaces it. When nobody answers, the new process starts as usual and binds its listeners. So the command of an upgrade is the command of a start, with the new binary.

The replacement takes a lent listener when its file has a listener of the same kind and address, and binds the others itself. A lent listener that its file does not have is closed. When the file has none of the lent listeners, the daemon at the path is another service, and the replacement gives up with ``UPG008`` before it says READY. A reload may not change the key.

The key needs Linux. On another system the file is refused, with a message that names ``global.reuse_port`` and a restart as the ways that system has.

The socket file is created in a private directory with mode 0600 and renamed to the path, as the admin socket of SID 0018 is. A socket file that nobody answers is replaced.

Who speaks to whom
~~~~~~~~~~~~~~~~~~

The replacement connects to the old process. The old process gives; the replacement takes. One handoff runs at a time. The messages below are in the order they are sent.

.. code-block:: text

   replacement (new)                        old process
   -----------------                        -----------
   checks its file
   connect  ------------------------------> accept, check peer credentials
   check peer credentials
   HELLO  min version, max version  ------> choose the version
          <------  LISTENERS  kind, address and descriptor of each listener
   check each descriptor
   build the edge on the descriptors,
   start HTTP, logs and counters.
   Nothing reads a descriptor yet.          serves as before: accepts, reads UDP
   READY  --------------------------------> stop reading UDP listeners and the
                                            server sockets of UDP mappings
          <------  FLOWS  the mappings, each with its server socket
          <------  COMMIT  number of mappings
   adopt the mappings
   start accepting on the TCP listeners     still accepts on the TCP listeners
   DONE  adopted, dropped  ---------------> stop accepting, forget the mappings,
   start reading UDP                        drain TCP streams, exit with status 0
   bind the upgrade socket and
   the admin socket
   "listeners ready"

The replacement has "validated its configuration, acquired listeners and acknowledged readiness", in the words of SID 0015, when it sends READY. Until then the old process has changed nothing. Between READY and DONE the old process accepts TCP and does not read UDP. That interval is the only one in which UDP datagrams wait. The old process measures it and writes it in its log line.

After DONE the old process removes the listeners from its poller. It does not accept and refuse, as a process does that drains on SIGTERM, because the listeners now belong to the replacement too. It serves on for 200 ms before it drains: a drain closes an HTTP connection that has sent no request yet, and the connections accepted in the last instant are in that state.

The frames
~~~~~~~~~~

The socket is a Unix stream socket. A frame has a header of seven bytes and a payload.

.. code-block:: text

   kind: 1 byte | payload length: 4 bytes, little endian | descriptors: 2 bytes | payload

The descriptors of a frame travel with its header in one ``sendmsg`` call, as one ``SCM_RIGHTS`` control message. The receiver reads every header with ``recvmsg`` and the flag ``MSG_CMSG_CLOEXEC``. It refuses a header whose count differs from the descriptors that arrived, a truncated control message, a payload above 65,536 bytes and more than 64 descriptors in a frame.

.. list-table::
   :header-rows: 1
   :widths: 14 12 74

   * - Frame
     - Sender
     - Payload
   * - HELLO
     - new
     - The bytes ``SBUP``, the lowest and the highest version the replacement speaks, 2 bytes each.
   * - REFUSE
     - either
     - A code of 2 bytes and a text of at most 512 bytes. The sender closes after it.
   * - LISTENERS
     - old
     - The chosen version, a flag that says whether more LISTENERS frames follow, and at most 64 listeners. A listener is its kind (TCP, HTTP or UDP) and its address. The frame carries one descriptor for each.
   * - READY
     - new
     - Empty.
   * - FLOWS
     - old
     - At most 64 mappings, with one descriptor for each: the connected server socket. The old process copies the descriptors of 4,096 mappings at a time, sends them and closes the copies, so the copies never fill its descriptor table.
   * - COMMIT
     - old
     - The number of mappings sent, 4 bytes.
   * - DONE
     - new
     - The mappings adopted and the mappings dropped, 4 bytes each.

A mapping is the index of its listener in the LISTENERS list, the client address, the server address, the milliseconds since its last datagram, its idle timeout, the milliseconds it has waited for a first answer if it has none yet, and the two reply credits that bound amplification.

Version 1 is the only version. The old process chooses the highest version in the range of the HELLO that it speaks too, and refuses when there is none. A later version may add frames and fields. It may not change version 1.

Bounds
~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 40 20 40

   * - Bound
     - Value
     - On excess
   * - Wait for HELLO, and for LISTENERS
     - 5 s
     - The handoff ends. The old process serves on.
   * - Wait for READY
     - 60 s
     - The handoff ends. The old process serves on.
   * - Cutover: from READY to DONE
     - 10 s
     - The old process ends the replacement and reads again.
   * - A step of the edge worker for the handoff
     - 5 s
     - The handoff ends.
   * - Listeners
     - 4,096
     - The old process refuses the handoff.
   * - Mappings
     - 1,048,576
     - The mappings beyond the bound are not sent and end. Which ones is not specified.
   * - Payload of a frame
     - 65,536 bytes
     - Protocol error.
   * - Descriptors in a frame
     - 64
     - Protocol error.

Authentication
~~~~~~~~~~~~~~

Three things guard the socket. The file has mode 0600 from the instant it has a name, so only the user of the daemon and root can connect. The old process reads the credentials of the connecting process with ``SO_PEERCRED`` and refuses a peer whose user differs from its own effective user. Root is refused too, when the daemon is not root: a replacement runs as the daemon does. The replacement reads the credentials of the process that listens and refuses in the same way, so a socket planted at the path by another user gives it nothing.

A process of the same user can already signal the daemon and read its memory. The handoff gives it no new power.

The replacement also checks what it is given. A descriptor of a listener must be a socket of the announced type, bound to the announced address, and a TCP listener must be listening. The server socket of a mapping must be a datagram socket connected to the announced server. A descriptor that fails ends the handoff before READY, or drops that one mapping after it.

Failure cases
~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 34 33 33

   * - What fails
     - Old process
     - Replacement
   * - The peer is another user.
     - Sends REFUSE, logs ``UPG012``, serves on.
     - Exits with ``UPG001``.
   * - No common version.
     - Sends REFUSE, logs ``UPG011``, serves on.
     - Exits with ``UPG002``.
   * - The daemon at the path serves none of the addresses of the replacement.
     - Sees the connection close before READY, logs ``UPG011``, serves on.
     - Exits with ``UPG008``.
   * - The file of the replacement does not check.
     - Sees nothing: the replacement never connects.
     - Exits with ``EDGE001`` as today.
   * - The replacement fails to start after LISTENERS: a certificate, a log file, a second handoff in progress.
     - Sees the connection close before READY, logs ``UPG011``, serves on. It never stopped.
     - Exits with the diagnostic of the failure.
   * - READY does not come in 60 s.
     - Closes the connection, logs ``UPG011``, serves on.
     - Finds the connection closed and exits with ``UPG005``.
   * - The replacement dies between READY and DONE.
     - Sees the connection close, reads its UDP sockets again, logs ``UPG011``. Datagrams that arrived meanwhile are read then.
     - Gone.
   * - DONE does not come in 10 s and the connection stays open.
     - Sends SIGKILL to the replacement, waits for the connection to close, reads again, logs ``UPG011``.
     - Killed.
   * - The old process is told to stop during a handoff.
     - Drains as told and still answers the replacement while it drains. When the replacement acknowledges, the old process stops accepting on the listeners.
     - Takes over when it acknowledges in time. When the old process ends first, it finds the connection closed, exits with ``UPG005`` and does not serve with the descriptors it holds.
   * - The replacement dies after DONE.
     - Is draining and exits. It does not come back.
     - Gone. The supervisor restarts it, and it binds as a first start does.

The old process resumes only when the connection is closed. A closed connection proves that the replacement has stopped: the replacement reads no UDP socket before it has written DONE, and it holds the connection open until then. A deadline alone proves nothing, because a stopped or slow replacement could wake and read. That is why the old process ends the replacement before it resumes, and does not trust a clock.

What survives
~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - State
     - Across the upgrade
   * - A connection waiting in a TCP listener
     - Survives. The listener is one socket in both processes.
   * - An accepted TCP stream, an HTTP connection
     - Stays with the old process until it ends or until ``global.shutdown_timeout``. Forced closes are counted in the last log line.
   * - A UDP mapping of a ``udp`` frontend
     - Survives with its server and its server socket, when the new file has the same listener, the pool of that listener still has a server at that address, and the new process has room under ``max_flows`` and ``max_udp_flows``. Otherwise it ends, and its client is given a server by its next datagram.
   * - A datagram that arrives during the cutover
     - Waits in the socket and is read by whoever reads next. It is lost only when the receive buffer of the socket overflows.
   * - A connection that the old process accepted and that has sent nothing 200 ms after the cutover
     - Is closed by the drain of the old process, as on any shutdown.
   * - A QUIC connection of an HTTP/3 frontend
     - Does not survive. Its state lives in the QUIC runtime of the old process. The UDP socket of HTTP/3 is not passed. The replacement binds its own beside the old one, so with ``upgrade_socket`` that socket shares its address as it does with ``global.reuse_port``. Until the old process exits the kernel gives it a share of the QUIC packets.
   * - Rate limit counters, latency estimates, health states, sticky tables, run-time commands
     - Start anew in the replacement, as after a restart.
   * - The mesh socket and the separate listener of ``observability.listen``
     - Not passed. See "Known gaps".

What a supervisor sees
~~~~~~~~~~~~~~~~~~~~~~

The replacement is an ordinary start. It stays in the foreground and prints ``Sibuna edge listeners ready`` when it serves. The old process exits by itself with status 0 after its drain. It must not be signalled: SIGTERM during the handoff ends the handoff.

A replacement that fails exits with status 1 and a diagnostic. The old process logs one line and serves on.

.. code-block:: text

   UPG010: handed 3 listeners and 1204 UDP mappings to pid 4711, 0 mappings dropped, UDP unread for 14 ms
   UPG011: the replacement pid 4711 failed before the cutover: reading the upgrade socket: the peer closed the connection. Serving on.
   UPG012: refused an upgrade peer: user 1001 is not user 990
   UPG013: the replacement pid 4711 cannot be ended. UDP stays unread until it is gone. End it by hand.

The replacement logs ``UPG020: took 3 listeners and 1204 UDP mappings from pid 4242, 0 mappings dropped`` before ``listeners ready``.

Under systemd the two processes are two instances of one template unit, for example ``sibuna-edge@a`` and ``sibuna-edge@b``, with ``Restart=on-failure``. Starting the idle instance replaces the active one, which exits with status 0 and becomes inactive. ``Restart=always`` must not be used: the old instance would start again and take the listeners back. The directory of the sockets must outlive an instance, so it is not the ``RuntimeDirectory`` of the unit. The operations chapter of the book gives the unit.

Structure
~~~~~~~~~

.. code-block:: text

   crates/upgrade     the socket, the frames, the two ends of the protocol, the FFI
        ^             (sendmsg, recvmsg, SO_PEERCRED, SO_TYPE, kill). No other crate.
        |
   crates/lb          Edge::bind_inherited, and in handoff.rs: lend_listeners,
        ^             freeze_datagrams, lend_flows, resume_datagrams, adopt_flows,
        |             arm_streams, arm_datagrams, release_listeners, waker
        |
   cmd/sibuna         edge/upgrade.rs: the gate thread of the old process and the
                      start of the replacement

The crate ``sibuna-upgrade`` knows sockets and addresses and nothing of the edge. Its FFI module is the only unsafe code of this record.

Rationale and alternatives
--------------------------

**The replacement connects, the old process does not spawn.** SID 0015 drew SIGUSR2 and an old process that starts the new binary. Then the supervisor's main process changes behind its back, and the old process must know the path and the arguments of the new binary. A replacement that is an ordinary start needs neither. The supervisor starts it, sees its exit status and its log.

**A socket of its own.** The admin socket carries one line and one answer for each connection, at most ten a second, and a tool speaks it. Descriptors and a conversation of several steps do not fit it.

**Killing a silent replacement.** We considered a lease: the replacement would give up when it could not acknowledge within half the deadline, measured on its own clock. A process that is stopped between its last check and its first read breaks that, and two readers would follow. Ending the process is the only fence that needs no clock. The peer is of our own user, so the signal is permitted.

**TCP overlaps, UDP does not.** Two processes that accept on one socket lose nothing: each connection goes to one of them. Two processes that read one UDP socket would give the datagrams of one client to two tables. So the TCP listeners have two acceptors for an instant, and the UDP sockets have none for an instant.

**The same server socket, not a new one.** The replacement could open a new socket to the server of a mapping. The server would then see a new source port and treat the client as new. Passing the socket keeps the return path.

**No handoff of TCP streams.** A relayed TCP stream is two sockets and a few counters, and could be passed. An HTTP connection is a parser in the middle of a message, and a TLS connection holds keys. We leave all of them with the old process, which SID 0015 specifies, and bound the wait.

**No QUIC handoff.** Passing the UDP socket of HTTP/3 without the connection state would end the connections at once, where today they live until the old process exits. Routing by connection ID between two processes is the "compatible stateless routing" of SID 0015 and is not built.

Security and operational considerations
---------------------------------------

Whoever can connect to the socket as the user of the daemon can take its listeners. The same user can stop the daemon by a signal, so the socket adds no power. The path belongs in a directory that only that user can write, as the admin socket does.

A start with this key replaces a running daemon. Starting the daemon twice by mistake no longer fails with ``ADDRESS IN USE``: the second replaces the first. An operator who wants the old refusal leaves the key out.

The replacement starts from its file. Run-time commands given to the old process, such as a drained server, are not carried over. The operator repeats them, or writes them in the file first.

The replacement needs descriptors for every mapping it adopts, beside those the old process holds. The limit of the service must allow for the new process as it does for the old.

During the cutover UDP datagrams wait in the kernel. We measure the interval in the acceptance table. A burst larger than the receive buffer in that interval is dropped by the kernel, as it is when the worker is busy.

The old process ends a silent replacement by the process id that the kernel recorded for the connection. Were that process gone and its id given to another process while a third process held the connection open, the signal would reach the wrong process. Our replacement never passes its connection on, and the peer is of our own user. A process descriptor (``SO_PEERPIDFD``, Linux 6.5) would close the hole and is not used.

Backwards compatibility
-----------------------

A file without ``global.upgrade_socket`` behaves as before. ``global.reuse_port`` keeps its meaning and can be combined with the new key: the listeners of the edge are then passed, and the UDP socket of HTTP/3 is shared as today. We did not test the two keys together. SID 0015 proposed descriptor passing "on Unix". We build Linux, because the credentials and the control messages differ on each system and we can test Linux only.

Acceptance criteria and implementation status
---------------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 6 54 40

   * - #
     - Criterion
     - Status
   * - 1
     - New TCP connections and requests during an upgrade lose none, also while the old process drains a long stream.
     - Met in the test. ``no_connection_is_lost_while_the_listeners_are_handed_over`` in ``cmd/sibuna/tests/edge_upgrade.rs``: 17,382 to 33,524 connections in a run, 0 failed, in 27 runs of the final code. ``the_reuse_port_path_is_measured_beside_the_handoff`` gives the same load to ``global.reuse_port``: 12,960 to 25,044 served and 9,943 to 22,516 failed in a run. Method below.
   * - 2
     - A UDP client keeps its server across the upgrade, and the server sees the same source address.
     - Met. ``udp_clients_keep_their_server_across_two_upgrades``: 41 mappings through two upgrades, a client that sends every 2 ms lost 0 and moved 0 of 97 to 390 datagrams, UDP unread for 0 to 1 ms. ``six_thousand_mappings_move_in_two_pieces``: 6,000 mappings, 0 dropped, 0 moved, UDP unread for 59 to 87 ms on a quiet machine and up to 252 ms beside other builds. In one process: ``a_mapping_keeps_its_server_and_its_source_in_the_replacement`` in ``crates/lb/tests/handoff.rs``.
   * - 3
     - A replacement that fails its check or its start leaves the old process serving, TCP and UDP.
     - Met. ``a_replacement_that_fails_leaves_the_old_process_serving``: a file that does not check, a start that fails after the listeners were taken, and a replacement that stops between READY and DONE, which is ended with SIGKILL after 10 s. HTTP and TCP answer during the stalled cutover, and the datagram that waited is answered by the same server. ``the_daemon_of_another_service_is_not_replaced`` covers a mistaken path.
   * - 4
     - A peer of another user is refused by both ends.
     - Met in the crate, partly through the binary. ``the_giver_refuses_a_peer_of_another_user_and_tells_it`` and ``the_taker_refuses_a_socket_served_by_another_user`` in ``crates/upgrade/src/tests.rs`` give each end a user id that is not its own. Through the binary, ``a_wrong_peer_is_refused_by_both_ends`` checks mode 0600, a stranger, a foreign version, a foreign socket at the path and a refusal. No test runs a second user: the tests may not change this machine.
   * - 5
     - A malformed, oversized or truncated frame ends the handoff.
     - Met. The tests of ``wire.rs`` and ``channel.rs`` in ``crates/upgrade``: every cut of a frame, a header that lies about its descriptors, an oversized payload. ``a_descriptor_that_is_not_the_announced_listener_ends_the_handoff`` and ``a_commit_that_counts_wrongly_ends_the_handoff`` in ``tests.rs``.
   * - 6
     - The cutover state machine has an acceptor for every TCP listener and at most one reader for every UDP socket.
     - Proved for the model. ``docs/sid/assets/upgrade-handoff.lean``, Lean 4 core: ``single_reader``, ``always_an_acceptor``, ``old_stops_only_after_done``, ``new_reads_after_done``, ``old_reads_before_ready``, ``failure_returns_service``, ``retry_is_possible``. The model is not derived from the code.

**Method.** All tests start the real binary, a debug build, on loopback, with two HTTP servers, two TCP echo servers and two UDP servers behind it. The load of criterion 1 is four client threads. Each opens a connection, sends one HTTP request and reads the answer, then opens a connection to the TCP frontend, sends four bytes and reads them back, without a pause. One more TCP stream stays open for 1.5 s after the replacement started, so the old process drains for about 1.7 s. A connection counts as failed when it is refused, reset, or closed without the answer. The numbers are from runs on a machine that built other code at the same time. They compare two paths under one load. They are not a throughput.

Under ``global.reuse_port`` the failures are the connections that the kernel gave to the listener of the draining process, which refuses what it accepts. They last as long as the drain. The handoff has no such listener.

The interval "UDP unread" is measured by the old process, from READY to DONE, and printed in ``UPG010``.

Known gaps
----------

- **Fleet-wide limits.** A UDP mapping that the replacement adopts is not counted against a limit of ``max_flows_scope: "fleet"`` (SID 0025). The share of the replacement starts anew, and we do not refuse an established flow. Until such mappings end, the server may hold that many flows beyond its limit.
- **Forwarded mappings.** A mapping that a peer forwarded (SID 0026) is adopted as a local one. Its replies leave from the address of this node and not through the peer, so a client behind a strict address filter may drop them. No test covers it.
- **Linux only.** SID 0015 proposed Unix. The FFI is built for Linux on x86-64, x86, aarch64, arm and riscv64, and tested on x86-64 only. Elsewhere the key is refused.
- **Mesh, cluster and observability listeners are not passed.** The mesh socket, the listener for cluster configuration and the separate listener of ``observability.listen`` are bound by the replacement itself. A node that has one of them cannot be replaced this way: the replacement should fail before READY with an address in use and leave the old process serving. We did not test that.
- **HTTP/3.** QUIC connections end with the old process. During its drain the old process still receives a share of the QUIC packets on its own socket. ``a_frontend_with_http3_is_replaced_and_its_tcp_listener_is_passed`` shows that such a frontend is replaced and that TCP loses nothing. It makes no HTTP/3 request.
- **A connection accepted in the last instant.** A drain closes an HTTP connection that has sent no request. Before we added the 200 ms of service after the cutover, one connection of about 300,000 was reset this way, in one run of 14. After it, none in 27 runs. A client that sends its request more than 200 ms after it connected, at that instant, is still closed. The principled repair is in the HTTP workers: let a connection that has served nothing read its first request while the process drains.
- **A crash after DONE is an outage.** When the replacement fails after it acknowledged, also in binding its admin socket, the old process does not come back. The supervisor restarts the replacement.
- **No ``sd_notify``.** systemd needs two instances of a template unit. One unit cannot hold both processes.
- **State that is not carried.** Run-time commands, rate counters, latency estimates, health states and sticky tables start anew. Flows that a peer forwards (SID 0026) were not considered.
- **Untested paths.** The line ``UPG013`` and a replacement that cannot be ended. A stop of the old process during a handoff. A handoff with more than 6,000 mappings, and the bound of 1,048,576. ``global.reuse_port`` together with the new key. A descriptor limit that is too low for the replacement. A real second user.
- **Process id.** See "Security and operational considerations".

Open questions
--------------

#. Should the mesh socket and the separate listener be passed too, so that a node of a mesh can be replaced this way?
#. Should the daemon tell systemd its state with ``sd_notify``, so that one unit can hold both processes?

Review history
--------------

- 2026-11-25. Merge with SID 0025, SID 0026 and SID 0032. A mapping now carries one more byte, whether the client address is validated, so that a QUIC mapping keeps its release from the reply bound across the handoff. A mapping that a peer forwarded answers the client directly after the handoff. An adopted mapping is outside the count of a fleet-wide limit.
- 2026-11-25. Initial draft, written before the code. The review of the draft found six faults and changed the design. (1) The first draft let the old process resume after a deadline. A slow replacement could then read beside it, so the old process now resumes only on a closed connection and ends a silent replacement first. (2) The first draft sent the mappings with the listeners. Mappings made while the replacement started would have been lost, so the mappings are sent after READY, when the old process has stopped reading. (3) The first draft bound the upgrade socket and the admin socket of the replacement before the cutover. A replacement that failed would have removed the paths of the old process, so both are bound after DONE. (4) The first draft stopped the TCP accept of the old process with the UDP read. That left an instant without an acceptor, so the old process now accepts until DONE and the replacement accepts before it sends DONE. (5) The old process refused connections while it drained, as it does on SIGTERM. After a handoff it must not accept at all, so it removes the listeners from its poller. (6) The replacement trusted the descriptors. It now checks type, address and listening state.

- 2026-11-25. Review of the code as a hostile reader, after the first tests passed. Nine findings, all repaired except where noted. (1) The gate thread waited up to 25 ms for each answer of the worker, so UDP stayed unread for about 50 ms plus 25 ms for every 4,096 mappings. The thread now wakes the worker. (2) A replacement whose file named the socket of another service would have taken that service down. It now gives up with ``UPG008``. (3) A drain closes HTTP connections that have sent nothing, and one connection in about 300,000 was lost to it. The old process now serves 200 ms more. This narrows the fault and does not remove it; see "Known gaps". (4) A process told to stop during a handoff stopped answering the gate thread and refused connections on listeners that the replacement had taken. It now answers while it drains. This repair has no test. (5) HTTP/3 needed ``global.reuse_port`` beside the new key, or the replacement failed with an address in use. The key now implies the shared address for that socket. (6) The first test with 6,000 clients failed two to four clients in a run. The cause was in the test: a loopback port that a wake-up socket of an ended process had used was given to a client, which then read a stray byte. The clients now accept datagrams from the listener only. (7) The bound on mappings said "the oldest". The code does not order them, and the text now says so. (8) The scene of the tests removed its directory when a start was retried. (9) The signal to a silent replacement uses a process id. The limit is recorded under security, not repaired. The review of the FFI found the layouts of ``msghdr`` and ``cmsghdr`` correct for the processors named, with glibc and musl, and no descriptor that leaks on a truncated control message.

References
----------

- SID 0015, Distributed Edge Load Balancer, section "Reload, drain and rollback".
- SID 0018, Quick Start and Admin Socket.
- SID 0020, Edge Observability.
- ``unix(7)`` and ``cmsg(3)`` of the Linux manual, for ``SCM_RIGHTS`` and ``SO_PEERCRED``.
