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

The replacement has "validated its configuration, acquired listeners and acknowledged readiness", in the words of SID 0015, when it sends READY. Until then the old process has changed nothing. Between READY and DONE the old process accepts TCP and does not read UDP. That interval is the only one in which UDP datagrams wait.

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
     - At most 64 mappings, with one descriptor for each: the connected server socket.
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
     - The oldest mappings beyond the bound are not sent and end.
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
     - Stops as told.
     - Finds the connection closed and exits with ``UPG005``. It does not serve with the descriptors it holds.
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
   * - A QUIC connection of an HTTP/3 frontend
     - Does not survive. Its state lives in the QUIC runtime of the old process. The UDP socket of HTTP/3 is not passed. The replacement binds its own, which needs ``global.reuse_port`` as today.
   * - Rate limit counters, latency estimates, health states, sticky tables, run-time commands
     - Start anew in the replacement, as after a restart.
   * - The mesh socket and the separate listener of ``observability.listen``
     - Not passed. See "Known gaps".

What a supervisor sees
~~~~~~~~~~~~~~~~~~~~~~

The replacement is an ordinary start. It stays in the foreground and prints ``Sibuna edge listeners ready`` when it serves. The old process exits by itself with status 0 after its drain. It must not be signalled: SIGTERM during the handoff ends the handoff.

A replacement that fails exits with status 1 and a diagnostic. The old process logs one line and serves on.

.. code-block:: text

   UPG010: handed 3 listeners and 1204 UDP mappings to pid 4711
   UPG011: the replacement pid 4711 failed before the cutover: connection closed. Serving on.
   UPG012: refused an upgrade peer: user 1001 is not user 990

Under systemd the two processes are two instances of one template unit, for example ``sibuna-edge@a`` and ``sibuna-edge@b``, with ``Restart=on-failure``. Starting the idle instance replaces the active one, which exits with status 0 and becomes inactive. ``Restart=always`` must not be used: the old instance would start again and take the listeners back. The directory of the sockets must outlive an instance, so it is not the ``RuntimeDirectory`` of the unit. The operations chapter of the book gives the unit.

Structure
~~~~~~~~~

.. code-block:: text

   crates/upgrade     the socket, the frames, the two ends of the protocol, the FFI
        ^             (sendmsg, recvmsg, SO_PEERCRED, SO_TYPE, kill). No other crate.
        |
   crates/lb          Edge::bind_inherited, and in handoff.rs: lend_listeners,
        ^             freeze_datagrams, resume_datagrams, adopt_flows, arm, release
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

Backwards compatibility
-----------------------

A file without ``global.upgrade_socket`` behaves as before. ``global.reuse_port`` keeps its meaning and can be combined with the new key: the listeners of the edge are then passed, and the UDP socket of HTTP/3 is shared as today. SID 0015 proposed descriptor passing "on Unix". We build Linux, because the credentials and the control messages differ on each system and we can test Linux only.

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
     - Pending.
   * - 2
     - A UDP client keeps its server across the upgrade, and the server sees the same source address.
     - Pending.
   * - 3
     - A replacement that fails its check or its start leaves the old process serving, TCP and UDP.
     - Pending.
   * - 4
     - A peer of another user is refused by both ends.
     - Pending.
   * - 5
     - A malformed, oversized or truncated frame ends the handoff.
     - Pending.
   * - 6
     - The cutover state machine has an acceptor for every TCP listener and at most one reader for every UDP socket.
     - Pending.

Known gaps
----------

To be written with the evidence.

Open questions
--------------

#. Should the mesh socket and the separate listener be passed too, so that a node of a mesh can be replaced this way?
#. Should the daemon tell systemd its state with ``sd_notify``, so that one unit can hold both processes?

Review history
--------------

- 2026-11-25. Initial draft, written before the code. The review of the draft found six faults and changed the design. (1) The first draft let the old process resume after a deadline. A slow replacement could then read beside it, so the old process now resumes only on a closed connection and ends a silent replacement first. (2) The first draft sent the mappings with the listeners. Mappings made while the replacement started would have been lost, so the mappings are sent after READY, when the old process has stopped reading. (3) The first draft bound the upgrade socket and the admin socket of the replacement before the cutover. A replacement that failed would have removed the paths of the old process, so both are bound after DONE. (4) The first draft stopped the TCP accept of the old process with the UDP read. That left an instant without an acceptor, so the old process now accepts until DONE and the replacement accepts before it sends DONE. (5) The old process refused connections while it drained, as it does on SIGTERM. After a handoff it must not accept at all, so it removes the listeners from its poller. (6) The replacement trusted the descriptors. It now checks type, address and listening state.

References
----------

- SID 0015, Distributed Edge Load Balancer, section "Reload, drain and rollback".
- SID 0018, Quick Start and Admin Socket.
- SID 0020, Edge Observability.
- ``unix(7)`` and ``cmsg(3)`` of the Linux manual, for ``SCM_RIGHTS`` and ``SO_PEERCRED``.
