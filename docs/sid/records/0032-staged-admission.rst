:sid-number: 0032
:sid-title: Staged Admission at the Socket Edge
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-25
:sid-updated: 2026-11-25
:sid-discussion: No external discussion URL assigned
:sid-summary: Completes the admission stages of SID 0015 for TCP and UDP frontends: a total fallback for TLS passthrough metadata that is absent, encrypted, incomplete or invalid, opt-in kernel listener admission that needs no privilege, and QUIC address validation by connection ID that lifts the reply bound of a validated client. Specifies the contract of edge-generated Retry and records why it is not built.
:sid-labels: ["architecture","load-balancer","network","ddos","tls","quic"]

Staged Admission at the Socket Edge
===================================

Abstract
--------

SID 0015 proposes a pipeline of admission stages for each frontend. Most of the stages exist. Three parts were missing, and this record specifies and builds them. First, a TCP passthrough frontend that inspects the TLS ClientHello now states what happens when the metadata is absent, encrypted, incomplete or invalid, and the bound on the inspected prefix is configurable. Second, a TCP or HTTP frontend can ask the kernel to hold a connection until its first bytes arrive and can set its listen backlog. Both need no privilege, and a node where they are off or unavailable runs as before. Third, a UDP frontend that carries QUIC can validate the address of a client by the connection ID that the origin chose, and then lifts the bound on replies that would otherwise starve a download.

We also specify the contract under which the edge could send QUIC Retry packets itself. We do not build it, because the QUIC library of the workspace cannot honour the contract. Cooperative platform-specific batching, the other proposal of SID 0015 at the socket edge, is left out of this record by decision of the project owner.

Motivation and scope
--------------------

The section "Admission and extension points" of SID 0015 lists seven stages. The table below says what each stage was before this record and what this record adds.

.. list-table::
   :header-rows: 1
   :widths: 24 40 36

   * - Stage
     - Before
     - This record
   * - Kernel listener admission
     - None. Listeners used the default backlog of the standard library.
     - ``defer_accept`` and ``backlog`` on a frontend.
   * - Local address and ban checks
     - Bans are checked for HTTP requests. A trusted proxy is exempt from the connection rate.
     - Unchanged. TCP and UDP frontends do not consult bans (known gap).
   * - Protocol-specific address validation
     - PROXY v2 is read only from trusted senders (SID 0020).
     - QUIC validation by connection ID. Retry is specified and not built.
   * - Packet and byte rate limits
     - ``rate_limit.conn_per_10s``, ``udp_defense.threshold_pps``, and replies bounded to three times the received bytes of a mapping.
     - The reply bound ends for a validated QUIC client.
   * - Bounded handshake inspection
     - ClientHello reassembly within 32,768 bytes and ``inspect_delay``. Rules on SNI, ALPN and JA4. Any failure closed the connection.
     - ``inspect_bytes``, ``inspect_fallback``, detection of the Encrypted ClientHello extension, and a screen for QUIC Initial datagrams.
   * - Flow and cache admission
     - ``global.max_flows``, ``global.max_udp_flows``, eviction of unanswered mappings.
     - Unchanged.
   * - HTTP gate or shield
     - Built (SID 0002, SID 0016).
     - Unchanged.

The record covers TCP and UDP frontends of the edge worker in ``sibuna-lb`` and two socket options in ``sibuna-reactor``. It does not change the HTTP firewall.

Specification
-------------

Invariants
~~~~~~~~~~

#. **Bounded prefix.** An inspection holds at most ``inspect_bytes`` bytes of a connection and ends at most one sweep period (100 ms) after ``inspect_delay``.
#. **Total fallback.** Every inspection that the client does not close ends in exactly one of two outcomes: the connection is refused, or it is forwarded to one named pool. No class of metadata is left without an outcome.
#. **Replay exactly once.** A forwarded connection delivers to its origin every byte that the edge read during the inspection, in order, once, before any later byte of the client. A connect attempt that fails receives none of them. A refused connection sends no byte to any origin.
#. **No parse panic.** The ClientHello parser and the QUIC header parser read untrusted bytes. They never panic, never read beyond their input and do work linear in the input.
#. **Unprivileged.** Kernel admission is opt-in. A node that does not ask for it makes no new system call. A node that asks for it and is refused by the platform notes the fact and serves without it.
#. **Reply bound before validation.** A UDP mapping whose client address is not validated sends to that address at most three times the bytes it received from it. Validation never happens on a value that an off-path sender can know.

TLS passthrough inspection
~~~~~~~~~~~~~~~~~~~~~~~~~~

A TCP frontend with ``"tcp_inspect": "tls_client_hello"`` reads the start of each connection before it selects a pool. Two bounds apply. ``inspect_bytes`` is the most bytes we buffer, from 1,024 to 32,768, and 32,768 when absent. A ClientHello with a post-quantum key share is about 1,800 bytes, so a bound below 4,096 leaves little room. ``inspect_delay`` is the longest time we wait, and 2 seconds when absent. The connection holds a flow slot from its acceptance, so ``global.max_flows`` bounds the number of inspections.

When the inspection ends we put the connection in one of five classes.

.. list-table::
   :header-rows: 1
   :widths: 16 60 24

   * - Class
     - Meaning
     - Default action
   * - visible
     - A whole, well-formed ClientHello with a server name and without the ``encrypted_client_hello`` extension.
     - ``rules`` (fixed)
   * - ``absent``
     - A whole, well-formed ClientHello without a server name.
     - ``rules``
   * - ``encrypted``
     - A whole, well-formed ClientHello that carries the ``encrypted_client_hello`` extension (0xfe0d).
     - ``rules``
   * - ``incomplete``
     - The byte bound or the time bound was reached before a whole ClientHello arrived.
     - ``deny``
   * - ``invalid``
     - The bytes are not a TLS handshake record that holds a ClientHello, or the ClientHello is malformed.
     - ``deny``

``inspect_fallback`` names the action of each of the four classes that are not visible.

.. code-block:: text

   inspect_fallback: {
       absent:     { action: "use_backend", backend: "default_tls" },
       encrypted:  { action: "rules" },
       incomplete: { action: "use_backend", backend: "plain_tcp" },
       invalid:    { action: "deny" },
   },

There are three actions. ``deny`` closes the connection. ``use_backend`` forwards it to the named TCP pool, or to ``default_backend`` when no pool is named, and does not consult the rules. ``rules`` evaluates the frontend rules on the metadata that is visible. ``rules`` is accepted only for ``absent`` and ``encrypted``, because the other two classes have no ClientHello to evaluate. The defaults are the behaviour before this record, so a file without ``inspect_fallback`` keeps its meaning.

Under ``rules`` an ``sni`` criterion never matches a ClientHello without a server name. For the ``encrypted`` class the visible server name is the outer name. A real Encrypted ClientHello puts the public name of the provider there. A client that only greases the extension, as current browsers do on every connection, puts the true name there. The edge cannot tell the two apart, and it is not meant to. Hence ``encrypted: deny`` refuses most browsers, and we document that.

A connection that the client closes or resets during the inspection ends there. There is nothing to forward.

A forwarded connection replays the buffered bytes. For ``incomplete`` and ``invalid`` these are whatever the client sent, possibly nothing. A pool with ``proxy_v2`` receives the PROXY header first. The header carries the server name and JA4 TLVs only when a ClientHello was parsed.

The decision function, written out:

.. code-block:: text

   decide(class, hello):
       visible                      -> rules(hello)
       class with action rules      -> rules(hello)
       class with action deny       -> refuse
       class with action use_backend-> forward(pool of the action)

   rules(hello): the first matching rule decides, deny or a pool. No match: default_backend.

JA4 describes a handshake. Any client can send the handshake of another client, and many clients share one fingerprint. A JA4 rule can separate populations of clients for routing or refuse a tool that does not disguise itself. It is no credential, and nothing that needs authentication may depend on it.

Kernel listener admission
~~~~~~~~~~~~~~~~~~~~~~~~~

A ``tcp`` or ``http`` frontend takes two options.

- ``defer_accept``, a duration from 1 second to 60 seconds. On Linux we set ``TCP_DEFER_ACCEPT``. The kernel then completes the handshake and gives the connection to the node only when the first data arrives, or after about that time without data. A connection that never sends a byte costs the node no descriptor, no flow slot and no wakeup until the time passes.
- ``backlog``, a number from 1 to 65,535. We call ``listen`` again on the bound socket with this length of the accept queue. The kernel clamps it to ``net.core.somaxconn`` without telling us.

Both calls need no capability, so they work in an unprivileged container. We apply them when the listener is bound and again at each reload, so an operator can change them without a restart. Removing ``defer_accept`` in a reload sets it to zero. Removing ``backlog`` leaves the queue as it is until the next start.

When the platform has no such option, or the call fails, the node keeps the listener, records a fault, and the daemon notes ``EDGE013`` with the frontend, the option and the error. The start and the reload succeed.

``defer_accept`` suits protocols where the client speaks first: TLS, HTTP, and PROXY v2 from a load balancer. For a protocol where the server speaks first it delays every connection by the configured time.

We do not attach a reuseport steering program (``SO_ATTACH_REUSEPORT_CBPF``). One process has one accepting socket for each bind, so there is nothing to steer between. During a takeover two processes share the address for a moment, and steering there would work against the handoff. SYN cookies are a setting of the host and stay with the host.

QUIC passthrough: validation by connection ID
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A UDP frontend forwards QUIC as it forwards any datagram, and bounds the replies of each mapping to three times what the client sent. The bound stops reflection through a spoofed source. It also throttles a real QUIC download, where the client sends small acknowledgements and the server sends large packets.

A UDP frontend with ``"udp_inspect": "quic"`` does three things.

#. **Initial screen.** A datagram from a client without a mapping opens one only when it starts with a QUIC long header, is at least 1,200 bytes long, and has connection ID lengths that fit the datagram, and that are at most 20 bytes when the version is 1 or 2. RFC 9000 section 14.1 obliges a client to pad its first datagrams to that size, so a conforming client passes. Other datagrams are dropped and counted as ``udp_not_quic``, and they allocate nothing.
#. **Learning.** The edge reads the header of each reply of the origin while the mapping is not validated. From the first reply that starts with a long header, has a version other than zero and has a source connection ID of at least 8 bytes it remembers that connection ID. This is the identifier that the origin chose for the connection. A Version Negotiation packet has version zero and repeats the connection IDs of the client, so the edge never learns from it. The edge also refuses an identifier equal to a connection ID of the datagram that opened the mapping, so an origin that echoes its input validates nobody.
#. **Validation.** When a later datagram of the client carries the remembered identifier as its destination connection ID, in a long or a short header, the mapping is validated. From then on the reply bound does not apply to it.

The argument is that of RFC 9000 section 8.1: a server may consider an address validated when the client uses a connection ID that the server chose and that has at least 64 bits of entropy. The reply that carries the identifier goes to the claimed address. A sender that spoofs the address does not receive it and must guess 64 bits. Each guess is a datagram that ``udp_defense`` counts. Until validation the three-times bound holds, as invariant 6 requires.

The edge trusts its own origins to choose random connection IDs. It can check the length and not the entropy. An origin that uses short or predictable connection IDs must not be put behind ``udp_inspect: "quic"``; with identifiers shorter than 8 bytes no mapping is ever validated, which is the safe failure.

Edge-generated Retry: the contract
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A Retry packet makes the client prove its address before the origin holds any state. If the edge sends it, edge and origin must agree on the following, and all of it must hold before the option may exist.

#. **Token format and key.** The edge seals a token and the origin opens it. Both hold the same key, rotated together, and the same layout: the client address as the origin will see it, the original destination connection ID, the connection ID that the Retry packet used as its source, and the time of issue.
#. **Address binding.** The token binds the client address. The origin must compare it with the client address, not with the address of the edge. So the origin must learn the client address for each datagram, or the edge must forward with the source address of the client.
#. **Connection ID contract.** The origin must put the original destination connection ID and the Retry source connection ID into its transport parameters (RFC 9000 section 7.3), taken from the token. Otherwise the client aborts the handshake.
#. **Retry integrity.** The edge computes the Retry integrity tag of RFC 9001 section 5.8 for each QUIC version it answers.
#. **Lifetime and replay.** Both sides use one lifetime, and the origin refuses a token whose address or connection ID does not match.
#. **Evidence.** Interoperability with the origin's library is tested on loopback, and the reply bound before validation is tested.

We do not build edge-generated Retry. The workspace uses quinn 0.11 (quinn-proto 0.11.19). Its token type and payload are private to the library (``pub(crate)`` in ``token.rs``), so the edge cannot seal a token that quinn opens without copying a private format that may change in any release. The token binds the full socket address of the client, and quinn compares it with the source of the datagram, which behind the edge is the address of the edge's mapping socket. Points 1 and 2 of the contract therefore fail with the stock library, and no loopback test can pass. The Retry of the origin itself keeps working through the edge, because the origin then sees one consistent address for the mapping.

Counters and log lines
~~~~~~~~~~~~~~~~~~~~~~

Two refusal reasons join the series of SID 0020. ``inspect_denied`` counts a TLS passthrough connection that a rule or a fallback refused. ``udp_not_quic`` counts a datagram that the Initial screen dropped. A flow log line of a connection refused by a rule or a fallback ends with ``inspect_denied``. An inspection that timed out and was refused keeps the end ``idle_timeout``.

Rationale and alternatives
--------------------------

**Classes and not error codes.** We considered one fallback for "anything but a good ClientHello". An operator who shares a port between TLS and a plain protocol wants the plain bytes forwarded and a truncated handshake refused. Four classes are the fewest that separate the cases SID 0015 names (absent, encrypted, incomplete) from garbage.

**Defaults that change nothing.** We considered ``deny`` as the default for ``absent`` and ``encrypted``. It would break files that work today, and it would refuse browsers that grease the extension.

**No decryption of Encrypted ClientHello.** The edge has no key for it and passthrough must not need one.

**Validation by connection ID and not by Retry.** Retry at the edge needs the contract above and a cooperating origin. Validation by connection ID needs nothing from the origin beyond what RFC 9000 already asks, and it adds no round trip. Its cost is that the origin holds handshake state for an unvalidated client, bounded by the origin's own limits and by ``udp_defense``.

**A longer reply burst instead of validation.** Raising the factor of three would make the edge an amplifier.

**Accept filters and steering programs.** FreeBSD has accept filters with a similar effect to ``TCP_DEFER_ACCEPT``. We build Linux first and report the option as unavailable elsewhere. Steering programs are rejected above.

**Applying kernel options strictly.** We considered refusing to start when ``defer_accept`` cannot be set. A container runtime with a narrow system call filter would then keep the node from starting over an optimisation. The user's requirement is that the node runs unchanged in an unprivileged container.

Security and operational considerations
---------------------------------------

The parsers are the attack surface. The ClientHello parser works on a copy bounded by ``inspect_bytes`` and refuses duplicate extensions, odd list lengths and trailing bytes. The QUIC parser reads at most the first 47 bytes of a datagram. Both are tested with truncations of valid input at every length and with mutated input.

A fallback that forwards ``incomplete`` connections lets a silent client reach a pool after ``inspect_delay``. It holds a flow slot for that time. ``rate_limit.conn_per_10s`` and ``global.max_flows`` bound the cost. An operator who does not need the fallback keeps ``deny``.

A fallback that forwards ``invalid`` bytes sends bytes of an unknown protocol to a pool. The pool must expect them.

``defer_accept`` moves waiting connections from the node into the kernel's queue of incomplete and deferred connections. That queue is bounded by the host. The option reduces the work of the node. It does not replace SYN cookies.

A validated QUIC mapping has no reply bound. The client proved that it receives at its address, so the traffic is not a reflection. The origin's own congestion control governs the rate. A sender that spoofs the address and the port of a validated client can send a new Initial on its mapping. The edge forwards it, and the origin answers within its own limit of three times, as RFC 9000 obliges it to. For further connections on a validated mapping the edge therefore relies on the origin.

With ``udp_inspect: "quic"`` a client whose mapping expired cannot resume with a short-header packet, because only an Initial opens a mapping. ``session_timeout`` of the frontend should exceed the idle timeout of the QUIC origin.

Backwards compatibility
-----------------------

Every option is new and optional. A file without them serves as before, with one difference in the counters: a connection that a rule denies is now counted under ``inspect_denied``.

Acceptance criteria and implementation status
---------------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 6 44 50

   * - #
     - Criterion
     - Status
   * - 1
     - Every class of TLS passthrough metadata has one outcome, and the file refuses a fallback that cannot be decided.
     - Met. ``inspect::tests::every_class_has_exactly_one_outcome_under_every_fallback`` checks the five classes under all 18 accepted fallbacks. ``the_file_refuses_a_fallback_that_cannot_be_decided`` in ``crates/lb/tests/inspect.rs`` checks nine refused files. ``decision_total`` and ``no_hello_ignores_rules`` in the Lean model.
   * - 2
     - The inspected prefix is bounded in bytes and in time.
     - Met. ``the_byte_bound_ends_a_hello_that_is_too_long`` and ``the_byte_bound_refuses_by_default`` send a ClientHello of about 3,100 bytes against ``inspect_bytes`` 1,024. ``a_silent_client_reaches_the_fallback_pool_and_the_server_may_speak_first`` ends an inspection at ``inspect_delay`` 200 ms. ``hello::tests::random_bytes_never_panic_and_never_exceed_the_bound`` checks the bound over 20,000 random streams. ``reads_bounded`` in the Lean model.
   * - 3
     - A forwarded connection gives its origin the buffered bytes exactly once, in order, before the rest.
     - Met. ``each_class_takes_its_configured_fallback_and_the_bytes_arrive_once`` compares what each pool received with what the client sent, for a ClientHello, a plain request and a ClientHello sent in two parts around the deadline. ``a_failed_connect_receives_nothing_and_the_next_server_receives_the_prefix_once`` puts a refusing server first in the pool. ``forwarded_origin_sees_the_stream`` and ``replay_exactly_once`` in the Lean model.
   * - 4
     - The ClientHello parser survives truncated and hostile input.
     - Met. Nine unit tests in ``crates/lb/src/hello.rs``: every truncation and every split of a valid hello, every single-byte change to three values, 20,000 random streams, 20,000 random bodies under a valid header, duplicate extensions, a false length, other protocols. No panic, and each input has the expected class.
   * - 5
     - Kernel admission is opt-in, needs no privilege, and a refusal does not stop the node.
     - Met on Linux 7.0 x86-64. The tests ran as an ordinary user with an empty effective capability set (``CapEff`` 0). ``a_deferred_frontend_admits_a_client_with_its_first_byte`` in ``crates/lb/tests/listen.rs``: a silent client reaches no server and takes no flow slot for 300 ms, and its first byte admits it. ``a_reload_turns_deferral_on_and_off``. ``listen::tests::options_that_are_not_named_change_nothing_and_report_nothing``. ``listen::tests::a_refusal_of_the_kernel_is_a_fault_and_not_a_failure`` uses a socket on which the kernel refuses both options. The ``EDGE013`` line of the daemon is not tested through the binary (gap 3).
   * - 6
     - Before validation a QUIC mapping sends at most three times what it received, and only an Initial opens a mapping.
     - Met. ``replies_are_bounded_to_three_times_until_the_client_repeats_the_connection_id`` in ``crates/lb/tests/quic_edge.rs``: of eight replies of 1,200 bytes to one Initial of 1,200 bytes, three arrive. A wrong guess of the connection ID lifts nothing. ``only_an_initial_opens_a_mapping_and_the_rest_allocates_nothing``: four other datagrams reach no server. ``unvalidated_replies_bounded`` in the Lean model.
   * - 7
     - Validation never uses a value that the client chose.
     - Met. ``version_negotiation_and_an_echo_validate_nobody`` over sockets, and ``quic_edge::tests::nothing_a_client_chose_is_learned_from_a_reply`` for six kinds of reply.
   * - 8
     - A real QUIC library works through the edge, and validation removes the throttle.
     - Met with quinn 0.11 on both sides through the binary, on loopback, debug build, three runs. ``cmd/sibuna/tests/edge_quic_passthrough.rs``: with ``udp_inspect`` an 8 MiB download took 83 ms to 86 ms. Without it 17,060 bytes arrived in 3 seconds, in each run. A server that answers with Retry serves 1 MiB through the edge.
   * - 9
     - Edge-generated Retry is enabled only under the stated contract.
     - Not built, by the rule of SID 0015. The contract is specified above. quinn-proto 0.11.19 keeps the token format private and binds the token to the source address of the datagram, so the contract cannot hold and no interoperability test can pass.

Known gaps
----------

#. TCP and UDP frontends do not consult the ban table. Bans belong to the HTTP firewall, and an edge without an HTTP frontend has no ban table. The stage "local address and ban checks" of SID 0015 is therefore complete for HTTP only.
#. Edge-generated Retry is specified and not built.
#. The ``EDGE013`` note is produced by a few lines of the daemon that no test runs on Linux, where the kernel accepts both options. The fault itself is tested in the library.
#. Kernel admission is built for Linux. On other Unix systems ``backlog`` is applied and ``defer_accept`` is reported as unavailable. FreeBSD accept filters are not used. Only Linux was run.
#. The effect of ``backlog`` on a full queue is not measured. The test checks that the call succeeds and the listener serves.
#. The edge cannot check the entropy of the connection IDs of an origin, only their length.
#. With ``udp_inspect: "quic"`` a short-header packet of a client without a mapping is dropped. The origin cannot answer it with a stateless reset, and the client waits for its idle timeout.
#. A QUIC client that migrates to a new address gets a new mapping only with an Initial. Connection migration through the edge does not work, as before this record.
#. A greased and a real Encrypted ClientHello are one class. The edge cannot tell them apart.
#. Per-prefix byte budgets for UDP, which SID 0015 names beside packet budgets, are not built. The packet rate is limited per prefix and the reply bytes per mapping.
#. The download figures come from one machine, loopback and a debug build. They show the size of the effect and are no benchmark.
#. Cooperative platform-specific batching is left out of this record by decision.

Open questions
--------------

#. Should TCP and UDP frontends refuse clients that the HTTP firewall banned?
#. Should the origin learn the client address of a QUIC mapping, which would make edge-generated Retry possible?

Review history
--------------

- 2026-11-25. Review of the code as a hostile reader. A client that sent fewer than five bytes of another protocol waited for the deadline, since the record header was judged only when whole. The first two bytes now decide. A validated mapping has no reply bound at the edge, and a sender that spoofs the address and port of a validated client can start further connections on it. The origin's own limit bounds those, and the security section now says so. A test sent a burst of 200 datagrams, overran a socket buffer and lost 32 of them. It now sends 60. A constant for the bytes read of a QUIC header was unused outside the tests and moved there. No fault was found in the replay path: the prefix leaves the edge in one place, when a connect succeeds.
- 2026-11-25. Initial draft, written before the code. The review of the draft found four faults. First, the edge would have learned the connection ID from a Version Negotiation packet, which repeats values that the client chose: a spoofing sender could then validate itself. The edge now learns only from a packet with a version other than zero, and never a value that the opening datagram carried. Second, ``rules`` was allowed for ``incomplete`` and ``invalid``, where there is no ClientHello to evaluate. It is now refused in the file. Third, a failed kernel option stopped the start. It is now a note. Fourth, the smallest ``inspect_bytes`` was 512, below a common ClientHello. It is now 1,024 with a warning in the text.

References
----------

- SID 0015, Distributed Edge Load Balancer.
- SID 0014, JA4 from Ingress. SID 0020, Edge Observability and Client Identity.
- RFC 8446 (TLS 1.3), RFC 9000 (QUIC transport) sections 7.3, 8.1 and 14.1, RFC 9001 section 5.8, RFC 9849 (TLS Encrypted Client Hello).
- FoxIO, *JA4+ Network Fingerprinting* (2023).
