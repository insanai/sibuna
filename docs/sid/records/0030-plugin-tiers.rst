:sid-number: 0030
:sid-title: Plugin Tiers: Native, Wasm and Agent Hooks
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-25
:sid-updated: 2026-11-25
:sid-discussion: No external discussion URL assigned
:sid-summary: Specifies where a hook attaches to the edge, what it sees and may change, and three tiers that run it: native Rust, a metered WebAssembly interpreter written in-house, and an agent in another process behind a deadline and a circuit breaker.
:sid-labels: ["architecture","load-balancer","plugins","wasm","security"]

Plugin Tiers: Native, Wasm and Agent Hooks
==========================================

Abstract
--------

An operator wants to add a decision of his own to the edge: an authorization service, a tenant check, a score. SID 0015 proposes three tiers for such code and leaves the Wasm runtime open. We fix three stages where a hook attaches, one view of the traffic that every tier reads, and one rule for what happens when a hook fails. We build the three tiers. The Wasm tier is an interpreter written in-house, with a page budget, fuel and a bound on host calls. The agent tier speaks a small versioned protocol over a Unix socket, under a deadline and a circuit breaker.

Motivation and scope
--------------------

The firewall decides with rules that we ship. Some decisions belong to the operator and change with his business. Compiling them into the daemon is right for code that we trust and review. It is wrong for code that changes weekly or that a third party wrote. Such code must not be able to stop a worker, read the host or grow without bound.

We specify the stages, the view, the verdicts, the failure rule, the configuration and its reload, the Wasm ABI and the agent protocol. We do not specify a hook on the response of a server, a hook that reads or rewrites a body, or a hook on each datagram. The section on rejected alternatives says why.

Specification
-------------

Invariants
~~~~~~~~~~

#. A deployment without hooks pays one load of an atomic word per request and per flow, and nothing else.
#. No lock is taken on the request path. Each thread that serves traffic owns its instances: its Wasm memories, its agent connections and its breakers. The published set of hooks is immutable.
#. A hook that decides is an authorization hook unless the operator wrote ``on_failure: "admit"``. A failure of an authorization hook denies. No failure of any hook admits traffic that the hook was asked to judge, except by that written choice.
#. A telemetry hook cannot change a request, a response or a verdict. Its failure drops one sample.
#. Work on behalf of a Wasm module is bounded before it starts: bytes of the module, pages of memory, fuel per invocation, depth of calls, host calls per invocation. Passing a bound is an error value. It is never a panic, a hang or an unbounded allocation.
#. A Wasm module reaches the host only through the functions of the module ``sibuna`` that this record lists. A module that imports anything else does not load. There is no WASI.
#. A call to an agent returns within its deadline. An open breaker returns at once.
#. A reload publishes a set of hooks only when every hook of the set loaded and passed its checks. A set that fails leaves the serving set in place.

Stages
~~~~~~

A hook attaches to a frontend at one or more of three stages.

.. list-table::
   :header-rows: 1
   :widths: 14 40 46

   * - Stage
     - When it runs
     - What it decides
   * - ``connection``
     - Once for each TCP connection of a TCP or HTTP frontend, after the connection rate and the flow budget admitted it. On a TCP frontend with ``tcp_inspect`` it runs after the ClientHello is read. Once for each new UDP mapping.
     - Admit or deny. A denied connection is closed. A denied datagram is dropped and opens no mapping.
   * - ``request``
     - Once for each HTTP request that the bans, the limiters and the firewall policy admitted, before a server is chosen.
     - Admit, deny or challenge. An admitting hook may add fields to the request for the server.
   * - ``telemetry``
     - Once for each HTTP request, when its answer ended.
     - Nothing.

The request stage has one place in the code, the function that hands an admitted request to a server. Every HTTP path reaches it: the event-driven workers of SID 0016 and SID 0024, the in-process exchanges of SID 0017 for HTTP/2 and HTTP/3, and the thread path. The connection stage has three places in the single-owner edge worker: the admission of a TCP connection, the end of a ClientHello inspection and the opening of a UDP mapping. The telemetry stage has one place, where SID 0020 settles the entry of a request.

The hooks of a stage run in the order of the list. The first verdict that is not an admission ends the chain. Hooks run after the cheap local checks, so traffic that a ban or a limiter refuses never costs a hook call. A request that the policy challenges or denies does not reach the request stage.

The view
~~~~~~~~

Every tier reads the same plain record, the view. The native tier borrows it. The Wasm tier and the agent tier receive its encoding, which the section on the wire form defines.

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Field
     - Meaning
   * - stage, protocol
     - The stage, and ``tcp``, ``udp``, ``http/1.1``, ``http/2`` or ``http/3``. At the connection stage of an HTTP frontend the protocol is ``tcp``.
   * - secure
     - The client reached us over TLS or QUIC.
   * - client, local
     - The address and port of the client and of our listener. At the request stage the client is the address that the firewall judges by, so a trusted proxy is resolved (SID 0020), and its port is zero when a proxy named it.
   * - frontend
     - The name of the frontend.
   * - server name, JA4
     - From the ClientHello of an inspected TCP flow, else empty.
   * - method, host, path, query, fields
     - The request head. The path is in normal form, the one that policy judged and the server receives.
   * - status, duration
     - Telemetry only: the status of the answer and the time from the request to its end in microseconds.

A hook may do four things: admit, deny, ask for a challenge, and add request fields. A hook may not do the following, and no tier gives it the means.

- Read or change a request body or a response body.
- Change the method, the path, the host or an existing field of a request, or remove a field.
- Add a field that carries framing or a hop (``Content-Length``, ``Transfer-Encoding``, ``Connection``, ``Host``, ``Upgrade``, ``TE``, ``Trailer``, ``Keep-Alive``, ``Proxy-*``), or a field that Sibuna writes as its own statement (``X-Sibuna-*``, ``X-Forwarded-*``, ``X-Real-IP``, ``X-Client-Cert-SHA256``). Such a field is dropped and counted.
- Change the response of a server, choose a server, or change a ban or a limiter.
- Open a file or a socket, read the clock except through the host function, or keep the worker past its budget.

One invocation may add at most 8 fields and 1,024 bytes. A field line holds a token name, a colon and a value without control characters.

A denial is answered 403 with the reason ``hook:NAME``. A challenge is the proof-of-work challenge of the firewall under the rule name ``hook:NAME``. A client that holds a session with enough work passes it, as it passes a challenge of the policy. The connection stage has no challenge: a hook that asks for one there denies.

The failure rule
~~~~~~~~~~~~~~~~

An invocation ends with a verdict or with a failure. There are four failures.

.. list-table::
   :header-rows: 1
   :widths: 16 84

   * - Failure
     - Cause
   * - ``timeout``
     - A Wasm hook spent its fuel. An agent did not answer within the deadline.
   * - ``overload``
     - The view does not fit the input buffer of the module or one frame of the agent. More calls wait for the agent than ``queue`` allows.
   * - ``trap``
     - A Wasm trap, a bound of the interpreter, a return value outside the ABI, a malformed answer of an agent, a native hook that reports an error.
   * - ``unavailable``
     - The agent cannot be reached, or its breaker is open.

Each plugin has ``on_failure``. It is ``"deny"`` when it is not written. The outcome of an invocation is then a function of three things, and the Lean model states it.

.. math::

   \mathit{outcome}(s, f, r) = \begin{cases} v & r = \mathrm{verdict}(v),\ s \ne \mathrm{telemetry} \\ \mathrm{deny} & r = \mathrm{failed},\ s \ne \mathrm{telemetry},\ f = \mathrm{deny} \\ \mathrm{admit} & r = \mathrm{failed},\ s \ne \mathrm{telemetry},\ f = \mathrm{admit} \\ \mathrm{admit} & s = \mathrm{telemetry} \end{cases}

Here :math:`s` is the stage, :math:`f` the written choice and :math:`r` the result. At the telemetry stage the outcome is always an admission, because there is nothing to refuse: the request has ended. A chain admits only when every hook of it has the outcome admit. It follows that a chain with a failing authorization hook never admits, whatever the other hooks answer. An admission by failure adds no fields.

Configuration and reload
~~~~~~~~~~~~~~~~~~~~~~~~

Plugins are named at the root of the topology, in JSON and in JLV alike. A frontend lists the names for each stage.

.. code-block:: text

   plugins: {
       tenant:  { kind: "native", hook: "require_header", settings: { name: "x-tenant" } },
       score:   { kind: "wasm", module: "/etc/sibuna/plugins/score.wasm",
                  fuel_limit: 100000, memory_pages: 4, host_calls: 16 },
       authz:   { kind: "agent", socket: "/run/authz.sock", deadline: "5ms", queue: 64,
                  breaker: { failures: 5, open: "1s" } },
       shipper: { kind: "agent", socket: "/run/metrics.sock", on_failure: "admit" },
   },
   frontends: {
       web: { binds: ["0.0.0.0:443"],
              hooks: { connection: ["score"], request: ["tenant", "authz"],
                       telemetry: ["shipper"] } },
   },

.. list-table::
   :header-rows: 1
   :widths: 18 14 68

   * - Key
     - Default
     - Meaning
   * - ``kind``
     - none
     - ``native``, ``wasm`` or ``agent``.
   * - ``on_failure``
     - ``deny``
     - ``deny`` or ``admit``. See the failure rule.
   * - ``hook``, ``settings``
     - none
     - Native: the name of a hook compiled into the daemon, and its settings.
   * - ``module``
     - none
     - Wasm: the path of the module. At most 4 MiB.
   * - ``fuel_limit``
     - 100,000
     - Wasm: the fuel of one invocation, 1,000 to 100,000,000.
   * - ``memory_pages``
     - 4
     - Wasm: the most pages of 64 KiB one instance may hold, 1 to 256.
   * - ``host_calls``
     - 16
     - Wasm: the most host calls of one invocation, 0 to 1,024.
   * - ``socket``
     - none
     - Agent: the path of its Unix socket.
   * - ``deadline``
     - ``5ms``
     - Agent: the longest wait for one answer, 1 ms to 1 s.
   * - ``queue``
     - 64
     - Agent: the most calls of the node that wait for the agent at one time, and the most kilobytes of telemetry frames one thread holds back.
   * - ``breaker``
     - 5, ``1s``
     - Agent: the breaker opens after ``failures`` failures in a row and stays open for ``open``.

A topology may name 16 plugins. A stage of a frontend may list 8.

A reload reads the configuration, loads every module file, decodes and validates it, instantiates it once and checks its exports. Only then does it publish the set. A thread sees the new set at its next request: it compares one generation number, and when the number moved it drops its instances and builds new ones. A request that is inside a hook finishes with the instance it has. A plugin that fails to load refuses the reload with a ``HOOK`` diagnostic, and the old set serves. The file of a module is read at reload only, so replacing the file takes effect at the next reload. An agent need not run at reload: the breaker handles its absence.

The native tier
~~~~~~~~~~~~~~~

A native hook implements one trait of three methods, one for each stage, each with a default that admits. The daemon holds a table of constructors by name, fixed at build time. A constructor reads the settings and returns the hook or an error. A native hook is ``Send`` and each thread builds its own, so a hook may keep state without a lock. It is trusted code: it runs without a budget, and a panic in it is a fault of the daemon. We ship one hook, ``require_header``, which denies a request that lacks a named field or, with ``value``, whose field differs.

The Wasm tier
~~~~~~~~~~~~~

The runtime is an interpreter in the crate ``sibuna-plugin``, written for this purpose. It has no JIT and no ``unsafe``. The section on rationale gives the comparison with an external interpreter.

*Loading.* The decoder reads the binary format with bounds on every count. The validator runs the type-checking algorithm of the specification over every function, and translates the function to a flat sequence of operations with resolved branch targets. A module that does not validate does not load. The interpreter therefore runs only typed code, and its own checks of the stack are a second line that returns an error.

*Instruction set.* We accept the MVP of WebAssembly 1.0 and four later proposals that current compilers emit by default: sign extension, saturating conversions, ``memory.copy`` and ``memory.fill``. We accept one memory, one table, and functions with at most one result. We refuse threads, SIMD, reference types beyond the one function table, multiple memories, exceptions and tail calls.

*Bounds.* The table lists every bound and what passing it does.

.. list-table::
   :header-rows: 1
   :widths: 30 26 44

   * - Bound
     - Value
     - On excess
   * - Bytes of a module
     - 4 MiB
     - Load error.
   * - Types, functions, globals, exports, data segments
     - 4,096; 8,192; 1,024; 1,024; 4,096
     - Load error.
   * - Parameters, locals of a function
     - 255; 4,096
     - Load error.
   * - Entries of the table
     - 65,536
     - Load error.
   * - Initial pages of memory
     - ``memory_pages``
     - Load error.
   * - Pages of memory at run time
     - ``memory_pages``
     - ``memory.grow`` answers -1, as the specification says for a refused growth.
   * - Fuel of one invocation
     - ``fuel_limit``
     - Failure ``timeout``.
   * - Depth of calls
     - 256 frames
     - Failure ``trap``.
   * - Values on the stack
     - 16,384
     - Failure ``trap``.
   * - Host calls of one invocation
     - ``host_calls``
     - Failure ``trap``.

Each operation costs one unit of fuel. ``memory.copy`` and ``memory.fill`` cost one unit more for each 16 bytes, and ``memory.grow`` one unit more for each 64 bytes of new memory, so no operation does unmetered work. Fuel is counted, so the same module on the same input always stops at the same operation. Wall-clock time per unit depends on the machine, and the acceptance section gives the measurement.

*State.* An instance keeps its memory and globals from one invocation to the next on its thread. A hook may therefore cache. It may not rely on it: a reload, a failure or a new thread starts from the initial image. After a failure we reset the instance, so a trap in the middle of a write cannot leave state that a later invocation trusts.

*The ABI, version 1.* A module exports its memory as ``memory`` and the following functions.

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Export
     - Contract
   * - ``sibuna_abi() -> i32``
     - Returns 1. Called once at instantiation.
   * - ``sibuna_input() -> i32``
     - The address of the input buffer. Called once at instantiation.
   * - ``sibuna_input_size() -> i32``
     - The size of the input buffer in bytes, at least 256. Called once at instantiation.
   * - ``sibuna_on_connection(len: i32) -> i32``
     - Judges the view of ``len`` bytes in the input buffer. Required for a hook at the connection stage.
   * - ``sibuna_on_request(len: i32) -> i32``
     - As above, for the request stage.
   * - ``sibuna_on_telemetry(len: i32) -> i32``
     - As above, for the telemetry stage. The return value is ignored.

The return codes are 0 for admit, 1 for deny and 2 for challenge. Any other value is a ``trap``. The three calls at instantiation run under the fuel of one invocation. A module may import these functions of the module ``sibuna``, and nothing else.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Import
     - Contract
   * - ``add_header(ptr: i32, len: i32) -> i32``
     - Adds the field line ``Name: value`` at ``ptr`` to the request for the server. Returns 0, or -1 when the line is refused, the budget of fields is spent, or the stage is not ``request``.
   * - ``now_ms() -> i64``
     - Unix time in milliseconds.

*The wire form of the view.* All integers are little-endian. A text is a ``u16`` length and its bytes.

.. code-block:: text

   offset  size  field
   0       1     wire version, 1
   1       1     stage: 1 connection, 2 request, 3 telemetry
   2       1     protocol: 1 tcp, 2 udp, 3 http/1.1, 4 http/2, 5 http/3
   3       1     flags: bit 0 secure, bit 1 the addresses are IPv6
   4       2     client port
   6       2     local port
   8       16    client address (IPv4 in the first four bytes, the rest zero)
   24      16    local address
   40      2     status
   42      2     number of fields
   44      4     duration in microseconds
   48            texts: frontend, server name, JA4, method, host, path, query
                 then for each field: name, value

A head that does not fit is not cut: the invocation fails with ``overload``. A hook that judged half a head would judge a different request.

The example hook ``cmd/sibuna-hook-wasm`` is 60 lines of Rust without ``std``. It denies a path under ``/admin`` unless the request carries ``x-role: admin``, and it marks admitted requests with a field. Its binary is committed as ``crates/plugin/tests/data/example_hook.wasm``, so no Wasm toolchain is needed to build or test the workspace.

The agent tier
~~~~~~~~~~~~~~

An agent is a process that listens on a Unix stream socket. Each thread that serves traffic holds its own connection, opened at its first call and reopened after a failure. A frame is the following.

.. code-block:: text

   offset  size  field
   0       4     length of the rest of the frame, at most 65,532
   4       1     protocol version, 1
   5       1     kind: 1 decide, 2 verdict, 3 sample
   6       2     zero
   8       8     identifier of the call
   16            payload

The payload of ``decide`` and ``sample`` is the wire form of the view. The agent answers a ``decide`` with a ``verdict`` of the same identifier. Its payload is one byte, 0 for admit, 1 for deny, 2 for challenge, followed by the field lines to add, each ending in CRLF. A ``sample`` has no answer.

*Deadline.* A thread sends the frame and waits for the answer for at most ``deadline``, measured from the start of the call, connection included. A late or malformed answer fails the call and closes the connection, so a stale answer can never be read as the answer to a later call.

*Queue.* A call first takes a place among the ``queue`` calls of the node that may wait for this agent. The count is one atomic word. A call that finds no place fails with ``overload`` and does not touch the socket. A sample never waits: we write what the socket takes at once and hold back the rest in a buffer of the thread, at most ``queue`` KiB. A sample that finds the buffer full is dropped and counted.

*Breaker.* Each thread keeps a breaker for each agent.

.. graphviz::
   :caption: The circuit breaker of one thread for one agent.
   :alt: Closed counts failures and opens at the threshold. Open refuses until its time ends, then lets one probe through. The probe closes or reopens the breaker.

   digraph breaker {
     rankdir=LR;
     node [shape=box, style=rounded];
     closed [label="closed\nn failures in a row"];
     open [label="open until t"];
     probe [label="half open\none call out"];
     closed -> closed [label="success: n = 0\nfailure: n + 1 < limit"];
     closed -> open [label="failure: n + 1 = limit"];
     open -> open [label="call before t:\nrefused"];
     open -> probe [label="call at t or later"];
     probe -> closed [label="success"];
     probe -> open [label="failure:\nt = now + open"];
   }

A call that the breaker refuses fails with ``unavailable`` and costs no system call. With :math:`w` threads, a dead agent costs each thread ``failures`` calls of one deadline each, and then one probe per thread for each ``open`` interval. A call that fails with ``overload`` is not a fault of the agent and does not count.

An agent call occupies its thread for the round trip. On an event-driven worker the other connections of that worker wait for it. The deadline bounds the wait and the breaker bounds how often it is paid. The section on known gaps returns to this.

Crates
~~~~~~

``sibuna-plugin`` is a library without dependencies. It holds the view, the trait, the failure rule, the breaker, the interpreter, the agent client and the published set. ``sibuna-lb`` reads the configuration into the plain specifications of that crate and calls a gate, a boxed closure, at the connection stage. The daemon builds the set, owns the table of native hooks and joins the stages to its request path.

Rationale and alternatives
--------------------------

*An interpreter written in-house against wasmi.* SID 0015 asks which runtime satisfies the instruction, host-call and dependency budgets. We compared our interpreter with wasmi 1.1.0, the mature pure-Rust interpreter with fuel metering. We ran both on the same modules and the same machine. The acceptance section holds the numbers and the method.

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - Measure
     - In-house
     - wasmi 1.1.0
   * - Lines of Rust to audit
     - WASM_LINES
     - 96,233 with its four companion crates and ``wasmparser``
   * - Uses of ``unsafe``
     - 0
     - 143 occurrences of the word in those sources
   * - New crates in the build
     - 0
     - 6 and their transitive dependencies
   * - Speed
     - WASM_SPEED
     - WASM_SPEED_WASMI

The rule of this project is that the standard library comes first and that an external crate must solve a large problem. A complete WebAssembly engine is a large problem. A hook runtime is a small one: one memory, one table, no threads, no SIMD, a fixed ABI, and budgets that we want to define ourselves. The instruction set is specified exactly and the validator is the published algorithm. wasmi is faster on long computations, because it translates to a register machine. A hook spends a few hundred to a few thousand operations on a request, and at that size the difference is below the cost of encoding the view. We chose the in-house interpreter. We would choose wasmi if hooks became compute-heavy, and the trait boundary of the tier lets us do so without changing the ABI.

*A JIT (Wasmtime, Wasmer).* Rejected. A JIT needs executable memory and ``unsafe`` code on a scale that we cannot audit, and its dependencies exceed the rest of the daemon.

*WASI.* Rejected. A hook judges a view. It needs no file, no socket and no environment. Two host functions are easier to bound than a system interface.

*A hook on the response of a server.* Rejected for this record. The head of a response passes three relays, each with its own editor, on the path of the client's bytes. A hook there would run while the client waits for bytes that the server already sent. Fields that depend on the request alone belong to the traffic policy of SID 0019. The telemetry stage sees the status.

*A hook on each datagram.* Rejected. A UDP frontend forwards a datagram in well under a microsecond. A hook call per datagram would dominate it. The mapping is the unit of admission.

*A hook that sees the body.* Rejected. A body is unbounded and streamed. Semantic inspection (SID 0004) is the place for bodies.

*Cutting a head that does not fit.* Rejected. The hook would admit a request that it did not see.

*One shared instance behind a lock.* Rejected by invariant 2.

*An agent protocol over HTTP, or SPOE.* Forward authorization (SID 0002) is the same idea with Sibuna as the callee: an ingress asks us over HTTP. For the call in the other direction we want a frame that we can encode in a few hundred nanoseconds and parse with a bound. HTTP brings a parser into the agent and a head into every call. SPOE is a larger protocol, with negotiation, fragmentation and actions that we do not offer. The view is already encoded for the Wasm tier, and the agent frame is that encoding behind 16 bytes.

*An asynchronous agent call.* A worker could park a request, serve others and resume when the answer arrives. This is the right design for slow agents. It needs a new state in the worker state machine of SID 0016, in the exchanges of SID 0017 and in the thread path. We chose the synchronous call with a short deadline first, and we state its cost.

*A breaker shared by all threads.* One probe for the node instead of one per thread. It needs shared mutable state that every call reads. The cost of the per-thread breaker is bounded and small, and its state machine is the one we proved.

Security and operational considerations
---------------------------------------

A Wasm module is untrusted input. It is decoded with bounds, validated before it runs, and run without ``unsafe`` code, so the worst a hostile module can do is spend its fuel on every invocation and deny or admit by its return value. The operator who attaches a module at an authorization stage trusts its verdicts. He does not have to trust its termination or its memory.

A hook sees request heads, with their cookies and authorization fields. An operator must treat a module and an agent as parties to that data. The socket of an agent is a file: its mode decides who may connect, and who may bind it decides who judges. We connect to the path that the configuration names and we do not create it.

A hook cannot forge the statements that a server reads as ours, because the fields of those names are refused. A hook can still add fields that a server trusts by convention. The operator chooses the names.

A failing authorization hook denies, so a broken agent takes the frontend down for its requests. This is the meaning of failing closed, and ``show hooks`` shows it: calls, denials, failures by cause and the number of threads whose breaker is open. The same numbers are series in the Prometheus text.

An authorization hook with ``on_failure: "admit"`` is an advisory hook. An attacker who can make it fail, for example by a head too large for its buffer, passes it. The documentation says so beside the key.

Backwards compatibility
-----------------------

A topology without ``plugins`` and without ``hooks`` behaves as before. The keys are new, and an older binary refuses a file that has them, as it refuses every unknown key. The wire form of the view and the agent protocol carry a version byte. The ABI names its version in ``sibuna_abi``. The agent tier needs Unix sockets: on other platforms a topology with an agent plugin is refused when it is read.

Acceptance criteria and implementation status
---------------------------------------------

ACCEPTANCE_TABLE

Known gaps
----------

KNOWN_GAPS

Open questions
--------------

#. Should an agent call park the request instead of occupying the thread? What deadline do real agents need?
#. Should a hook be able to add fields to a response that Sibuna itself writes, such as a denial?

Review history
--------------

- 2026-11-25. Initial draft, written before the code.
- 2026-11-25. Review of the draft. It found seven faults, and the text above has the corrections. (1) The draft ran request hooks before the policy, so a client that a rule would have denied could spend an agent call: hooks now run only for admitted requests. (2) The draft cut a head that did not fit the input buffer: a hook would then admit a request it had not seen, so the invocation now fails. (3) The draft let ``on_failure`` default to the choice of each tier: it now defaults to ``deny`` everywhere, and the telemetry stage ignores it. (4) The draft charged one unit of fuel for ``memory.fill`` of any length, which made fuel no bound on time. (5) The draft kept the memory of an instance after a trap. (6) The draft kept an agent connection after a timeout and matched answers by identifier alone: a late answer could then be read by the next call if identifiers were reused after a reconnect, so the connection now closes. (7) The draft counted an ``overload`` as a failure of the agent, so a burst of our own could open the breaker.

References
----------

- SID 0015, Sibuna Edge: TCP, UDP and HTTP Load Balancing. This record builds its plugin tiers and answers its third open question.
- SID 0016, SID 0017 and SID 0024, the HTTP paths that reach the request stage.
- SID 0019, Traffic Policy, whose request edit carries the added fields.
- SID 0020, Edge Observability, whose settled entry feeds the telemetry stage.
- WebAssembly Core Specification 1.0, W3C Recommendation (2019), and its appendix on the validation algorithm.
- The proposals for sign-extension operators, non-trapping float-to-int conversions and bulk memory operations, merged into WebAssembly 2.0.
- Nygard, *Release It!* (2007), for the circuit breaker.
