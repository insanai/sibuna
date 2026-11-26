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
     - Once for each TCP connection of a TCP or HTTP frontend, after the connection rate and the flow budget admitted it. On a TCP frontend with ``tcp_inspect`` it runs after the ClientHello is read. Once for each new UDP mapping. Once for each QUIC connection of a frontend that serves HTTP/3, when the ClientHello of the connection is read: the view has the protocol ``quic``, the client address and the server name, and no JA4. This is the first moment at which the QUIC library (quinn 0.11) tells the server name. Before it, at ``Incoming``, only the address is known. The library goes on with the handshake while the hooks judge, and gives us no way to hold it. So the verdict does not stop the handshake. It decides whether the connection may serve: no request stream is accepted before the verdict, and a denied connection is closed. The TCP connections of the same frontend are judged at their accept, as on every HTTP frontend.
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
     - The stage, and ``tcp``, ``udp``, ``http/1.1``, ``http/2``, ``http/3`` or ``quic``. At the connection stage of an HTTP frontend the protocol is ``tcp`` for a TCP connection and ``quic`` for a QUIC connection.
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

The telemetry view is built from the entry that SID 0020 settles. It has the frontend, the protocol, the client address without a port, the listener, the method, the host, the path, the status and the duration. It has no query and no fields, and its host and path are cut at the bounds of the access log, 255 and 1,024 bytes. A telemetry hook observes, so a cut text cannot change a decision.

A hook may do four things: admit, deny, ask for a challenge, and add request fields. A hook may not do the following, and no tier gives it the means.

- Read or change a request body or a response body.
- Change the method, the path, the host or an existing field of a request, or remove a field.
- Add a field that carries framing or a hop (``Content-Length``, ``Transfer-Encoding``, ``Connection``, ``Host``, ``Upgrade``, ``TE``, ``Trailer``, ``Keep-Alive``, ``Proxy-*``), or a field that Sibuna writes as its own statement (``X-Sibuna-*``, ``X-Forwarded-*``, ``X-Real-IP``, ``X-Client-Cert-SHA256``). Such a field is dropped and counted.
- Change the response of a server, choose a server, or change a ban or a limiter.
- Open a file or a socket, read the clock except through the host function, or keep the worker past its budget.

One invocation may add at most 8 fields and 1,024 bytes. A field line holds a token name, a colon and a value without control characters.

A denial is answered 403 with the reason ``hook:NAME``. A challenge is the proof-of-work challenge of the firewall under the rule name ``hook:NAME``. A client that holds a session with enough work passes it, as it passes a challenge of the policy. The hook then counts as one that admitted without fields, and the chain goes on with the hooks behind it. A cleared challenge therefore never skips a hook. A denial is never cleared. The connection stage has no challenge: a hook that asks for one there denies.

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

A reload reads the configuration, loads every module file, decodes and validates it, instantiates it once and checks its exports. Only then does it publish the set. We finish the fallible listener and route checks before publishing the hooks. We publish the hooks immediately before the new routes. A refused route revision leaves the serving hooks and their generation intact. A thread sees the new set at its next request: it compares one generation number, and when the number moved it drops its instances and builds new ones. A request that is inside a hook finishes with the instance it has. A plugin that fails to load refuses the reload with a ``HOOK`` diagnostic, and the old set serves. The file of a module is read at reload only, so replacing the file takes effect at the next reload. An agent need not run at reload: the breaker handles its absence.

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
   2       1     protocol: 1 tcp, 2 udp, 3 http/1.1, 4 http/2, 5 http/3, 6 quic
   3       1     flags: bit 0 secure, bit 1 the client address is IPv6, bit 2 the local one is
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

The example hook ``cmd/sibuna-hook-wasm`` is one file of 223 lines of Rust without ``std``, its tests included. Its module has 1,268 bytes. It denies a path under ``/admin`` unless the request carries ``x-role: admin``, and it marks admitted requests with a field. Its binary is committed as ``crates/plugin/tests/data/example_hook.wasm``, so no Wasm toolchain is needed to build or test the workspace.

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

.. typst-diagram:: ../diagrams/breaker.typ
   :caption: The circuit breaker of one thread for one agent.
   :alt: Three states. The breaker starts closed and counts n failures in a row: a success sets n to 0, and a failure with n + 1 below the limit counts it. A failure with n + 1 equal to the limit opens the breaker until t, which is now plus the open time. While open, a call before t is refused with unavailable. A call at t or later goes out alone, in the half-open state. Its success closes the breaker, and its failure opens it again until a new t.

A call that the breaker refuses fails with ``unavailable`` and costs no system call. With :math:`w` threads, a dead agent costs each thread ``failures`` calls of one deadline each, and then one probe per thread for each ``open`` interval. A call that fails with ``overload`` is not a fault of the agent and does not count.

An agent call occupies the thread that makes it for the round trip. At the request stage that thread is the one that serves the request, and on an event-driven worker the other connections of that worker wait for it. The deadline bounds the wait and the breaker bounds how often it is paid. The section on known gaps returns to this.

Parking a connection
~~~~~~~~~~~~~~~~~~~~

At the connection stage the calling thread is the edge worker, which accepts for every frontend, or a thread of the HTTP/3 runtime. Neither may wait for an agent. So a connection whose chain names an agent is *parked*, and judges decide it.

.. typst-diagram:: ../diagrams/parking.typ
   :caption: A parked connection and the judges.
   :alt: The edge worker or an HTTP/3 task holds the socket of a parked connection and reads nothing. It puts a case, an owned copy of the view, into a bounded queue of hook_judges.queue cases. The judges, hook_judges.threads of them, take it and make the blocking calls to the agent, with a deadline and a breaker. They return the verdict and wake the worker. When the queue is full, the worker sheds: it runs the chain itself, and every agent fails with overload.

The root object ``hook_judges`` has the two numbers of this section, ``threads`` and ``queue``. The *judges* are a small set of threads, ``hook_judges.threads`` of them (4 unless the file says otherwise, 1 to 64), for each of the two callers. A judge owns its own instances of the hooks, as every thread does: its Wasm memories, its agent connections and its breakers. It takes a *case*, an owned copy of the view, runs the whole chain of the frontend on it with the blocking calls of this section, and gives the verdict back. The edge worker receives it through its wake socket. An HTTP/3 task receives it through a one-shot channel.

A chain without an agent is never parked. It runs on the calling thread as before, and costs what it cost.

While a connection is parked the worker holds its socket and its flow permit, and does not read it. A parked UDP client has its first datagram kept, and its further datagrams are dropped until the verdict: a mapping does not exist yet. When the verdict admits, the flow starts where it would have started. When it denies, the connection is closed and counted with the reason ``hook``. A client that closes while it is parked changes nothing: the verdict arrives, and the flow that starts sees the end of its client at once.

The wait is bounded at every step. The queue holds ``hook_judges.queue`` cases (256 unless the file says otherwise, 1 to 4,096). When it is full, the chain runs on the calling thread *shedding*: native and Wasm hooks run, and every agent hook fails with ``overload`` without a call. The failure rule then decides as for every failure, so a full queue takes the ``on_failure`` outcome of each agent in the chain. A judge sheds in the same way a case that waited in the queue longer than the longest ``deadline`` of the agents of the plan. So a parked connection waits at most that deadline in the queue, and then at most the sum of the deadlines of its chain. The worker also drops a parked connection that has no verdict after five seconds, and counts it as refused by a hook. This happens only if a judge died.

A dead agent therefore costs the judges, not the worker. Each judge pays ``failures`` deadlines, its breaker opens, and its calls fail at once until the probe. Meanwhile connections of frontends without that agent are not delayed at all, and connections of the same frontend wait for a judge or are shed.

The Lean model has the shed case: a shed chain is the chain of the same hooks in which every agent has the result ``failed``, so a chain whose agents all fail closed never admits by shedding what a denying native hook would deny, and a full queue never admits a connection that an agent with ``on_failure: "deny"`` guards.

Crates
~~~~~~

``sibuna-plugin`` is a library without dependencies. It holds the view, the trait, the failure rule, the breaker, the interpreter, the agent client and the published set. ``sibuna-lb`` reads the configuration into the plain specifications of that crate. Its edge worker owns its own instances and asks them at the connection stage. The daemon builds the set, owns the table of native hooks and joins the stages to its request path.

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
     - 2,324 in the seven files of ``crates/plugin/src/wasm``, unit tests included
     - 96,233 with its four companion crates and ``wasmparser``
   * - Uses of ``unsafe``
     - 0
     - 143 occurrences of the word in those sources
   * - New crates in the build
     - 0
     - 8: ``wasmi``, ``wasmi_core``, ``wasmi_ir``, ``wasmi_collections``, ``wasmparser``, ``spin``, ``libm``, ``bitflags``
   * - Speed
     - 20,000 SHA-256 hashcash trials in 413 ms. One call of the example hook in 2.2 microseconds.
     - The same trials in 210 ms. The same call in 0.77 microseconds.

The rule of this project is that the standard library comes first and that an external crate must solve a large problem. A complete WebAssembly engine is a large problem. A hook runtime is a small one: one memory, one table, no threads, no SIMD, a fixed ABI, and budgets that we want to define ourselves. The instruction set is specified exactly and the validator is the published algorithm. wasmi is two to three times faster, because it translates to a register machine. A hook spends a few hundred to a few thousand operations on a request. The example hook spends 635, and the difference between the two interpreters is then 1.4 microseconds for a request. We accept that cost for an interpreter of a fortieth of the size, without ``unsafe`` and without a new crate. We chose the in-house interpreter. We would choose wasmi if hooks became compute-heavy, and the trait boundary of the tier lets us do so without changing the ABI.

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

The state of this record is ``discussion``. The code below is on the branch ``sid-0030-plugins``. Every row names the test that is its evidence. All tests run on loopback.

.. list-table::
   :header-rows: 1
   :widths: 4 40 12 44

   * - #
     - Criterion
     - Status
     - Evidence
   * - 1
     - The native tier admits, denies, challenges and fails with its configured outcome.
     - Met
     - ``crates/plugin/tests/tiers.rs`` (``the_native_tier_admits_denies_challenges_and_fails_closed``, ``an_advisory_native_hook_admits_on_failure_and_adds_nothing``); ``cmd/sibuna/tests/edge_hooks.rs`` (``a_native_hook_admits_and_denies_requests``) through the binary, on the workers and on the thread path.
   * - 2
     - The Wasm tier admits, denies, challenges, times out, traps and overflows with its configured outcome.
     - Met
     - ``tiers.rs`` (``the_example_hook_admits_denies_and_challenges``, ``a_wasm_hook_that_spins_times_out_with_its_configured_outcome``, ``a_wasm_hook_that_traps_fails_with_its_configured_outcome``, ``a_view_larger_than_the_input_buffer_overflows_and_is_never_cut``, ``host_calls_beyond_the_bound_trap``); ``edge_hooks.rs`` (``the_example_wasm_hook_admits_with_a_field_denies_and_challenges``, ``a_wasm_hook_that_spins_or_traps_gets_the_configured_outcome``, ``a_request_too_large_for_the_input_buffer_overflows_and_is_not_cut``).
   * - 3
     - The agent tier admits, denies, challenges, times out, is unavailable and overflows with its configured outcome.
     - Met
     - ``crates/plugin/tests/agent.rs`` (11 tests against an agent in the test process); ``edge_hooks.rs`` (``an_agent_admits_with_a_field_denies_and_times_out``, ``an_advisory_agent_that_is_away_admits``).
   * - 4
     - Fuel holds against an infinite loop, and fuel is a count.
     - Met
     - ``crates/plugin/tests/wasm.rs`` (``an_infinite_loop_stops_when_its_fuel_is_spent``, ``growth_and_bulk_operations_cost_fuel_in_proportion``).
   * - 5
     - The page budget holds against memory growth, and the frame limit against deep recursion.
     - Met
     - ``wasm.rs`` (``memory_growth_stops_at_the_page_budget``, ``unbounded_recursion_stops_at_the_frame_limit``, ``a_module_that_starts_above_the_page_budget_does_not_instantiate``); ``tiers.rs`` (``a_hook_that_grows_its_memory_without_end_is_stopped_by_pages_and_fuel``).
   * - 6
     - A malformed binary is refused without a panic or a hang.
     - Met
     - ``wasm.rs``: every prefix of a real module, 20,000 mutated copies of it that load or fail and then run within their budget, counts of four billion refused before an allocation, and ten kinds of code that does not type-check.
   * - 7
     - The interpreter computes what the compiled code means.
     - Met
     - ``tiers.rs`` (``the_interpreter_runs_the_compiled_solver_to_the_native_result``): the proof-of-work solver of the project, built by rustc, finds the nonce that the native code finds, and its sequential-work proof passes the native verifier.
   * - 8
     - The breaker opens after failures in a row and closes after a good probe.
     - Met
     - ``agent.rs`` (``the_breaker_opens_after_failures_in_a_row_and_closes_after_a_good_probe``, ``a_probe_that_fails_keeps_the_breaker_open``, ``each_thread_has_a_breaker_of_its_own``, ``a_call_beyond_the_queue_is_an_overload_and_does_not_blame_the_agent``); ``edge_hooks.rs`` (``the_breaker_of_an_agent_opens_and_closes``); unit tests of ``breaker.rs``.
   * - 9
     - No WASI and no other import.
     - Met
     - ``tiers.rs`` (``a_module_that_imports_wasi_does_not_load``); ``edge_hooks.rs`` (``a_plugin_that_does_not_load_is_a_diagnostic_of_the_check``, ``HOOK005``).
   * - 10
     - A reload publishes only a set that loaded, and the counters go on.
     - Met
     - ``edge_hooks.rs`` (``a_reload_changes_the_hooks_and_a_bad_module_keeps_the_serving_ones``); ``tiers.rs`` (``a_thread_takes_a_new_plan_at_its_next_run_and_the_counters_go_on``).
   * - 11
     - The connection stage judges a TCP connection, an inspected connection by its server name, and a UDP mapping once.
     - Met
     - ``crates/lb/tests/hooks.rs`` (5 tests on real sockets, one of them an inspection that takes its fallback); ``edge_hooks.rs`` (``a_connection_hook_closes_a_connection_before_any_request``).
   * - 12
     - A paid challenge of a hook is cleared, and the hooks behind it still judge.
     - Met
     - ``edge_hooks.rs`` (``a_paid_challenge_of_a_hook_is_cleared_and_the_hook_behind_it_still_judges``): the test solves the proof of work and presents the session. ``tiers.rs`` (``a_cleared_challenge_lets_the_chain_go_on_to_the_hooks_behind_it``).
   * - 13
     - A hook cannot add a field of framing or a statement of Sibuna.
     - Met
     - Unit tests of ``view.rs``; ``tiers.rs`` (``a_field_that_a_hook_may_not_add_is_refused_and_counted``); ``agent.rs`` (an agent that answers ``Host: evil``).
   * - 14
     - The telemetry stage delivers a sample and never holds a thread.
     - Met
     - ``edge_hooks.rs`` (``a_telemetry_agent_receives_a_sample_of_every_answered_request``); ``agent.rs`` (``an_agent_that_does_not_read_fills_a_bounded_backlog_and_never_holds_the_thread``).
   * - 15
     - Without hooks the request path costs one load, and with hooks it takes no lock.
     - Met by construction, measured in part
     - ``Slot::has`` is one relaxed load of a byte, 1.1 ns. The request path reads it through one ``OnceLock``, so the cost is two loads. With hooks a thread uses its own instances. The counters of a plugin are shared atomic words that every thread adds to. We did not measure their contention on many cores.
   * - 16
     - The failure rule and the breaker are modelled.
     - Met
     - ``docs/sid/assets/plugin-tiers.lean``, checked with Lean 4, core only: 12 theorems on the outcome, the chain, shedding and fuel, 10 on the breaker.
   * - 17
     - A slow or dead agent at the connection stage stops no other flow.
     - Met
     - ``crates/lb/tests/parked.rs`` on real sockets: with an agent that never answers and a deadline of 400 ms, twenty connections of another frontend are each served in under 100 ms, and four connections of the guarded frontend start together after one deadline (``a_silent_agent_delays_no_other_flow_of_the_worker``). A full queue takes the outcome of the agent (``a_full_queue_of_judges_takes_the_outcome_of_the_agent``). A parked inspection is judged by its server name, and the first datagram of a parked UDP client is not lost. ``crates/plugin/tests/agent.rs`` (``judges_decide_parked_cases_and_a_silent_agent_never_holds_the_caller``).
   * - 18
     - A QUIC connection of an HTTP/3 frontend is judged once, with its client and its server name, and the TCP side is judged for itself.
     - Met
     - ``cmd/sibuna/tests/edge_hooks_secure.rs`` through the binary (``a_quic_connection_is_judged_once_by_its_client_and_server_name``, ``a_silent_agent_serves_no_quic_connection_and_holds_none_longer_than_its_deadline``).
   * - 19
     - The request stage admits with a field, denies and challenges over TLS, HTTP/2 and HTTP/3.
     - Met
     - ``edge_hooks_secure.rs`` (``the_request_stage_judges_tls_http2_and_http3_on_the_workers`` and ``..._on_the_thread_path``). The tests found no fault.

Measured cost
~~~~~~~~~~~~~

All numbers are from one machine with 32 hardware threads that ran other builds at the time (load average about 20), in optimized builds, on loopback. We took the best of repeated rounds. They are an order of magnitude and a comparison, not a benchmark of the product.

*One invocation, in process.* ``cargo test -p sibuna-plugin --release --test cost -- --ignored --nocapture --test-threads 1``. The view is a request of eight fields, 433 bytes encoded. The native hook does what the example module does.

.. list-table::
   :header-rows: 1
   :widths: 40 20 40

   * - Case
     - Time
     - Note
   * - No hook, ``Slot::has``
     - 1.1 ns
     - One load.
   * - Native
     - 42 ns
     - The chain, the counters and the hook.
   * - Wasm, the example module
     - 2.2 to 2.4 us
     - Encoding the view, copying it in and 635 operations.
   * - Agent
     - 12 to 18 us
     - A round trip on a Unix socket to a thread of the same process.

*A parked agent call.* The same command prints both lines. One thread gives a case to one judge and waits for the answer on a channel, 50,000 times. On a quiet machine (load average below 1) three runs gave 11.7, 12.1 and 12.3 us for the call on the calling thread and 22.8, 22.8 and 22.9 us for the parked call. Parking costs about 11 us: two handoffs between threads. The edge worker adds one wake of its poller, which this number does not include.

*One request, end to end.* ``cargo test -p sibuna --release --test edge_hooks -- --ignored --nocapture cost``. One client sends 5,000 requests after one another on a kept connection to the edge binary, which relays to an origin that answers one byte. Four edges run side by side, one for each case, and their rounds alternate. Two runs gave these means per request.

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - Case
     - Run 1
     - Run 2
   * - No hook
     - 41.8 us
     - 42.2 us
   * - Native ``require_header``
     - 40.0 us
     - 41.2 us
   * - Wasm, the example module
     - 47.1 us, +5.2
     - 48.4 us, +6.1
   * - Agent in the test process
     - 63.4 us, +21.5
     - 60.6 us, +18.4

The native hook is below the noise of the method, which is about 2 us. The Wasm hook costs about 3 us more end to end than in process. We did not find out why.

*The interpreter against wasmi 1.1.0.* A scratch program outside the repository linked wasmi with fuel metering on, built without network from the local registry. Both ran the committed modules. The solver, ``pow_solver.wasm``, ran 20,000 SHA-256 trials, 110 million operations of our interpreter. The example module judged the same encoded view.

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - Workload
     - In-house
     - wasmi 1.1.0
   * - 20,000 SHA-256 trials
     - 413 to 650 ms
     - 210 to 264 ms
   * - One call of the example module
     - 2.2 to 3.9 us
     - 0.77 to 1.1 us
   * - Loading the solver, 15 KiB
     - 0.2 ms
     - 0.2 to 0.3 ms

The same trials take 1.0 ms in native code with the SHA extensions of the processor. A hook is not the place for a hash loop.

Known gaps
----------

#. *An agent call at the request stage holds its thread.* The connection stage parks. The request stage does not: on an event-driven worker every connection of that worker waits for the round trip, at most ``deadline``, and over HTTP/2 and HTTP/3 the thread that decides the request waits. Each of several threads pays, not the one thread that accepts, and the breaker bounds the repetition. Parking a request needs a suspended state in the request path of the workers, which holds borrowed buffers today. It is the first open question.
#. *The verdict on a QUIC connection does not stop its handshake.* The library completes the handshake while the hooks judge. A denied client therefore learns the certificate of the frontend and costs one handshake, and then its connection is closed without a request served. The connection rate and the client bound, which run before the handshake, are unchanged.
#. *A parked flow costs two thread handoffs.* A healthy agent call takes about 23 us parked and about 12 us on the calling thread. Parked connections of one caller share ``hook_judges.threads`` judges, so a slow agent that answers within its deadline serves at most ``threads / latency`` connections in a second, and the rest are shed with the ``on_failure`` outcome. Calls are not multiplexed on one agent connection.
#. *The judges are started with the first parked flow and keep their number.* A reload that changes ``hook_judges`` takes effect at a restart. The edge worker and the HTTP/3 runtime have a set each, so a node has up to twice ``threads`` judges, each with its own agent connection and breaker.
#. *A parked UDP client keeps one datagram.* Its further datagrams are dropped until the verdict.
#. *No metric counts the parked flows.* The calls, the overloads and the timeouts of the plugin are counted as before.
#. *The telemetry stage covers HTTP requests.* The end of a TCP or UDP flow is not shown to a hook. A sample has no query, no fields and no client port.
#. *Requests that Sibuna answers itself reach no request hook:* the reserved routes, a redirect or a fixed answer of the traffic policy, a ban, a limit. The hook judges what would reach a server.
#. *A native hook is added by editing the table in ``cmd/sibuna/src/plugins.rs``.* There is no registration from another crate. One hook is shipped.
#. *The counters of a plugin are shared atomic words.* Every thread adds to them on each call. The path takes no lock, and we did not measure the cache traffic on many cores.
#. *Each thread holds its own instance,* so a Wasm plugin costs ``memory_pages`` of memory for each thread that has served its frontend, and an agent one connection for each such thread. On the thread path that is one for each thread of the pool.
#. *A reload rebuilds every instance,* whether or not the plugins changed, and an open breaker starts closed again.
#. *The connector thread of an agent* ends with its set of hooks. A connect that blocks for ever on a socket whose backlog is full keeps that thread.
#. *The interpreter is two to three times slower than wasmi,* and it is new code. Its evidence is the tests above. It has had no external review and no fuzzing beyond the 20,000 mutations of one module.
#. *The measurements were taken on a busy machine* and not repeated on a quiet one.
#. *Plugins exist in the edge only.* The firewall daemon that runs without an edge topology has none.
#. *A connection that a peer forwarded (SID 0026) is judged on the node that serves it,* with the address that the client reached. No test drives a hook over a forwarded connection or a forwarded UDP client. An inspected connection whose reached address matches no listener of the serving node is not judged.
#. *An inspection that takes a fallback (SID 0032)* is judged without a server name and without a JA4, because the client sent no whole ClientHello. A hook that decides by the server name must deny an empty one.
#. *Every QUIC connection of an HTTP/3 frontend takes one more step before it serves,* also without hooks: one await and one small allocation. Its cost is not measured.
#. *The parked path is not measured through the binary,* only in process, and no metric counts parked flows.
#. *Not built:* a hook on a response, a hook that sees a body, a hook per datagram, a TCP transport for agents.

Open questions
--------------

#. Should an agent call at the request stage park the request, as the connection stage parks a connection? What deadline do real agents need?
#. Should a hook be able to add fields to a response that Sibuna itself writes, such as a denial?

Review history
--------------

- 2026-11-25. Initial draft, written before the code.
- 2026-11-25. Review of the draft. It found seven faults, and the text above has the corrections. (1) The draft ran request hooks before the policy, so a client that a rule would have denied could spend an agent call: hooks now run only for admitted requests. (2) The draft cut a head that did not fit the input buffer: a hook would then admit a request it had not seen, so the invocation now fails. (3) The draft let ``on_failure`` default to the choice of each tier: it now defaults to ``deny`` everywhere, and the telemetry stage ignores it. (4) The draft charged one unit of fuel for ``memory.fill`` of any length, which made fuel no bound on time. (5) The draft kept the memory of an instance after a trap. (6) The draft kept an agent connection after a timeout and matched answers by identifier alone: a late answer could then be read by the next call if identifiers were reused after a reconnect, so the connection now closes. (7) The draft counted an ``overload`` as a failure of the agent, so a burst of our own could open the breaker.
- 2026-11-25. Review of the code against this record. It found six faults, all corrected. (1) A session that cleared the challenge of a hook ended the chain as an admission, so the hooks behind it did not run: the chain now goes on, the Lean model has the theorem, and a test pays a real challenge. (2) The HTTP server started before it was given the hooks, so a request in the first moments could pass unjudged: it now receives them before it starts. (3) A reload published the hooks after the routes, so a new frontend served a moment without its hooks: the order is reversed, and a refused reload restores the set. (4) A connection hook on an HTTP/3 frontend was accepted and never asked: the file is now refused. (5) The request view gave the port of the socket peer beside the address of a forwarded client. (6) The telemetry stage found no host and no path unless the access log was on. The review also measured the interpreter against wasmi and replaced a sentence of the draft that called the difference negligible: it is 1.4 microseconds for the example hook.
- 2026-11-25. Merge with the admission stages (SID 0032), peer forwarding (SID 0026) and the handoff (SID 0029). Two faults of the merge were found and corrected. The variable that told the hooks of an HTTP/3 frontend shadowed the new ``udp_inspect`` setting of the listener. An inspection that ended by its fallback started a flow without asking the connection hooks: every ended inspection is now judged, with an empty server name when there is no ClientHello.
- 2026-11-25. Three known gaps closed, after a review of the text and then of the code. *Parking.* The draft of this change let the worker register the agent socket with its poller. We rejected it: a chain may name several hooks around the agent, so the worker would need a resumable chain and a non-blocking agent client, and the breaker and the queue would move into the worker. Judges with their own instances run the unchanged blocking chain, and the worker only parks and resumes. The cost is two thread handoffs and no multiplexing. The review of the code found that a judge thread which could not start left a QUIC connection without an answer until its handshake bound: it is now shed. *QUIC.* The text first said that the verdict comes before the handshake ends. The test of a silent agent showed the handshake complete on the client within 100 ms: the library does not wait for us. The text now says what the verdict decides. *Request stage.* The tests over TLS, HTTP/2 and HTTP/3 passed as written, on the workers and on the thread path.

References
----------

- SID 0015, Sibuna Edge: TCP, UDP and HTTP Load Balancing. This record builds its plugin tiers and answers its third open question.
- SID 0016, SID 0017 and SID 0024, the HTTP paths that reach the request stage.
- SID 0019, Traffic Policy, whose request edit carries the added fields.
- SID 0020, Edge Observability, whose settled entry feeds the telemetry stage.
- WebAssembly Core Specification 1.0, W3C Recommendation (2019), and its appendix on the validation algorithm.
- The proposals for sign-extension operators, non-trapping float-to-int conversions and bulk memory operations, merged into WebAssembly 2.0.
- Nygard, *Release It!* (2007), for the circuit breaker.
