:sid-number: 0018
:sid-title: Simple Setup and Run-Time Configuration of the Edge
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-24
:sid-updated: 2026-11-24
:sid-discussion: No external discussion URL assigned
:sid-summary: Starts the edge load balancer with one command and no file, prints the equivalent JLV module, changes servers at run time through a local admin socket while the file stays the authority, and makes a reload fail no request.
:sid-labels: ["architecture","load-balancer","operations","configuration"]

Simple Setup and Run-Time Configuration of the Edge
===================================================

Abstract
--------

We make the edge load balancer of SID 0015 easy to start and safe to change while it runs. One command serves traffic without a file. A second command prints the JLV module that describes the same topology. A local admin socket drains, weighs, adds and removes servers without a restart, and a client subcommand speaks to it.

An operator observes four things. ``sibuna lb --bind 0.0.0.0:8080 --server 10.0.0.1:80 --server 10.0.0.2:80`` balances HTTP at once. The same line with ``--print-config`` prints a five-line ``edge.jlv``. ``sibuna ctl SOCKET set server app/10.0.0.1:80 state drain`` takes a server out of rotation for new flows. The file remains the description of the node, and ``show servers`` marks every entry that differs from it.

Motivation and scope
--------------------

SID 0015 gave the edge a complete topology file. A first-time operator must write that file before the first request is served. The smallest file names a protocol twice, a default backend, and a name for each server. None of these carries information when there is one pool.

SID 0015 changes the topology by a file reload. A reload is the right tool for a reviewed change. It is a heavy tool for taking one server out of rotation during a deployment. HAProxy has a runtime API for this purpose. We want the useful part of it, kept small.

This record covers the edge mode of the daemon on one node. It adds a quick-start command, defaults that shorten the file, a Unix admin socket with a line protocol, a client subcommand, and an optional file watcher. It does not add a TCP admin listener, a cluster-wide command, an HTTP API, or run-time changes to frontends, routes, certificates and policy. Those change by reload, as before.

Specification
-------------

Invariants
~~~~~~~~~~

#. The quick start and the file pass through the same parser. The quick start writes a document and validates it with ``Config::parse``. There is no second way to build a topology.
#. The configuration file is the authority for the topology. The serving topology is the last accepted file revision with a set of run-time changes laid over it. After a reload the servers, addresses and weights are those of the file.
#. A drain is an operator's statement about a machine, not a part of the topology. It ends only when the operator says ``ready``, when the server leaves the file, or when the daemon restarts.
#. A run-time change applies to new flows only. An established TCP stream, UDP mapping or running HTTP exchange keeps its server.
#. A rejected command or a rejected reload changes nothing. The client that sent the command learns why.
#. A run-time change is local to the node. On a mesh of nodes the pools whose placement the nodes must agree on change only by reload.
#. Every input on the admin socket has a bound: the length of a line, the time to send it, and the rate of commands.
#. The admin socket is reachable by the user of the daemon only. No TCP listener is opened for administration.

Quick start
~~~~~~~~~~~

.. code-block:: text

   sibuna lb --bind ADDR [--bind ADDR]... --server ADDR [--server ADDR]...
             [--proto http|tcp|udp] [--tls PEM] [--health PATH|tcp]
             [--firewall off|gate|shield] [--admin SOCKET]
             [--print-config] [--format jlv|json]

``--bind`` is a numeric address and port. ``:8080`` means ``0.0.0.0:8080``. ``--server`` is a numeric address and port. Both may repeat. ``--proto`` defaults to ``http``. ``--tls`` names a combined PEM file or a directory of them and turns the frontend into a TLS listener. ``--health`` takes an absolute path for an HTTP probe, or ``tcp`` for a connect probe. ``--admin`` opens the admin socket at that path.

``--firewall`` defaults to ``off``. The command is named after the load balancer, and a first run must not answer a health checker or a load test with a challenge page or a rate limit. The startup line names the surface and how to turn the firewall on. A topology file keeps the default of SID 0015, which is ``shield``.

The command builds a ``QuickStart`` value, writes it as a JSON document in memory, and parses that document as a file would be parsed. The frontend is named ``web`` and the pool ``app``. A server is named by its address.

``--print-config`` prints the module and exits without binding a socket. It prints JLV. ``--format json`` prints the JSON document. Printing JLV needs no JLV compiler, so every build prints it. A build without the ``jlv`` feature cannot load a ``.jlv`` file. Such a build prints JSON by default and says so in its help.

.. code-block:: text

   $ sibuna lb --bind :8080 --server 10.0.0.1:80 --server 10.0.0.2:80 --print-config
   // Written by `sibuna lb --print-config`. Check it with `sibuna check -f edge.jlv`.
   fn edge() -> Map<Value> {
       return {
           http: { surface: "off" },
           frontends: { web: { binds: ["0.0.0.0:8080"] } },
           backends: { app: { servers: ["10.0.0.1:80", "10.0.0.2:80"] } },
       }
   }

When three or more servers share a port, the module lists the hosts once and generates the servers with a comprehension. This is the JLV idiom of SID 0015 for a pool, and it is shorter.

.. code-block:: text

   fn edge() -> Map<Value> {
       let hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
       return {
           http: { surface: "off" },
           frontends: { web: { binds: ["0.0.0.0:8080"] } },
           backends: { app: { servers: [for host in hosts: "${host}:80"] } },
       }
   }

Defaults that shorten the file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table:: New defaults
   :header-rows: 1
   :widths: 30 70

   * - Key
     - Default
   * - ``frontends.*.proto``
     - ``"http"``
   * - ``backends.*.mode``
     - ``"http"``
   * - ``frontends.*.default_backend``
     - The only backend of the frontend's protocol. With two or more such backends the key is required, and the error names them.
   * - A server written as a string
     - ``"10.0.0.1:80"`` means ``{"name": "10.0.0.1:80", "addr": "10.0.0.1:80"}``. The name is the address in its canonical form.

Every file that SID 0015 accepts keeps its meaning. A file that omitted a required key was rejected before and is accepted now.

Two keys join the ``global`` object.

.. list-table:: New ``global`` keys
   :header-rows: 1
   :widths: 22 14 64

   * - Key
     - Default
     - Meaning
   * - ``admin_socket``
     - none
     - The path of the admin socket, at most 86 bytes. Without it no socket is opened. Changing the path takes a restart.
   * - ``watch``
     - none
     - A duration of 1 s to 1 h. The daemon looks at the file at this interval and reloads it when it changed. A reload may turn the watcher on, off or change its interval.
   * - ``shutdown_timeout``
     - ``"5s"``
     - How long a shutdown waits for established flows before it closes them, up to 1 h. SID 0015 fixed this at five seconds.

The admin socket
~~~~~~~~~~~~~~~~

The socket is a Unix stream socket with mode 0600. It exists on Unix only. A topology with ``admin_socket`` is refused on other systems.

A socket bound with the standard library takes its mode from the umask, and setting the mode afterwards leaves a moment in which another user may connect. A connection made in that moment waits in the backlog and would be served later. We close this window without changing the umask of the process. The daemon creates a directory with mode 0700 beside the final path, binds the socket inside it, sets the mode of the socket to 0600, and renames the socket to the final path. A bound socket keeps working under its new name. Before the rename only the daemon's user can reach it.

A stale socket file of a dead daemon is replaced by the rename. The daemon first connects to an existing socket. If a daemon answers, startup fails, because two daemons must not share a path. A path that holds another kind of file is refused. The daemon removes the socket when it stops.

A connection carries one command. The client sends one line of at most 512 bytes of printable ASCII, ending in a line feed. The daemon answers and closes. The first line of the answer is ``ok`` or ``error CODE TITLE``. After ``ok`` the lines are the result. After ``error`` the second line is the explanation and the third line begins with ``Hint:``.

.. list-table:: Commands
   :header-rows: 1
   :widths: 46 54

   * - Command
     - Effect
   * - ``show servers``
     - One line per server: pool, name, address, state, weight, flows, health and what changed at run time.
   * - ``show info``
     - The version, the process, the source of the topology, the number of reloads, the flows, the drops and the number of run-time changes.
   * - ``set server POOL/NAME state ready|drain``
     - ``drain`` stops new flows to the server. Its health probes continue, so ``show servers`` tells when it is healthy again. ``ready`` admits it again. ``maint`` is accepted as another word for ``drain``.
   * - ``set server POOL/NAME weight N``
     - Sets the weight, 1 to 65,535. There is no weight 0. We drain instead.
   * - ``add server POOL/NAME ADDR [weight N]``
     - Adds a server to a pool. It takes the pool's health check and starts in service. The name has 1 to 64 characters from letters, digits and ``. _ : [ ] -``. The address passes the checks of the file: numeric, unicast, not a listener of the node, and new to the pool.
   * - ``del server POOL/NAME``
     - Removes a server from a pool. Its established flows finish. The last server of a pool cannot be removed. We drain it instead.
   * - ``reload``
     - Loads the file and applies it, as SIGHUP does. The answer is ``ok`` after the new revision serves, or the reason for which it was rejected.
   * - ``help``
     - Lists the commands.

``set server ... weight``, ``add server`` and ``del server`` are refused for two kinds of pool. A pool with ``bounded_maglev``, and the default pool of a node with a ``mesh``, place clients by a table that every node builds from the file. A node that changed its table alone would send a client to a different server than its peers do. A pool with ``http_version`` or ``tls`` reaches its servers through protocol adapters that a reload prepares. For both kinds we edit the file and reload. ``drain`` works for every pool, because each node already excludes servers by its own health checks.

HAProxy distinguishes ``drain`` from ``maint`` by session persistence and by health checks. The edge has no persistence that a drain could honor, so one state suffices.

A single thread serves the socket, one connection at a time. A client has two seconds to send its line and two seconds to read the answer. Commands are limited by a token bucket of 20 with a refill of 10 per second. The thread parses the command. For ``reload`` it also loads and checks the file, off the worker, as the signal thread does for SIGHUP. It then passes the command to the edge worker over a channel and waits up to five seconds for the answer. The worker applies commands between two readiness batches, at most 16 per batch. The request path takes no new lock for the TCP and UDP pools. HTTP pools are behind the route table's mutex, which a command holds for the time of one field update.

The daemon writes one log line for each command that changes state, with the code ``EDGE010``.

.. list-table:: Errors
   :header-rows: 1
   :widths: 14 30 56

   * - Code
     - Title
     - Cause
   * - ``ADM001``
     - ``MALFORMED COMMAND``
     - The line is longer than 512 bytes, is not printable ASCII, or did not arrive in two seconds.
   * - ``ADM002``
     - ``UNKNOWN COMMAND``
     - The words are not a command. The hint lists the commands.
   * - ``ADM003``
     - ``UNKNOWN POOL``
     - No backend has this name. The hint offers the nearest name.
   * - ``ADM004``
     - ``UNKNOWN SERVER``
     - The pool has no server of this name. The hint offers the nearest name.
   * - ``ADM005``
     - ``INVALID VALUE``
     - A state, weight, name or address is outside its domain.
   * - ``ADM006``
     - ``DUPLICATE SERVER``
     - The pool already has this name or this address.
   * - ``ADM007``
     - ``CHANGE REFUSED``
     - The pool changes only by reload, is full, or would become empty.
   * - ``ADM008``
     - ``RELOAD REJECTED``
     - The file was rejected, or the daemon was started without a file.
   * - ``ADM009``
     - ``TOO MANY COMMANDS``
     - The command rate is exhausted.
   * - ``ADM010``
     - ``NO ANSWER``
     - The worker did not answer in five seconds, or the daemon is stopping.

Run-time changes and the file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Run-time changes live in memory. They are an overlay on the last accepted revision of the file. The daemon never writes the file.

.. list-table:: What happens to a run-time change
   :header-rows: 1
   :widths: 28 24 24 24

   * - Change
     - Successful reload
     - Rejected reload
     - Restart
   * - ``state drain``
     - Kept while the file still has a server of that pool, name and address
     - Kept
     - Lost
   * - ``weight``
     - Replaced by the file
     - Kept
     - Lost
   * - ``add server``
     - Replaced by the file
     - Kept
     - Lost
   * - ``del server``
     - Replaced by the file
     - Kept
     - Lost

The reload rule has two parts because the changes are of two kinds. A weight, an addition and a removal are topology. The file can express each of them, so the file wins, and the run-time form is a rehearsal of the edit. A drain is not topology. The file has no key for it, and it usually means that somebody is working on the machine. A reload that returned a drained server to rotation would do so at the worst time, and with the watcher it would do so with nobody at the keyboard. So a drain survives a reload as long as the file still describes the same server. If the file gives that name another address, it describes another machine, and the drain ends.

The log line of a reload states both numbers: ``Sibuna edge routes reloaded: 1 drain kept, 2 run-time changes replaced by the file``.

.. typst-diagram:: ../diagrams/authority.typ
   :caption: Authority. The file decides the topology at every reload. Commands lay changes over it, and only drains pass a reload.
   :alt: The JLV or JSON file is compiled and checked into a revision. A reload makes the revision the serving topology. The admin socket applies commands to the serving topology as an overlay. At a reload the weights, additions and removals of the overlay are dropped and its drains are carried over.

``show servers`` has a column ``changed``. It holds ``-`` for a server that is served as the file describes it, ``added`` for a server that a command added, and the changed fields ``state`` and ``weight`` otherwise. ``show info`` counts the run-time changes and lists the servers of the file that a command removed.

To make a change permanent we edit the file. For a JLV module that means the source. A server added with ``add server app/blue 10.0.0.3:80`` becomes a new element of the list that the module returns, or a new host in the list that its comprehension reads. The daemon cannot make this edit for us, because a module is a program and many programs return the same document.

A daemon that was started by ``sibuna lb`` has no file. Its ``reload`` and its SIGHUP are refused, and its run-time changes last until it stops.

The file watcher
~~~~~~~~~~~~~~~~

With ``global.watch`` a thread reads the modification time and the length of the file at the given interval. We call this pair the stamp of the file. The watcher loads the file when its stamp differs from the stamp of the last load and equals the stamp of the previous look. The second condition waits for an editor or a copy to finish. A JLV edge module is a single file, so one stamp covers the whole source.

Every load records the stamp it read, whoever asked for it. After SIGHUP or ``reload`` the watcher therefore finds nothing new, and one edit causes one reload. A file that was rejected is not loaded again until its stamp changes, so a broken file logs ``EDGE002`` once.

The watcher is off by default. A signal or ``sibuna ctl SOCKET reload`` after ``sibuna check -f`` is the safer habit: the operator sees the result. The watcher suits a file that a deployment tool replaces by rename.

A reload fails no request
~~~~~~~~~~~~~~~~~~~~~~~~~

Changing the TCP relay count or listener port sharing requires a restart. An allocated sticky table also requires a restart to change its capacity. We reject these edits before publishing a revision.

SID 0015 binds each HTTP request to a policy generation. The firewall decides the request under the engine of generation :math:`n`, and the route table then selects a server only if its revision is also :math:`n`. A reload publishes the routes of revision :math:`n+1` and then the engine of generation :math:`n+1`. A request whose decision began before the reload and whose selection came after it met a table of another revision and was answered 503. A test of 49,522 requests during 30 reloads counted 32 such answers.

The route table now keeps the routes and pools of the revision that a reload replaced, for ten seconds. A request of generation :math:`n` that arrives at a table of revision :math:`n+1` is routed by the kept revision :math:`n`. The invariant of SID 0015 holds in a stronger form: a request is routed by the revision it was decided under, where before it was refused. A request two revisions behind is still refused. The kept pools share the load records of the serving pools, so the flow counts of a server stay whole. The protocol adapters of the replaced revision close after the engine is published, not before.

A run-time command changes no revision, so it cannot cause this refusal.

Startup failures
~~~~~~~~~~~~~~~~

A failure to start prints a diagnostic with a title rule, the cause and a hint. All carry the code ``EDGE001``, which the single line of SID 0015 had.

.. list-table:: Startup diagnostics
   :header-rows: 1
   :widths: 34 66

   * - Title
     - Cause and hint
   * - ``CONFIGURATION FILE NOT FOUND``
     - The path after ``--config-file`` or ``check -f`` holds no file. The hint names ``--print-config``.
   * - ``ADDRESS IN USE``
     - A listener address is taken. The message names the listener. The hint names ``ss -ltnp``.
   * - ``ADDRESS NOT AVAILABLE``
     - A listener address is not an address of the host.
   * - ``PERMISSION DENIED``
     - A bind was refused. The hint names ``CAP_NET_BIND_SERVICE`` and the packaged unit.
   * - ``CERTIFICATE NOT LOADED``
     - A PEM file is missing, unreadable or malformed. The hint shows how to build a combined PEM file.
   * - ``INVALID CONFIGURATION``
     - The topology checks rejected a key, which the message names.
   * - ``FILE NOT READABLE``
     - Another file of the topology, such as the policy, is missing or unreadable.
   * - ``EDGE NOT STARTED``
     - Any other cause.

The systemd unit
~~~~~~~~~~~~~~~~

The Linux packages install ``sibuna-edge.service`` beside ``sibuna.service`` and start neither. The unit of the classic listener has an empty capability set and cannot bind port 80 or 443. The edge unit runs ``sibuna --config-file /etc/sibuna/edge.jlv`` as the account ``sibuna`` with the ambient capability ``CAP_NET_BIND_SERVICE`` and no other. It sets ``LimitNOFILE=65536``, ``RuntimeDirectory=sibuna`` with mode 0700 for the admin socket, ``Restart=on-failure`` after five seconds, and the hardening options of the existing unit. ``ExecStartPre`` and the first ``ExecReload`` run ``sibuna check -f``, and the second ``ExecReload`` sends SIGHUP, so a file that fails the check is neither started nor applied.

The client
~~~~~~~~~~

.. code-block:: text

   sibuna ctl SOCKET COMMAND...

The client joins its arguments with spaces, sends the line and prints the answer. It exits with status 0 after ``ok`` and 1 otherwise. An error is printed as a diagnostic with a title rule, the explanation and the hint.

Worked example
~~~~~~~~~~~~~~

.. code-block:: text

   $ sibuna lb --bind :8080 --server 10.0.0.1:80 --server 10.0.0.2:80 --admin /run/sibuna/edge.sock &
   $ sibuna ctl /run/sibuna/edge.sock set server app/10.0.0.1:80 state drain
   ok
   $ sibuna ctl /run/sibuna/edge.sock add server app/blue 10.0.0.3:80 weight 2
   ok
   $ sibuna ctl /run/sibuna/edge.sock show servers
   pool name        address      state weight flows health changed
   app  10.0.0.1:80 10.0.0.1:80  drain 1      4     -      state
   app  10.0.0.2:80 10.0.0.2:80  ready 1      9     -      -
   app  blue        10.0.0.3:80  ready 2      0     -      added

Rationale and alternatives
--------------------------

*A quick start that writes a document.* We could build the internal ``Config`` directly from the arguments. Then the quick start and the file would be two builders, and ``--print-config`` would need a third piece of code that must agree with both. Writing the document first makes the printed file the specification of the quick start.

*A Unix socket, not HTTP.* An HTTP API needs authentication, TLS and a listener. File permissions on a Unix socket give the same protection as the configuration file has, with no new secret.

*The file is the authority.* HAProxy keeps run-time state in the process and loses it at reload unless a state file is configured. We make the same choice without the state file. Two durable authorities would have to be merged at every start, and a merge has cases that surprise.

*Drains pass a reload.* The first draft let a reload replace every run-time change. That rule is the shortest to state. It fails the operator in the most common use: a server is drained for a deployment, a colleague or the watcher reloads the file for an unrelated reason, and the server receives traffic while it is being replaced. Keeping all changes across a reload fails the other way, because the file would no longer say what is served. The split follows what the file can express.

*One command per connection.* It needs no framing of answers and no state between commands. A client reads until the daemon closes. The cost is one ``connect`` per command, which is nothing on a Unix socket at ten commands per second.

*No run-time change to consistent-hash pools.* Rebuilding a Maglev table on one node is possible. It would silently break the agreement between nodes that the table exists to provide.

*Synchronous reload.* The first draft let ``reload`` raise the same flag as SIGHUP and report in the log. A command whose result appears elsewhere invites scripts that do not check it.

Security and operational considerations
---------------------------------------

Whoever can write to the socket can send traffic to an address of his choice with ``add server``. The socket has the same trust as the configuration file. Its mode is 0600 from the moment it is reachable, and its directory should belong to the daemon's user. Under systemd ``RuntimeDirectory=sibuna`` provides ``/run/sibuna`` with that owner.

A client that connects and sends nothing holds the admin thread for two seconds. Only the daemon's user can do this, and the request path does not depend on the admin thread.

A drain that outlives a reload could be forgotten. ``show servers`` shows it, ``show info`` counts it, and every reload logs the number of drains it kept.

A command is a line of bounded length. The parser never allocates in proportion to anything but that line. The answer to ``show servers`` is bounded by 128 pools of 128 servers.

Backwards compatibility
-----------------------

Existing files, the ``--config-file`` option, ``sibuna check -f`` and SIGHUP keep their behavior. ``lb`` and ``ctl`` are new first words of the command line. The classic listener has no option with these names.

Acceptance criteria and implementation status
---------------------------------------------

The record is implemented on Linux as specified. The table lists the evidence.

.. list-table:: Evidence
   :header-rows: 1
   :widths: 40 60

   * - Criterion
     - Evidence
   * - The quick start and the file are one mechanism.
     - ``QuickStart::config`` parses the JSON form with ``Config::parse``. ``crates/jlv/tests/quick.rs`` compiles the printed modules, with and without a comprehension, and with a path that needs escaping. ``the_printed_configuration_passes_the_check`` passes the printed module to ``sibuna check -f``.
   * - One command serves traffic without a file.
     - ``the_quick_start_serves_without_a_file_and_takes_commands`` starts ``sibuna lb``, sends requests and reads the tags of two servers.
   * - Drain, weight, add and remove apply to new flows only.
     - ``crates/lb/tests/runtime.rs`` holds exchanges across each change and checks which server they and the next ones have. The binary test repeats it through ``sibuna ctl``.
   * - A reload returns to the file and keeps drains.
     - ``a_reload_returns_to_the_file_and_keeps_the_drain`` drains, weighs and adds, reloads through the socket, rejects a broken file, and reloads by SIGHUP a file that moves the drained name to another address.
   * - Every bad input is answered and changes nothing.
     - ``mistakes_on_the_socket_are_answered_and_change_nothing`` receives ``ADM001`` to ``ADM008``, sends a line of 600 bytes on a raw socket, and starts a second daemon on the same socket path. Unit tests cover the parser, the wire form and the token bucket.
   * - The socket has mode 0600.
     - The quick-start test reads the mode of the socket file.
   * - One edit causes one reload.
     - ``the_watcher_reloads_a_replaced_file_once`` replaces the file, waits for the reload and finds one reload after two more intervals.
   * - A reload fails no request.
     - ``reloads_and_commands_under_load_fail_no_request`` runs four clients during 30 reloads and 30 drains. It failed with 32 of 49,522 requests before the change and passed with about 50,000 requests in each of three runs after it. ``a_request_decided_before_a_reload_is_routed_by_its_revision`` checks the rule in the library.
   * - Shutdown waits as long as the file says.
     - ``shutdown_waits_for_flows_as_long_as_the_file_says`` holds one flow open with a one-second timeout and measures the wait.
   * - Startup failures are explained.
     - ``startup_failures_are_explained_with_a_hint`` provokes an address in use, a missing file, a missing certificate and an invalid file.

Known gaps
~~~~~~~~~~

#. The admin socket changes servers only. Frontends, routes, certificates, limits and policy change by reload.
#. Run-time changes do not survive a restart. A drain cannot be written in the file.
#. Pools placed by a Maglev table and pools behind protocol adapters take ``drain`` only.
#. A server name with a space, and a pool name with a slash, cannot be written in a command. Such servers are changed in the file.
#. The path of the socket is limited to 86 bytes, because the private directory lengthens the path that is bound.
#. During the ten seconds after a reload, a request of the replaced generation is routed by the pools of the replaced revision. A drain commanded in those seconds does not reach those pools. The lookups for the firewall switch and the WebSocket rule of such a request read the new revision.
#. Two reloads within the decision time of one request still refuse that request.
#. A server added at run time starts in service before its first health probe, as a server of the file does.
#. The watcher compares the modification time and the length. Two writes of equal length within the resolution of the file system's clock look like one.
#. ``show servers`` has one text form.
#. The admin socket and the rename of a bound socket are tested on Linux only. Other systems than Unix have no admin socket.
#. The package scripts list the new unit. No package was built or installed in this work.
#. The chapter of the book teaches JLV in its first sections and in every new section. Its older examples of single keys remain JSON, which is also valid JLV after ``return``.

Formal model
~~~~~~~~~~~~

The reload rule is the one algorithm of this record. ``docs/sid/assets/simple-setup-and-runtime-configuration.lean`` models a pool as a list of servers with a name, an address, a weight and a drain flag. It defines the commands and the reload, and it proves that a reload yields the names, addresses and weights of the file, that a drain passes a reload exactly when the file keeps the name and the address, that a reload never drains a server that no operator drained, that reloading the same file twice equals reloading it once, and that selection never returns a drained server. The socket, the parser and the watcher have no algorithm worth a model. Tests cover them.

Open questions
--------------

#. Should the file have a ``state`` key for a server, so that a drain can be made durable in the source?
#. Should ``show servers`` have a JSON form?
#. Should a mesh carry a drain to the other nodes?
#. Should the socket accept changes to routes, so that a canary needs no reload?

Review history
--------------

- 2026-11-24. Initial draft: quick start through the file parser, shorter defaults, a Unix admin socket with one command per connection, run-time changes replaced by a reload.
- 2026-11-24. Author's review of the design. It found seven faults and changed the record for each. A reload returned a drained server to rotation; drains now pass a reload. Setting the socket's mode after ``bind`` left a window; the socket is now bound in a private directory and renamed. ``reload`` reported only in the log; it is now synchronous. A run-time weight would have rebuilt a Maglev table on one node of a mesh; such pools now change only by reload, as do pools behind protocol adapters. ``maint`` had no meaning apart from ``drain``; it is now a synonym. The watcher could load a half-written file and reload twice after SIGHUP; it now waits for a stable stamp and shares the stamp of the last load. ``del server`` could empty a pool; the last server now stays. The review also added the error table, the bounds on names, the behavior without a file, and the decision on the formal model.
- 2026-11-24. Implementation and its review. The owner asked that JLV be the form we teach; the quick start prints JLV, and the first topology of the book is a module. The review of the implementation found six defects, all fixed. The private directory made the bound path longer than the final one, and a long path failed with an obscure error; the path is now limited to 86 bytes with a message that says so. Closing the socket with unread input reset the client before it read an error; the daemon now ends its answer and takes the rest of the input for a moment. The rate limit answered before it read the line, with the same effect; it now reads first. ``reload`` in a daemon without a file advised to check a file; it has its own hint. Adding and removing servers left load records until the next reload; removal now prunes them. The mesh rule was stated for every pool of a mesh node; it holds for pools placed by a table. The review added ``help`` and recorded the known gaps.
- 2026-11-24. Production audit. Four findings were taken into this record: the 503 answers of a reload under load, which were measured and removed; the fixed shutdown time, now ``global.shutdown_timeout``; the single line of a startup failure, now a diagnostic per cause; and the missing unit for edge mode, now packaged.

References
----------

- SID 0015 and SID 0016.
- HAProxy Management Guide, section 9.3, "Unix Socket commands", https://docs.haproxy.org/3.0/management.html#9.3
- Envoy, "xDS configuration API overview", https://www.envoyproxy.io/docs/envoy/latest/configuration/overview/xds_api

.. rubric:: Lifecycle event

::

   2026-11-24: prediscussion -> discussion. First draft by the author; open
   for discussion before implementation
