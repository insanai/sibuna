:sid-number: 0018
:sid-title: Simple Setup and Run-Time Configuration of the Edge
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-24
:sid-updated: 2026-11-24
:sid-discussion: No external discussion URL assigned
:sid-summary: Starts the edge load balancer with one command and no file, prints the equivalent JLV module, and changes servers at run time through a local admin socket while the file stays the authority.
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
#. The configuration file is the authority. The serving topology is the last accepted file revision with a set of run-time changes laid over it.
#. A run-time change applies to new flows only. An established TCP stream, UDP mapping or running HTTP exchange keeps its server.
#. A rejected command or a rejected reload changes nothing.
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
     - The path of the admin socket. Without it no socket is opened. Changing the path takes a restart.
   * - ``watch``
     - none
     - A duration of 1 s to 1 h. The daemon looks at the file at this interval and reloads it when it changed. A reload may turn the watcher on, off or change its interval.

The admin socket
~~~~~~~~~~~~~~~~

The socket is a Unix stream socket with mode 0600. The daemon binds it and then sets its mode. A stale socket file of a dead daemon is replaced. A path that holds a live socket or another kind of file is refused at startup.

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
   * - ``set server POOL/NAME state ready|drain|maint``
     - ``drain`` and ``maint`` stop new flows to the server. ``maint`` also stops its health probes. ``ready`` admits it again.
   * - ``set server POOL/NAME weight N``
     - Sets the weight, 1 to 65,535.
   * - ``add server POOL/NAME ADDR [weight N]``
     - Adds a server to a pool. It takes the pool's health check and starts in service.
   * - ``del server POOL/NAME``
     - Removes a server from a pool. Its established flows finish.
   * - ``reload``
     - Requests a reload of the file, as SIGHUP does. The log reports the result.

A single thread serves the socket, one connection at a time. A client has two seconds to send its line and two seconds to read the answer. Commands are limited by a token bucket of 20 with a refill of 10 per second. The thread parses the command and passes it to the edge worker over a channel. The worker applies it between two readiness batches and answers. The request path takes no new lock for the TCP and UDP pools. HTTP pools are behind the route table's mutex, which a command holds for the time of one field update.

The daemon writes one log line for each command that changes state, with the code ``EDGE010``.

Run-time changes and the file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Run-time changes live in memory. A successful reload replaces them all: the new revision of the file is served as written. A restart starts from the file. A rejected reload keeps the serving revision with its run-time changes.

``show servers`` has a column ``changed``. It holds ``-`` for a server that is served as the file describes it, ``added`` for a server that a command added, and the changed fields ``state`` and ``weight`` otherwise. ``show info`` lists the servers of the file that a command removed.

To make a change permanent we edit the file. For a JLV module that means the source: a server added with ``add server`` is a new element of the list that the module returns.

A weight change, an addition and a removal rebuild the Maglev table of a pool that uses ``bounded_maglev``.

The file watcher
~~~~~~~~~~~~~~~~

With ``global.watch`` a thread reads the modification time and the length of the file at the given interval. When they differ from those of the last load, it loads the file as SIGHUP does. The watcher is off by default. An explicit signal after a reviewed edit is the safer habit, and a watcher reloads a file that an editor has only half written.

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

Security and operational considerations
---------------------------------------

Whoever can write to the socket can send traffic to an address of his choice with ``add server``. The socket has the same trust as the configuration file. Its mode is 0600 and its directory should belong to the daemon's user.

A command is a line of bounded length. The parser never allocates in proportion to anything but that line. The answer to ``show servers`` is bounded by 128 pools of 128 servers.

Backwards compatibility
-----------------------

Existing files, the ``--config-file`` option, ``sibuna check -f`` and SIGHUP keep their behavior. ``lb`` and ``ctl`` are new first words of the command line. The classic listener has no option with these names.

Acceptance criteria and implementation status
---------------------------------------------

This is a proposal. Nothing is implemented yet. We require unit tests for the document writer, the command parser and the pool operations, and a test that starts the binary, serves through the quick start, and exercises drain, add, remove, weight and the reload rule through ``sibuna ctl``.

Formal model
~~~~~~~~~~~~

To be decided with the design review.

Open questions
--------------

#. Should the socket carry several commands on one connection?
#. Should ``show servers`` have a JSON form?

Review history
--------------

- 2026-11-24. Initial draft: quick start through the file parser, shorter defaults, a Unix admin socket with one command per connection, run-time changes replaced by a reload.

References
----------

- SID 0015 and SID 0016.
- HAProxy Management Guide, section 9.3, "Unix Socket commands", https://docs.haproxy.org/3.0/management.html#9.3
- Envoy, "xDS configuration API overview", https://www.envoyproxy.io/docs/envoy/latest/configuration/overview/xds_api

.. rubric:: Lifecycle event

::

   2026-11-24: prediscussion -> discussion. First draft by the author; open
   for discussion before implementation
