:sid-number: 0028
:sid-title: A Database as the Authority for the Topology
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-25
:sid-updated: 2026-11-25
:sid-discussion: No external discussion URL assigned
:sid-summary: Lets a database own the published topology of an edge while the file of each node keeps what belongs to its host. One command checks a source, shows the difference and commits a numbered revision on the condition that nobody committed in between. Nodes follow the revision, keep the last one that checked, and the history allows a rollback.
:sid-labels: ["architecture","load-balancer","cluster","configuration","storage"]

A Database as the Authority for the Topology
============================================

Abstract
--------

SID 0015 names two modes. In file mode the file is the authority. In persistent mode the file owns what belongs to one host and a database owns the published topology. We build the second mode. ``sibuna authority apply`` evaluates a source, checks it, shows what would change and commits a new revision in one transaction, on the condition that the database still holds the revision that the command read. Every node reads the committed revision whole, checks it itself, serves it and reports the revision that it serves. A node that cannot read the database, or that refuses a revision, keeps serving the last revision that checked. Every revision stays in the database, so we can list the history and roll back.

Motivation and scope
--------------------

SID 0023 gives a small cluster one file and one command that sends it to the peers. It records what it lacks: a history, a rollback and a repair for a node that was down when the file was sent. A file that is sent has no order either. Two operators who send two files at the same time each win on some nodes.

A database gives one order. A commit either follows the revision that the operator saw or fails. A node that was down reads the head when it returns. The price is a service that must be reachable to change the topology. It need not be reachable to serve.

We specify the split between the file and the database, the schema, the commands, the way a node follows and what it does when it cannot. We keep ``reload cluster`` and ``show cluster`` of SID 0023. We do not specify a console that edits the topology, and we do not prune the history.

Specification
-------------

Invariants
~~~~~~~~~~

#. The revisions are numbered 1, 2, 3 and so on without a gap. A revision that is committed never changes. The head is the highest number.
#. A commit names the head that it expects. It succeeds only when the database holds that head, and then the head grows by one. Of two commits that expect the same head, one fails.
#. A node serves only a document that it has checked itself, composed with its own file. The check of the command that committed the revision does not stand for it.
#. A node that cannot read the database, or that refuses the head, keeps the revision that it serves. A refusal never changes its routes and never replaces a run-time change.
#. A node reports a revision as applied only after its worker serves it.
#. The edge worker never waits for the database. One thread of its own reads the database and leaves a checked revision for the worker, as the signal for a reload does.

The two owners
~~~~~~~~~~~~~~

A topology document has six sections. In persistent mode they have two owners.

.. list-table::
   :header-rows: 1
   :widths: 22 18 60

   * - Section
     - Owner
     - Reason
   * - ``global``
     - file
     - Workers, the flow table, the admin socket and the storage of certificates belong to one process on one host.
   * - ``mesh``
     - file
     - It names this node, its peers and the path of a key.
   * - ``observability``
     - file
     - It names a log file and a listener of this host.
   * - ``frontends``
     - database
     - The routes and the firewall selection of the cluster. The file may replace the ``binds`` of a frontend.
   * - ``backends``
     - database
     - The pools and their servers.
   * - ``http``
     - database
     - The firewall settings of the cluster.

The file of a node in persistent mode has a section ``authority`` and none of the three sections of the database.

.. code-block:: text

   {
     "global": { "admin_socket": "/run/sibuna/edge.sock" },
     "authority": {
       "postgres_url_file": "/etc/sibuna/authority.url",
       "node": "fra-edge-01",
       "poll": "5s",
       "cache": "/var/lib/sibuna/authority.cache",
       "binds": { "dns": ["10.0.0.1:53"] }
     }
   }

``sqlite`` names a database file and ``postgres_url_file`` names a file that holds a PostgreSQL URL. A node states exactly one. ``node`` is the name under which the node reports. It is required with PostgreSQL and is ``local`` by default with SQLite. ``poll`` is the time between two looks at the head, from 100 ms to one hour, five seconds by default. ``cache`` names a file where the node keeps the last revision that it served. ``binds`` gives a frontend other listener addresses on this host. A frontend that the file does not name binds what the published document says. A name in ``binds`` that no published frontend has is reported with ``DBA015`` and changes nothing.

The document that a node serves is the composition: the three sections of its file, the three sections of the revision, and the ``binds`` of the file in the place of those of the revision. The node checks the composition as it checks a file.

What SQLite is for
~~~~~~~~~~~~~~~~~~

SQLite serves one host. A single node gets numbered revisions, a commit that cannot overwrite the work of another, a history and a rollback, without a database service. Several processes of one host may share the file: a daemon and the one that replaces it under ``global.reuse_port``, or the nodes of a test. SQLite is not a cluster store. A file on a network file system does not give the locks that the commit relies on, and we do not support it. SQLite sends no notification, so a node sees a commit at its next poll. A cluster of several hosts uses PostgreSQL.

One store behind one trait
~~~~~~~~~~~~~~~~~~~~~~~~~~

The crate ``sibuna-authority`` has a trait ``Store`` with seven operations: ``head``, ``revision``, ``commit``, ``history``, ``report``, ``nodes`` and ``wait``. ``SqlStore`` implements it over the ``Database`` of SID 0011, which already hides the dialect: each statement is written once, and the few texts that differ are written twice. ``MemoryStore`` implements it in memory. It is the executable form of the Lean model and serves the tests of the follower. The follower and the commands know only the trait.

``SqlStore`` connects when it is first used. After an operation that fails because the database is unreachable it drops its connections and connects again at the next use. It then reads the URL file again, so a rotated password takes effect without a restart.

Schema
~~~~~~

We store one checked document for each revision. We do not store one row for each frontend, backend and server, as SID 0015 sketched.

.. code-block:: text

   edge_head(id = 1, revision)
   edge_revisions(revision, origin, restored, document, digest,
                  source, source_name, source_digest, author, note, committed_at)
   edge_nodes(node, applied, digest, refused, detail, seen_at)

``edge_head`` has one row, the number of the head. ``edge_revisions`` has one row for each revision: the canonical JSON text of the published sections, its SHA-256 digest, the source as the operator gave it, with its file name and digest, how it came about (``apply`` or ``rollback``, with the revision that a rollback restored), who committed it, a note and the time. ``edge_nodes`` has one row for each node: the revision that it serves, the revision that it refused with the reason, and when it last reported.

The canonical text has the keys of every object in order and no white space. Two sources that evaluate to the same document have the same digest. The tables are the component ``authority`` of ``sibuna_schema`` (SID 0011) with migrations of their own, so they can live in the database of the firewall or in another.

The commit is one transaction with two statements.

.. code-block:: text

   UPDATE edge_head SET revision = :expected + 1 WHERE id = 1 AND revision = :expected
   INSERT INTO edge_revisions (revision, ...) VALUES (:expected + 1, ...)

When the first statement changes no row the head is another, and the commit fails with the head that the database holds. PostgreSQL locks the row for the first writer. The second writer waits, reads the new head and changes no row. SQLite takes its write lock when the transaction begins. On PostgreSQL a trigger on ``edge_head`` sends ``NOTIFY sibuna_edge``.

A node reads a revision with one statement that returns one row. It is therefore whole and committed. The node compares the digest of the text with the digest of the row and refuses a revision whose digests differ.

The commands
~~~~~~~~~~~~

The commands talk to the database. They need no running daemon. ``-c FILE`` names a file with an ``authority`` section: the file of a node, or a file of the operator that holds only that section.

.. code-block:: text

   sibuna authority apply    -c FILE -f SOURCE [--expect N] [--note TEXT] [--author NAME]
   sibuna authority diff     -c FILE -f SOURCE
   sibuna authority dump     -c FILE [--revision N] [--source]
   sibuna authority history  -c FILE [--limit N]
   sibuna authority rollback -c FILE REVISION [--expect N] [--note TEXT] [--author NAME]
   sibuna authority status   -c FILE

``apply`` takes these steps and stops at the first that fails.

#. It evaluates the source, JSON or JLV, within the limits of a file.
#. It refuses a section that it does not know. It takes the three sections of the database and names the sections that it leaves out, because they belong to the file of a node.
#. It composes the document with ``FILE`` and checks the topology: references, protocols, binds and bounds. It does not open the files that the topology names, because they are on the nodes.
#. It reads the head. When the digest of the head is the digest of the document, it says so and commits nothing.
#. It prints the difference between the head and the document.
#. It commits with the expected revision: the head that it read, or the number after ``--expect``. A head that moved gives ``DBA002 REVISION CONFLICT``.

``diff`` is ``apply`` without the last step. The difference names what was added, removed and changed by its path. Members of a list that have names, such as servers, are compared by name.

.. code-block:: text

   ~ backends.app.servers[web2].weight: 1 -> 3
   + backends.app.servers[web3]: {"addr":"10.0.0.3:80","name":"web3"}
   - frontends.old

``dump`` prints the evaluated document of the head or of a revision. Applying a dump commits nothing, because the digest is the same. ``dump --source`` prints the source as it was given. Only the source reproduces the text of a program. ``history`` lists the revisions, newest first. ``rollback`` commits a new revision that holds the document and the source of an earlier one. It checks the document first, because a newer binary may refuse an old document. It is conditioned on the head as ``apply`` is. ``status`` prints the head and the report of every node.

``apply`` and ``rollback`` create and migrate the tables, so they need the role that owns them. ``diff``, ``dump``, ``history`` and ``status`` only read, and the role of a node is enough for them. When the head is damaged, ``apply`` and ``rollback`` say so, print the whole document as added and commit over it, so that the operator can repair the head.

How a node follows
~~~~~~~~~~~~~~~~~~

A thread of its own, ``edge-authority``, owns the store. It looks at the head when PostgreSQL notifies, when ``poll`` has passed, when the operator runs ``reload`` and when the worker has settled a revision. A notification that was lost costs one poll. A database that did not answer is asked again after two seconds at most, whatever the poll is.

.. code-block:: text

   head = store.head()
     unreachable -> keep the revision, log DBA012 once, look again later
   head is new   -> read the revision, compose it with the file, check it
     refused     -> keep the revision, log DBA011, remember the refusal
     checked     -> leave it for the worker
   worker serves it -> applied = revision, log DBA010, write the cache, report
   worker refuses   -> keep the revision, log DBA011, remember the refusal

The node remembers the head that it refused and does not check it again at every poll. ``reload`` and SIGHUP check it again, so that a repair on the host, such as a certificate that was missing, takes effect. A reload in persistent mode reads the file again and composes it with the head. When the head is refused it composes the file with the revision that the node serves, so a change to the file still applies. A new revision is composed with the file as the worker last took it, and not with the file on the disk. The file changes the node at a reload only, so a file that is half edited does not stop the node from following.

A node starts from the head. When it cannot read the database, or refuses the head, it starts from the cache and logs ``DBA014``. Without a cache it does not start. A database with no revision does not start a node either.

What the node shows
~~~~~~~~~~~~~~~~~~~

``show authority`` prints the view of this node: the store, its name, the revision that it serves with its digest, the head that it last saw, its state and when it last looked. ``show cluster`` prints one line for each node from ``edge_nodes``.

.. code-block:: text

   revision 7 3fa9c1d2e4b5
   node         applied state                          seen
   fra-edge-01  7       current, this node             0s
   fra-edge-02  7       current                        2s
   fra-edge-03  6       refused 7: frontends.web: ...  1s

When the database cannot be read the command prints the line of this node from memory and says that the database is unavailable. In persistent mode ``show cluster`` prints this table and not the table of SID 0023, because the files of the nodes differ by design. For the same reason ``reload cluster`` answers ``DBA009`` on such a node, and such a node refuses a file that a peer sends: its file holds its own name, its own binds and the path of its own secret.

Codes
~~~~~

.. list-table::
   :header-rows: 1
   :widths: 12 30 58

   * - Code
     - Title
     - Meaning
   * - DBA001
     - SOURCE REJECTED
     - The source does not evaluate or does not check.
   * - DBA002
     - REVISION CONFLICT
     - The head is not the expected revision.
   * - DBA003
     - DATABASE UNAVAILABLE
     - A command cannot reach the database.
   * - DBA004
     - NO REVISION
     - Nothing is published, or the revision does not exist.
   * - DBA005
     - INVALID AUTHORITY
     - The ``authority`` section, or the file that should hold it, is wrong.
   * - DBA006
     - NO AUTHORITY
     - The edge serves a file, and the command needs a database.
   * - DBA007
     - MISSING COMMAND
     - The command line is not one of the commands.
   * - DBA008
     - REVISION DAMAGED
     - A stored revision does not have the digest of its row, or a column out of its range.
   * - DBA009
     - FILE IS LOCAL
     - ``reload cluster`` on a node that follows a database.
   * - DBA010
     - log
     - A revision was applied.
   * - DBA011
     - log
     - A revision was refused. The node keeps the one it serves.
   * - DBA012
     - log
     - The database is unavailable. The node keeps the revision it serves.
   * - DBA013
     - log
     - The database is available again.
   * - DBA014
     - log
     - The node started from its cache.
   * - DBA015
     - log
     - ``authority.binds`` names a frontend that is not published.
   * - DBA016
     - log
     - The node cannot write its report or its cache.

What the Lean model establishes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The companion file is ``docs/sid/assets/database-authority.lean``. We check it with Lean 4.19.0 and no library.

.. code-block:: sh

   lean docs/sid/assets/database-authority.lean

- **Commit.** ``commit_conflict`` leaves the store alone when the expected head is not the head. ``commit_head`` adds exactly one revision. ``commit_keeps`` proves that every earlier revision reads as before. ``commit_reads_new`` reads the new document at the new head. ``second_commit_conflicts`` covers two writers that expect the same head: after the first the second fails.
- **Completeness.** ``read_complete`` gives a document for every number from one to the head.
- **Rollback.** ``rollback_restores`` reads the document of the restored revision at the new head, and ``rollback_keeps`` keeps the history.
- **Follower.** ``step_unavailable`` and ``step_invalid`` keep the node as it was. ``step_serves_valid`` proves that a node only ever holds a document that passed its check. ``step_agrees`` proves that what a node holds is the revision of the store that it names. ``poll_converges`` proves that one look at a valid head brings the node to the head, so a lost notification costs one period. ``applied_le_head`` and ``applied_monotone`` bound and order the revisions that a node reports.

The model has one history and transactions that run one after another, as the row lock and the write lock arrange. Isolation levels, the network and the clock are outside it.

Rationale and alternatives
--------------------------

**A document, not rows.** The topology is checked as a whole: a frontend names a backend, two binds must not overlap, a bound covers all listeners. One row for each revision is read whole by construction, on both databases, with no isolation level to choose. Rows for frontends, backends and servers would repeat every option of a schema that still grows (SID 0019 and SID 0021 added many), with a migration for each, and the checker would still need the document. History and rollback are trivial with documents: every revision is kept, and a rollback is a commit. The cost is that SQL cannot ask "which revisions name server X". The difference between two revisions answers that from the documents.

**A rollback that appends.** Moving the head back to an old number would make the numbers of the nodes ambiguous: "applied 5" could be before or after "applied 7". It would also leave no record that somebody rolled back. A rollback is therefore a new revision.

**The expected revision is the one that was read.** A commit conditioned on "the head, whatever it is" protects nothing. The command conditions on the head against which it printed the difference, so what the operator saw is what the commit replaces.

**The node checks again.** The command checks the topology and cannot check the files of a node. A node composes the revision with its own file and its own binds. So the last word is with the node, as in SID 0023.

**Commands on the database, not on a node.** ``apply`` through the admin socket of a node would make that node a part of every change and would bound the source by the line of the socket. The database is the authority, so the command talks to it.

**No new client.** The workspace has ``sqlx`` for both databases (SID 0011), with SCRAM-SHA-256, TLS under ``postgres-tls`` and ``LISTEN``. We use it through ``sibuna-storage`` and add no crate. ``sibuna-storage`` gains one small function that listens on a named channel.

**The file sent by SID 0023** stays for clusters that want no database. Both can be used at once: the mesh carries bans and drains, the database carries the topology.

Security and operational considerations
---------------------------------------

**How a node authenticates.** A node connects with a PostgreSQL URL that holds a role and its password. PostgreSQL verifies it with SCRAM-SHA-256. The URL is in a file that only the user of the daemon may read. The daemon refuses a file that group or others can read, and never prints its content. The path is in the file of the node, the secret is not. With the feature ``postgres-tls`` the URL can state ``sslmode=verify-full`` and ``sslrootcert``, as for the storage of SID 0011. Without TLS the topology crosses the network in clear text and the password is protected only by SCRAM.

**Two roles.** A node needs to read ``edge_head``, ``edge_revisions`` and ``sibuna_schema`` and to write its row of ``edge_nodes``. It needs no right to commit. The operator role owns the tables. A node that is taken over can then report a false revision and cannot change the topology. The operations chapter gives the grants. Only the commands create and migrate the tables. A node never does.

**What the database holds.** The topology names paths of secrets and not the secrets. It shows addresses and routes. The source is stored as given, so a secret written into a source would be stored too.

**Bounds.** A document and a source hold at most 256 KiB each, a note 200 bytes, a name 128 bytes. ``history`` returns at most 1,000 rows and ``show cluster`` at most 256 nodes. The detail of a refusal is cut at 300 bytes. The difference prints at most 200 lines.

**Availability.** A running node needs the database only to learn of a change. With ``cache`` a node also restarts without the database. The cache is checked by its digest and by the check of the node.

**A schema that is newer** than the binary knows makes a node keep what it serves and say so. A downgrade of the binary must come before a migration, or after the tables are restored.

Backwards compatibility
-----------------------

A file without ``authority`` is read as before, and nothing else changes. ``reload``, ``reload cluster`` and ``show cluster`` keep their answers on an edge without ``authority``. The mode is fixed when the daemon starts: adding or removing ``authority`` needs a restart. A build without storage refuses a file with ``authority``, and a build without the feature ``postgres`` refuses ``postgres_url_file``.

Acceptance criteria and implementation status
---------------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 6 44 50

   * - #
     - Criterion
     - Status
   * - 1
     - ``apply`` commits a checked source as a numbered revision and prints the difference.
     - Met. ``apply_shows_the_difference_and_a_stale_expectation_is_a_conflict`` in ``cmd/sibuna/tests/edge_authority.rs`` runs ``diff`` and ``apply`` of the binary: the difference names ``backends.app.servers[b]``, the same source again commits nothing, and a source with an unknown section or a dangling backend is refused with ``DBA001``.
   * - 2
     - A commit on a stale expected revision fails and changes nothing.
     - Met. The same test applies with ``--expect 0`` at head 1 and gets ``DBA002`` with the head unchanged. ``of_eight_sqlite_writers_on_one_head_one_wins`` and ``postgresql_keeps_the_invariants_and_one_of_eight_writers_wins`` in ``crates/authority/tests/store.rs`` run eight writers on one expected head: one commits and seven get the conflict.
   * - 3
     - Two nodes follow a revision and report it.
     - Met. ``two_nodes_follow_a_revision_and_show_cluster_names_what_each_applied`` (SQLite, poll 200 ms) and ``nodes_follow_a_notification_with_a_role_that_cannot_commit`` (PostgreSQL, poll 60 s). ``show cluster`` on each node and ``authority status`` name both nodes as current. Measured on a debug build, from the start of ``apply`` to the log line ``DBA010`` on both nodes: 176 ms to 203 ms with SQLite over four runs, 128 ms to 155 ms with PostgreSQL over three runs, where only the notification can be that fast.
   * - 4
     - A node that refuses a revision keeps its routes and says why.
     - Met. ``a_revision_that_a_node_cannot_serve_is_refused_and_the_node_keeps_its_snapshot`` publishes a revision that names a policy file which the node lacks. The node logs ``DBA011``, keeps its servers, shows ``refused 2`` with the reason in ``show cluster``, ``show authority`` and ``authority status``, restarts from its cache with ``DBA014`` and applies the next good revision. ``an_outage_changes_nothing_and_a_damaged_revision_is_refused`` writes a revision past the command with a digest that does not fit: both nodes refuse it.
   * - 5
     - A node keeps serving when the database is down and follows when it returns.
     - Met for PostgreSQL. ``an_outage_changes_nothing_and_a_damaged_revision_is_refused`` stops the server at once: both nodes log ``DBA012`` and keep their servers, ``show cluster`` says that the database is unavailable, ``apply`` fails with ``DBA003``. After the server starts again the nodes log ``DBA013`` and apply the next revision 121 ms to 136 ms after ``apply`` began. For SQLite ``a_node_keeps_serving_and_restarts_from_its_cache_without_the_database`` covers the restart without the database and the return. A SQLite file that vanishes under a running node is not tested, see the gaps.
   * - 6
     - History lists the revisions and a rollback restores an earlier one.
     - Met. ``history_lists_every_revision_and_rollback_appends_an_earlier_one``: four revisions with origin, author, source and note, ``rollback 1`` commits revision 4 with the document of revision 1, revision 3 still dumps, a stale ``--expect`` gives ``DBA002``. The two-node test rolls back under running nodes and both follow.
   * - 7
     - A dump applies to the same revision, and the source is returned as given.
     - Met. ``a_dump_applies_to_the_same_revision_and_the_source_comes_back_as_given``: applying the dump commits nothing, a second database that takes the dump holds the same digest and dumps the same bytes, and ``dump --source`` returns the JSON and the JLV source byte for byte.
   * - 8
     - Both stores pass the same tests.
     - Met for the store. ``crates/authority/tests/store.rs`` runs the same invariants against the model in memory, SQLite and PostgreSQL 17. The binary tests of the commands run on SQLite, and the tests of following, outage and damage run on PostgreSQL too. The PostgreSQL tests need ``--features postgres`` and a PostgreSQL on the machine, and skip with a line otherwise.
   * - 9
     - ``reload cluster`` and ``show cluster`` of SID 0023 keep working.
     - Met. ``cmd/sibuna/tests/edge_cluster_reload.rs`` passes unchanged on an edge without ``authority``. In persistent mode ``reload cluster`` answers ``DBA009`` (tested) and ``show cluster`` prints the revisions.

Known gaps
----------

#. The history is never pruned. A row of ``edge_nodes`` stays after its node is gone, until the operator deletes it.
#. Two nodes that state the same ``node`` overwrite the report of each other. Nothing detects it.
#. ``global``, ``mesh`` and ``observability`` belong to the file as a whole. No option of ``global`` can be published for all nodes.
#. The command cannot check the files that a topology names. Only the nodes can, and they refuse one by one. There is no staged rollout, and ``apply`` does not wait for the nodes: ``status`` shows them afterwards.
#. A change at run time, such as a weight, is not a revision. A new revision is a reload, and a reload replaces such changes as SID 0018 says.
#. SQLite has no notification, so a node on SQLite learns of a change by its poll. We did not test a SQLite file that vanishes under a running node: the node holds the file open and keeps reading it.
#. A database role that lacks a right gets ``DBA003 DATABASE UNAVAILABLE`` with the message of the database, and not a code of its own.
#. ``show cluster`` asks the thread that owns the store and waits at most four seconds on the admin thread when the database is slow.
#. The author of a revision is what the command states. The database role is not recorded.
#. The time of a commit is the clock of the machine that ran the command.
#. A database that was restored to an earlier head is followed down to that head. A unit test covers a known number with another digest. No binary test restores a database.
#. Changing ``sqlite``, ``postgres_url_file``, ``node``, ``poll`` or ``cache`` needs a restart, as adding or removing ``authority`` does.
#. A node with a mesh and a database is not tested through the binary. The refusal of a file that a peer sends to such a node has no test.
#. TLS to PostgreSQL (feature ``postgres-tls``) is not tested with the authority. The tests use one PostgreSQL 17 server on loopback with SCRAM-SHA-256. Replication and failover of the database are outside this record.
#. The console of SID 0015 does not edit the topology. The commands are the only writers.
#. Only Linux is tested. The other platforms build.

Open questions
--------------

#. Should the history be pruned, and by age or by count?
#. Should a run-time change of the admin socket, such as a weight, become a revision, as SID 0015 asks for the console?

Review history
--------------

- 2026-11-25. Review of the code. It found seven faults and corrected them. The follower composed a new revision with the file on the disk, so a half edited file made the node refuse a good revision and fall behind until a reload: it composes with the file that the worker last took. A node with a poll of one minute asked a database that was down only once a minute: it asks again after two seconds. ``apply`` and ``rollback`` read the head for the difference and failed on a damaged head, so the operator could not repair it: they say so and commit over it. Every command migrated the tables, so ``status`` failed with the role of a node: the reading commands only read. ``reload cluster`` sent the file of a node, with its name and its binds, to its peers: ``DBA009``, and a node in persistent mode refuses such a file. ``show cluster`` waited four seconds for a database that the node already knew to be down: it answers from memory. A table with an empty last cell ended its line with a space.
- 2026-11-25. Initial draft, before the implementation. The review of the draft found nine faults and corrected them. The draft let a node migrate the schema, which would give every node the right to change tables: only the commands migrate now. It counted a revision as applied when it passed the check of the follower, although the worker can still refuse it: the worker settles it now. It dropped the sections of a source that it did not know, so a misspelled ``frontends`` would have published an empty topology: an unknown section is refused. It never checked a refused head again, even after a repair on the host: a reload does. It had no way to restart during an outage of the database: the cache. It conditioned a commit on the head at the time of the commit, which protects nothing: the head that was read. It rolled back by moving the head, which made the numbers ambiguous: a rollback appends. It let a refused revision pass through the ordinary reload, which would have replaced run-time changes with the same routes: the follower offers a revision only when it checked. It ignored a name in ``binds`` that no frontend has, which hides a misspelling: ``DBA015``.

References
----------

- SID 0011, SQL storage. SID 0012, TLS for PostgreSQL.
- SID 0015, Distributed Edge Load Balancer, sections "Configuration and authority" and "File and database authority".
- SID 0018, Quick Start and Admin Socket.
- SID 0023, One Configuration File for a Cluster.
