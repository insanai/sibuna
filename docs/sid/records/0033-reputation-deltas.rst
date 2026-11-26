:sid-number: 0033
:sid-title: Reputation by Deltas
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-26
:sid-updated: 2026-11-26
:sid-discussion: https://github.com/insanai/sibuna/issues/2
:sid-summary: A reputation change no longer rebuilds the policy engine. Every change of ip_reputation is stamped by a counter that writers take in commit order, and each node applies the changes after its cursor to a reputation set published beside the engine. The set holds exact addresses in a hash table and ranges in a trie of their own, so it holds the million rows that storage allows.
:sid-labels: ["architecture","storage","postgresql","sqlite","data-plane","performance"]

Reputation by Deltas
====================

Abstract
--------

The firewall daemon keeps reputation in the database table ``ip_reputation``: bans from the honeypot and from rule limits, and the entries an operator or a country set writes. Until this record, every change of that table raised the policy revision. Every node then read all policies and up to a million reputation rows, compiled a new engine and inserted every row into a trie of 8,192 nodes. The trie fills after a few hundred to a few thousand addresses. From then on every rebuild failed, and a node stopped applying the operator's policy changes.

We separate reputation from the engine. A change of ``ip_reputation`` is recorded in a change log, stamped by a counter that writers update in their own transaction, so the stamps become visible in commit order. Each node keeps a cursor, applies the changes after it to a reputation set, and publishes the set beside the engine in the slot that request threads already read. A policy change still rebuilds the engine, and no longer reads reputation. This holds for PostgreSQL in a cluster and for SQLite on one node.

Motivation and scope
--------------------

Issue 2 states the fault and its measurements. In short:

- A ban written by any node raised ``policy_revision`` through the statement trigger on ``ip_reputation``. Under PostgreSQL it also sent ``NOTIFY sibuna_policy``.
- Each node then ran ``Worker::rebuild``: it read all policies, the inspection row and up to ``MAX_REPUTATION_ROWS`` (1,000,000) reputation rows, and ``build_engine`` compiled the recipe and inserted every row.
- The engine's ``PrefixTrie`` had the default capacity of 8,192 nodes. An address is a path of up to 128 nodes in the mapped key space. With 1,000 neighbouring addresses a rebuild took 0.54 ms; with 5,000 it failed with ``invalid reputation entry``.
- A failed rebuild left ``applied_revision`` behind, so every tick read everything again and failed again. Policy changes stopped reaching the node.
- The expiry of the earliest ban forced a full rebuild as well.

Request threads never waited for any of this: they read the engine through ``EngineCache``. The cost was CPU and database time on every node, and the loss of policy updates under an attack.

This record covers the reputation of the firewall daemon with storage, on PostgreSQL and on SQLite. It also states what an edge reload costs on its worker, because the question of the data plane covers both. It does not change policies, the inspection settings, page templates or incidents.

Specification
-------------

Invariants
~~~~~~~~~~

#. *No request waits.* A request thread reads the engine and the reputation set with one acquire load of the slot's generation, as before. No lock, query or allocation is added to the request path.
#. *Exactness.* After a node has applied the change log up to cursor :math:`c`, its reputation set answers every lookup as a set built from the rows of ``ip_reputation`` at the commit that produced :math:`c` would answer it.
#. *No lost change.* A change that commits is applied by every node that keeps running, at the latest at the tick after it becomes visible, or the node reloads the whole table.
#. *Bounded work.* Applying :math:`b` changes to a set of :math:`n` entries costs :math:`O(b + \sqrt{n})` amortised element copies per change at most, and no database read beyond the changes themselves.
#. *Isolation of failure.* A row that the set cannot hold is refused alone and counted. It never stops the publication of the other rows or of a policy change.

The change log
~~~~~~~~~~~~~~

Migration 3 of the core schema adds two tables and replaces the revision triggers of ``ip_reputation``.

.. code-block:: sql

   CREATE TABLE reputation_clock (
       id INTEGER PRIMARY KEY CHECK (id = 1),
       seq BIGINT NOT NULL CHECK (seq >= 0));
   CREATE TABLE reputation_changes (
       seq BIGINT PRIMARY KEY CHECK (seq >= 1),
       ip_or_cidr TEXT NOT NULL,
       reputation_score INTEGER NOT NULL,
       banned_until BIGINT,
       removed BOOLEAN NOT NULL);

A statement trigger runs before every insert, update and delete of ``ip_reputation`` and locks the counter row (``SELECT ... FOR UPDATE`` in PostgreSQL). Then a row trigger on every insert, update and delete does two things in the writer's transaction: it adds one to ``reputation_clock.seq``, and it inserts a change with the new value of ``seq`` and the new state of the row. A delete inserts a change with ``removed`` set. Under PostgreSQL the trigger also sends ``NOTIFY sibuna_policy``, so the nodes tick at once; PostgreSQL delivers one notification per channel and transaction. Changes of ``ip_reputation`` no longer raise ``policy_revision``.

A change carries the whole new state of its row, never a difference. Applying a change sets or removes one key.

``TRUNCATE`` fires no row triggers in PostgreSQL. A statement trigger after ``TRUNCATE`` therefore adds one change with an empty ``ip_or_cidr`` and ``removed`` set. A node that reads it loads the whole table. SQLite has no ``TRUNCATE``, and its ``DELETE`` fires the row triggers.

Why the stamps are in commit order
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PostgreSQL sequences are not in commit order: a transaction can take number 10, another number 11, and 11 can commit first. A reader that saw 11 and moved its cursor past it would never see 10. We therefore do not use a sequence.

The counter is a row. The first statement of a transaction that changes reputation locks it, and the lock is held until the transaction ends. A second writer waits for that lock before it locks any row of ``ip_reputation``. Under PostgreSQL's read committed level it then reads the committed value of the counter and adds one to it. Because every writer of reputation takes the counter before any row of the table, two writers cannot deadlock on the table and the counter. So the writers that change reputation are serialized: every stamp of the first transaction is smaller than every stamp of the second, and the first commits before the second takes the lock. A transaction that aborts rolls its update of the counter back, so it consumes no stamp.

Hence the committed stamps are always exactly :math:`1, 2, \ldots, m` with no gap, and a snapshot that contains stamp :math:`s` contains every stamp below :math:`s`. SQLite has one writer at a time, which gives the same order.

A reader can check this. It asks for the changes after its cursor :math:`c` in ascending order and expects :math:`c+1, c+2, \ldots`. A gap means that the log was pruned past its cursor. It then reloads the whole table.

Loading the whole table
~~~~~~~~~~~~~~~~~~~~~~~

A node loads the whole table at its start, after a gap, and after a failed tick. It does this without a long transaction:

#. Read :math:`c_0`, the counter.
#. Read the rows of ``ip_reputation`` that decide (a score of at most -50 or at least 50) and have not expired.
#. Read the changes after :math:`c_0` and apply them in order. The cursor is the last one applied. If they do not begin at :math:`c_0 + 1`, retention removed some meanwhile: the node starts the load again, at most three times in one tick, and otherwise keeps its last set and tries at the next tick.

The rows of step 2 may already contain changes after :math:`c_0`. That does no harm. For every key, the row read in step 2 is the state after some change :math:`s` of that key, and every change of that key after :math:`c_0` is in the log of step 3. Applying them in order ends with the state after the last one, whatever :math:`s` was. The Lean model proves this.

What a node holds
~~~~~~~~~~~~~~~~~

The daemon keeps a builder on the storage thread and publishes snapshots from it. A snapshot is three shared parts:

- *base*: a hash table from an exact address to a verdict, with IPv4 addresses as 32-bit keys and IPv6 addresses as 128-bit keys;
- *overlay*: a small hash table from an exact address to an entry or to a mark of removal;
- *ranges*: a prefix trie of entries for the rows that are true ranges, with room for 1,048,576 nodes.

A verdict is deny or allow. The builder keeps the time at which each entry ends beside it, not in the published set. A row whose prefix covers one address (``/32`` for IPv4, ``/128`` for IPv6, or a bare address) is exact. Every other row is a range. Keys use the mapped form of the existing trie, so ``::ffff:192.0.2.1`` and ``192.0.2.1`` are one key.

A batch of changes goes into the overlay. When the overlay holds more than :math:`K = \max(256, \lceil\sqrt{n}\rceil)` keys, where :math:`n` is the size of the base, the builder merges it into a new base and empties it. A change of a range rebuilds the range trie, which holds few rows.

Each publication shares the base and the range trie of the last one and copies the overlay. Publishing :math:`b` changes costs at most :math:`K + b` copies, and a merge costs :math:`n + K` copies once every :math:`K` changes. Per change that is at most :math:`K + (n + K) / K \le 2\sqrt{n} + O(1)` copies, the bound of invariant 4.

Lookup
~~~~~~

A request's address is looked up in four places, and the longest prefix wins:

#. the overlay: a removal mark hides the exact key of the base, an entry is the answer;
#. the base, for the exact address;
#. the range trie, with the length of the prefix it matched;
#. the engine's own trie, which holds the reputation of the policy file, with its length.

An exact address is the longest possible prefix, so steps 1 and 2 answer first. Between the range trie and the engine's trie the longer prefix wins, and the range trie wins a tie. This is what one trie that held the file's rows and then the database's rows answered before. A lookup reads no clock: an entry that ended is gone from the set at the next tick (see Expiry).

Expiry
~~~~~~

The builder keeps the times at which its entries end, ordered. At every tick it removes the entries that have ended, as removals of its own, and publishes them with the batch. The database rows stay until an operator or retention removes them; the load of step 2 above ignores them. Expiry no longer causes a rebuild.

Retention of the log
~~~~~~~~~~~~~~~~~~~~

Each node deletes the changes more than 1,000,000 stamps behind the counter, at most once a minute. The delete is idempotent, so several nodes may run it. A node that was away longer than the log covers finds a gap and loads the table.

Policy changes
~~~~~~~~~~~~~~

A change of policies, of the inspection row or of a page template still raises ``policy_revision``. The storage thread rebuilds the engine as before, without reading reputation, and publishes it with the current reputation set. A rebuild that fails keeps the old engine and the reputation set keeps moving.

The edge
~~~~~~~~

The edge daemon has no ``ip_reputation``. Its bans live in memory and travel over the mesh (SID 0022). Its topology may come from the database (SID 0028): a revision is fetched, composed and checked on the ``edge-authority`` thread, and Maglev tables are built while the configuration is parsed, off the worker. Only the swap runs on the edge worker. We measured it with a release build: 2 us for one pool, 33 us for ten pools of ten servers, 160 to 180 us for 50 pools of ten servers. A topology may have at most 128 pools. We keep the swap on the worker, where the order of flows and revisions is simple, and record the bound.

Rationale and alternatives
--------------------------

*A bigger trie.* Raising the trie's capacity to cover a million addresses needs about 100 million nodes in the worst case, and it still rebuilds everything on every change. The hash table answers an exact address in one probe; a million IPv4 addresses take about 50 MiB.

*A sequence for the stamps.* Rejected for the reason above: sequences are not in commit order.

*A timestamp column with a lag.* Readers would wait a guessed lag and could still miss a long transaction. The counter makes the order exact and lets a reader detect a gap.

*Logical replication or ``LISTEN`` payloads.* Logical replication needs privileges and a slot per node. A notification payload is lost when the listener is disconnected. The table is the record of what happened, and the notification only wakes the node.

*The spill cache of SID 0027.* Its contract allows it to lose any entry at any time. A lost ban would let a banned client in, so the set must be exact. The hash table is bounded by ``MAX_REPUTATION_ROWS``.

*FoundationDB or Kafka.* Neither removes the need for SQL queries in the console, both add a system to run, and the write rate of reputation is small. The change log gives the pattern of a log inside the database we already have.

Security and operational considerations
---------------------------------------

The change log holds the same data as ``ip_reputation`` and needs the same protection. Its retention bounds its size: one million changes is about 100 MB in PostgreSQL. A node that cannot read the log keeps its last published set and its engine and serves on.

Every writer of ``ip_reputation`` now waits briefly for the counter row while another transaction that changes reputation is open. Incident batches write their bans in short transactions, so the wait is the length of one batch. An operator who opens a long transaction that changes ``ip_reputation`` holds other writers of reputation until it ends.

Memory: a full set of a million exact IPv4 addresses takes 49 MiB resident (measured), and a merge holds two bases for its duration. The range trie may use up to 1,048,576 nodes of 16 bytes.

Backwards compatibility
-----------------------

Migration 3 runs once. It fills ``reputation_clock`` with 0 and leaves the log empty. Nodes of the older version do not read the log; they keep rebuilding on ``policy_revision``, which reputation no longer raises. They therefore see no new bans until they are upgraded. In a cluster we upgrade all nodes together, as the operations chapter says for every schema change.

Acceptance criteria and implementation status
---------------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 46 54

   * - Criterion
     - Evidence
   * - Changes are stamped in commit order and a reader detects a gap
     - ``overlapping_writers_get_stamps_in_commit_order`` (PostgreSQL: the second writer waits for the first, its stamps come after, an aborted writer consumes no stamp); ``a_reader_detects_a_gap_in_the_stamps``.
   * - A full load followed by the log equals the table
     - ``reputation_follows_its_change_log_and_rebuilds_no_engine`` on SQLite and PostgreSQL: inserts, a delete, a renamed key, a pruned change that opens a gap and makes the node load once; ``a_truncate_makes_the_node_load_the_table``; ``migration_three_keeps_the_rows_of_a_version_two_database``.
   * - Overlay and base answer as one set; a merge changes no answer
     - ``random_changes_answer_as_the_naive_model_through_every_merge``: 4,000 random sets, removals and expiries checked against a naive longest-prefix model; ``the_overlay_merges_at_its_bound_and_no_answer_changes``.
   * - Expired entries stop matching without a rebuild
     - ``entries_end_at_their_time_without_a_rebuild``; ``the_follower_applies_changes_expires_and_publishes_only_on_a_change``.
   * - A reputation change rebuilds no engine; a policy change reads no reputation
     - ``reputation_follows_its_change_log_and_rebuilds_no_engine`` counts the published engines; ``PolicySnapshot`` no longer has reputation fields.
   * - The engine's own reputation and the set answer by the longest prefix
     - ``published_reputation_and_the_engines_own_answer_by_the_longest_prefix``.
   * - A set of a million exact addresses publishes and answers
     - Measured with ``cost_of_a_change_and_a_lookup`` and ``memory_of_a_million_addresses`` (release build, one thread): see Measurement.
   * - The Lean model checks
     - ``docs/sid/assets/reputation-deltas.lean``: ``replay_key``, ``load_then_replay``, ``view_note``, ``merge_keeps_answers``, ``view_noteAll``, ``stamps_have_no_gap``, ``snapshot_has_no_gap``, ``merge_cost``.

Measurement
-----------

Before this record a ban rebuilt the engine. With the default recipe and a release build the rebuild took 0.29 ms with no reputation, 0.54 ms with 1,000 neighbouring addresses, and failed with 5,000.

After it, one change and its publication cost, averaged over 10,000 changes so that merges are included:

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - Entries in the set
     - Per change and publication
     - Per lookup
   * - 10,000
     - 0.4 us
     - 17 ns
   * - 100,000
     - 0.4 us
     - 23 ns
   * - 1,000,000
     - 1.9 us
     - 48 ns

A million IPv4 addresses take 49 MiB resident. A first version kept every key as 128 bits and copied a drained overlay at each publication: 33 ms per change at a million entries and 99 MiB. The review below records both faults.

Known gaps
----------

#. The console's policy test composes a candidate engine with the old trie of 8,192 nodes and reports ``TrieFull`` for a larger set. It is not on the request path.

Open questions
--------------

#. Should retention of the log be by time rather than by count?

Review history
--------------

- 2026-11-26. Review of the code with measurements. A drained overlay kept the allocation of a million keys, and every publication copied that empty table: 33 ms per change. The merge now takes the overlay. Keys of 128 bits used 99 MiB for a million IPv4 addresses: IPv4 keys now have 32 bits, and a full load writes into the base while no set shares it, 49 MiB. The PostgreSQL tests showed the order of stamps as specified.
- 2026-11-26. Review of the draft. Three faults. The row trigger took the counter lock after the row lock, so a statement that changed two rows could deadlock with another writer: the counter is now locked by a statement trigger before any row. ``TRUNCATE`` fires no row trigger and would have left stale bans on every node: it now writes a reset change. Retention could remove changes between the two reads of a full load: the load checks the first stamp and starts again, with a bound.
- 2026-11-26. Initial draft, from issue 2.

References
----------

- Issue 2, "storage: a reputation change rebuilds the whole policy engine on every node".
- SID 0011, SQL storage; SID 0013, console storage; SID 0022, replicated bans; SID 0027, spill cache; SID 0028, database authority.
- PostgreSQL documentation, "Transaction Isolation" (read committed and row locks) and "NOTIFY".
