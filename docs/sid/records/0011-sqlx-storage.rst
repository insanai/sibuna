:sid-number: 0011
:sid-title: Storage Through sqlx: SQLite for One Node, PostgreSQL for Clusters
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-10-15
:sid-updated: 2026-10-15
:sid-discussion: No external discussion URL assigned
:sid-summary: Replaces Zaxonlite with storage through sqlx, an embedded SQLite file for a single node and one shared PostgreSQL database for a cluster, while storage stays optional and one storage thread owns all SQL off the request path.
:sid-labels: ["storage","rust","cluster"]

Storage Through sqlx: SQLite for One Node, PostgreSQL for Clusters
==================================================================

Abstract
--------

The Rust port removes Zaxonlite. Persistent state (dynamic policies, IP reputation, incident forensics and the console's tables) is stored through ``sqlx``. A single node uses an embedded SQLite file in its data directory. A cluster points every node at one PostgreSQL database, whose availability is PostgreSQL's concern. Storage stays optional, as in SID 0005: without ``--data-dir`` or ``--database-url`` the daemon is the in-memory firewall of SID 0002, and a build without the storage features contains no external crate. The request path never waits on the database; one storage thread owns all SQL, as before.

Motivation and scope
--------------------

SID 0005 chose Zaxonlite, a replicated SQLite built on Multi-Paxos, so that every node could read and write the same SQL state. It worked, but it made a firewall depend on a young consensus system: 48,000 lines of Zig, its own journal format (changed incompatibly in 0.7.0), OpenSSL for mutual TLS, and a shutdown path that could block on consensus. Sibuna stores little: a few hundred policy rows, a reputation table, and forensic incidents that operators also export to external systems. That state does not need a bespoke replicated engine. It needs a reliable SQL store, local for one node and shared for many.

This record covers the persistent layer of SID 0005 and the console storage of SID 0007. It does not change what is stored or when; it changes where and how.

Specification
-------------

Backends and selection
~~~~~~~~~~~~~~~~~~~~~~

.. list-table:: Storage configurations
   :header-rows: 1
   :widths: 25 35 40

   * - Configuration
     - Option
     - Store
   * - In-memory (default without options)
     - none
     - nothing persists; policies come from ``--policy-file``
   * - Single node
     - ``--data-dir <path>``
     - SQLite file ``<path>/sibuna.db`` in WAL mode with ``synchronous=NORMAL`` and a busy timeout
   * - Cluster
     - ``--database-url postgres://...`` and ``--cluster-node <id>``
     - one PostgreSQL database shared by every node

``--cluster-node`` keeps its meaning from the Zig daemon: it binds challenge keys to the issuing node and occupies the top bits of incident identifiers. With PostgreSQL it is required and must be unique per node. The Zaxonlite options ``--cluster-listen``, ``--cluster-peer``, ``--cluster-secret-file`` and the cluster TLS options are removed; giving one stops startup with a diagnostic that names this record. The PostgreSQL connection string may carry its own TLS parameters when the build enables the TLS feature.

The storage thread
~~~~~~~~~~~~~~~~~~

One storage thread owns a single-threaded asynchronous runtime and the connection pool. Request threads never await: they push incident records into the bounded MPSC ring (1 slot of 512 per record, dropping and counting when full) and read the published engine. Every ``--storage-poll-ms`` (default 500) the thread runs one tick:

1. Drain up to 32 queued incidents and write them in one transaction.
2. Read the policy revision. When it changed, or a reputation entry expired, rebuild the engine from the policy file, the ``policies`` and ``policy_inspection`` tables and ``ip_reputation``, and publish it.
3. Run the console's due work (SID 0007), when the console is enabled.

A rebuild reads the revision before and after loading; if a writer committed in between, the candidate is discarded and the old engine stays live, exactly as SID 0005 required.

Schema and migrations
~~~~~~~~~~~~~~~~~~~~~

The schema is the one of SID 0005 and SID 0007, written once per dialect and applied by numbered migrations compiled into the binary. A table ``sibuna_schema(version, applied_at)`` records them. A node refuses to start against a database whose schema version is newer than it knows, with a diagnostic naming both versions. Migrations run in one transaction; under PostgreSQL an advisory lock serialises nodes that start together.

.. list-table:: Dialect differences
   :header-rows: 1
   :widths: 30 35 35

   * - Concern
     - SQLite
     - PostgreSQL
   * - 64-bit keys
     - ``INTEGER PRIMARY KEY``
     - ``BIGINT PRIMARY KEY``
   * - byte strings
     - ``BLOB``
     - ``BYTEA``
   * - larger of two values
     - ``MAX(a, b)``
     - ``GREATEST(a, b)``
   * - upsert
     - ``ON CONFLICT ... DO UPDATE``
     - ``ON CONFLICT ... DO UPDATE``
   * - full-text search
     - FTS5 external-content table ``incidents_fts``
     - generated ``tsvector`` column with a GIN index
   * - revision triggers
     - ``CREATE TRIGGER ... BEGIN UPDATE sibuna_meta ...; END``
     - a PL/pgSQL function and ``AFTER`` statement triggers
   * - change notification
     - polling only
     - polling, plus ``NOTIFY sibuna_policy`` so nodes tick early

Every statement binds its values as parameters. The Zig layer built SQL text with quoted literals; parameters remove the quoting code and its failure modes.

Policy revision
~~~~~~~~~~~~~~~

Operators may write the ``policies``, ``ip_reputation`` and ``policy_inspection`` tables directly. Triggers on insert, update and delete increment ``sibuna_meta.policy_version`` in the writer's transaction, so a direct write is seen by every node on its next tick, as in SID 0005. Under PostgreSQL the trigger also issues ``NOTIFY sibuna_policy``; a node that receives it ticks at once, and polling remains the guarantee.

Incidents and campaigns
~~~~~~~~~~~~~~~~~~~~~~~

An incident identifier is ``(node_id << 40) | sequence``. Each node keeps a durable receipt ``incident_cursor_<node>`` in ``sibuna_meta``, advanced in the same transaction as the batch, and every insert is guarded by the receipt, so replaying a batch after an ambiguous failure writes nothing twice. These rules are unchanged from SID 0005.

Zaxonlite linked sqlite-vec and assigned campaigns with a nearest-neighbour query over every stored embedding. The Rust port stores the 64-dimension embedding of SID 0006 as 256 bytes (little-endian ``f32``) in ``security_incidents.embedding`` and searches in the storage thread: it keeps the most recent 16,384 embeddings of all nodes in memory (4 MiB), refreshed incrementally from the database on each tick, and assigns an incident to the campaign of its nearest neighbour when the cosine distance is at most 0.35. The distance threshold, the embedding and the campaign identifiers are unchanged. Clustering against older incidents than the window is a deliberate omission: campaigns are recent by nature, and the bound keeps memory and work fixed.

Reputation and bans
~~~~~~~~~~~~~~~~~~~

``ip_reputation`` keeps its columns and upsert rules: a honeypot hit sets the score to -100 and extends ``banned_until`` with the greater of the two values; a rebuild loads unexpired bans into the engine's CIDR trie and schedules the next rebuild at the earliest expiry.

Console storage
~~~~~~~~~~~~~~~

The console's tables of SID 0007 move unchanged in meaning. Where SID 0007 relied on SQLite triggers to enforce audit and integrity invariants (for example "a token update writes an audit row", "a retention delete cannot remove an incident under investigation"), the Rust console performs the same statements explicitly inside one transaction in a single function per invariant, and tests assert the invariant against both backends. Triggers remain only for the policy revision, because operators may write those tables directly.

Rationale and alternatives
--------------------------

**Why sqlx.** It supports SQLite and PostgreSQL behind one API, is maintained, is widely used, and its SQLite driver bundles SQLite 3.51 with FTS5 compiled in. We use it without macros, without its migration framework and without TLS by default (``default-features = false`` with ``runtime-tokio``, ``sqlite-bundled`` and ``postgres``), which keeps the build free of a database at compile time. The cost is about one hundred transitive crates (``tokio``, the ``futures`` family, the ``url`` and ICU stack, ``libsqlite3-sys`` and its C build). They are confined to ``sibuna-storage`` and to the storage thread, and both backends are cargo features.

**Why not keep Zaxonlite through its C ABI.** It would keep the cluster design of SID 0005 but would require the Zig toolchain to build the Rust daemon and keep the consensus failure modes we are removing.

**Why not a hand-written store.** The console's queries (time windows, rankings, audit filters, full-text search) are naturally SQL. Writing a query engine is not Sibuna's job.

**Why PostgreSQL for clusters.** Sibuna nodes need shared, consistent, durable state, and PostgreSQL provides exactly that with mature replication and failover (streaming replication, Patroni or a managed service). Sibuna's write rate is small (batched incidents, rare policy changes), so one primary is not a bottleneck.

Security and operational considerations
---------------------------------------

The data plane does not depend on the database being reachable: if it is down, the last published engine keeps serving, incidents queue in the bounded ring and are dropped with a counter once it is full, and the storage thread retries with backoff. This matches the Zig daemon's behaviour when a cluster lost quorum. Connection strings are secrets: ``--database-url-file`` reads one from an owner-only file, and the banner never prints it. A cluster's consistency is now PostgreSQL's: a node that loses the database keeps its last policy until it reconnects.

Backwards compatibility
-----------------------

A Zaxonlite data directory is not read. Operators export policies (``sibuna console policies export``) from the Zig daemon and import them into the Rust daemon. Forensic history is not migrated automatically. The removed cluster options fail with a diagnostic rather than being ignored.

Acceptance criteria and implementation status
---------------------------------------------

1. The storage tests of the Zig persistent layer pass against SQLite, and against PostgreSQL when ``SIBUNA_TEST_DATABASE_URL`` names a test database.
2. A three-node test with one local PostgreSQL shows a policy inserted on one node enforced by all three within one tick, a honeypot ban on one node enforced by the others, and incident identifiers that never collide.
3. Stopping PostgreSQL does not stop request service; restarting it resumes storage without a daemon restart.
4. The console's storage invariants hold on both backends.

Status: in progress.

Open questions
--------------

- Whether to offer TLS to PostgreSQL in the default build or only behind a feature.

Review history
--------------

- 2026-10-15: drafted with the Rust port (SID 0010).
- 2026-10-15 (Rust port): the implementation in ``sibuna-storage`` differs from this specification as follows. The schema table is ``sibuna_schema(component, version, applied_at)``: the ``component`` column lets the console add its own numbered migrations without making nodes that lack the console refuse the database. Incident text is stored as UTF-8 with NUL bytes dropped and invalid sequences replaced by U+FFFD, because PostgreSQL text holds neither; Zig stored raw bytes. PostgreSQL full-text search uses a generated ``tsvector`` with the ``simple`` configuration (no stemming, like the default FTS5 tokenizer) and ``websearch_to_tsquery``, so a query string never fails to parse there, while SQLite keeps the FTS5 ``MATCH`` syntax. Under PostgreSQL a batch with honeypot bans locks the revision row first, so two nodes that ban the same addresses in different orders cannot deadlock, and the revision triggers also cover ``TRUNCATE``. Startup retries only transient connection errors, for a bounded time. The console's evidence, head and country sidecars are not written yet; the console port adds them with its own migrations.

References
----------

- SID 0005: the Zaxonlite storage architecture this record replaces.
- SID 0007: the console and its storage.
- SID 0010: the Rust port.
- sqlx 0.9 documentation; SQLite FTS5; PostgreSQL text search and ``NOTIFY``.


.. rubric:: Lifecycle event

::

   2026-10-15: prediscussion -> discussion. Specification of the storage
   replacement, drafted before the code
