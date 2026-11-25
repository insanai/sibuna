:sid-number: 0027
:sid-title: A Mapped Spill Cache for Affinity Hints
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-25
:sid-updated: 2026-11-25
:sid-discussion: No external discussion URL assigned
:sid-summary: Adds an optional disk tier under a learned source-affinity table of the edge. The tier is a fixed-size mapped file of 64 shards and four-way buckets with a frequency sketch for admission. Every slot is validated before use, so a torn or foreign file costs hints and nothing else.
:sid-labels: ["architecture","load-balancer","cache","storage"]

A Mapped Spill Cache for Affinity Hints
=======================================

Abstract
--------

SID 0015 proposes an optional disk cache for the hints that do not fit in memory. We build it. A new crate, ``sibuna-spill``, keeps fixed-size records in a file that it maps into memory. The edge keeps a small table in memory that remembers which server last served a client. That table spills into the file and is refilled from it. The file survives a restart of the daemon, and the hints with it.

A hint may be lost, stale or wrong. The edge treats it as a wish: it uses the hint only for a new flow, only when the named server exists in the pool and may serve now. No ban, no counter and no live flow depends on the file.

Motivation and scope
--------------------

A pool with ``sticky: "source"`` ranks its servers for each client by a rendezvous hash (SID 0019). The ranking needs no memory. It also has no memory: when a server joins the pool, a share of the clients moves to it, and when a server returns from an outage, its clients move back. An application that keeps a session on its server loses the session at each move.

A table that remembers the server of each client avoids those moves. The table must be bounded, and the clients of a busy edge do not fit a small table. SID 0015 answers with two tiers: a table in memory and a larger one on disk that holds what memory dropped.

We specify the file format, the admission rule, the validation of a slot, the behaviour after a crash, and the interface between the pool and the two tiers. We do not replicate hints between nodes: SID 0025 does that. We do not run the 50-million-key qualification of SID 0015.

Specification
-------------

Invariants
~~~~~~~~~~

#. Only hints enter the cache. A hint is a key of at most 24 bytes, a value of at most 16 bytes and the time at which it expires.
#. A reader gets an entry only when the slot passes every check: the lengths, the padding, the checksum bound to the file and to the slot, the key, and an expiry that lies after now and at most the longest lifetime after now.
#. A full bucket admits a candidate only when the estimated frequency of the candidate exceeds that of the victim. The victim is the entry of the bucket with the smallest estimate. A rejected candidate leaves the bucket as it was.
#. A bucket never holds more than four entries, and the file never grows.
#. A packet worker never touches the file and never waits for it. It offers work to a bounded queue and goes on. A full queue drops the work and counts it.
#. One thread owns the mapping. No reference into the mapping exists: every access copies one slot in or out.
#. The edge uses a hint only for a new flow and only when the hinted server is in the pool, is not a backup and may serve now. An active flow never consults the cache. Bans are never stored in it.
#. With ``global.spill`` absent nothing changes: no table, no thread, no file.

The file
~~~~~~~~

The file has a fixed length. It starts with two pages of 4,096 bytes and continues with the slots.

.. code-block:: text

   page 0   header (64 bytes used)
   page 1   one write counter of 32 bits for each of the 64 shards
   slots    64 shards x B buckets x 4 slots x 64 bytes

   header   magic "SIBSPILL" | version | slot length | shards | ways |
            buckets per shard | file length | salt | creation time | checksum

   slot     checksum 8 | expiry 8 | stamp 4 | key length 1 | value length 1 |
            zero 2 | key 24 | value 16

The number of buckets per shard :math:`B` is the largest that fits the configured size, so the file is at most 16 KiB shorter than the size. All numbers are little-endian. The salt is drawn at random when the file is created. The checksum of the header is a wyhash over the 56 bytes before it. The checksum of a slot is a wyhash over its other 56 bytes, seeded with the salt and the number of the slot. So a slot that was copied to another place, or into another file, fails its check.

A key belongs to one shard and one bucket. Both come from a wyhash of the key seeded with the salt: the low six bits name the shard, and the other bits are scaled to the number of buckets. A client that can choose its key cannot choose its bucket without the salt.

Opening the file
~~~~~~~~~~~~~~~~

We open the file read-write and take an exclusive advisory lock without waiting. Then we look at it.

#. The file does not exist or is empty: we create it.
#. The file does not start with the magic: we refuse to start and name the file. We never overwrite a file that is not ours.
#. The header fails its checksum, has another version, describes another geometry than the configured size, or the file has another length than its header states: we discard the file and create a new one. The note of the daemon says which.
#. Otherwise we reuse the file. We do not read the slots now. Each slot is checked when it is read.

Creation never happens in place. We write a complete new file beside the path, with every block allocated and the header last, flush it, and rename it over the path. So the path holds no file, a foreign file or a complete file, and never a half-made one.

A second process that finds the lock taken runs without the disk tier and says so. This is the case of a new process that starts while the old one drains.

Validating a slot
~~~~~~~~~~~~~~~~~

A slot is in one of four states.

- *Empty*: the expiry is zero. A new file is all zero.
- *Corrupt*: a length is out of range, the padding is not zero, the checksum does not match, or the expiry lies further ahead than the longest lifetime.
- *Expired*: the slot is whole and its expiry is not after now.
- *Live*: none of the above.

Only a live slot yields an entry, and a lookup returns it only when its key equals the key asked for. The other three states are free space. A corrupt slot is counted.

Admission
~~~~~~~~~

Each shard has a count-min sketch of four-bit counters in memory, one counter for each slot of the shard, rounded up to a power of two. A lookup and an offer both count the key in four counters. The estimate of a key is the smallest of its four counters. After ten counts for each slot of the shard, every counter is halved. This is the aging of TinyLFU.

An offer of a key first counts it. Then it looks at the four slots of the bucket.

#. A live slot holds the key: we overwrite it.
#. A slot is free: we write there.
#. Otherwise the victim is the live slot with the smallest estimate, and among equals the one written longest ago. We overwrite the victim when the estimate of the candidate exceeds the estimate of the victim. Otherwise we reject the candidate.

A key that is offered once has the estimate one. It cannot displace an entry whose estimate is one or more. A key that keeps returning can. Aging halves the estimates, so an entry that was popular long ago gives way in time. A collision in the sketch can raise an estimate and never lowers one. The sketch starts empty after a restart, so the first offers after a restart are admitted more freely. Each of these changes which hint is kept and none changes what a hint may do.

The age of a slot comes from its stamp. Each shard counts its writes in 32 bits and stamps each slot with the count. The age is the count minus the stamp modulo :math:`2^{32}`. It is exact while fewer than :math:`2^{32}` writes lie between the stamp and now. Beyond that the wrong slot may be chosen among equals, which is safe. The counter is not checksummed for the same reason: every value of it is safe.

The two tiers in the edge
~~~~~~~~~~~~~~~~~~~~~~~~~

.. graphviz::
   :caption: A worker reads and writes the table in memory. Only the storage thread touches the file.
   :alt: Workers use an atomic table in memory. A bounded queue carries offers and questions to the storage thread, which owns the mapped file and answers into the table.

   digraph tiers {
     node [shape=box];
     worker [label="Worker: choose a server"];
     ram [label="Table in memory\n(atomic entries, four-way sets)"];
     queue [label="Bounded queue"];
     disk [label="Storage thread\nmapped file"];
     shed [label="Count shed work"];
     worker -> ram [label="recall, learn"];
     ram -> queue [label="offer, ask"];
     queue -> disk;
     queue -> shed [label="full"];
     disk -> ram [label="promote"];
   }

The key of a hint is a hash of 64 bits over the name of the pool and the address of the client. The value is a tag of 31 bits of the name of the server. A hint lives for ``ttl`` and is renewed when it is used in the second half of its life.

The table in memory has four-way sets of entries. An entry is two atomic words: the key, and the tag with the expiry. The second word is stored masked with a mix of the key, so a reader that catches two halves of different writes decodes noise, and noise fails the checks of expiry and tag. Every access is an atomic load or store. Workers share the table without a lock.

When a worker chooses a server for a new flow of a pool that is sticky by source, it recalls the hint of the client.

#. A hit names a server. The pool uses it when it may serve, before the rendezvous ranking.
#. A miss asks the storage thread, and the flow goes on with the ranking. The answer of the disk fills the table for the next flow of that client.

After the choice the worker learns it.

#. The choice after a miss is *tentative*: it enters the table and is not written to disk, because the disk may hold the older and better hint. An answer of the disk replaces a tentative entry.
#. The choice after a hit is *definite*. A new or changed definite hint is offered to the disk at once. An entry that leaves the table in memory is offered once more.
#. A choice of a backup server is not learned.

So a client meets at most one flow without its hint after a restart: the flow that found the table empty.

Crash safety
~~~~~~~~~~~~

The file is written through the mapping and never forced to disk on the request path. The kernel writes dirty pages when it chooses. We flush once when the daemon stops.

A crash of the process loses nothing that was written: the pages belong to the kernel. A loss of power can leave each page old or new, and a page that was being written may be mixed. We list what the file can then hold and why each is safe.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - What is left
     - Why it is safe
   * - A slot with its old content
     - It is a valid older hint, or free space. A stale hint names a server that served this client before. The pool checks that the server may serve now.
   * - A slot that mixes old and new bytes
     - The checksum fails, the slot is free space, and the hint is lost.
   * - A removed or replaced hint that returns
     - It is a valid older hint, as in the first row.
   * - One key in two slots of a bucket
     - A lookup returns the copy with the younger stamp. An offer overwrites the first copy and clears the others. Either copy is a hint.
   * - A write counter of a shard with an old value
     - Ages are wrong for a while. Ages only order victims of equal estimate.
   * - A damaged header
     - The header is written once, before the file gets its name. If it is damaged later, the whole file is discarded at the next start.

In none of these states does the daemon trust a byte that did not pass its check, and nothing but hints depends on a byte that did.

Configuration
~~~~~~~~~~~~~

.. code-block:: text

   global: {
       spill: {
           path: "/var/lib/sibuna/hints.spill",
           size: "64m",
           memory: "1m",     // the table in memory; default 1m
           ttl: "1h",        // the life of a hint; default 1h
       },
   },

``path`` and ``size`` are required. ``size`` is from 64 KiB to 64 GiB. ``memory`` is from 4 KiB to 1 GiB and is rounded down to a power of two. ``ttl`` is from one minute to 30 days. A change of ``global.spill`` needs a restart.

The cost in memory beside the table is the sketch, half a byte to one byte for each slot, which is under 2% of the file, and the queue of 4,096 requests of 64 bytes. The pages of the file are page cache: the kernel may drop them when memory is short. The daemon reports the parts at start.

The crate
~~~~~~~~~

``sibuna-spill`` depends on ``sibuna-crypto`` for wyhash and on nothing else. ``load_cache`` opens a file in one call and returns a ``Cache`` with ``put``, ``get`` and ``remove``, which take the time as an argument. ``start_service`` moves a ``Cache`` to a storage thread behind a bounded queue and returns a ``Service`` with ``offer`` and ``ask``. The foreign calls are ``mmap`` and ``munmap`` in one module. On a platform without them the cache lives in memory and the report says that it does not persist.

Rationale and alternatives
--------------------------

We map the file because the kernel then keeps the hot pages in memory and drops cold ones under pressure, without a second cache of our own. The price is that a fault on the file becomes a signal and not an error value. We keep the mapping away from the workers for that reason and for the page faults.

We considered ``pread`` and ``pwrite`` on the storage thread. They return errors where the mapping raises a signal, and they cost a system call for each slot. SID 0015 fixed the mapping, and the measurement below shows what it buys. The interface of the crate would allow the change.

We considered reading the mapping from the workers, each owning some shards. A client reaches any worker, so a shard would still be read from many threads, and a page fault would stop a worker. One owner and a queue keep the workers free of the disk.

We considered a write-ahead log or a database. Hints need neither order nor durability. A checksum on each slot is enough to refuse a torn write.

We considered scanning the file at start to warm the table in memory. The scan would read the whole file from disk before the node is useful. We check slots as they are read.

We considered keeping the sketch in the file. A sketch is rebuilt by traffic within minutes, and a sketch from before a restart describes old traffic.

We considered spilling only on eviction from memory, as the figure of SID 0015 shows. A restart would then lose exactly the hints in use. We write a definite hint through when it is new or changes.

Security and operational considerations
---------------------------------------

The file is created with mode 0600. Whoever can write the file can place hints and steer clients among the servers of their pool that may serve. They cannot reach a server outside the pool, a drained server or a server that is down, and they cannot change a ban. Whoever can truncate the file while the daemon runs can stop the daemon: an access beyond the end of a mapped file raises a signal. A read error of the disk does the same. Keep the file on a local disk in a directory of the daemon.

Every block is allocated at creation, so a full disk is found at start and not at the first write. A file system that copies on write can still run out of space later.

The checksum is not a signature. It detects accidents and not an attacker who knows the format.

A hint is local to its node. In a mesh, two nodes may hold different hints for one client, where the rendezvous ranking would agree. SID 0025 shares the entries.

A client address is stored only as a hash with a fixed seed. The file names no address.

Backwards compatibility
-----------------------

A configuration without ``global.spill`` behaves as before. With it, a pool that is sticky by source prefers the server that last served a client to the server the ranking names. Pools with other settings are untouched. The file format has a version, and a file of another version is discarded.

Acceptance criteria and implementation status
---------------------------------------------

Pending the implementation.

Known gaps
----------

Pending the implementation.

Open questions
--------------

#. Should the first flow after a restart wait a bounded time for the disk, so that it also finds its hint?
#. Should the checksum be keyed with a secret of the node, so that a file written elsewhere is refused?

Review history
--------------

- 2026-11-25. Initial draft. The review of the draft found six faults. A hint offered after a miss could overwrite the better hint on disk, so the choice after a miss became tentative. A file of zeros or of another program would have been overwritten, so a file without the magic is now refused. Creation in place could leave a half-made file under the final name, so a new file is built beside the path and renamed. A sparse file would fault on a full disk, so every block is written at creation. Two processes could map one file during a handoff, so the file is locked. A reference into the mapping would make a foreign write undefined behaviour, so every access copies a slot.

References
----------

- SID 0015, Distributed Edge Load Balancer, section "Bounded memory and disk state".
- SID 0019, Traffic Policy, for sticky sessions.
- SID 0025, shared affinity across the mesh.
- Einziger, Friedman and Manes, *TinyLFU: A Highly Efficient Cache Admission Policy* (2017).
