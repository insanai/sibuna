:sid-number: 0027
:sid-title: A Mapped Spill Cache for Affinity Hints
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-11-25
:sid-updated: 2026-11-25
:sid-discussion: No external discussion URL assigned
:sid-summary: Adds an optional disk tier under the learned sticky table of the edge (SID 0025). The tier is a fixed-size mapped file of 64 shards and four-way buckets with a frequency sketch for admission. Every slot is validated before use, so a torn or foreign file costs hints and nothing else.
:sid-labels: ["architecture","load-balancer","cache","storage"]

A Mapped Spill Cache for Affinity Hints
=======================================

Abstract
--------

SID 0015 proposes an optional disk cache for the hints that do not fit in memory. We build it. A new crate, ``sibuna-spill``, keeps fixed-size records in a file that it maps into memory. The learned sticky table of SID 0025 remembers in memory which server serves a client. With the cache under it, every choice of the table is offered to the file, and a lookup that finds nothing in memory asks the file. The file survives a restart of the daemon, and the hints with it.

A hint may be lost, stale or wrong. The edge treats it as a wish: it uses the hint only for a new flow, only when the named server exists in the pool and may serve now. No ban, no counter and no live flow depends on the file.

Motivation and scope
--------------------

A pool with ``sticky: "table"`` balances the first flow of a client and remembers the server (SID 0025). The table is in memory and has a fixed number of slots. So it forgets twice: when more clients come than it has slots, and when the daemon restarts. An application that keeps a session on its server loses the session each time.

SID 0015 answers with two tiers: a table in memory and a larger one on disk. SID 0025 left the place for it: the pool and the mesh reach the table through the trait ``AffinityStore``, and a store on disk can stand behind it.

We specify the file format, the admission rule, the validation of a slot, the behaviour after a crash, and the store that joins the two tiers. We do not replicate entries between nodes: SID 0025 does that, on the table in memory. The measurements below distinguish the disk admission workload from the client-visible result of both tiers.

An earlier state of this branch built a table of its own for ``sticky: "source"``, because the sticky table did not exist yet. It is removed. "Review history" keeps what its reviews found.

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
#. The edge uses a hint only as an entry of the sticky table, and the pool uses such an entry only for a new flow and only when the server it names is in the pool and may serve now (SID 0025). An active flow never consults the cache. Bans are never stored in it.
#. With the ``spill`` section absent nothing changes: no table, no thread, no file.

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

We open the file read-write and take an exclusive advisory lock without waiting. Then we check that the path still names the file we locked: another process may have renamed a new file over the path meanwhile, and then the cache is in use. Then we look at the file.

#. The file does not exist or is empty: we create it.
#. The file does not start with the magic: we refuse to start and name the file. We never overwrite a file that is not ours.
#. The header fails its checksum, has another version, describes another geometry than the configured size, or the file has another length than its header states: we discard the file and create a new one. The note of the daemon says which.
#. Otherwise we reuse the file. We do not read the slots now. Each slot is checked when it is read.

We create a private sibling with a fresh name and exclusive creation. We allocate the blocks, write the header last, flush the file and rename it over the destination while holding both locks. On an ordinary error we remove our temporary file. A process killed during construction can leave that file behind. We preserve pre-existing siblings.

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

Each shard has a count-min sketch of four-bit counters in memory, eight counters for each slot of the shard, rounded down to a power of two. A lookup and an offer both count the key in four counters, and a count raises only the counters that equal the smallest of the four. The estimate of a key is the smallest of its four counters. After four counts for each slot of the shard, every counter is halved. This is the aging of TinyLFU.

An offer of a key first counts it. Then it looks at the four slots of the bucket.

#. A live slot holds the key: we overwrite it.
#. A slot is free: we write there.
#. Otherwise the victim is the live slot with the smallest estimate, and among equals the one written longest ago. We overwrite the victim when the estimate of the candidate exceeds the estimate of the victim. Otherwise we reject the candidate.

A *guess* is a weaker offer, ``put_new``. It leaves a live hint of the same key as it is, it takes a free slot only, and it does not count in the sketch. So no number of guesses displaces an entry.

A key that is offered once has the estimate one. It cannot displace an entry whose estimate is one or more. A key that keeps returning can. Aging halves the estimates, so an entry that was popular long ago gives way in time. A collision in the sketch can raise an estimate and never lowers one. The sketch starts empty after a restart, so the first offers after a restart are admitted more freely. Each of these changes which hint is kept and none changes what a hint may do.

The age of a slot comes from its stamp. Each shard counts its writes in 32 bits and stamps each slot with the count. The age is the count minus the stamp modulo :math:`2^{32}`. It is exact while fewer than :math:`2^{32}` writes lie between the stamp and now. Beyond that the wrong slot may be chosen among equals, which is safe. The counter is not checksummed for the same reason: every value of it is safe.

The two tiers in the edge
~~~~~~~~~~~~~~~~~~~~~~~~~

.. graphviz:: ../diagrams/tiers.dot
   :caption: A worker reads and writes the table in memory. Only the storage thread touches the file.
   :alt: Workers and the mesh thread use the store. The store holds the table in memory. A bounded queue carries offers and questions to the storage thread, which owns the mapped file and answers into the table.

With the ``spill`` section the store of the edge is a ``SpillStore``. It implements ``AffinityStore`` with the table of SID 0025 in front, so the pool, the mesh thread and ``show affinity`` work as before. The edge makes it the store with ``ClusterState::use_store`` before it builds its first pool.

The key of a hint is the key of the table: 16 bytes of a keyed hash over the pool and the client. The value is the entry of the table: the hash of the server's name and the Unix millisecond at which the choice ends. The hint expires on disk at that end, rounded up to a second. The disk refuses an expiry that lies more than a day and a minute ahead, because the ``ttl`` of a table is at most a day.

``find`` reads the table in memory. When it finds nothing, it asks the storage thread and returns nothing: the flow goes on with the balanced choice. The storage thread answers every question it serves. A hint fills the table.

``keep`` merges an entry into the table as before, and offers what was stored to the disk.

#. An entry for a key that memory does not hold is a *guess*. The lookup found nothing, so the disk may hold the older choice. The disk takes a guess only into a free slot and only when it holds no hint for the key.
#. An entry for a key that memory holds is a change of server or a renewal. It replaces the hint on disk and competes for a full bucket. The pool renews an entry when a quarter of its life has passed, so a client has to return over time, or move, to displace another. Clients that come once displace nothing.

The disk is asked only after memory held nothing. So when the answer finds another server in the table, that server is a guess, and the hint of the disk replaces it. The table merges by the later end, so the hint gets an end one millisecond past the guess. It then wins here, and on every node that the mesh tells.

The answer can also come before the guess is stored, in the time one reservation takes. A small array of marks decides who stores first. A lookup that asks sets the mark of its key. The storage thread stores its hint under the mark and leaves word, and ``keep`` then drops a guess that names another server. When ``keep`` comes first, it holds the mark while it stores, and the storage thread waits those two steps. While the storage thread stores, ``keep`` stores nothing and reports ``Busy``, which the pool counts as not written. Two keys can share a mark. Then the later lookup has it, and the earlier guess may win over the hint of the disk. That costs one hint and nothing else.

So after a restart a client goes without its hint only until the disk has answered. That is one flow, or more when they come at once.

``scan``, ``slot_count`` and ``evicted_count`` are those of the table in memory. The mesh walks memory only. What a node hears from a peer goes through ``keep`` and is offered to the file like any other entry.

Crash safety
~~~~~~~~~~~~

The file is written through the mapping and never forced to disk on the request path. The kernel writes dirty pages when it chooses. We flush once when the daemon stops.

If only the process exits, the kernel retains completed writes to shared pages. Queued work can be lost, and a slot being written can be incomplete. A loss of power can leave each page old or new, and a page that was being written may be mixed. We list what the file can then hold and why each is safe.

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

   spill: {
       path: "/var/lib/sibuna/hints.spill",
       size: "64m",
   },

The section stands at the top of the file, beside ``global``. Both members are required. ``size`` is from 64 KiB to 64 GiB. A change of the section needs a restart. The table in memory keeps its own setting, ``global.sticky_entries``, and the life of a choice is the ``ttl`` of its pool (SID 0025).

The reported table capacity includes rounding up to a power of two. The cost in memory beside the table is the sketch, two to four bytes for each slot, which is 3% to 6% of the file, the queue of 4,096 requests and 32 KiB of marks. The pages of the file are page cache. The kernel may drop them when memory is short, but they count as memory of the process, and "Known gaps" says what that means under a memory limit. The daemon reports the parts at start.

The section has an effect only on pools with ``sticky: "table"``. With the section the table in memory is made at start, also when no pool uses it.

The crate
~~~~~~~~~

``sibuna-spill`` depends on ``sibuna-crypto`` for wyhash and on nothing else. ``load_cache`` opens a file in one call and returns a ``Cache`` with ``put``, ``get`` and ``remove``, which take the time as an argument. ``put_new`` is a ``put`` that leaves a live hint of the same key alone. ``start_service`` moves a ``Cache`` to a storage thread behind a bounded queue and returns a ``Service``. The ``Service`` owns the thread: dropping it stops the thread, flushes the file and releases the lock. A ``Handle`` is a cheap copy of the sending side with ``offer``, ``offer_new`` and ``ask``. The function given to ``start_service`` hears the answer to every question that was served, a hint or ``None``. The split exists because the edge keeps snapshots of its routes in each worker thread, and a snapshot must not keep the file open after the edge is gone. The foreign calls are ``mmap`` and ``munmap`` in one module. On a platform without them the cache lives in memory and the report says that it does not persist.

Rationale and alternatives
--------------------------

We map the file because the kernel then keeps the hot pages in memory and drops cold ones under pressure, without a second cache of our own. The price is that a fault on the file becomes a signal and not an error value. We keep the mapping away from the workers for that reason and for the page faults.

We considered ``pread`` and ``pwrite`` on the storage thread. They return errors where the mapping raises a signal, and they cost a system call for each slot. SID 0015 fixed the mapping, and the measurement below shows what it buys. The interface of the crate would allow the change.

We considered reading the mapping from the workers, each owning some shards. A client reaches any worker, so a shard would still be read from many threads, and a page fault would stop a worker. One owner and a queue keep the workers free of the disk.

We considered a write-ahead log or a database. Hints need neither order nor durability. A checksum on each slot is enough to refuse a torn write.

We considered scanning the file at start to warm the table in memory. The scan would read the whole file from disk before the node is useful. We check slots as they are read.

We considered keeping the sketch in the file. A sketch is rebuilt by traffic within minutes, and a sketch from before a restart describes old traffic.

We considered spilling only on eviction from memory, as the figure of SID 0015 shows. A restart would then lose exactly the hints in use. We offer every entry when it is stored.

Security and operational considerations
---------------------------------------

The file is created with mode 0600. Whoever can write the file can place hints and steer clients among the servers of their pool that may serve. They cannot reach a server outside the pool, a drained server or a server that is down, and they cannot change a ban. Whoever can truncate the file while the daemon runs can stop the daemon: an access beyond the end of a mapped file raises a signal. A read error of the disk does the same. Keep the file on a local disk in a directory of the daemon.

Every block is written at creation, so on a file system that stores what is written a full disk is found at start and not at the first write. A file system that compresses or copies on write does not keep that promise. On ZFS with compression a new file of 16,769,024 bytes took 141 KiB, because zeros are not stored. Such a file system can run out of space later, and the write through the mapping then raises a signal.

In a container the cache needs no privilege, no capability and no kernel setting: it maps, locks and renames an ordinary file. Four settings decide whether it is useful there. The path must lie on a volume that the user of the daemon can write, because the image runs with a read-only root file system. The volume must outlive the container, or the file is empty after each replacement; a ``tmpfs`` keeps the file in memory and is never right. A memory limit must lie above the size of the file plus the memory of the daemon, as the measurement shows. Each replica needs a file of its own, because the file is locked and the second user runs in memory alone. The book describes these settings for Docker and Kubernetes.

The checksum is not a signature. It detects accidents and not an attacker who knows the format.

A hint is local to its node. In a mesh, two nodes may hold different hints for one client, where the rendezvous ranking would agree. SID 0025 shares the entries.

A client address is stored only as a hash with a fixed seed. The file names no address.

Backwards compatibility
-----------------------

A configuration without the ``spill`` section behaves as before. With it, the sticky table of SID 0025 has a file under it, and nothing else changes. An earlier state of this branch read ``memory`` and ``ttl`` in the section. They are gone and are refused as unknown members. No release had them. The file format has a version, and a file of another version is discarded.

Measurement
-----------

The machine has 32 hardware threads, 121 GiB of memory, Linux 7.0 and ZFS. The builds are release builds. The file has 256 MiB, which is 4,194,048 slots. Resident memory is read from ``/proc/self/status``: ``RssAnon`` for memory of our own and ``RssFile`` for mapped pages.

The first program is ``cargo run --release -p sibuna-spill --example spill_measure -- 256 /var/tmp``. It calls the cache from one thread, without the queue. We ran it four times.

.. list-table::
   :header-rows: 1
   :widths: 44 56

   * - Phase
     - Result
   * - Offer 8,388,096 distinct keys, twice the slots
     - 2.1 to 2.9 million offers in a second. 4.13 million were stored in free slots, 1.33 million replaced a victim and 2.92 million were rejected.
   * - A working set of 1,048,512 keys, each read or offered four times
     - 2.7 to 3.6 million operations in a second. 99.6% of the set is held. The rest found its bucket full of its own kind.
   * - A flood of 16,776,192 new keys, with three uses of the working set between two of them
     - 67.1 million operations at 1.5 to 3.4 million in a second. 1,043,849 to 1,044,093 keys of the working set are held at the end, a net loss of 10 to 15. These older runs counted occupancy without comparing individual keys.
   * - Close, map again, read the working set
     - Every hint that was held is found. 3.5 to 3.7 million lookups in a second, with the pages in the page cache.
   * - Four threads offer through the queue without a pause
     - The calls return at 35 to 57 million in a second. The queue of 4,096 sheds 98% to 99% of them. No caller waits.
   * - Resident memory
     - 8.6 MiB of our own, of which 8 MiB are the sketch. 257.5 MiB of mapped pages, which is the whole file. After the file is closed 1.8 MiB remain.

The second program is the ignored test ``measure_two_tiers`` of ``sibuna-lb``, run with ``SIBUNA_SPILL_DIR=/var/tmp cargo test --release -p sibuna-lb --lib measure_two_tiers -- --ignored --nocapture``. It drives the store behind ``AffinityStore`` as a pool does: a lookup, and a choice when the lookup found nothing. The table in memory has 65,536 slots. There are 2,000,000 clients, thirty times the table. We ran it twice.

.. list-table::
   :header-rows: 1
   :widths: 44 56

   * - Phase
     - Result
   * - The first flow of every client: a miss, a choice, a guess for the disk
     - 1.6 and 1.8 million flows in a second, with a wait for the storage thread after every 1,000. Nothing is shed.
   * - Every client returns with two lookups
     - 49,152 clients are still in memory at the first lookup. 1,939,963 and 1,940,215 of 2,000,000 clients, 97.0%, have their choice at the second lookup. 1,933,818 guesses were stored, so 3.3% found their bucket full: the file is half full, and a bucket of four overflows that often.
   * - Four threads, 16,000 clients that fit in memory
     - 82 million flows in a second for all four threads together. This is the table of SID 0025 alone.
   * - Four threads, all clients, without a pause
     - 4.5 and 6.4 million in a second. Nearly every one misses, and the queue sheds three quarters of the questions.
   * - Resident memory
     - 11.4 MiB of our own. 258.9 MiB of mapped pages.

We also ran the first program in a control group with a memory limit of 96 MiB and no swap, ``systemd-run --user --scope -p MemoryMax=96M -p MemorySwapMax=0``. The kernel killed it for lack of memory in three runs. In two of them the creation of the file alone took 12 and 130 seconds. A fourth run did not finish creating the file in 110 seconds and we stopped it. So on this machine the kernel did not take the pages of the file back fast enough to keep the process inside a limit below the size of the file. The file system is ZFS, which has a cache of its own. We had no other file system to compare.

We repeated this on a second host, an unprivileged LXC container on ZFS with 16 processors. Without a limit the flood ran at 3.3 million operations in a second. With a limit of 320 MiB the program ran at the same rate, the control group counted no event at its limit, and its peak was 281,595,904 bytes: the file of 268,427,264 bytes and 13 MiB more. A file of 64 MiB under a limit of 96 MiB ran at full rate too. With the file of 256 MiB under a limit of 96 MiB the kernel did not kill the program. It reached the limit 410,479 times, and the first phase, which takes 3 seconds without a limit, had not ended after 17 minutes when we stopped it. Under these limits we observed a kill on one host and prolonged storage delay on the other. While the process survives, workers can continue with the balanced choice when the disk queue fills.

We also ran the daemon itself in that container, on two hosts as a mesh of two nodes, each with a file of 16 MiB and eight workers. After a restart of both nodes the first flow of 300 clients found another server for 191 of them, and the second flow found the remembered server for all 300. The counters said 300 lookups on disk, 300 hits and 191 choices preferred over the tentative one.

The fifty-million-key experiment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On 2026-11-25 we ran release builds on two x86-64 Linux 7.0 hosts with 16 CPUs, 12 GiB of RAM and ZFS storage. We used a fresh 512 MiB arena for each run. Each workload introduced 50,000,000 distinct candidates and accessed the working set three times per candidate. The times below exclude compilation.

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - Measurement
     - Mapped cache, host 19
     - Edge affinity store, host 20
   * - Flood / whole experiment
     - 83.15 s / 106.05 s
     - 349.05 s / 352.34 s
   * - Original choices present after the flood
     - 2,080,855 of 2,088,051 seeded keys (99.655%)
     - 244,157 of 260,178 seeded clients (93.842%)
   * - Process peak RSS
     - 544,376 KiB
     - 583,596 KiB
   * - Minor / major page faults, whole process
     - 1,934,254 / 131,132
     - 2,499,062 / 131,270

The direct cache workload calls the mapping synchronously. When a hot key misses during the flood, we offer its original value again. We measure which members of the seeded cohort are present at the end. All 2,088,026 hot keys present at close were found on reopen, including keys absent at the seed measurement. The final, separate four-producer queue test accepted 76,504 offers and shed 8,311,848.

The edge workload calls the production affinity store from one caller while a storage thread serves its queue. The table has 1,048,576 slots (40 MiB). The sketch, queue, marks and scratch space bring the cache structures to about 56.3 MiB within the 64 MiB RAM budget. The 536,862,720-byte mapping also contributes to RSS. We offered 262,144 clients the original server. A miss during the flood assigns a different server. The harness calls the store directly and omits the pool's periodic renewal of live entries. We count a seeded client only when its first lookup after the flood returns the original server. A subsequent disk promotion cannot repair that first decision. The flood queued 136,980,333 storage operations and shed 1,683,064. The sampled p99 for a group of four affinity decisions was 14,668 ns across 12,216 samples. These calls exclude network and HTTP processing. Both retention measurements fell below the proposed 99.9%.

We also measured two storage failure modes on host 19 with four million distinct candidates and twelve million hot accesses per mode. We held the storage thread inside its first lookup callback throughout one flood. It accepted 4,097 operations including that lookup, shed 11,385,334 and completed the flood in 2.49 s. The caller's four-decision p99 was 1,002 ns. We then opened the same file while its owner held the lock. The memory-only store queued nothing and finished in 2.39 s with a p99 of 942 ns. Each p99 used 978 samples. A physical I/O error on a live mapping remains a separate failure mode.

We can repeat these measurements on a local volume with at least 512 MiB of free space. We give each invocation a fresh file. For process RSS and faults we measure the built executable directly.

.. code-block:: sh

   cargo run --release --locked -p sibuna-spill --example spill_measure -- 512 /var/tmp 0 50000000
   SIBUNA_SPILL_DIR=/var/tmp cargo test --release --locked -p sibuna-lb --lib measure_fifty_million_candidates -- --ignored --nocapture
   SIBUNA_SPILL_DIR=/var/tmp cargo test --release --locked -p sibuna-lb --lib measure_storage_unavailability -- --ignored --nocapture

Testing a 99% first-lookup threshold
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This check asks what fraction of clients whose original server we found at seeding still return that server on the first lookup after the flood. We divide the number retained by the number seeded and check the exact counts against 99%. We also report how many clients we offered at seeding. The loss of a disk hint, a lookup shed from a full queue and a disk answer that arrives after the first decision can all affect the result. The caller uses the same production affinity store and forced fallback as the preceding two-tier experiment. The check excludes network transfers and the pool's periodic renewals.

Each run starts with a fresh mapped arena of 512 MiB and the same key permutation. An unpaced caller offers work as fast as it can. A paced caller offers up to 100,000 distinct cold candidates per second in batches of 128, with three hot accesses per candidate. Each run introduces 50 million distinct candidates. We reject a measurement if the original entries could have expired during the run.

.. list-table::
   :header-rows: 1

   * - Host
     - Hot clients offered
     - RAM table
     - Cold rate cap
     - Retained / seeded
     - Queue operations shed
     - Flood time
   * - 19
     - 16,384
     - 40 MiB
     - unpaced
     - 5,694/16,384 (34.753%)
     - 53,488,964
     - 19.52 s
   * - 19
     - 16,384
     - 40 MiB
     - 100,000/s
     - 16,335/16,384 (99.701%)
     - 248,882
     - 529.57 s
   * - 19
     - 16,384
     - 40 MiB
     - 100,000/s
     - 16,335/16,384 (99.701%)
     - 134,460
     - 528.21 s
   * - 20
     - 262,144
     - 40 MiB
     - unpaced
     - 244,166/260,178 (93.846%)
     - 942,218
     - 348.12 s
   * - 20
     - 262,144
     - 40 MiB
     - 100,000/s
     - 244,178/260,178 (93.850%)
     - 883,033
     - 524.84 s
   * - 20
     - 262,144
     - 160 MiB
     - unpaced
     - 259,199/262,136 (98.880%)
     - 844,537
     - 344.18 s
   * - 21
     - 262,144
     - 40 MiB
     - 100,000/s
     - 244,163/260,178 (93.845%)
     - 0
     - 522.67 s
   * - 21
     - 262,144
     - 160 MiB
     - 100,000/s
     - 259,200/262,136 (98.880%)
     - 0
     - 522.75 s

Host 21 had 32 CPUs and about 121 GiB of RAM. On that host we changed only the configured table capacity between the two paced runs. The 40 MiB table and spill structures used about 56.3 MiB before mapped pages. With the maximum supported 4,194,304 slots they used about 176.3 MiB, above the original 64 MiB budget. Neither run shed storage work. The larger table preserved 259,200 first choices. Reaching 99% required 259,515. A RAM miss returns immediately, even when the storage thread can later recover the hint.

With 16,384 hot clients and the rate cap, host 19 passed 99% twice. Both runs preserved 16,335 original choices from separate fresh files. At full producer speed the same host and working set retained 34.753% and shed more than 53 million storage operations. A retention claim must specify the working set, the configured table capacity and the offered rate.

We can run the qualification with the original 262,144-client working set. A result below 99% makes the command exit unsuccessfully. Omitting the rate gives the unpaced run.

.. code-block:: sh

   SIBUNA_SPILL_DIR=/var/tmp SIBUNA_AFFINITY_HOT_KEYS=262144 \
     SIBUNA_AFFINITY_TABLE_SLOTS=1048576 SIBUNA_AFFINITY_COLD_PER_SECOND=100000 \
     cargo test --release --locked -p sibuna-lb --lib qualify_ninety_nine_percent_affinity -- --ignored --nocapture

Acceptance criteria and implementation status
---------------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 6 40 54

   * - #
     - Criterion
     - Status
   * - 1
     - A reusable crate keeps hints in a mapped file of fixed size, with 64 shards and buckets of four.
     - Met. ``crates/spill`` depends on ``sibuna-crypto`` only. ``the_geometry_fits_the_size_and_places_every_hash_inside`` and ``the_budget_names_every_part`` check the layout.
   * - 2
     - A full bucket admits a candidate only when its estimate exceeds that of the victim. The sketch ages.
     - Met. ``a_full_bucket_rejects_a_key_seen_once_and_admits_a_key_that_returns``, ``the_victim_is_the_least_frequent_entry_not_the_oldest``, ``aging_lets_a_new_key_displace_entries_that_were_popular_long_ago``, ``a_working_set_in_use_is_kept_under_a_flood_of_new_keys`` and the tests of ``sketch.rs``. The model proves the rule for exact estimates.
   * - 3
     - Ages are right when the write counter wraps.
     - Met. ``ages_are_right_across_a_wrap_of_the_write_counter``, and ``age_exact`` in the model.
   * - 4
     - A damaged header, another version, a truncated file and a file of another size are detected and the file is treated as empty.
     - Met. ``a_damaged_header_discards_the_whole_file``, ``another_version_discards_the_whole_file``, ``a_truncated_or_grown_file_is_discarded``, ``a_file_of_another_size_is_discarded``, ``a_header_is_read_back_and_every_damage_is_named``.
   * - 5
     - A damaged or torn slot is not trusted and costs only its own hint.
     - Met. ``every_flipped_bit_of_a_slot_is_found`` flips each of the 512 bits. ``a_slot_that_was_half_written_is_not_trusted``, ``damaged_slots_cost_their_hints_and_no_others``, ``a_slot_copied_to_another_place_is_not_trusted``.
   * - 6
     - A hostile file causes no panic.
     - Met for what we tried: ``arbitrary_bytes_never_panic_and_are_almost_never_live`` and ``a_cache_of_noise_yields_nothing_and_does_not_panic`` fill slots and a whole file with noise. There is no fuzzer run.
   * - 7
     - A file that is not ours is never overwritten, and two processes never map one file.
     - Met. ``a_file_that_is_not_a_cache_is_refused_and_left_alone``, ``a_second_opener_finds_the_cache_in_use``, ``creating_the_cache_preserves_an_existing_sibling_and_its_target``, and through the binary ``a_file_that_is_not_a_cache_stops_the_daemon_with_a_diagnostic``. ``a_lock_on_a_file_that_lost_its_name_does_not_open_the_cache`` checks the comparison of names. No test runs two processes through the race itself.
   * - 8
     - A worker never waits for the disk.
     - Met. ``a_full_queue_sheds_work_and_never_blocks``. The table in memory is that of SID 0025, and the marks are single atomic words.
   * - 8a
     - A guess does not overwrite what the disk knows, and clients that come once displace no hint on disk.
     - Met for one worker. ``a_guess_made_while_the_disk_is_asked_gives_way_to_what_the_disk_knows`` lets the answer come before and after the guess. ``a_flood_of_clients_seen_once_displaces_no_hint_on_disk`` has 26 clients for every slot. ``a_guess_takes_a_free_slot_only_however_often_it_was_seen``. No test drives the marks from several workers at once.
   * - 9
     - The edge uses a hint only for a server that may serve, and a wrong hint changes only the choice for a new flow.
     - Met. ``a_damaged_file_costs_the_hints_and_the_edge_serves_on``. The check that a server may serve is that of the pool of SID 0025, unchanged.
   * - 10
     - Hints survive a restart of the daemon.
     - Met. ``cmd/sibuna/tests/edge_spill.rs`` serves 40 clients, kills the daemon with SIGKILL and starts another on the same file with a third server of weight 200. After one request each, every client is with its old server. Without the file more than 30 of 40 go to the heavy server.
   * - 11
     - The tier is off by default and has no cost then.
     - Met. ``the_spill_section_is_off_by_default_and_has_bounds``, ``the_spill_section_changes_only_with_a_restart_and_is_off_without_it``. Without the section the store is the table of SID 0025 and no code of this SID runs.
   * - 12
     - The cost in memory is reported and bounded.
     - Met. The daemon notes ``EDGE015`` with slots, bytes on disk and bytes of memory, and ``show info`` repeats them. The measurement above confirms the numbers.
   * - 13
     - The admission rule and the validation of a slot are modelled.
     - Met. ``docs/sid/assets/spill-cache.lean`` checks with Lean 4.19.0 and uses the core library only.
   * - 14
     - A platform without ``mmap`` builds and runs.
     - Partly. The fallback is a cache in memory that reports ``persistent: false``; ``a_cache_in_memory_works_and_says_that_it_does_not_persist`` runs it on Linux. We did not build for another platform.

Deviations from SID 0015
------------------------

#. SID 0015 lets each worker own some shards. Here one storage thread owns all 64, and the workers reach it through a queue. The section on alternatives says why.
#. SID 0015 spills an entry when it leaves memory. Here every entry is offered when it is stored, so that a restart finds the entries in use. Nothing is offered at eviction: the table of SID 0025 does not say what it evicts.
#. ``size`` is the size of the file. The sketch, the marks and the queue come on top and are reported, and the table in memory has its own setting. SID 0015 asks for a budget that counts them. The report counts them, but one number does not bound them all.
#. The sketch takes 2 to 4 bytes for each slot, 3% to 6% of the file, not the smaller share a sketch of one counter for each slot would take. The smaller sketch kept only 77% of a working set under a flood.
#. Only the sticky table spills. SID 0015 also names other stick tables, and this version has none.

Known gaps
----------

#. The pages of the file count as memory of the process. Under a memory limit below the size of the file, the measurement program was killed. We did not find out whether another file system behaves better. The operator has to set a limit above the file.
#. A truncation of the file by another process, or a read error of the disk, raises a signal that ends the daemon. Reading and writing with system calls would turn both into errors.
#. The store behind ``AffinityStore`` was written after the merge with SID 0025 and was reviewed by its author only. The second reader saw the earlier table and the crate, not this store.
#. No test drives the marks from several workers and the storage thread at once. The argument for them is in the text above and is not modelled.
#. Two keys that share a mark, or a lookup whose choice is never stored, leave a mark that is wrong for a later call. The cost is one guess that wins over the hint of the disk, or one change of server that is not stored and is stored at the next flow.
#. An entry that a node hears from a peer is treated like a local one: as a guess when memory does not hold the key, and as a change when it does. So a peer can replace a hint on disk, as SID 0025 lets it replace the entry in memory.
#. The first flow of a client after a restart, or after its entry left memory, goes without the hint. In the measurement 3.0% of the clients were also without it at the second lookup, because their bucket on disk was full when they came.
#. A hint enters a full bucket only by a renewal or a move. A new client whose bucket is full has no hint on disk until it is still in memory after a quarter of its ``ttl``.
#. One storage thread serves all workers. It handles about one to three million operations in a second. Beyond that the queue sheds, which costs hints. We measure the latency of the caller separately.
#. A healthy slot whose expiry lies more than a day and a minute ahead is treated as corrupt, cleared and counted in ``spill_disk_corrupt``. This happens to recent hints after the clock stepped back by more than a minute.
#. A file system that compresses or copies on write does not reserve the blocks that we write at creation. When it fills up later, a write through the mapping raises a signal that ends the daemon. We do not detect such a file system and print no warning.
#. The cache has not been run under Docker or Kubernetes. It ran in an unprivileged LXC container, with and without a memory limit of a control group.
#. A file that we reuse is trusted to have its blocks. A sparse file of the right length with a valid header, as a backup tool may restore it, raises a signal at the first write to a hole on a full disk.
#. A reused file keeps its permission bits. Only a file we create gets mode 0600.
#. The daemon opens the file, and replaces a damaged one, before it binds its listeners. A start that then fails has already replaced the file.
#. A second process on the same file runs with the table in memory only until its next start. So during the replacement of the binary the new process writes nothing to the file.
#. The send to the queue is ``try_send`` of the standard library. It never waits for the disk. We did not verify that it takes no lock inside when the storage thread sleeps, so "no lock on the request path" is not proven for this one call.
#. The sketch of a file of 64 GiB takes 2 GiB of memory, and aging walks the 32 MiB of one shard on the storage thread. Stopping the daemon waits for the flush of the file.
#. The checksum is not keyed. A file written by someone who knows the format is trusted as hints.
#. The model proves the admission rule for exact frequencies and one bucket, and the validation of a slot. It does not model the sketch collisions, the guess, the two tiers or concurrency.
#. There is no test of a loss of power. The table of crash safety is an argument over the states a page can be left in, and the tests write those states by hand.
#. A measured retention fraction depends on the working set, the traffic mix, the admission rule and the storage device. The capacity measurements above do not establish a retention guarantee across workloads.
#. A ``spill`` section without a pool that is sticky by a table costs the file and the memory and does nothing. ``sibuna check`` does not warn.

Open questions
--------------

#. Should the first flow after a restart wait a bounded time for the disk, so that it also finds its hint?
#. Should the checksum be keyed with a secret of the node, so that a file written elsewhere is refused?

Review history
--------------

- 2026-11-25. Review for containers, with measurements on a second host. The claim that a full disk is found at start is false on a compressing file system and was narrowed. The memory limit was measured again: no kill on this host, but the storage thread stops being useful. The settings a container needs are stated here and in the book. Two known gaps were added.
- 2026-11-25. Merge with SID 0025. The sticky table of SID 0025 arrived on ``main`` with the trait ``AffinityStore``. The table of hints that this branch had built for ``sticky: "source"`` was removed, with its hook in the pool, and the cache went under the sticky table as ``SpillStore``. The members ``memory`` and ``ttl`` of the section went with it. The tentative bit of the old table had no place in an entry of SID 0025, so the store tells a guess by whether memory holds the key, and the answer of the disk replaces a guess by an end one millisecond later. The first version of the store lost the hint of the disk for about one client in three hundred of the restart test: the answer and the guess were stored at the same moment and the guess had the later end. The marks close that window. The author reviewed this store. No second reader did.
- 2026-11-25. Review of the implementation by a second reader who had not written it. It found no fault of memory safety and no way for a hint to choose a server that may not serve. It found ten points. Fixed: a second flow turned a guess into a definite hint before the disk had answered and overwrote the hint on disk, so the storage thread now answers every question and a guess stays tentative until then. Clients seen once were counted twice and displaced the hints in use, so a guess now takes a free slot only and does not count, and the offer at eviction is a guess. A lock could be taken on a file that had lost its name to a rename, so the name is compared after the lock. The file under construction was opened through a link and left behind on failure, so it is created anew and removed on failure. The wrong number in the comment on torn entries was corrected. Recorded under "Known gaps" and not fixed: the table in memory without admission and with a public hash, the sparse reused file, the healthy slots counted as corrupt after a lower ``ttl`` or a clock step, the busy file that disables the disk tier until the next start, the permission bits of a reused file, the cost of a large sketch, and the unverified inside of ``try_send``.
- 2026-11-25. Review of the code by its author before that. A retry was learned as the new server of a client, so one failed request moved the client for good: a retry is no longer learned. A choice after a miss was never written to disk, so a client with flows far apart never got a hint saved: it is offered as a guess. The storage thread reads the clock once for a batch, so a hint stamped by a worker a second later was judged corrupt: the disk tier allows a minute of slack. The note ``EDGE015`` came before the line ``listeners ready`` and broke harnesses that read the first line: it follows now.
- 2026-11-25. Initial draft. The review of the draft found six faults. A hint offered after a miss could overwrite the better hint on disk, so the choice after a miss became tentative. A file of zeros or of another program would have been overwritten, so a file without the magic is now refused. Creation in place could leave a half-made file under the final name, so a new file is built beside the path and renamed. A sparse file would fault on a full disk, so every block is written at creation. Two processes could map one file during a handoff, so the file is locked. A reference into the mapping would make a foreign write undefined behaviour, so every access copies a slot.

References
----------

- SID 0015, Distributed Edge Load Balancer, section "Bounded memory and disk state".
- SID 0019, Traffic Policy, for sticky sessions.
- SID 0025, shared affinity across the mesh.
- Einziger, Friedman and Manes, *TinyLFU: A Highly Efficient Cache Admission Policy* (2017).
