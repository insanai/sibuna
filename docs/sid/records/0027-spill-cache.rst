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

Creation never happens in place. We write a complete new file beside the path, at the path with ``.tmp`` after it, with every block allocated and the header last, flush it, and rename it over the path. What lies at that name before is removed and never written through, so a link there is not followed. When the creation fails, the file under construction is removed. So the path holds no file, a foreign file or a complete file, and never a half-made one.

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
#. A miss asks the storage thread, and the flow goes on with the ranking. The storage thread answers every question it serves: with the hint of the disk, or with the fact that the disk has none.

After the choice the worker learns it.

#. The choice after a miss is *tentative*, because the disk may hold the older and better hint. It enters the table, and it is offered to the disk as a guess.
#. A tentative entry stays tentative until the disk has answered. The hint of the disk replaces it. The answer that the disk has none makes it *definite*. A flow that uses a tentative entry asks the disk again, because a question can be shed.
#. A definite hint that changes its server, or that is used in the second half of its life, is offered to the disk at once and replaces what the disk holds. Only these two offers compete for a full bucket. So a client must return over time, or move, to displace another, and clients that come once displace nothing.
#. A definite entry that leaves the table in memory is offered once more, as a guess: the disk has it already unless that offer was shed or found no room.
#. A choice of a backup server is not learned. Neither is the server of a retry: one failed request must not move a client for good.

So after a restart a client goes without its hint only until the disk has answered. That is one flow, or more when they come at once.

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

   spill: {
       path: "/var/lib/sibuna/hints.spill",
       size: "64m",
       memory: "1m",     // the table in memory; default 1m
       ttl: "1h",        // the life of a hint; default 1h
   },

The section stands at the top of the file, beside ``global``. ``path`` and ``size`` are required. ``size`` is from 64 KiB to 64 GiB. ``memory`` is from 4 KiB to 1 GiB and is rounded down to a power of two. ``ttl`` is from one minute to 30 days. A change of the section needs a restart.

The cost in memory beside the table is the sketch, two to four bytes for each slot, which is 3% to 6% of the file, and the queue of 4,096 requests. The pages of the file are page cache. The kernel may drop them when memory is short, but they count as memory of the process, and "Known gaps" says what that means under a memory limit. The daemon reports the parts at start.

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

A configuration without the ``spill`` section behaves as before. With it, a pool that is sticky by source prefers the server that last served a client to the server the ranking names. Pools with other settings are untouched. The file format has a version, and a file of another version is discarded.

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
     - 67.1 million operations at 1.5 to 3.4 million in a second. 1,043,849 to 1,044,093 keys of the working set are held at the end, which is all that were held before but 10 to 15.
   * - Close, map again, read the working set
     - Every hint that was held is found. 3.5 to 3.7 million lookups in a second, with the pages in the page cache.
   * - Four threads offer through the queue without a pause
     - The calls return at 35 to 57 million in a second. The queue of 4,096 sheds 98% to 99% of them. No caller waits.
   * - Resident memory
     - 8.6 MiB of our own, of which 8 MiB are the sketch. 257.5 MiB of mapped pages, which is the whole file. After the file is closed 1.8 MiB remain.

The second program is the ignored test ``measure_two_tiers`` of ``sibuna-lb``. The table in memory has 1 MiB, which is 65,536 entries. There are 2,000,000 clients, thirty times the table. We ran it twice.

.. list-table::
   :header-rows: 1
   :widths: 44 56

   * - Phase
     - Result
   * - The first flow of every client: a miss, a choice, a guess for the disk
     - 1.0 to 1.2 million flows in a second, with a wait for the storage thread after every 1,000. Nothing is shed.
   * - Every client returns with two flows
     - 1,908,157 of 2,000,000 clients, 95.4%, have their hint at the second flow. The disk answered 98.1% of the questions with a hint. 1,934,606 guesses were stored, so 3.3% found their bucket full: the file is half full, and a bucket of four overflows that often.
   * - Four threads, 16,000 clients that fit in memory
     - 9.8 and 17.5 million recalls with their learns in a second, for all four threads together.
   * - Four threads, all clients, without a pause
     - 10.9 and 11.3 million in a second. Nearly every one misses, and the queue sheds most of the questions.
   * - Resident memory
     - 10.1 MiB of our own. 258.7 MiB of mapped pages.

We also ran the first program in a control group with a memory limit of 96 MiB and no swap, ``systemd-run --user --scope -p MemoryMax=96M -p MemorySwapMax=0``. The kernel killed it for lack of memory in three runs. In two of them the creation of the file alone took 12 and 130 seconds. A fourth run did not finish creating the file in 110 seconds and we stopped it. So on this machine the kernel did not take the pages of the file back fast enough to keep the process inside a limit below the size of the file. The file system is ZFS, which has a cache of its own. We had no other file system to compare.

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
     - Met. ``a_file_that_is_not_a_cache_is_refused_and_left_alone``, ``a_second_opener_finds_the_cache_in_use``, ``what_lies_at_the_name_of_the_new_file_is_removed_and_not_written_through``, and through the binary ``a_file_that_is_not_a_cache_stops_the_daemon_with_a_diagnostic``. ``a_lock_on_a_file_that_lost_its_name_does_not_open_the_cache`` checks the comparison of names. No test runs two processes through the race itself.
   * - 8
     - A worker never waits for the disk.
     - Met. ``a_full_queue_sheds_work_and_never_blocks``. The table in memory is atomic words: ``workers_that_learn_and_recall_at_once_read_only_hints_that_were_written``.
   * - 8a
     - A guess does not overwrite what the disk knows, and clients that come once displace no hint on disk.
     - Met. ``a_guess_never_becomes_definite_before_the_disk_has_answered``, ``a_flood_of_clients_seen_once_displaces_no_hint_on_disk`` with 26 clients for every slot, and ``a_guess_takes_a_free_slot_only_however_often_it_was_seen``.
   * - 9
     - The edge uses a hint only for a server that may serve, and a wrong hint changes only the choice for a new flow.
     - Met. ``a_damaged_file_costs_the_hints_and_the_edge_serves_on``, ``a_retry_serves_one_request_elsewhere_and_does_not_move_the_client``. The eligibility check is the one the cookie of SID 0019 uses.
   * - 10
     - Hints survive a restart of the daemon.
     - Met. ``cmd/sibuna/tests/edge_spill.rs`` serves 40 clients, kills the daemon with SIGKILL and starts another on the same file with a third server of weight 200. After one request each, every client is with its old server. Without the file more than 30 of 40 go to the heavy server.
   * - 11
     - The tier is off by default and has no cost then.
     - Met. ``the_spill_section_is_off_by_default_and_has_bounds``, ``the_spill_section_changes_only_with_a_restart_and_is_off_without_it``. Without the section a pool holds ``None`` and makes no call.
   * - 12
     - The cost in memory is reported and bounded.
     - Met. The daemon notes ``EDGE013`` with slots, bytes on disk and bytes of memory, and ``show info`` repeats them. The measurement above confirms the numbers.
   * - 13
     - The admission rule and the validation of a slot are modelled.
     - Met. ``docs/sid/assets/spill-cache.lean`` checks with Lean 4.19.0 and uses the core library only.
   * - 14
     - A platform without ``mmap`` builds and runs.
     - Partly. The fallback is a cache in memory that reports ``persistent: false``; ``a_cache_in_memory_works_and_says_that_it_does_not_persist`` runs it on Linux. We did not build for another platform.

Deviations from SID 0015
------------------------

#. SID 0015 lets each worker own some shards. Here one storage thread owns all 64, and the workers reach it through a queue. The section on alternatives says why.
#. SID 0015 spills an entry when it leaves memory. Here a hint is also written when it is learned, so that a restart finds the hints in use.
#. SID 0015 speaks of stick tables and affinity. This version has no stored stick table to put the cache under, so this SID adds a small one for source stickiness. Cookie stickiness stays stateless.
#. ``size`` is the size of the file. The sketch, the table and the queue come on top and are reported. SID 0015 asks for a budget that counts them, and the report counts them, but one number does not bound them all.
#. The sketch takes 2 to 4 bytes for each slot, 3% to 6% of the file, not the smaller share a sketch of one counter for each slot would take. The smaller sketch kept only 77% of a working set under a flood.

Known gaps
----------

#. The pages of the file count as memory of the process. Under a memory limit below the size of the file, the measurement program was killed. We did not find out whether another file system behaves better. The operator has to set a limit above the file.
#. A truncation of the file by another process, or a read error of the disk, raises a signal that ends the daemon. Reading and writing with system calls would turn both into errors.
#. The first flow of a client after a restart, or after its hint left memory, goes without the hint. In the measurement 4.6% of the clients were also without it at the second flow: 3.3% never fitted their bucket, and the rest lost their entry in memory to a neighbour before they used it.
#. The table in memory has no admission. Its sets are chosen with a hash that is not secret, so someone who knows the name of the pool and controls many addresses can push the hint of a client out of memory again and again. That client then meets one flow without its hint each time. The file is salted and is not exposed in this way.
#. A flood of clients that come once empties the table in memory of the hints in use. They come back from the disk, one flow late. The disk keeps them: see the acceptance table.
#. A hint enters a full bucket only by a renewal or a move. A new client whose bucket is full has no hint on disk until it is still in memory after half of ``ttl``.
#. Each definite entry that leaves memory costs one request of the queue that the disk mostly answers with "kept". In the measurement that was 1.8 million of 8 million requests.
#. A healthy slot whose expiry lies more than ``ttl`` plus a minute ahead is treated as corrupt, cleared and counted in ``spill_disk_corrupt``. This happens to older hints after ``ttl`` was lowered, and to recent ones after the clock stepped back by more than a minute.
#. A file that we reuse is trusted to have its blocks. A sparse file of the right length with a valid header, as a backup tool may restore it, raises a signal at the first write to a hole on a full disk.
#. A reused file keeps its permission bits. Only a file we create gets mode 0600.
#. The daemon opens the file, and replaces a damaged one, before it binds its listeners. A start that then fails has already replaced the file.
#. The send to the queue is ``try_send`` of the standard library. It never waits for the disk. We did not verify that it takes no lock inside when the storage thread sleeps, so "no lock on the request path" is not proven for this one call.
#. The sketch of a file of 64 GiB takes 4 GiB of memory, and aging walks the 64 MiB of one shard on the storage thread. Stopping the daemon waits for the flush of the file.
#. One storage thread serves all workers. It handles about two to three million operations in a second. Beyond that the queue sheds, which costs hints and no latency.
#. Hints are local to a node. In a mesh, two nodes can choose different servers for one client until SID 0025 shares the entries. With the section absent the ranking agrees on all nodes.
#. The tag of a server has 31 bits of its ranking seed. Two servers of a pool with the same tag would be confused for hinted clients. We do not detect that.
#. The checksum is not keyed. A file written by someone who knows the format is trusted as hints.
#. Creation overwrites ``path.tmp`` without asking.
#. A second process on the same file runs with the table in memory only, so during the replacement of the binary the new process learns afresh and writes nothing.
#. The model proves the admission rule for exact frequencies and one bucket. It does not model the sketch collisions, the two tiers, the guess that leaves a known hint alone, or concurrency.
#. There is no test of a loss of power. The table of crash safety is an argument over the states a page can be left in, and the tests write those states by hand.
#. The 50-million-key qualification of SID 0015 is not run. The largest file we measured has 4.2 million slots.
#. The code ``EDGE013`` was the next free number on this branch. Another branch may have taken it.

Open questions
--------------

#. Should the first flow after a restart wait a bounded time for the disk, so that it also finds its hint?
#. Should the checksum be keyed with a secret of the node, so that a file written elsewhere is refused?

Review history
--------------

- 2026-11-25. Review of the implementation by a second reader who had not written it. It found no fault of memory safety and no way for a hint to choose a server that may not serve. It found ten points. Fixed: a second flow turned a guess into a definite hint before the disk had answered and overwrote the hint on disk, so the storage thread now answers every question and a guess stays tentative until then. Clients seen once were counted twice and displaced the hints in use, so a guess now takes a free slot only and does not count, and the offer at eviction is a guess. A lock could be taken on a file that had lost its name to a rename, so the name is compared after the lock. The file under construction was opened through a link and left behind on failure, so it is created anew and removed on failure. The wrong number in the comment on torn entries was corrected. Recorded under "Known gaps" and not fixed: the table in memory without admission and with a public hash, the sparse reused file, the healthy slots counted as corrupt after a lower ``ttl`` or a clock step, the busy file that disables the disk tier until the next start, the permission bits of a reused file, the cost of a large sketch, and the unverified inside of ``try_send``.
- 2026-11-25. Review of the code by its author before that. A retry was learned as the new server of a client, so one failed request moved the client for good: a retry is no longer learned. A choice after a miss was never written to disk, so a client with flows far apart never got a hint saved: it is offered as a guess. The storage thread reads the clock once for a batch, so a hint stamped by a worker a second later was judged corrupt: the disk tier allows a minute of slack. The note ``EDGE013`` came before the line ``listeners ready`` and broke harnesses that read the first line: it follows now.
- 2026-11-25. Initial draft. The review of the draft found six faults. A hint offered after a miss could overwrite the better hint on disk, so the choice after a miss became tentative. A file of zeros or of another program would have been overwritten, so a file without the magic is now refused. Creation in place could leave a half-made file under the final name, so a new file is built beside the path and renamed. A sparse file would fault on a full disk, so every block is written at creation. Two processes could map one file during a handoff, so the file is locked. A reference into the mapping would make a foreign write undefined behaviour, so every access copies a slot.

References
----------

- SID 0015, Distributed Edge Load Balancer, section "Bounded memory and disk state".
- SID 0019, Traffic Policy, for sticky sessions.
- SID 0025, shared affinity across the mesh.
- Einziger, Friedman and Manes, *TinyLFU: A Highly Efficient Cache Admission Policy* (2017).
