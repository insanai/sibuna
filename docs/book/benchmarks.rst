Part VIII: Empirical Evaluation
===============================

We present the measurements of the Rust port against the Zig original, recorded by three committed harnesses: primitive latencies, whole products under an external load generator with CPU and memory accounting, and latency at equal offered load from an open-loop generator. A console run with eight live dashboards completes the record. Every number in this part comes from a committed result file, which each table names with its generation time, or from a design record. The Zig implementation's comparison with Anubis and its cluster measurements were not repeated for the port; we keep the Anubis results, condensed and labelled, as historical measurements of the Zig implementation. A functional pass and a performance measurement answer different questions.

Methodology
-----------

.. admonition:: Objectives

   By the end of this chapter, we should be able to reproduce every number in this part, say what each harness includes and excludes, explain what the spread columns mean, and tell a measured figure from a historical or a published one.

Three performance harnesses replace the Python and shell drivers of the Zig repository (SID 0010). They are commands of one Rust tool, ``tools/bench`` (the binary ``sibuna-bench``), run through ``cargo xtask bench``. A fourth tool records the console run.

.. list-table:: Harnesses and their result files, all under ``benchmarks/results/``
   :header-rows: 1
   :widths: 24 50 26

   * - Harness
     - What it measures
     - Results file
   * - ``cargo xtask bench primitives``
     - The sixteen primitive workloads of the Zig ``benchmarks/benchmark.zig``, plus two rows for the hashed rate limiter path, for the Rust crates and for the Zig benchmark binary on the same CPU: seven batches, median per operation with the min-max spread
     - ``primitives-latest.json``, ``primitives-latest.md``
   * - ``cargo xtask bench product``
     - Whole daemons under ``wrk``: throughput, latency percentiles, CPU time per request and peak resident memory for Gate and Shield, Rust and Zig, in forward-auth and reverse-proxy modes; the successor of the Zig ``tools.py``
     - ``product-latest.json``, ``product-latest.md``
   * - ``cargo xtask bench latency``
     - Latency percentiles of admitted requests at fixed offered rates, from an open-loop generator that alternates between the two daemons
     - ``latency-latest.json``, ``latency-latest.md``
   * - ``sibuna-browser dashboards`` (``tools/browser``)
     - A functional console run: eight live dashboards in headless Chromium while a generator sends traffic
     - ``console-8-dashboards-2026-10-15.md``

The ``.md`` files are summaries. The ``.json`` files hold every repetition, the machine, the revision, and the path, size and SHA-256 of both daemons. Git keeps the history, so the directory keeps only the latest files.

Primitives
~~~~~~~~~~

Each workload runs in seven timed batches after an untimed warm-up of at most 1,000 operations. Mutable state (the spent set, the rate limiter) is rebuilt before each batch, outside the timer. Timers surround whole batches, never single operations: a clock read per operation would cost as much as the sub-100 ns work it measures. Per-operation percentiles are therefore not reported, and the spread is across batches. We report the median batch per operation, with the fastest and the slowest batch beside it. The inputs, iteration counts and order are those of ``benchmark.zig``.

The Rust suite runs in a child process (``sibuna-bench primitives-run``) and the Zig suite in its own binary. Both are pinned to the same CPU, and both print the same JSON document, so one parser reads both. On a shared host a busy SMT sibling or a lower clock slows a whole suite run. The tool therefore alternates the Zig and Rust suites over three rounds (``--rounds``) and keeps, per row, the round with the lowest median. Within a round the statistics are Zig's.

Whole Products
~~~~~~~~~~~~~~

For each mode (forward auth, reverse proxy), each surface (Gate, Shield) and each daemon (Rust, then Zig), the harness starts the daemon in memory with the flags of the Zig ``tools.py`` (``--algorithm hashcash --difficulty 8 --rate-limit 100000000 --idle-timeout 5``) and four workers, one per CPU of its set. It obtains a session by solving the daemon's Hashcash challenge with ``sibuna-pow``, as a browser would. It then drives four workloads with ``wrk`` over keep-alive connections: 2 threads, 64 connections, 5 seconds, 3 repetitions.

- ``admitted``: ``GET /private`` with a valid session cookie. In reverse-proxy mode the request reaches the origin and its answer is relayed; in forward-auth mode the daemon answers ``200`` itself.
- ``challenged``: the same request without a cookie, from a browser User-Agent. The daemon serves its challenge: ``200`` with HTML in reverse-proxy mode, ``401`` in forward-auth mode.
- ``allowed_static``: ``GET /robots.txt`` from ``curl/8.0``, which both surfaces admit without a challenge.
- ``attack``: a valid session plus ``q=' OR 1=1--``. Only Shield refuses it (``403``). Gate admits it, and in reverse-proxy mode relays it to the origin.

The origin is a stub (``sibuna-bench origin``): standard library only, one thread per connection, keep-alive, and the same 41-byte page that ``caddy respond`` served for ``tools.py``. CPU time per request is the daemon's user plus system time from ``/proc/<pid>/stat`` over the run (10 ms ticks), divided by the requests ``wrk`` counted; the origin's CPU is not included. Peak memory is ``VmHWM`` from ``/proc/<pid>/status``, reset through ``/proc/<pid>/clear_refs`` before each run, so that each run reports its own peak. Every figure is the median of the repetitions, with the minimum and maximum kept beside it in the JSON file. The harness measures one daemon after the other; it does not interleave their repetitions, so a slow drift of the host between the Rust and the Zig runs of one case is not cancelled.

``wrk`` is a closed-loop generator: it keeps 64 requests in flight. A faster daemon therefore receives more requests, and ``wrk``'s percentiles leave out the requests it did not send while it waited for a slow answer (coordinated omission). Its p99 shows how each daemon behaves under its own saturation, not how the two compare at the same load. The third harness answers that question.

Latency at Equal Load
~~~~~~~~~~~~~~~~~~~~~

The open-loop generator (``sibuna-bench generate``) runs one blocking thread per connection. Each of 64 connections sends ``GET /private`` with a session on a fixed schedule: request :math:`k` of a connection is due at :math:`t_0 + o + kT`, where :math:`o` is the connection's offset and :math:`T` its interval, independent of earlier answers. When an answer arrives after the next request was due, that request goes out at once and its latency counts from the time it was due, as in ``wrk2``. When the connection was idle at the due time, latency counts from the actual send, so the generator's own sleep overshoot is not charged to the daemon.

.. code-block:: text
   :caption: One connection of the open-loop generator. S is a send, A an answer, d a due time that passed while the connection waited. Request 1 is answered after request 2 was due, so request 2 is sent at once and its latency counts from 2T; request 3 finds the connection idle and counts from its send.

   time        0         T         2T        3T        4T
   due         |         |         |         |         |
   k = 0       S--A
   k = 1                 S---------------A
   k = 2                           d.....S--A
   k = 3                                     S--A

The harness runs the Shield surface and the admitted workload at five offered rates: 10,000, 25,000, 50,000, 100,000 and 150,000 requests per second, each with a 2-second warm-up, 10 measured seconds and 3 runs. Both daemons run at the same time on the same CPU set, and the idle one uses no CPU. The generator alternates between them at every rate and repetition, so that slow drift of the machine affects both alike. Percentiles are nearest-rank over every measured request of one run; each figure is the median of the three runs, with the min-max of p99 beside it.

CPU Sets
~~~~~~~~

The CPU sets matter more than any other setting. The daemons run on CPUs 0 to 3 (``--cpus``; ``--workers`` is the size of that set). ``wrk``, the latency generator and the stub origin run on CPUs 8 to 15 (``--load-cpus``). The primitive suites run on CPU 4 (``--cpu``). Every process is pinned with ``taskset -c`` before it starts, so every thread it creates inherits the set; the Zig ``tools.py`` re-pinned threads after start.

.. code-block:: text
   :caption: CPU sets on the AMD Ryzen 9 5950X. CPUs 0 to 7 are the eight cores of the first CCD, 8 to 15 those of the second, and 16 to 31 their SMT siblings. Daemon and load generator never share a core.

   CCD 0   cores  0  1  2  3 |  4         |  5  6  7
                  daemons    |  primitive |  not assigned
                  (--cpus)   |  suites    |
                             |  (--cpu)   |
   CCD 1   cores  8  9 10 11 12 13 14 15
                  wrk, latency generator, stub origin (--load-cpus)
   SMT     16 to 31: siblings of 0 to 15, not assigned

On other machines we choose sets that do not share cores (``lscpu -e`` shows the topology).

Machine and Conditions
~~~~~~~~~~~~~~~~~~~~~~

The current files were recorded on 15 October 2026 on ``paxos-zig``: an AMD Ryzen 9 5950X 16-Core Processor (32 logical CPUs), Linux 7.0.0-28-generic x86_64, the ``powersave`` governor with boost enabled, rustc 1.99.0 and Zig 0.16.0. The Rust daemon is ``cargo build --release -p sibuna``, the default build with SQLite storage and the console compiled in (SID 0010); the product and latency files name a binary of 49,113,856 bytes. The Zig daemon and benchmark binary are a ``ReleaseFast`` build of the Zig repository; its daemon has 34,576,440 bytes. Each file records the revision (``efce14d`` for the primitives, ``249d913`` for the product and latency runs) with ``dirty: true``, because the port was in progress; the working tree of the latter already held the reused connection threads that SID 0002 records, and SID 0002 cites ``latency-latest.md`` for their effect.

The README of ``benchmarks/results/`` records that the host was shared with other build and test jobs on the day of the runs, and that nothing kept those jobs off the benchmark CPUs. The files record one-minute load averages of 2.46 at the primitive run, 1.30 before and 52.31 after the latency run, and 52.31 before and 33.39 after the product run.

.. admonition:: Measurement scope

   Only local measurements are emitted. Every run uses one host over loopback: no TLS, no WAN, no real browsers. Both daemons run in memory, without storage. Timers surround batches; state resets and warm-up are untimed. The harness does not count allocations (the files say "not instrumented; API/source audit only"); the allocation-free request path is checked by the steady-state tests of Part V instead. No harness links into the daemon or adds a hook to the request path: the product and latency harnesses run the release binary unmodified, identified by its SHA-256. A ranking on this host is not a ranking on another.

How to Reproduce
~~~~~~~~~~~~~~~~

We need Linux, ``taskset`` (util-linux) and ``wrk`` on ``PATH``. For a comparison with Zig we also need a Zig release build of the daemon and of its benchmark binary: ``zig build -Doptimize=ReleaseFast`` in the Zig repository gives ``zig-out/bin/sibuna`` and ``zig-out/bin/sibuna-benchmark``.

.. code-block:: sh

   cargo xtask bench primitives --zig <zig-out/bin/sibuna-benchmark> --zig-daemon <zig-out/bin/sibuna>
   cargo xtask bench product --zig <zig-out/bin/sibuna>
   cargo xtask bench latency --zig <zig-out/bin/sibuna>
   cargo xtask bench help

``cargo xtask bench`` first builds the daemon with ``cargo build --release -p sibuna``, then runs ``sibuna-bench`` in release mode. The tool finds the Rust daemon beside its own binary; ``--rust <path>`` overrides it. ``cargo xtask bench help`` lists the options, among them ``--cpus``, ``--load-cpus``, ``--cpu``, ``--rounds``, ``--repetitions``, ``--seconds``, ``--rates`` and ``--warmup``.

Primitive Latencies
-------------------

The table gives every row of the primitive run. Rust/Zig below 1 means the Rust port is faster. The JSON file names each row by subsystem and workload (``pow_verify`` and ``hashcash_16_bits``, for example). The two rate limiter rows for a hashed client have no Zig counterpart; the section on state explains them.

.. list-table:: Primitive timings in nanoseconds per operation, Rust port and Zig original on one Ryzen 9 5950X core (``benchmarks/results/primitives-latest.md``, generated 2026-10-15T22:34:59Z)
   :header-rows: 1
   :widths: 32 11 18 11 18 10

   * - Workload
     - Rust ns/op
     - Rust min-max
     - Zig ns/op
     - Zig min-max
     - Rust/Zig
   * - Hashcash verify (16 bits)
     - 70.2
     - 69.9-71.0
     - 74.1
     - 73.9-74.3
     - 0.95
   * - PoSW verify (depth 13, t = 16)
     - 22272.4
     - 22257.0-22316.4
     - 23622.8
     - 23534.1-23694.2
     - 0.94
   * - Bot signatures (40, Aho-Corasick)
     - 55.7
     - 55.3-57.2
     - 73.7
     - 72.6-76.7
     - 0.76
   * - Bot signatures (40, sequential search)
     - 763.0
     - 762.2-763.5
     - 936.4
     - 935.1-937.9
     - 0.81
   * - IPv4 CIDR lookup
     - 32.0
     - 31.8-32.2
     - 45.8
     - 45.5-46.0
     - 0.70
   * - IPv6 CIDR lookup
     - 79.3
     - 78.5-79.6
     - 90.3
     - 90.0-91.6
     - 0.88
   * - Session token (keyed BLAKE3)
     - 155.8
     - 155.3-156.4
     - 303.4
     - 302.5-305.3
     - 0.51
   * - Session token (Ed25519)
     - 40587.5
     - 40544.6-40631.1
     - 51437.3
     - 51368.3-51566.8
     - 0.79
   * - Spent set (Robin Hood), spend and look up
     - 21.0
     - 20.8-21.3
     - 30.7
     - 30.4-31.0
     - 0.69
   * - Rate limiter (GCRA), client bytes
     - 12.8
     - 12.7-12.8
     - 5.7
     - 5.6-5.8
     - 2.25
   * - Rate limiter, four rule scopes, client bytes
     - 13.1
     - 13.0-13.2
     - 5.8
     - 5.7-5.9
     - 2.28
   * - Rate limiter (GCRA), hashed client
     - 6.2
     - 6.1-6.3
     - n/a
     - n/a
     - n/a
   * - Rate limiter, four rule scopes, hashed client
     - 6.3
     - 6.2-6.4
     - n/a
     - n/a
     - n/a
   * - HTTP parse and cookie
     - 132.5
     - 132.3-133.2
     - 1146.0
     - 1145.1-1149.6
     - 0.12
   * - Classification, Shield profile
     - 790.8
     - 787.2-793.1
     - 1292.2
     - 1288.0-1295.5
     - 0.61
   * - Classification, Gate profile
     - 75.9
     - 75.6-76.1
     - 185.2
     - 183.6-187.5
     - 0.41
   * - WAF body scan (8 KiB)
     - 12784.3
     - 12771.5-12809.2
     - 19223.1
     - 19197.6-19299.6
     - 0.67
   * - WAF body scan (8 KiB), SQL injection audited
     - 15485.4
     - 15460.9-15530.1
     - 97038.7
     - 97001.5-97168.1
     - 0.16

The Rust port is faster on fourteen of the sixteen rows that both suites share, from 0.95 of Zig's time for Hashcash verification down to 0.12 for the HTTP parser. The two rate limiter rows that take client bytes are 2.25 and 2.28 times slower, for a reason the state section gives. The spreads are narrow: no batch of any row, Rust or Zig, lies more than 4.2% from its row's median.

Proof-of-Work Verification
~~~~~~~~~~~~~~~~~~~~~~~~~~

Hashcash verification hashes a challenge, a separator and a decimal nonce. The sequential-work verifier checks graph openings; its hash invocations and SHA-256 compression counts differ from Hashcash's because the inputs differ in length. Both rows are bound by SHA-256, and both implementations use the SHA-NI instructions (the Rust port detects them at run time, SID 0010). These are the rows closest to parity: 0.95 and 0.94.

Matching
~~~~~~~~

The dense Aho-Corasick automaton and sequential substring search use identical patterns and any-match semantics. In the Rust port the automaton is 13.7 times faster than the sequential search on the same 40 signatures (55.7 against 763.0 ns), and 0.76 of Zig's time. Its tables use byte classes instead of 256 columns per state (SID 0006, Part F), which shrinks the bot signature table from 200,952 to 42,244 bytes (the footprint table below). The CIDR classifiers run at 0.70 (IPv4) and 0.88 (IPv6) of Zig's time.

Tokens
~~~~~~

The BLAKE3 MAC token verifies in 155.8 ns, half of Zig's 303.4 ns. The ``sibuna-crypto`` crate implements BLAKE3 portably, without Zig's SIMD paths; those win on large inputs, but Sibuna hashes inputs under 100 bytes with BLAKE3, where the portable code is faster. Ed25519 compact tokens verify in 40,587.5 ns, 0.79 of Zig's time: the verifier uses width-5 and width-8 NAF digits instead of signed 4-bit windows and keeps the decoded public key, and it accepts and rejects exactly the same inputs. One Ed25519 verification costs about as much as 260 MAC verifications; the MAC is Sibuna's default token scheme.

State
~~~~~

The spent-set row inserts a fresh tag and looks it up again: 21.0 ns against Zig's 30.7 ns. The row is set up as ``benchmark.zig`` sets it up. The table has Zig's capacity, 16 shards of 4,096 slots (65,536 tags; the daemon's default is 1,048,576), and it is emptied in place before each batch, outside the timer, as Zig's ``ctx.* = .{}`` does. Every batch therefore probes resident memory. An earlier version of the Rust suite built a fresh zeroed table of the daemon's default size for each batch; it timed the kernel mapping the table's pages on first write, a cost a running daemon pays once, and it is not the row we report.

The rate limiter rows need care. The two rows for client bytes (``gcra_check`` and ``gcra_four_rule_scopes``) call the byte API that Zig also has: each check takes the client's address as bytes. In the Rust port that API first computes a keyed SipHash-1-3 of the client under a secret drawn from operating-system randomness. This is a security fix (SID 0010 and the ``sibuna-store`` documentation): Zig placed keys with Wyhash under seeds written in the source, so anyone could compute addresses that share a victim's probe window. The rows therefore time a hash that Zig did not compute, and they are 2.25 and 2.28 times slower: 12.8 and 13.1 ns against 5.7 and 5.8 ns.

The daemon does not use the byte API on the request path. It hashes the client once per request (``ClientHasher``) and passes the hash to every table it consults. The two rows for a hashed client (``gcra_check_hashed`` and ``gcra_four_rule_scopes_hashed``) measure that path, with the hashes computed before the loop: 6.2 and 6.3 ns per check. The gap between the medians of the byte and hashed rows, 6.6 ns, is about the price of the keyed hash on these inputs, which the daemon pays once per request rather than once per table.

HTTP Parser
~~~~~~~~~~~

The parser row parses a 400-byte browser request and looks up a cookie: 132.5 ns against Zig's 1,146.0 ns, the largest ratio in the table (0.12). The crate's own timing test agrees (``crates/http``: about 135 to 180 ns against 1,119 to 1,145 ns for Zig on the same machine). Both parsers are zero-copy; every field is a slice of the connection's buffer.

Policy Engine
~~~~~~~~~~~~~

A full classification of a browser request takes 790.8 ns (0.61 of Zig) and the Gate profile 75.9 ns (0.41). The rows leave the request's parsed client address empty, so the engine parses the client address text inside evaluation, as the Zig engine did. The daemon parses the address once per request, before evaluation, so these rows include a small cost that the daemon pays outside the engine. The engine's heap tables total 209,052 bytes, against 853,728 bytes for the fixed-capacity Zig value, with the same capacities (SID 0002).

WAF Inspection
~~~~~~~~~~~~~~

The semantic scan of an 8 KiB body takes 12,784.3 ns, 0.67 of Zig's time, or :math:`12784.3 / 8192 \approx 1.56` ns per byte. The second row scans the same body with the SQL injection category audited and the others enforced: 15,485.4 ns against Zig's 97,038.7 ns (0.16). The gap is the design change recorded in SID 0004 ("inspection modes"): when some category is audited rather than enforced, each field is inspected per category, and Zig then scanned the field with the signature automaton once per category, four scans in all. The port scans it once for the set of categories whose signatures occur, then searches only the wanted categories among them. The findings are the same.

Whole-Product Comparison
------------------------

.. admonition:: Objectives

   Read the throughput, latency, CPU time and memory of the Rust and Zig daemons as complete processes, say in which rows the daemon and in which rows the load generator sets the limit, and check the port's performance criterion against the record.

The tables give the medians of three five-second ``wrk`` runs for each daemon, surface and workload. The status beside each workload is the answer the harness expected and received.

Forward-Auth Mode
~~~~~~~~~~~~~~~~~

The ingress asks the daemon whether to admit a request; there is no origin and no body relay, so this is the purest measure of admission cost.

.. list-table:: Forward-auth mode, Gate and Shield, Rust and Zig; latency in microseconds (``benchmarks/results/product-latest.md``, generated 2026-10-15T23:15:24Z)
   :header-rows: 1
   :widths: 9 22 7 11 7 7 7 10 11

   * - Surface
     - Workload (status)
     - Impl
     - req/s
     - p50
     - p90
     - p99
     - CPU us/req
     - Peak RSS KiB
   * - Gate
     - ``admitted`` (200)
     - Rust
     - 211,345
     - 151
     - 175
     - 305
     - 11.84
     - 15912
   * - Gate
     - ``challenged`` (401)
     - Rust
     - 198,315
     - 160
     - 180
     - 326
     - 13.15
     - 16176
   * - Gate
     - ``allowed_static`` (200)
     - Rust
     - 211,053
     - 152
     - 175
     - 305
     - 11.73
     - 16176
   * - Gate
     - ``attack`` (200)
     - Rust
     - 211,618
     - 151
     - 176
     - 305
     - 11.84
     - 16176
   * - Gate
     - ``admitted`` (200)
     - Zig
     - 209,235
     - 151
     - 186
     - 310
     - 14.45
     - 30416
   * - Gate
     - ``challenged`` (401)
     - Zig
     - 198,067
     - 158
     - 301
     - 329
     - 15.68
     - 32132
   * - Gate
     - ``allowed_static`` (200)
     - Zig
     - 211,373
     - 151
     - 174
     - 305
     - 12.40
     - 30328
   * - Gate
     - ``attack`` (200)
     - Zig
     - 208,915
     - 151
     - 181
     - 311
     - 14.39
     - 30464
   * - Shield
     - ``admitted`` (200)
     - Rust
     - 208,101
     - 152
     - 178
     - 308
     - 12.87
     - 15928
   * - Shield
     - ``challenged`` (401)
     - Rust
     - 197,532
     - 161
     - 183
     - 327
     - 13.77
     - 16192
   * - Shield
     - ``allowed_static`` (200)
     - Rust
     - 211,636
     - 151
     - 175
     - 305
     - 11.78
     - 16192
   * - Shield
     - ``attack`` (403)
     - Rust
     - 210,549
     - 152
     - 175
     - 307
     - 12.32
     - 16192
   * - Shield
     - ``admitted`` (200)
     - Zig
     - 196,611
     - 156
     - 278
     - 359
     - 15.50
     - 30536
   * - Shield
     - ``challenged`` (401)
     - Zig
     - 188,965
     - 163
     - 301
     - 375
     - 16.29
     - 31808
   * - Shield
     - ``allowed_static`` (200)
     - Zig
     - 209,145
     - 152
     - 176
     - 308
     - 12.95
     - 30488
   * - Shield
     - ``attack`` (403)
     - Zig
     - 208,846
     - 151
     - 189
     - 311
     - 14.70
     - 31336

In forward-auth mode the daemons are not the bottleneck. Their cores busy (CPU time over wall time, ``cores_busy_median`` in the JSON file) stay between 2.47 and 3.11 of the four daemon CPUs, and every row of both daemons lies between 188,965 and 211,636 requests per second. That points to the load generator, not the daemons, as the ceiling. Near that ceiling a difference under about 5% between the daemons moves between runs: the Zig Shield ``admitted`` row alone spans 192,850 to 205,154 requests per second over its three runs. The useful comparison in this mode is CPU time per request, where Rust needs 0.82 to 0.95 of Zig's.

Reverse-Proxy Mode
~~~~~~~~~~~~~~~~~~

The daemon sits in front of the stub origin and relays admitted requests and responses. Proxied rows therefore include the origin's own cost and one extra loopback hop.

.. list-table:: Reverse-proxy mode, Gate and Shield, Rust and Zig; latency in microseconds (``benchmarks/results/product-latest.md``, generated 2026-10-15T23:15:24Z)
   :header-rows: 1
   :widths: 9 22 7 11 7 7 7 10 11

   * - Surface
     - Workload (status)
     - Impl
     - req/s
     - p50
     - p90
     - p99
     - CPU us/req
     - Peak RSS KiB
   * - Gate
     - ``admitted`` (200)
     - Rust
     - 142,498
     - 427
     - 548
     - 768
     - 27.68
     - 15896
   * - Gate
     - ``challenged`` (200)
     - Rust
     - 199,465
     - 160
     - 181
     - 324
     - 12.98
     - 16160
   * - Gate
     - ``allowed_static`` (200)
     - Rust
     - 147,303
     - 411
     - 541
     - 759
     - 26.88
     - 16324
   * - Gate
     - ``attack`` (200)
     - Rust
     - 143,900
     - 422
     - 555
     - 745
     - 27.67
     - 16348
   * - Gate
     - ``admitted`` (200)
     - Zig
     - 131,525
     - 462
     - 596
     - 1679
     - 29.89
     - 31228
   * - Gate
     - ``challenged`` (200)
     - Zig
     - 194,904
     - 160
     - 205
     - 330
     - 15.55
     - 32120
   * - Gate
     - ``allowed_static`` (200)
     - Zig
     - 140,517
     - 431
     - 560
     - 804
     - 28.15
     - 31232
   * - Gate
     - ``attack`` (200)
     - Zig
     - 132,464
     - 462
     - 595
     - 951
     - 29.97
     - 31320
   * - Shield
     - ``admitted`` (200)
     - Rust
     - 138,965
     - 438
     - 571
     - 857
     - 28.57
     - 16064
   * - Shield
     - ``challenged`` (200)
     - Rust
     - 195,188
     - 162
     - 185
     - 328
     - 13.73
     - 16328
   * - Shield
     - ``allowed_static`` (200)
     - Rust
     - 145,673
     - 415
     - 551
     - 746
     - 27.27
     - 16328
   * - Shield
     - ``attack`` (403)
     - Rust
     - 209,507
     - 151
     - 177
     - 306
     - 12.17
     - 16328
   * - Shield
     - ``admitted`` (200)
     - Zig
     - 127,899
     - 477
     - 619
     - 1295
     - 30.88
     - 31800
   * - Shield
     - ``challenged`` (200)
     - Zig
     - 194,827
     - 159
     - 308
     - 333
     - 16.42
     - 32252
   * - Shield
     - ``allowed_static`` (200)
     - Zig
     - 138,373
     - 440
     - 583
     - 864
     - 28.67
     - 31736
   * - Shield
     - ``attack`` (403)
     - Zig
     - 206,970
     - 150
     - 275
     - 312
     - 14.76
     - 31700

Here the proxied rows (``admitted``, ``allowed_static``, and Gate's ``attack``, which Gate relays) are CPU bound: cores busy is 3.95 to 3.98 of four for both daemons. In these five rows Rust serves 1.05 to 1.09 times Zig's requests at 0.92 to 0.96 of its CPU time per request. The ``challenged`` rows and Shield's ``attack`` row are answered by the daemon itself, and they look like forward-auth rows. Under saturation ``wrk``'s p99 is the scheduler's tail at the daemon's own rate, so we read the tails of the next chapter instead.

Rust Against Zig
~~~~~~~~~~~~~~~~

.. list-table:: Rust against Zig, ratios of medians; req/s above 1 and p99 or CPU below 1 favour Rust (``benchmarks/results/product-latest.md``, generated 2026-10-15T23:15:24Z)
   :header-rows: 1
   :widths: 18 10 20 14 14 14

   * - Mode
     - Surface
     - Workload
     - req/s Rust/Zig
     - p99 Rust/Zig
     - CPU/req Rust/Zig
   * - forward auth
     - Gate
     - ``admitted``
     - 1.01
     - 0.98
     - 0.82
   * - forward auth
     - Gate
     - ``challenged``
     - 1.00
     - 0.99
     - 0.84
   * - forward auth
     - Gate
     - ``allowed_static``
     - 1.00
     - 1.00
     - 0.95
   * - forward auth
     - Gate
     - ``attack``
     - 1.01
     - 0.98
     - 0.82
   * - forward auth
     - Shield
     - ``admitted``
     - 1.06
     - 0.86
     - 0.83
   * - forward auth
     - Shield
     - ``challenged``
     - 1.05
     - 0.87
     - 0.85
   * - forward auth
     - Shield
     - ``allowed_static``
     - 1.01
     - 0.99
     - 0.91
   * - forward auth
     - Shield
     - ``attack``
     - 1.01
     - 0.99
     - 0.84
   * - reverse proxy
     - Gate
     - ``admitted``
     - 1.08
     - 0.46
     - 0.93
   * - reverse proxy
     - Gate
     - ``challenged``
     - 1.02
     - 0.98
     - 0.84
   * - reverse proxy
     - Gate
     - ``allowed_static``
     - 1.05
     - 0.94
     - 0.96
   * - reverse proxy
     - Gate
     - ``attack``
     - 1.09
     - 0.78
     - 0.92
   * - reverse proxy
     - Shield
     - ``admitted``
     - 1.09
     - 0.66
     - 0.93
   * - reverse proxy
     - Shield
     - ``challenged``
     - 1.00
     - 0.98
     - 0.84
   * - reverse proxy
     - Shield
     - ``allowed_static``
     - 1.05
     - 0.86
     - 0.95
   * - reverse proxy
     - Shield
     - ``attack``
     - 1.01
     - 0.98
     - 0.82

SID 0010 accepts the port when the benchmarks show the Rust daemon at or above the Zig daemon's throughput, with p99 latency no worse, on the same machine. In these files every throughput ratio is at least 1.00 and every p99 ratio at most 1.00. SID 0010 still calls this evidence preliminary: the final figures are to be taken on a quiet machine after the console port.

In three Rust reverse-proxy rows ``wrk`` counted responses outside the 2xx and 3xx classes where none was expected: 3 of 2,162,579 requests (Gate ``attack``), 1 of 2,082,640 (Shield ``admitted``) and 1 of 2,204,358 (Shield ``allowed_static``), summed over the three runs. The files do not record which status these were. Reproducing the run with the daemon's metrics showed ``503`` answers counted in ``sibuna_overloaded_total``: ``wrk`` opens its 64 connections from one address, exactly the default ``--max-connections-per-ip``, and when a connection was closed after its 4,096th request, ``wrk`` reconnected before the old connection had given its place back. The daemon now gives the place back before it writes the closing response (SID 0002, "bug fix"); the tables predate that fix.

Footprint
~~~~~~~~~

.. list-table:: Sizes and resident memory of the two daemons (``benchmarks/results/product-latest.json``, generated 2026-10-15T23:15:24Z, and ``primitives-latest.json``, generated 2026-10-15T22:34:59Z)
   :header-rows: 1
   :widths: 46 27 27

   * - Measure
     - Rust
     - Zig
   * - Daemon binary
     - 49,113,856 bytes
     - 34,576,440 bytes
   * - Idle resident memory, product runs
     - 5,592 to 5,788 KiB
     - 11,892 to 12,060 KiB
   * - Peak resident memory during a workload
     - 15,896 to 16,348 KiB
     - 30,328 to 32,252 KiB
   * - Resident memory after the workloads
     - 16,176 to 16,348 KiB
     - 29,136 to 29,624 KiB
   * - Idle resident memory, primitive run
     - 6,052 KiB
     - 11,392 KiB
   * - Policy engine tables
     - 209,052 bytes (heap)
     - 853,728 bytes (``@sizeOf``)
   * - Bot signature table
     - 42,244 bytes (heap)
     - 200,952 bytes (``@sizeOf``)
   * - WAF table
     - 164,908 bytes (heap)
     - 465,320 bytes (``@sizeOf``)
   * - Browser solver module (WebAssembly)
     - 14,744 bytes
     - not recorded

The ranges run over the four runs of each daemon (two modes, two surfaces), and for the peak over their sixteen workloads. The Rust daemon holds about half of Zig's resident memory at idle and under load. Its binary is larger; the record does not break the size down. The Rust table sizes are heap sizes reported by the engine, where Zig reported ``@sizeOf`` of fixed tables.

Latency at Equal Offered Load
-----------------------------

.. admonition:: Objectives

   Compare the two daemons' latency distributions at the same offered load, read a tail percentile together with its spread, and follow one tail defect from its measurement to its fix.

Both tables come from one run of ``cargo xtask bench latency``. The errors column counts the generator's connection, I/O and framing errors.

.. list-table:: Forward-auth mode, Shield, admitted requests at fixed offered rates; latency in microseconds (``benchmarks/results/latency-latest.md``, generated 2026-10-15T23:07:14Z)
   :header-rows: 1
   :widths: 10 6 10 8 8 16 8 8 6 8

   * - Offered req/s
     - Impl
     - Achieved req/s
     - p50
     - p90
     - p99 (min-max)
     - p99.9
     - max
     - Errors
     - CPU us/req
   * - 10,000
     - Rust
     - 10,000
     - 30
     - 32
     - 37 (36-39)
     - 58
     - 355
     - 0
     - 16.92
   * - 10,000
     - Zig
     - 10,000
     - 33
     - 34
     - 44 (38-58)
     - 61
     - 1030
     - 0
     - 19.92
   * - 25,000
     - Rust
     - 25,000
     - 28
     - 31
     - 34 (32-34)
     - 45
     - 1035
     - 0
     - 15.83
   * - 25,000
     - Zig
     - 25,000
     - 30
     - 33
     - 36 (36-37)
     - 47
     - 496
     - 0
     - 17.90
   * - 50,000
     - Rust
     - 50,000
     - 25
     - 27
     - 30 (30-30)
     - 40
     - 3029
     - 0
     - 13.83
   * - 50,000
     - Zig
     - 50,000
     - 27
     - 29
     - 32 (32-32)
     - 47
     - 1686
     - 0
     - 16.28
   * - 100,000
     - Rust
     - 99,998
     - 24
     - 26
     - 41 (40-42)
     - 62
     - 2358
     - 0
     - 13.48
   * - 100,000
     - Zig
     - 99,996
     - 26
     - 28
     - 47 (47-48)
     - 112
     - 3116
     - 0
     - 15.95
   * - 150,000
     - Rust
     - 149,996
     - 25
     - 36
     - 51 (51-52)
     - 74
     - 1753
     - 0
     - 14.16
   * - 150,000
     - Zig
     - 149,992
     - 28
     - 43
     - 62 (62-63)
     - 978
     - 7767
     - 0
     - 16.73

.. list-table:: Reverse-proxy mode, Shield, admitted requests at fixed offered rates; latency in microseconds (``benchmarks/results/latency-latest.md``, generated 2026-10-15T23:07:14Z)
   :header-rows: 1
   :widths: 10 6 10 8 8 16 8 8 6 8

   * - Offered req/s
     - Impl
     - Achieved req/s
     - p50
     - p90
     - p99 (min-max)
     - p99.9
     - max
     - Errors
     - CPU us/req
   * - 10,000
     - Rust
     - 10,000
     - 56
     - 61
     - 65 (65-66)
     - 76
     - 555
     - 0
     - 32.25
   * - 10,000
     - Zig
     - 10,000
     - 57
     - 61
     - 67 (67-70)
     - 78
     - 1676
     - 0
     - 35.00
   * - 25,000
     - Rust
     - 25,000
     - 51
     - 54
     - 58 (58-60)
     - 72
     - 1105
     - 0
     - 28.63
   * - 25,000
     - Zig
     - 25,000
     - 51
     - 55
     - 61 (60-61)
     - 73
     - 518
     - 0
     - 30.80
   * - 50,000
     - Rust
     - 50,000
     - 47
     - 50
     - 60 (58-66)
     - 74
     - 3066
     - 0
     - 27.45
   * - 50,000
     - Zig
     - 49,998
     - 49
     - 52
     - 65 (58-70)
     - 94
     - 2833
     - 0
     - 29.92
   * - 100,000
     - Rust
     - 99,996
     - 55
     - 75
     - 100 (100-104)
     - 150
     - 2239
     - 0
     - 28.42
   * - 100,000
     - Zig
     - 99,993
     - 61
     - 87
     - 120 (120-121)
     - 1597
     - 7665
     - 0
     - 31.06
   * - 150,000
     - Rust
     - 134,344
     - 583934
     - 1544160
     - 1906273 (1631234-2218760)
     - 1967134
     - 1989964
     - 4
     - 29.22
   * - 150,000
     - Zig
     - 122,974
     - 1268822
     - 2055001
     - 2352672 (2316494-2388052)
     - 2458152
     - 2502766
     - 0
     - 31.52

In forward-auth mode the Rust daemon's p50 is 2 to 3 us lower at every rate, its p99 is lower at every rate, and it spends 13.48 to 16.92 us of CPU per request against Zig's 15.95 to 19.92 us. The tails separate at high rates: at 100,000 requests per second the p99.9 is 62 us against 112 us, and at 150,000 it is 74 us against 978 us.

In reverse-proxy mode the p50s are within 6 us of each other up to 100,000 requests per second, and the Rust p99 is lower at each of those rates (100 us against 120 us at 100,000). The p99.9 at 100,000 requests per second is 150 us against 1,597 us. At 150,000 requests per second both daemons saturate: the Rust daemon completes 134,344 requests per second and the Zig daemon 122,974, and latency grows to seconds, as an open-loop test should show above capacity. These rates are close to the closed-loop proxied throughput of the previous chapter (138,965 and 127,899 requests per second for Shield ``admitted``). The four errors of the Rust row occurred in that overload.

The p99 spreads are narrow below saturation; the widest is Zig's forward-auth p99 at 10,000 requests per second, 38 to 58 us. The max column is one request out of up to 1.5 million in a run. On a shared host we read it as the host's worst moment, not as a property of either daemon.

What the Measurement Changed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

External load has changed Sibuna's design twice. The first time was in the Zig implementation. The first run of the Zig ``tools.py`` measured a version in which each accept thread served one connection to completion and every proxied response closed the client connection. Under 64 concurrent connections the 99th-percentile latency was over 130 ms, because sixty connections waited for four workers, and the reverse-proxy runs exhausted the host's ephemeral ports with sockets in ``TIME_WAIT``. Neither defect was visible in the primitive suite. Three changes followed (SID 0002): a bounded thread per connection with a ``503`` overload path, origin response framing so that proxied connections stay open, and a pooled origin connection. The second run, with framing but a fresh origin connection per request, managed about 1,400 proxied requests per second before it exhausted the ephemeral ports. Those superseded runs were not retained as result files (measured on the Zig implementation, September 2026).

The second time was in the port. The Rust daemon kept the thread per connection (SID 0010), and its first latency runs found a tail that ``wrk`` had not shown. With 64 connections, each closed by the daemon after 4,096 requests, the 99.9th percentile at 100,000 admitted requests per second was 0.3 to 2 ms, against 0.1 ms for Zig.

The diagnosis, recorded in SID 0002 and in the documentation of ``cmd/sibuna/src/tasks.rs``, is thread turnover. Creating and ending a thread maps and unmaps its signal stack and returns its stack pages, and those address-space changes stalled the daemon's other threads. One experiment settled it: a build that never closed connections, so that no thread was created during the run, gave 54 to 60 us at the same rate. The fix reuses connection threads: a thread that finishes its connection parks and takes the next one, so a steady stream of new connections creates no threads. A thread parked for 10 seconds ends and is joined by the next launch or the next thread to finish a task, so a burst does not leave its stacks resident. A thread whose connection panics ends instead of parking. At most ``--max-connections`` connections are served at once, as before.

The tables above are from the run after the fix: a p99.9 of 62 us (Zig 112 us) in forward-auth mode and 150 us (Zig 1,597 us) in reverse-proxy mode at 100,000 requests per second. The runs before the fix are not retained as result files, which is why their figures appear only in SID 0002 and in this section.

.. admonition:: Worked example: why the stall showed at p99.9

   At 100,000 requests per second over 64 connections, each connection carries :math:`100000 / 64 = 1562.5` requests per second. The daemon closes a keep-alive connection after 4,096 requests (``MAX_REQUESTS_PER_CONNECTION`` in ``cmd/sibuna/src/connection.rs``), so a connection lasts :math:`4096 / 1562.5 \approx 2.62` s, and the generator opens about :math:`64 / 2.62 \approx 24.4` new connections per second. With a thread per connection, that is about 24 thread starts and 24 thread exits every second.

   A 10-second run at this rate measures 1,000,000 requests. Its p99.9 is exceeded by 1,000 of them, 100 per second; its p99 by 1,000 per second. If each turnover delays about :math:`100 / 24.4 \approx 4` requests in flight on other threads by a fraction of a millisecond, the delayed requests alone fill the top 0.1%, while the top 1% is still made of ordinary queueing. A rare, periodic stall moves the far tail long before it moves p99. This is why such a defect needs p99.9 and a timer on every request to be seen.

Console Overhead
----------------

SID 0007 sets the console's isolation contract. Enabling the console may cost at most 1% of data-plane throughput and at most 10% of p99 latency, measured over a matrix of configurations (compiled out, compiled in but disabled, idle, and eight active dashboards) and workloads, with repeated interleaved runs and reported uncertainty. Inconclusive or noisy runs do not establish compliance, and primitive baselines and smoke runs cannot substitute for the gate.

For the Rust port, SID 0010 records one measurement: with the console compiled in, disabled, storage only, or enabled and idle, the 16 product workloads stay within about 1% of the daemon built without it, which is within noise. The record names no result file for it. The configuration with eight active dashboards under load has not been measured for the port, so the formal gate of SID 0007 remains open for the Rust daemon. It was not passed for the Zig daemon either: SID 0007 records inconclusive formal verdicts and a supplementary paired reading of September 2026 that suggested at most 0.8% runtime cost for single nodes and 0.5% for the local cluster, accepted as an exception and not as a pass (measured on the Zig implementation).

The eight-dashboard run checks function, not overhead. ``sibuna-browser dashboards`` started a release daemon on one SQLite node with its console, four workers and a policy that allows ``/static/*``, ``/about``, ``/missing/*`` and ``/broken/*`` and challenges everything else; an origin fixture answers ``/missing/*`` with 404 and ``/broken/*`` with 500. A generator sent 200 requests per second for 30 seconds, rotating ten paths (one an SQL injection), three User-Agents and 500 forwarded addresses. Each dashboard ran in its own Chromium with its own session: dashboards 1 to 3 as administrator sessions, dashboards 4 to 8 as wall displays opened with codes the first one minted, because the console allows five sign-ins per minute per address and per account.

.. list-table:: Eight Traffic dashboards on one node (``benchmarks/results/console-8-dashboards-2026-10-15.md``, recorded 2026-10-15, Chromium 155.0.8059.39). Result: PASS
   :header-rows: 1
   :widths: 40 60

   * - Measure
     - Value
   * - Data-plane requests
     - 6,000 in 30.0 s (200 per second, 4 threads, one connection per request)
   * - Answered
     - 6,000: 200 x 1,200, 401 x 3,000, 403 x 600, 404 x 600, 500 x 600
   * - Errors (no reply)
     - 0
   * - Latency p50 / p90 / p99 / max
     - 246 / 311 / 373 / 552 us (connect included)
   * - Daemon VmRSS at start
     - 36,152 KiB
   * - Daemon VmRSS with 8 dashboards open
     - 38,028 KiB
   * - Daemon VmRSS after the traffic
     - 41,496 KiB (VmHWM 41,496 KiB)

The tiles were read every two seconds during the traffic and 3 seconds after it. Every dashboard ended with the same totals (Requests 6,000, Admitted 2,400, Challenged 3,000, Policy denied 600, Origin 4xx 600, Origin 5xx 600), received 134 to 139 ``stats`` deltas, kept its WebSocket open, and reported no exception, console error or Content-Security-Policy violation. Eight browser subscribers are well under the console's limit of 64. The daemon of this run has SQLite storage and the console, unlike the in-memory daemons of the product harness, so its resident memory is not comparable with theirs.

Historical Measurements of the Zig Implementation
-------------------------------------------------

The Zig repository measured more than the Rust harness does: whole products and admission operations against Anubis, and local clusters. The Rust harness runs neither Anubis nor a cluster under load, and these measurements were not repeated for the port. We keep the Anubis results below, condensed, as a record of the Zig implementation measured on 12 September 2026 on the same host (``paxos-zig``), at Zig revision ``41925dd``, against Anubis v1.27.0. They predate the Zig request-path changes of 1 October 2026, and they say nothing about the Rust daemon.

Sibuna and Anubis as Whole Products
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``tools.py`` started an origin stub (``caddy respond``), then each product in turn. It obtained a valid session by solving each product's challenge exactly as a browser would, and drove the four workloads of the product harness with ``wrk`` (2 threads, 64 connections, medians of three five-second runs). Sibuna used four accept threads and Anubis ``GOMAXPROCS=4``. Hashcash difficulty was matched (8 zero bits; 2 zero hex digits), with one fixed signing secret. CPU time came from ``ps`` and memory from samples every 100 ms.

.. list-table:: Historical: the Zig implementation and Anubis v1.27.0 under ``wrk``, requests per second (status) and p99 in microseconds, measured on the Zig implementation (Zig repository ``benchmarks/results/tools-comparison-latest.json``, recorded 2026-09-12T07:22:26Z, revision ``41925dd``)
   :header-rows: 1
   :widths: 14 16 14 14 14 10 10

   * - Mode
     - Workload
     - Gate req/s
     - Shield req/s
     - Anubis req/s
     - Shield p99
     - Anubis p99
   * - forward auth
     - ``admitted``
     - 219,551 (200)
     - 218,762 (200)
     - 34,105 (200)
     - 310
     - 6503
   * - forward auth
     - ``challenged``
     - 205,479 (401)
     - 204,257 (401)
     - 109,182 (401)
     - 345
     - 2379
   * - forward auth
     - ``allowed_static``
     - 219,483 (200)
     - 216,708 (200)
     - 85,247 (200)
     - 310
     - 3041
   * - forward auth
     - ``attack``
     - 218,315 (200)
     - 219,695 (403)
     - 34,309 (200)
     - 319
     - 6546
   * - reverse proxy
     - ``admitted``
     - 109,120 (200)
     - 108,193 (200)
     - 17,697 (200)
     - 5438
     - 9902
   * - reverse proxy
     - ``challenged``
     - 204,123 (200)
     - 205,427 (200)
     - 27,715 (200)
     - 327
     - 9902
   * - reverse proxy
     - ``allowed_static``
     - 116,500 (200)
     - 116,387 (200)
     - 28,333 (200)
     - 5744
     - 18285
   * - reverse proxy
     - ``attack``
     - 107,138 (200)
     - 218,583 (403)
     - 20,157 (200)
     - 325
     - 14889

In forward-auth mode Sibuna served more than six times Anubis's admitted requests (219,551 against 34,105 for Gate) with a p99 of hundreds of microseconds against milliseconds. In reverse-proxy mode Anubis's rows fell further, to 17,697 to 28,333 requests per second, and its resident memory after the reverse-proxy workloads was 580,820 KiB, against 21,524 to 21,616 KiB at idle. Sibuna's Zig daemon idled at 9,952 to 10,120 KiB and held 27,136 to 27,864 KiB after the workloads. The binaries had 34,289,568 bytes (Sibuna) and 40,001,698 bytes (Anubis).

.. admonition:: Reading the Anubis rows

   Anubis is a capable, widely deployed product, and these rows are not a claim that it is slow. It runs a garbage-collected runtime, verifies an Ed25519 signature per session check, and keeps challenge state in a store; those are design choices with benefits this harness does not measure. The rows show what a request cost each product on one host under one load shape, in September 2026. The most likely cause of the low reverse-proxy rows and the large memory is origin-connection churn under 64 concurrent clients (Go's HTTP transport keeps only two idle connections per host by default, and Anubis ran with its default flags), but the harness did not confirm that and recorded only what it observed.

Admission Operations
~~~~~~~~~~~~~~~~~~~~

``compare.py`` measured admission operations with two Python clients against forward-auth endpoints, two Sibuna workers and ``GOMAXPROCS=2``, so its absolute numbers are limited by the clients rather than the products. It compared the shape of four operations across products and token schemes: a session check, an unauthenticated check, a challenge bootstrap (interstitial plus challenge record), and the verification of a fresh proof prepared outside the timed batch.

.. list-table:: Historical: admission operations per second through two Python clients, measured on the Zig implementation (Zig repository ``benchmarks/results/admission-comparison-latest.json``, recorded 2026-09-12T07:22:04Z)
   :header-rows: 1
   :widths: 20 14 14 14 14 10

   * - Product (token)
     - Session check
     - Unauthenticated
     - Bootstrap
     - Proof verification
     - RSS
   * - Sibuna (blake3)
     - 22,010
     - 21,754
     - 11,773
     - 18,272
     - 9.5 MiB
   * - Anubis (ed25519)
     - 10,118
     - 18,301
     - 8,257
     - 10,306
     - 31.5 MiB
   * - Anubis (hs512)
     - 13,271
     - 18,342
     - 8,363
     - 11,333
     - 26.0 MiB

Clusters
~~~~~~~~

The Zig repository's ``cluster.py`` and ``distributed.py`` ran one node and three local nodes replicated through Zaxonlite, the Multi-Paxos SQLite of SID 0005, over a pre-shared key and over mutual TLS. In the three-node cases of the last recorded run (12 September 2026), a session minted by node 1 was accepted by every node, a request with that session and an SQL-injection query was refused by every node, and a solution spent on node 1 was rejected with ``400`` when replayed to node 2. Those properties come from the shared seed and the issuer-bound challenge, which the Rust port keeps bit for bit (SID 0010). The throughput, idle cost, ban propagation and failover figures of those runs measured Zaxonlite's replication, which the Rust port replaced with one shared PostgreSQL database (SID 0011); they have no counterpart, and we drop them.

Not Measured
------------

.. list-table:: What this part does not measure, and what stands in for a measurement
   :header-rows: 1
   :widths: 22 39 39

   * - Subject
     - Why it is not measured here
     - What stands in
   * - Anubis
     - The Rust harness has no Anubis runner; the comparison was not repeated for the port
     - The historical Zig measurements above (September 2026)
   * - SafeLine community edition 9.x
     - Ships only as a Docker Compose stack; the host had no Docker daemon, and the detector image is not an open-source build that can be compiled there
     - Published, vendor-reported facts (checked September 2026): detection rate 71.65% (balance) and 76.17% (strict), false positives 0.07% (balance) and 0.22% (strict); minimum host Linux x86_64 or arm64 with SSSE3, 1 CPU core, 1 GB RAM, 5 GB disk, Docker 20.10.14+ and Compose 2.0+
   * - Cloudflare WAF
     - A hosted service; a loopback measurement would measure the network path, not the WAF
     - Published plan quotas (checked September 2026): custom rules Free 5, Pro 20, Business 100, Enterprise 1000; rate limiting rules Free 1, Pro 2, Business 5, Enterprise 100
   * - A cluster under load
     - No harness drives several nodes on one PostgreSQL database yet
     - The cluster's protocol properties, which the Zig runs checked and the port keeps (above)
   * - Storage on the request path
     - Both daemons run in memory in every harness
     - SID 0011: one storage thread owns all SQL, and the request path never waits on it
   * - TLS, WAN, real browsers
     - The harnesses use loopback and HTTP; sessions are solved once per case by ``sibuna-pow``
     - Nothing; a deployment measures its own path
   * - The browser solver's solve time
     - The harness solves at 8 bits with the native solver
     - The module size above; Part VII explains why native timings do not stand for browser solve times
   * - Allocation counts
     - The harness does not instrument the allocator
     - The steady-state tests of Part V
   * - Console isolation with eight active dashboards under load
     - The formal gate of SID 0007 has not been run for the port
     - The SID 0010 figure (within about 1%, console idle) and the functional run above

A row in this table is not a claim about the product's performance. SafeLine's own numbers concern detection quality, not throughput, and Cloudflare publishes plan quotas rather than per-request costs. Anyone with a Docker host can run SafeLine behind the same ``wrk`` workloads.

.. admonition:: Exercise 8.1

   Run ``cargo xtask bench primitives --zig <binary>`` on another machine and compare the Hashcash verification and token verification rows with the reference host. Which of the two depends most on hardware hash instructions, and why?

.. admonition:: Exercise 8.2

   In the forward-auth table, compute the cores busy of a row as its CPU microseconds per request times its requests per second, divide the CPU microseconds per request by it, and compare the result with the measured latency. Why is the per-request CPU cost higher than the primitive classification cost from the first table, and which components account for the difference?

   *Hint:* list everything between ``accept`` and the flushed response that the primitive suite does not time.

.. admonition:: Explain the invariant

   Every figure in this part is a median over repetitions, with its spread beside it. Explain the difference between a median-of-batches figure and a per-request p99.9, why the primitive table reports the former and the latency table the latter, and why only the latter could reveal the thread-turnover stall described above.
