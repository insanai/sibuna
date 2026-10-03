# zaxonlite

A distributed SQL database built on SQLite. Write to any node, read from
any node, and consensus keeps every copy identical.

**Read the book:**
[The Zaxonlite book (PDF)](https://insanai.github.io/zxdocs/zaxonlite.pdf)
-- architecture, formats, operations, verification, and conformance,
rebuilt on every change by the
[zxdocs](https://github.com/insanai/zxdocs) workflow.

## The problem

SQLite is a wonderful thing. It is one file, one library, no server. You
link it, you open a path, and you have a real SQL database. Then the disk
that holds the file dies, and you have nothing.

So you want copies. Three machines, one database, and every copy exactly
the same, even while machines crash and restart and the network misbehaves.
The moment you say "exactly the same", you have a consensus problem. This
project solves it with [paxos-zig](https://github.com/insanai/paxos-zig),
a Multi-Paxos library, and it stays embeddable: link one Zig library (or
the C ABI), open one data directory, and you get a durable SQL database as
a single node or as a distributed cluster that accepts reads and writes at
every node. The companion CLI is `zaxon`.

## Two ideas worth understanding

Everything else in this repository follows from two decisions.

**Replicate the bytes, not the SQL.** Most replicated SQL systems send the
SQL text to every node and execute it everywhere. That is a trap. Run
`insert ... values (random())` on three machines and you get three different
databases, each one convinced it is right. Zaxonlite executes each
transaction once, on the leader. SQLite's own write-ahead log tells us
exactly which pages that transaction committed, and those page images are
what Paxos replicates. Nondeterministic SQL is safe by construction, because
nothing is ever executed twice. Replicas converge to byte-identical files,
and the tests verify that with digests across cluster members.

**The journal is the truth; the database file is a cache.** Every protocol
write is framed, checksummed, appended, and fsynced before the consensus
layer is allowed to proceed. A write is acknowledged only after its slot
commits and carries the client's own batch. The SQLite file is just
materialized state: delete `current.db` and the node rebuilds it from the
last durable state anchor plus the journal suffix. If you remember one
thing about operating zaxonlite, remember this one.

## What you get

- Reads and writes at every node. A follower answers a write with a leader
  redirect that the client follows automatically; one elected leader orders
  each transaction. One to nine voters, and any number of non-voting nodes:
  `standby` (promotion-eligible copy), `read-replica` (read copy),
  `witness` (votes, holds no SQL), and `gateway` (a stateless router).
- Exactly-once sessions. Session state rides inside the replicated
  transaction, so retries replay recorded results across restarts and
  leader failover.
- Three read levels: `any` (local, possibly stale, labeled, with a
  freshness bound), `leader`, and `linearizable` (a quorum read fence with
  no log append and no disk sync per read).
- Bounded recovery without rollover: slots are 64-bit and never reset,
  periodic durable state anchors bound restart replay to the journal
  suffix, and the cluster trims history it has certified as applied
  everywhere -- no epoch seal, no full-database copy or hash on the write
  path, whatever the database size.
- Decided membership: served clusters persist a consensus-decided
  registry, and `zaxon replace-voter` replaces one failed data voter
  online -- same database identity, client connections stay open, and the
  removed node ID is retired forever.
- Hybrid search that replicates like any other table: SQLite FTS5 for
  text, the statically linked sqlite-vec (v0.1.9, pinned) for vector
  storage with a compact one-bit coarse scan reranked by an exact SIMD
  cosine kernel, and `rrf`/`dbsf` fusion functions registered on every
  connection. The application supplies embeddings; zaxonlite never runs a
  model. A typed `search` operation enforces the 4,096-candidate ceiling.
- Mutual TLS 1.3 on every production TCP listener, with short-lived
  single-use certificate enrollment (`zaxon enroll`).
- A C ABI: `libzaxonlite.a` plus `include/zaxonlite.h`.
- A crash matrix that kills real processes at chosen write-path points and
  proves recovery, plus fuzzing, soak, and network-fault suites.

## Connection deadlines and shutdown

Client connection establishment has a ten-second total budget, including the
socket connection, TLS, and PSK authentication. Zig callers can configure
`client.Transport.connect_timeout_ms`; `null` disables the budget and zero
expires immediately. `Connection.openWithTransportDeadline` accepts an outer
`std.Io.Clock.Timestamp` on the `.awake` clock and uses the earlier deadline.
`Connection.callWithDeadline` bounds a request and its response; after timeout,
close that connection. Ordinary RPCs and backup streams retain their existing
operation-duration behavior.

The cluster client tries another seed after a connection failure and follows
verified leader redirects. Once request transmission begins, a transport error
is returned without automatically resending the request: a lost reply does not
mean a write failed. Use session IDs and sequences to retry uncertain writes
idempotently.

`Embedded.open` applies `startup_timeout_ms` to the entire readiness probe,
including authentication and the status response. `Embedded.close` signals the
local server directly and joins it; shutdown cancels consensus waits without
requiring further Paxos ticks. An in-flight write may still have committed.
Callers must finish using an embedded object before destroying it.

## Quick start

One durable local node, authorized by owner-only socket permissions:

```sh
zaxon serve --data ./d1 --node 1 --listen unix:./zaxon.sock
zaxon sql   --data ./d1        # interactive shell, embedded mode
```

A three-voter cluster (repeat symmetrically on nodes 2 and 3):

```sh
zaxon serve --data ./n1 --node 1 --listen 127.0.0.1:9901 \
    --peer 2@127.0.0.1:9902/data-voter \
    --peer 3@127.0.0.1:9903/data-voter \
    --tls-cert n1.crt --tls-key n1.key --tls-ca ca.crt
```

Then talk to it. The client follows leader redirects:

```sh
zaxon wait   --connect 127.0.0.1:9901 --leader
zaxon exec   --connect 127.0.0.1:9901,127.0.0.1:9902 --sql "insert ..."
zaxon query  --connect ... --sql "select count(*) from t" --level linearizable
zaxon status --connect 127.0.0.1:9902 --json
zaxon backup --data ./d1 --to ./backup.db
```

Every client TCP command supplies its identity with `--tls-cert`,
`--tls-key`, and `--tls-ca`. For a one-machine experiment, `--dev-psk`
permits PSK-only TCP on loopback addresses only.

`zaxon sql` on a terminal is a rich REPL: readline-style editing, arrow-key
history with `ctrl+r` search, SQL highlighting, aligned tables, and a pager.
It is built on the shared
[zaxon-cli-ui](https://github.com/insanai/zaxon-cli-ui) module. Piped or
scripted invocations keep plain, byte-for-byte stable output.

Exit codes: `0` ok, `1` SQL/session error, `2` usage, `3` integrity
failure, `4` unavailable.

## The library

```zig
const zaxonlite = @import("zaxonlite");

var node = try zaxonlite.Node.open(gpa, io, .{ .directory = "./data" });
defer node.close();

_ = try node.exec("create table items(id integer primary key, v text)");

const session = try node.openSession();
_ = try node.execIdempotent(session, 1, "insert into items(v) values ('tea')");

var rows = try node.query(gpa, "select id, v from items order by id");
defer rows.deinit();
```

And from C:

```c
#include <zaxonlite.h>
zaxonlite *db;
zaxonlite_open("./data", &db);
int64_t changes;
zaxonlite_exec(db, "insert into items(v) values ('tea')", &changes);
zaxonlite_close(db);
```

## Benchmarks

The comparison harnesses live in [`benchmarks/`](benchmarks/), and every
recorded run, with environment metadata, is in
[`benchmarks/results/`](benchmarks/results/). The systems compared are
[rqlite](https://github.com/rqlite/rqlite) (v10.2.7, installed binaries)
and [dqlite](https://github.com/canonical/dqlite) (v1.18.7, Linux-only).
Each comparison harness runs three durable voters
per system with equal payloads, excluded warmup, verified results, and
percentile latency.

First, the boring benchmark: one client, sequential single-row writes, each
waiting for full durability. macOS arm64, three local voters, 256-byte rows,
recorded 27 August 2026 with zaxon 0.6.0.

| System            | Writes/s | p50 latency | p99 latency |
| ----------------- | -------: | ----------: | ----------: |
| zaxonlite 0.6.0   |     65.9 |     15.1 ms |     21.8 ms |
| rqlite v10.2.7    |     45.9 |     21.4 ms |     32.2 ms |

Earlier recorded runs of this same table had zaxonlite losing it (28
writes/s against 44.5 in July 2026), and honesty required printing that.
The global-slot journal that replaced the old epoch rollover (ZDS 0011)
removed enough bookkeeping around the disk that the ranking flipped. Both
systems still pay for a full cache flush on every write; the difference
is what happens around the flush. If a benchmark table only shows the
rows its author likes, you should not trust the other rows either.

Second, the benchmark that looks like a product: a deterministic
order-processing simulation. Four clients, idempotent writes, linearizable
reads, and a fixed crash schedule: kill a follower under traffic, kill the
leader under traffic, catch each up, then restart the whole three-node
cluster. Both systems must pass correctness checks at the end: inventory,
revenue, ledger, uniqueness, and per-node convergence.

The table below was recorded 13 September 2026 on Linux x86-64 with
zaxonlite 0.7.0 and rqlite v10.2.7.

| Measure                        | zaxonlite | rqlite v10.2.7 |
| ------------------------------ | --------: | -------------: |
| Healthy throughput             |  1,083/s  |      6,439/s   |
| Throughput, follower down      |    280/s  |      5,820/s   |
| Throughput, leader down        |    188/s  |        206/s   |
| Leader crash to first success  |    592 ms |      1,713 ms  |
| Follower catch-up              |    280 ms |         51 ms  |
| Full cluster restart           |    485 ms |      1,588 ms  |

Older recordings of this simulation showed zaxonlite near 1,800
operations per second; those runs predate the full-fsync default, so
their writes did not flush the drive cache. The table above is the
durability-matched run, and it is the one to trust. The two tables
measure different things: one client waiting on one disk, and a cluster
doing concurrent work while members die and recover. Run the harnesses
yourself before believing anyone's table, including this one:

The Linux host also ran the narrower sequential-write comparison against
dqlite. This is 1,000 measured 256-byte autocommit writes after warmup; every
measured value was read back. It does not include the realistic workload's
failure, catch-up, or restart phases.

| System             | Writes/s | p50 latency | p99 latency |
| ------------------ | -------: | ----------: | ----------: |
| zaxonlite 0.7.0    |    3,030 |     0.32 ms |     0.42 ms |
| dqlite v1.18.7     |      945 |     0.97 ms |     1.56 ms |

These are observations from the same Linux x86-64 run on 13 September 2026,
not portable throughput claims.

```sh
zig build benchmark                       # write/read/recovery microbenchmarks
zig build bench-cluster -- tls 2000 2000  # three-node transport benchmark
sh benchmarks/compare-rqlite-3node.sh     # needs installed rqlited/rqlite
sh benchmarks/compare-dqlite-3node.sh     # Linux; needs pinned dqlite-demo
```

## The security boundary, plainly

Production TCP requires mutual TLS 1.3. Peer certificate common names are
bound to configured node IDs, and TLS covers SQL, results, payloads, and
state transfers. An optional provider-file PSK adds sequenced HMAC protection
inside TLS. `--dev-psk` is for loopback experiments only; plaintext TCP is
gated behind test failpoints; local single-node service uses an owner-only
Unix socket. The decided membership registry is the authorization
boundary: only identities it names can connect, and a replaced voter's ID
is rejected even with an otherwise valid certificate. Privileged
membership operations additionally require a `zaxon-admin-<name>`
certificate from the server's allow-list.

Files on disk (database, WAL, journal, backups) are plaintext.
If you need protection from someone holding the disk, use full-disk or
filesystem encryption. We would rather tell you that than have you assume
otherwise.

## Current limits

Writes are accepted at any node but ordered by one elected leader at a
time; there is no multi-master concurrency. One to nine voters. Voter
replacement is a decided, operator-initiated operation -- one voter at a
time, at least three voters -- and nothing replaces a voter
automatically. Transactions are capped at 64 MiB minus framing. Windows needs release 1809 or Server 2019 and newer, on NTFS:
the storage layer relies on POSIX rename semantics and on the NTFS
metadata log to persist directory entries, and a node refuses to start
where a probe shows they are missing rather than quietly weakening the
guarantee. Unix socket listeners are POSIX-only; use loopback TCP on
Windows. Native Windows CI runs the C ABI contract and the zxlite DB-API,
server/client, search, threading, and SQLAlchemy suites. The 10,000-crash
stress gates and the 1 GiB recovery target are deferred; the checked
recovery fixture is 1 MiB. POSIX hosts enforce owner-only modes on data and
provider files; Windows deployments must apply equivalent NTFS ACLs because
Windows has no POSIX mode-bit boundary.

## Build and test

Requires Zig 0.16 and system OpenSSL 3. SQLite 3.50.4 (built with FTS5)
and sqlite-vec 0.1.9 are pinned `build.zig.zon` dependencies. The [paxos-zig](https://github.com/insanai/paxos-zig)
library is declared as a path dependency, so a checkout expects it beside
this one; released builds pin it by content hash with `zig fetch`.
Cross-builds pass `-Dopenssl-prefix` for the
target OpenSSL SDK.

```sh
zig build                    # zig-out/bin/zaxon and libzaxonlite.a
zig build check              # compile every binary without running
zig build test               # unit + shell + single-process integration
zig build test-crash         # spawned-process crash matrix
zig build test-cluster       # three-process scenario (-Dcluster-runs=N)
zig build test-replace-cluster # decided voter replacement under mTLS
zig build test-roles         # voters, witness, standby, read replica
zig build test-gateway       # stateless end-to-end gateway
zig build test-fault-network # loss/duplication/reorder/fragmentation
zig build test-cli           # CLI contract
zig build test-cabi          # C ABI smoke test
zig build fuzz               # seeded property fuzzing
zig build soak               # sustained mixed load
```

API documentation: `zig build docs`, then `zig build docs-serve` and open
http://localhost:8000 (the autodoc output is a WASM application that
browsers refuse to load from `file://`).

## Data directory layout

```text
data/
  LOCK                     # exclusive process lock
  identity                 # node/database IDs, current configuration
  consensus/               # lifetime journal: slot-named segments,
                           #   MANIFEST, APPLIED.0/1 anchors, TRIM state
  payloads/aa/<hash>       # immutable frame payloads by SHA-256
  registries/<config>      # canonical decided-registry blobs
  REGISTRY                 # active decided-registry pointer
  PENDING-OP               # one in-flight replacement request, if any
  JOIN                     # one-shot join descriptor on an enrolling node
  current.db               # materialized SQLite image (rebuildable)
```

## Where the deep answers live

The full book (architecture, on-disk and wire formats, operations,
verification, conformance) and the design records are in the separate
[insanai/zxdocs](https://github.com/insanai/zxdocs) repository; the
compiled PDF is always at
[insanai.github.io/zxdocs/zaxonlite.pdf](https://insanai.github.io/zxdocs/zaxonlite.pdf).
Start with
the product plan and safety argument (ZDS 0002), the wire/disk
compatibility policy (ZDS 0004), and the interactive shell design
(ZDS 0005).

## Related projects

- [paxos-zig](https://github.com/insanai/paxos-zig): the consensus library
  underneath.
- [zaxon-cli-ui](https://github.com/insanai/zaxon-cli-ui): the shared
  terminal UI behind the `zaxon sql` shell.
- [zxdocs](https://github.com/insanai/zxdocs): books and design records.

## License

MIT. Copyright 2026 Vikrant Rathore and Ronak Rathore. See
[LICENSE](LICENSE).
