#import "theme.typ": *
#import "figures.typ": *

#part_page("V", [Deterministic Memory and Zero-Allocation Engineering], [
  We follow a connection from accept to response through one stack buffer, and examine the
  concurrent data structures that let many worker threads share state without heap
  allocation on the request path.
])

== The Connection Loop

#objectives([
  By the end of this chapter, you should be able to explain how one 64 KB buffer serves an
  entire keep-alive connection, how the head and body are located without copying, why every
  connection gets its own bounded thread, and how the proxy learns the origin's framing so a
  proxied client connection can stay open.
])

=== One Thread per Connection, Bounded

Accept threads (`--workers`, one per CPU by default) share the listening socket. Each accepted
connection gets its own thread with a one-megabyte stack. The accept loop then returns to
`accept`. The first design served a connection on the accept thread itself. It performed
well with one client, but at sixty-four connections most clients waited for a worker to
finish its 256-request quota. In that comparison, tail latency fell from over 100 ms to
under one millisecond after introducing a thread per connection (Part VIII).

The number of connection threads is bounded by `--max-connections` (1,024 by default). Past
the bound, the accept loop returns `503 Service Unavailable`, closes the new socket and
increments `sibuna_overloaded_total`. It creates no connection thread.

A connection thread touches about 100 KB of its stack in the ordinary path. The connection
limit bounds how many such stacks can be active; CRS workspace has its own reserved pool.
The idle reaper interrupts connections that stop making progress for `--idle-timeout`.
Active streams can live longer, but they remain subject to the connection quota.

=== One Buffer per Connection

Request-path allocations introduce memory growth, fragmentation and allocator contention.
Sibuna instead reserves the storage needed for classification, proof verification and proxy
handling. These operations perform no heap allocation. The connection handler owns a 64 KB
read buffer and a 16 KB write buffer on its thread's stack. Parsed request fields borrow
slices from the read buffer; the optional CRS engine leases its preallocated workspace.

```zig
pub fn handleConnection(stream: Io.net.Stream, io: Io, state: *AppState) void {
    defer stream.close(io);
    var conn_buf: [max_request_bytes]u8 = undefined;   // 64 KB
    var reader = stream.reader(io, &conn_buf);
    var writer_buf: [16 * 1024]u8 = undefined;
    var writer = stream.writer(io, &writer_buf);
    // ... format the peer address once, then serve up to 4096 requests
    while (served < max_requests_per_connection) : (served += 1) {
        const keep = serveOne(&conn) catch break;
        if (!keep) break;
    }
}
```

`readHead` fills the buffer until the blank line appears, refusing heads over 16 KB with `431`.
The parser produces a `Request` whose method, path, query, headers and cookies borrow the
buffer. The body follows the head and is read up to the available capacity.
`toss(body_end)` advances the reader to the next keep-alive request.

The request target must be origin-form (`/...`), or `*` for `OPTIONS`. Absolute-form, authority-form
(`CONNECT`), fragments and any other target are answered `400` before policy, CRS or the
origin see them. Otherwise, a rule for `/admin` could miss `http://host/admin`, or `CONNECT`
could create an uninspected tunnel. RFC 9112 §3.2.2 requires accepting absolute-form;
Sibuna's rejection is a documented compatibility deviation. The control-character scan also
rejects `#`, so it needs no extra pass.

Following RFC 9112 §3.2, HTTP/1.1 requests receive `400` for repeated, missing or empty `Host`
fields. Sibuna also requires literal host bytes with an optional port. It rejects percent
escapes so that a value such as `localhost%00` cannot name different hosts to policy and
origin.

Internal responses have explicit lengths and can keep the connection open. Proxied responses
can also keep it open when the origin supplies framing, as described below.

=== The Proxy Head Rewrite

The head is not forwarded verbatim. `writeHead` re-emits the request line and each header,
dropping hop-by-hop fields such as `Connection` and `Transfer-Encoding`. It also replaces
incoming `X-Forwarded-For` and appends Sibuna's audit fields. Body framing is generated.
A `Content-Length` is
re-emitted. A chunked body that ended within the connection buffer is decoded in place and
sent with its length. A longer one is announced as `Transfer-Encoding: chunked` and
re-chunked one read at a time (SID 0009). The added fields are:

```
Connection: close
X-Forwarded-For: <client>
X-Real-IP: <client>
X-Sibuna-Status: PASS
X-Sibuna-Rule: session | robots-txt | ip/cidr-trie | ...
```

Bodies larger than the buffer stream from the client reader to the origin writer. The relay
uses the buffer space after the request head. This keeps borrowed paths and headers alive
for audit and telemetry that run after the upload, without copying the head. The unit test
in `proxy.zig` verifies that the rewrite removes spoofed `X-Forwarded-For` and adds the
audit fields.

=== Relaying the Origin Response

The first proxy read until the origin closed, then closed the client connection. Every
request therefore needed a new TCP connection. Load tests produced many sockets in
`TIME_WAIT` and eventually exhausted loopback's ephemeral ports. The proxy now reads the
origin's head, bounded to 16 KB, and determines body framing using RFC 9112:

#api_anchor([`proxy.parseResponseHead`], [
  Returns the status and one of four framings: no body (HEAD, 1xx, 204, 304), a
  `Content-Length`, chunked transfer coding, or close-delimited.
], source: "libs/net/src/proxy.zig")

```zig
pub const Framing = union(enum) { none, length: u64, chunked, until_close };

pub fn parseResponseHead(head: []const u8, head_request: bool) ?ResponseHead {
    if (head.len < 13 or !std.mem.startsWith(u8, head, "HTTP/1.") or
        (head[7] != '0' and head[7] != '1') or head[8] != ' ' or head[12] != ' ')
        return null;
    const status = std.fmt.parseInt(u16, head[9..12], 10) catch return null;
    if (status < 100) return null;
    var framing: Framing = .until_close;
    var chunked = false;
    var encoded = false;
    var keep_alive = head[7] == '1';
    var closing = false;
    // ... validate headers, collect framing and Connection flags in one pass
    if (head_request or status / 100 == 1 or status == 204 or status == 304) {
        framing = .none;
    } else if (encoded) framing = if (chunked) .chunked else .until_close;
    if (framing == .until_close or closing) keep_alive = false;
    // ... reject framing fields nominated by Connection
    return .{ .status = status, .framing = framing, .keep_alive = keep_alive };
}
```

The head is re-emitted to the client with the origin's `Connection` headers replaced by
Sibuna's own decision. The relay uses `streamExact` for an explicit length, forwards size
lines, data and trailers for chunked coding, and uses `streamRemaining` for a close-delimited
body. A close-delimited body requires closing the client connection to signal its end.
Framed responses can reuse the client connection if the client permits it.

=== The Origin Pool

Parsing the framing also tells the proxy whether the *origin* socket can be used again: an
HTTP/1.1 response without `Connection: close` (or an HTTP/1.0 one with `keep-alive`) whose body
was fully consumed leaves the socket at a clean request boundary. Such sockets go into a fixed
pool of 256 idle origin connections guarded by a lock. The next proxied request can reuse
one instead of connecting. In the earlier four-core measurement, creating an origin
connection for every request limited throughput to about 1,400 requests per second before
loopback ran out of ephemeral ports (Part VIII).

A pooled socket may have been closed by the origin while idle. The proxy notices in one of two
ways: a failed write, or end-of-stream before the first response byte. No response has reached
the client at that point. For a fully buffered `GET`, `HEAD` or `OPTIONS` request, it retries
once on a fresh connection. It does not take another pooled socket, because that socket
could also be stale.

Other methods and streamed uploads are not replayed. When their origin exchange fails
before a response, the client receives `502`. This avoids repeating a mutation or attempting
to resend body bytes the relay no longer owns. Unit tests compare the relayed bytes, allowing
for the rewritten connection header. An end-to-end test sends two requests on one client
socket and uses an origin sequence header to confirm reuse of the origin connection.

#exercise([5.1], [
  A client sends a 200 KB upload. Trace which bytes live in the 64 KB buffer, which are relayed
  by `relayBody`, and why the proxy must write the head to the origin *before* relaying.
])

== Concurrent State Without Allocation

#objectives([
  Analyse the adaptive lock, the Robin Hood spent set, the GCRA limiter, the lock-free ban table,
  the MPSC incident ring, and the read-copy-update engine slot.
])

=== Short Locks and Sharding

Most table updates need a short critical section. `core.Lock` first attempts an atomic
acquisition and spins briefly if the lock is occupied. If the wait continues, it parks the
thread on a futex so that the holder can run. An uncontended operation needs no kernel wait.

Tables are split into 16 shards by key hash. For independent uniformly distributed hashes,
two operations choose the same shard with probability $1/16$. Traffic concentrated on a few
keys can still contend heavily within their shards.

=== The Robin Hood Spent Set

Only accepted proofs enter the spent set (chapter 3). Each shard is an open-addressed array of
4096 entries of `{tag: [16]u8, expires_at: u64, dist: u8, occupied: bool}`. Robin Hood insertion
(Celis, 1986) displaces any occupant closer to its home than the incoming key, which keeps probe
lengths tightly clustered; lookups stop as soon as they meet an entry nearer its home than they
are to theirs.

```zig
fn insert(self: *Shard, tag: *const Tag, expires_at: u64, now: u64) StoreError!void {
    if (!self.canInsert(tag, now)) return error.StoreFull;
    var carry = Entry{ .tag = tag.*, .expires_at = expires_at, .dist = 0,
    .occupied = true };
    var idx = home(tag);
    while (carry.dist < MAX_PROBE) {
        const e = &self.entries[idx];
        if (!e.occupied) { e.* = carry; self.live += 1; return; }
        // Overwriting an expired occupant is safe only when the new
        // distance is not smaller, so keys probing past this slot still
        // pass the early-termination test.
        if (e.expired(now) and carry.dist >= e.dist) { e.* = carry; return; }
        if (carry.dist > e.dist) {
            std.mem.swap(Entry, &carry, e);
            if (carry.expired(now)) return;
        }
        idx = (idx + 1) % SHARD_CAPACITY;
        carry.dist += 1;
    }
    return error.StoreFull;
}
```

The expired-slot rule is the subtle part: an expired entry may be overwritten in place only by a
key at least as far from its home, otherwise a later key that probes past the slot would stop
early and be lost. Expired entries that get displaced are simply dropped. No sweeper thread is
needed. Insertion first checks that bounded displacement can succeed without losing a live tag.

=== GCRA: Rate Limiting in One Integer

The Generic Cell Rate Algorithm (ATM Forum, 1996) is the virtual-scheduling form of the leaky
bucket. Per client it stores one *theoretical arrival time* (TAT). With emission interval
$T = max(1, ceil(W / N))$ for a positive limit $N$ per window $W$, and burst tolerance $tau = (N - 1) T$:

$ "arrival at" t "conforms" <=> "TAT" <= t + tau, quad "then" "TAT" <- max("TAT", t) + T. $

#callout([Theorem (token-bucket bound)], [
  After the first conforming arrival at $t_1$, the $k$-th conforming arrival satisfies
  $t_k - t_1 >= (k - 1) T - tau$. Hence any interval of length $L$ contains at most
  $N + floor(L / T)$ conforming arrivals: a burst of $N$, then one per $T$. There is no
  fixed-window boundary artefact beyond the defined burst, and no per-request history.
])

#book_figure([GCRA admission for a limit of 5 per second: a burst of five, then one every 200 ms], gcra_timeline())

```zig
fn check(self: *Shard, io: Io, key: u64, now_ms: u64, limits: Limits) Decision {
    const interval = limits.emissionInterval();
    const tau = limits.burstTolerance();
    self.lock.lock(io);
    defer self.lock.unlock(io);
    const cell = self.locate(key, now_ms) orelse return .{
        .capacity_exhausted = true, .limited = true,
        .retry_after_ms = interval, .remaining = 0,
    };
    const tat = @max(cell.tat_ms, now_ms);
    if (tat > now_ms +| tau) {
        return .{ .limited = true, .retry_after_ms = tat - tau - now_ms, .remaining = 0 };
    }
    cell.tat_ms = tat +| interval;
    // ... remaining = floor((t + tau - TAT) / T) + 1
}
```

Cells are 16 bytes in 16 shards of 512 slots with a 16-slot probe window. A cell with
$"TAT" <= t$ has drained and can be reclaimed immediately. The `Retry-After` header is
computed from the same arithmetic. Saturated probe windows refuse new clients rather than
evicting active quota state; a zero configured rate refuses requests.

=== The Versioned Ban Table

Bans use 4096 slots with atomic key, expiry and version fields. A writer brackets updates with
version increments; readers accept only a stable even version and retry concurrent changes.
Sequential consistency prevents mixing an old identity with a replacement expiry. Readers
take no mutex, but can wait for a writer and are not wait-free. These atomic operations have
real cost, measured indirectly in the HTTP harness rather than assumed free.

=== The MPSC Incident Ring

When Shield denies a request or the honeypot fires, the incident is copied into a
fixed 1.3 KB record and pushed onto a bounded multi-producer single-consumer ring (Vyukov's
sequence-stamped design, 512 slots). Producers are worker threads; the consumer is the storage
thread. A full ring drops the newest record instead of blocking a response. The drop counter
makes this loss visible. Once the storage thread moves a record into a pending batch, it
retains that record until commit is confirmed, including after a database error.

=== Read-Copy-Update Engine Slots

The policy engine has fixed-capacity automaton tables and is rebuilt off the hot path when
policies change. Workers must never observe a half-built engine, and the builder must never
overwrite an engine a request is still reading. Sibuna uses two slots with reader counts:

#book_figure([Engine slot swap: workers pin a slot; the storage thread swaps the pointer and waits for the old slot's readers to drain before rebuilding into it], rcu_swap())

```zig
pub fn acquireEngine(self: *AppState) *EngineSlot {
    while (true) {
        const slot = self.slot.load(.seq_cst);
        _ = slot.readers.fetchAdd(1, .seq_cst);
        if (self.slot.load(.seq_cst) == slot) return slot;
        _ = slot.readers.fetchSub(1, .seq_cst);
    }
}

pub fn publishEngine(self: *AppState, fresh: *EngineSlot) *EngineSlot {
    const old = self.slot.swap(fresh, .seq_cst);
    while (old.readers.load(.seq_cst) != 0) std.atomic.spinLoopHint();
    return old;
}
```

Sequentially consistent pointer and reader-count operations establish one total order
across the two atomics. Merely using acquire/release on separate objects is insufficient.
The re-check after incrementing closes the race in which a writer swaps between the reader's
load and its increment and observes zero readers: the reader notices the pointer changed,
releases it and retries on the new slot. A caller must release its slot before waiting for a
rebuild. Keeping a slot pinned while waiting would prevent that rebuild from completing.

Each physical slot owns its own allocation arena, so a rebuild into the spare slot cannot free
strings the active engine still references. A request copies the matched rule name into a
bounded buffer and releases its slot *before* proxy I/O begins; otherwise a slow origin would
hold a reader count and stall the next publication for as long as the origin took to answer.

#exercise([5.2], [
  Using the GCRA theorem, compute the maximum number of requests a single client can get
  through in the first 3 seconds after being idle, for `--rate-limit 100 --rate-window 10`.
  Compare with a fixed 10-second window counter and with a true sliding-window log.
])

#teach_back([
  Explain why an expired Robin Hood entry can be overwritten only by a key with a distance at
  least as large, using a three-slot example.
])
