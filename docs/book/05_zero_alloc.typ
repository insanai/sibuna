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
connection is handed to its own thread with a one-megabyte stack, and the accept loop goes
straight back to `accept`. The alternative, serving a connection to completion on the accept
thread, was the first design: it measured well on a single client and badly on sixty-four,
because sixty of them waited for a worker to finish its 256-request quota. The tail latency
under that design was over 100 ms at 64 connections; with a thread per connection it is
under one millisecond (Part VIII).

The number of connection threads is bounded by `--max-connections` (1,024 by default). Past
the bound the accept loop answers `503 Service Unavailable` on the new socket and closes it
without spawning anything, and counts the event in `sibuna_overloaded_total`. Memory is
bounded the same way: a connection thread touches about 100 KB of its stack, so the worst case
is a known number rather than a function of how many sockets a client can open. The idle
reaper (below) closes connections that stop sending, so a slow client cannot pin a thread
past `--idle-timeout`.

=== One Buffer per Connection

Every dynamic allocation on a request path is a denial-of-service lever: fragmentation over
days, allocator lock contention across threads, and amplification by attackers who craft
requests that maximise allocation. Sibuna's rule is absolute: classification, verification, and
proxy hand-off run with zero heap allocation. The connection handler owns a 64 KB buffer on its
thread's stack and a 16 KB write buffer; everything else is a slice into them.

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
The parser produces a `Request` whose method, path, query, headers, and cookies are slices of
the buffer; the declared body is filled up to what fits and sliced after the head; then
`toss(body_end)` advances the reader so the next keep-alive request starts cleanly. The request
target must be origin-form (`/...`), or `*` for `OPTIONS`. Absolute-form, authority-form
(`CONNECT`), fragments and any other target are answered `400` before policy, CRS or the
origin see them: a path rule written as `/admin` would not match `http://host/admin`, and an
origin that honours `CONNECT` could open a tunnel nothing inspects. RFC 9112 §3.2.2 asks
servers to accept absolute-form; Sibuna refuses it rather than guess a normalization. The
same byte loop that rejects control characters rejects `#`, so the check adds no pass. `Host`
follows RFC 9112 §3.2: a repeated field, or a missing or empty one in HTTP/1.1, is answered
`400`, and the value must be literal host bytes with an optional port. Percent escapes are
refused, so `localhost%00` cannot name one virtual host to policy and another to the origin.
Internal
routes are length-delimited and keep the connection open. Proxied requests keep it open too,
provided the origin's response is framed; the next section shows how the proxy decides.

=== The Proxy Head Rewrite

The head is not forwarded verbatim. `writeHead` re-emits the request line and each header,
dropping hop-by-hop fields (`Connection`, `Transfer-Encoding`, any incoming `X-Forwarded-For`)
and appending the audit set. Body framing is generated, never copied. A `Content-Length` is
re-emitted. A chunked body that ended within the connection buffer is decoded in place and
sent with its length. A longer one is announced as `Transfer-Encoding: chunked` and
re-chunked one read at a time (SID 0009). The audit set:

```
Connection: close
X-Forwarded-For: <client>
X-Real-IP: <client>
X-Sibuna-Status: PASS
X-Sibuna-Rule: session | robots-txt | ip/cidr-trie | ...
```

Bodies larger than the buffer are relayed in 16 KB chunks from the client reader to the origin
writer before the response is streamed back. The unit test in `proxy.zig` asserts the rewrite
drops a spoofed `X-Forwarded-For` and injects the audit fields.

=== Relaying the Origin Response

The first proxy streamed the origin's bytes until the origin closed and then closed the client:
correct framing with no parsing, at the price of a new TCP connection per proxied request.
Under a load generator that price was visible as tens of thousands of sockets in `TIME_WAIT`
and, on loopback, exhausted ephemeral ports. The proxy now reads the origin's head (at most
16 KB) and classifies the body by RFC 9112's rules:

#api_anchor([`proxy.parseResponseHead`], [
  Returns the status and one of four framings: no body (HEAD, 1xx, 204, 304), a
  `Content-Length`, chunked transfer coding, or close-delimited.
], source: "libs/net/src/proxy.zig")

```zig
pub const Framing = union(enum) { none, length: u64, chunked, until_close };

pub fn parseResponseHead(head: []const u8, head_request: bool) ?ResponseHead {
    if (head.len < 12 or !std.mem.startsWith(u8, head, "HTTP/1.")) return null;
    const status = std.fmt.parseInt(u16, head[9..12], 10) catch return null;
    var framing: Framing = .until_close;
    var chunked = false;
    // ... one pass over the header lines for Transfer-Encoding and Content-Length
    if (head_request or status / 100 == 1 or status == 204 or status == 304) framing = .none;
    if (chunked) framing = .chunked;
    return .{ .status = status, .framing = framing };
}
```

The head is re-emitted to the client with the origin's `Connection` headers replaced by
Sibuna's own decision, and the body is relayed exactly: `streamExact` for a length, chunk by
chunk (size line, data, trailers) for chunked coding, `streamRemaining` for the legacy case.
Only the legacy case closes the client.

=== The Origin Pool

Parsing the framing also tells the proxy whether the *origin* socket can be used again: an
HTTP/1.1 response without `Connection: close` (or an HTTP/1.0 one with `keep-alive`) whose body
was fully consumed leaves the socket at a clean request boundary. Such sockets go into a fixed
pool of 256 idle origin connections guarded by a spinlock; the next proxied request takes one
instead of connecting. The measurement that forced this (Part VIII) was blunt: with a new
origin connection per request, a four-core proxy managed about 1,400 requests per second
before loopback ran out of ephemeral ports.

A pooled socket may have been closed by the origin while idle. The proxy notices in one of two
ways, a failed write or an end-of-stream before the first response byte, and in both cases
nothing has reached the client yet, so it closes the socket and retries once on a fresh
connection, never on another pooled one: after an idle period every pooled socket may be
stale, and the first version of this retry, which took a second pooled socket, answered `502`
to the first request after every quiet spell. The retry is allowed only when the request body was fully buffered; a body that
was relayed in chunks cannot be sent again, and the client gets `502`. Unit tests relay fixed
byte strings through the same function and assert the output is byte-identical apart from the
connection header; an end-to-end test sends two proxied requests on one client socket and
checks, through a sequence header the stub origin adds, that the second reused the pooled
origin connection.

#exercise([5.1], [
  A client sends a 200 KB upload. Trace which bytes live in the 64 KB buffer, which are relayed
  by `relayBody`, and why the proxy must write the head to the origin *before* relaying.
])

== Concurrent State Without Allocation

#objectives([
  Analyse the spinlock, the Robin Hood spent set, the GCRA limiter, the lock-free ban table,
  the MPSC incident ring, and the read-copy-update engine slot.
])

=== Spinlocks and Sharding

The critical sections in Sibuna's tables are tens of instructions long, far shorter than a
kernel futex round trip, so shards are guarded by a two-state atomic spinlock with
`spinLoopHint` in the wait loop. Tables are split into 16 shards by key hash so two operations
contend with probability $1/16$.

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
fn check(self: *Shard, key: u64, now_ms: u64, limits: Limits) Decision {
    const interval = limits.emissionInterval();
    const tau = limits.burstTolerance();
    self.lock.lock();
    defer self.lock.unlock();
    const cell = self.locate(key, now_ms, tau) orelse return .{
        .limited = true, .retry_after_ms = interval, .remaining = 0,
    };
    const tat = @max(cell.tat_ms, now_ms);
    if (tat > now_ms +| tau) {
        return .{ .limited = true, .retry_after_ms = tat - tau - now_ms, .remaining = 0 };
    }
    cell.tat_ms = tat +| interval;
    // ... remaining = floor((t + tau - TAT) / T) + 1
}
```

Cells are 16 bytes in 16 shards of 512 slots with a 16-slot probe window; a cell whose TAT is
older than $t - tau$ has drained and is reclaimed on the spot. The `Retry-After` header is
computed from the same arithmetic. Saturated probe windows refuse new clients rather than
evicting active quota state; a zero configured rate refuses requests.

=== The Versioned Ban Table

Bans use 4096 slots with atomic key, expiry and version fields. A writer brackets updates with
version increments; readers accept only a stable even version and retry concurrent changes.
Sequential consistency prevents mixing an old identity with a replacement expiry. Readers
take no mutex, but can wait for a writer and are not wait-free. These atomic operations have
real cost, measured indirectly in the HTTP harness rather than assumed free.

=== The MPSC Incident Ring

When the Shield surface denies a request or the honeypot fires, the incident is copied into a
fixed 1.3 KB record and pushed onto a bounded multi-producer single-consumer ring (Vyukov's
sequence-stamped design, 512 slots). Producers are worker threads; the consumer is the storage
thread. A full ring drops the newest record rather than blocking a response, an explicit loss policy rather than a durability guarantee. The drop counter makes that loss
observable. After moving a record into a pending batch, the storage thread retains it until
commit is confirmed; it does not silently discard it on a database error.

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
releases, and retries on the new slot. The test suite includes a scenario that deadlocked when a
test held a slot across a rebuild, which is exactly the guarantee working as designed.

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
