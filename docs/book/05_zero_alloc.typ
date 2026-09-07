#import "theme.typ": *
#import "figures.typ": *

#part_page("V", [Zero-Allocation Engineering in Pure Zig], [
  We follow a connection from accept to response through one stack buffer, and examine the
  concurrent data structures that let many worker threads share state without heap
  allocation on the request path.
])

= The Connection Loop

#objectives([
  By the end of this chapter, you should be able to explain how one 64 KB buffer serves an
  entire keep-alive connection, how the head and body are located without copying, and why
  proxied requests close the connection while internal routes keep it open.
])

== One Buffer per Connection

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
    // ... format the peer address once, then serve up to 256 requests
    while (served < max_requests_per_connection) : (served += 1) {
        const keep = serveOne(&conn) catch break;
        if (!keep) break;
    }
}
```

`readHead` fills the buffer until the blank line appears, refusing heads over 16 KB with `431`.
The parser produces a `Request` whose method, path, query, headers, and cookies are slices of
the buffer; the declared body is filled up to what fits and sliced after the head; then
`toss(body_end)` advances the reader so the next keep-alive request starts cleanly. Internal
routes are length-delimited and keep the connection open. Proxied requests stream the origin's
response until it closes, so the daemon closes the client too: correct framing without parsing
the origin's response.

== The Proxy Head Rewrite

The head is not forwarded verbatim. `writeHead` re-emits the request line and each header,
dropping hop-by-hop fields (`Connection`, `Transfer-Encoding`, any incoming `X-Forwarded-For`)
and appending the audit set:

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

#exercise([5.1], [
  A client sends a 200 KB upload. Trace which bytes live in the 64 KB buffer, which are relayed
  by `relayBody`, and why the proxy must write the head to the origin *before* relaying.
])

= Concurrent State Without Allocation

#objectives([
  Analyse the spinlock, the Robin Hood spent set, the GCRA limiter, the lock-free ban table,
  the MPSC incident ring, and the read-copy-update engine slot.
])

== Spinlocks and Sharding

The critical sections in Sibuna's tables are tens of instructions long, far shorter than a
kernel futex round trip, so shards are guarded by a two-state atomic spinlock with
`spinLoopHint` in the wait loop. Tables are split into 16 shards by key hash so two operations
contend with probability $1/16$.

== The Robin Hood Spent Set

Only solved challenges are stored (Part III, Lemma 4). Each shard is an open-addressed array of
4096 entries of `{tag: [16]u8, expires_at: u64, dist: u8, occupied: bool}`. Robin Hood insertion
(Celis, 1986) displaces any occupant closer to its home than the incoming key, which keeps probe
lengths tightly clustered; lookups stop as soon as they meet an entry nearer its home than they
are to theirs.

```zig
fn insert(self: *Shard, tag: *const Tag, expires_at: u64, now: u64) StoreError!void {
    var carry = Entry{ .tag = tag.*, .expires_at = expires_at, .dist = 0, .occupied = true };
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
needed. A spend-and-lookup pair costs 22.8 ns.

== GCRA: Rate Limiting in One Integer

The Generic Cell Rate Algorithm (ATM Forum, 1996) is the virtual-scheduling form of the leaky
bucket. Per client it stores one *theoretical arrival time* (TAT). With emission interval
$T = W / N$ for a limit of $N$ per window $W$, and burst tolerance $tau = W - T$:

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
    const cell = self.locate(key, now_ms, tau);
    const tat = @max(cell.tat_ms, now_ms);
    if (tat > now_ms + tau) {
        return .{ .limited = true, .retry_after_ms = tat - tau - now_ms, .remaining = 0 };
    }
    cell.tat_ms = tat + interval;
    // ... remaining = floor((t + tau - TAT) / T) + 1
}
```

Cells are 16 bytes in 16 shards of 512 slots with a 16-slot probe window; a cell whose TAT is
older than $t - tau$ has drained and is reclaimed on the spot. The `Retry-After` header is
computed from the same arithmetic. A check costs 4.8 ns.

== The Lock-Free Ban Table

Bans are rare writes and constant reads, so the table is optimised for readers: 4096 slots of
two atomics (`key`, `until`) probed within a window of eight. Readers perform two acquire loads
per probe and take no lock; writers serialise on a spinlock and publish `until` before `key` so
no reader pairs a fresh key with a stale expiry.

== The MPSC Incident Ring

When the Shield surface denies a request or the honeypot fires, the incident is copied into a
fixed 1.3 KB record and pushed onto a bounded multi-producer single-consumer ring (Vyukov's
sequence-stamped design, 512 slots). Producers are worker threads; the consumer is the storage
thread. A full ring drops the newest record rather than blocking a response, the correct trade
for forensics under a flood.

== Read-Copy-Update Engine Slots

The policy engine is several megabytes of automaton tables and is rebuilt off the hot path when
policies change. Workers must never observe a half-built engine, and the builder must never
overwrite an engine a request is still reading. Sibuna uses two slots with reader counts:

#book_figure([Engine slot swap: workers pin a slot; the storage thread swaps the pointer and waits for the old slot's readers to drain before rebuilding into it], rcu_swap())

```zig
pub fn acquireEngine(self: *AppState) *EngineSlot {
    while (true) {
        const slot = self.slot.load(.acquire);
        _ = slot.readers.fetchAdd(1, .acq_rel);
        if (self.slot.load(.acquire) == slot) return slot;
        _ = slot.readers.fetchSub(1, .acq_rel);
    }
}

pub fn publishEngine(self: *AppState, fresh: *EngineSlot) *EngineSlot {
    const old = self.slot.swap(fresh, .acq_rel);
    while (old.readers.load(.acquire) != 0) std.atomic.spinLoopHint();
    return old;
}
```

The re-check after incrementing closes the race in which a writer swaps between the reader's
load and its increment and observes zero readers: the reader notices the pointer changed,
releases, and retries on the new slot. The test suite includes a scenario that deadlocked when a
test held a slot across a rebuild, which is exactly the guarantee working as designed.

#exercise([5.2], [
  Using the GCRA theorem, compute the maximum number of requests a single client can get
  through in the first 3 seconds after being idle, for `--rate-limit 100 --rate-window 10`.
  Compare with a fixed 10-second window counter and with a true sliding-window log.
])

#teach_back([
  Explain why an expired Robin Hood entry can be overwritten only by a key with a distance at
  least as large, using a three-slot example.
])
