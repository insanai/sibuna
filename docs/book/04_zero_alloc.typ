#import "theme.typ": *
#import "figures.typ": *

#part_page("IV", [Zero-Allocation Engineering in Pure Zig], [
  We examine how Sibuna eliminates the dynamic heap from its request classification and
  verification paths, replacing kernel syscalls with cache-line atomic spinlocks.
])

= The Hot Path Without Heap Allocations

#objectives([
  By the end of this chapter, you should be able to design a zero-allocation HTTP request
  parser in Zig, explain the mechanics of string slicing over stack-allocated connection buffers,
  and calculate the memory footprint of Sibuna under maximum concurrency.
])

== The Anatomy of Zero-Allocation Design

In conventional systems programming, dynamic memory allocation (`malloc`, `free`, or runtime GC
allocations) is treated as an ordinary convenience. When an HTTP header is parsed, a string is
allocated; when query parameters are parsed, a map is created.

In an edge security firewall, however, every dynamic allocation is a catastrophic vulnerability:
1. *Heap Fragmentation:* Sustained high-frequency allocations of varying sizes fragment the heap,
   causing memory residency to drift upward over days of operation.
2. *Lock Contention in the Allocator:* When multiple worker threads allocate memory concurrently,
   they contend for global allocator locks (such as arenas in `ptmalloc` or `mimalloc`).
3. *Denial-of-Service Amplification:* An attacker can craft requests with hundreds of unique
   headers specifically designed to maximize memory consumption in the firewall.

Sibuna eliminates this entire failure class by enforcing a non-negotiable architectural invariant:
*the entire request classification, policy evaluation, and Proof-of-Work verification pipeline
must execute with zero dynamic heap allocations.*

== Stack Buffering and Slice Lifecycles

When a client establishes a TCP connection, the socket worker allocates a fixed-size connection
buffer directly on the thread's stack or within a pre-allocated connection pool:

```zig
var raw_req_buf: [8192]u8 = undefined;
const req_bytes = try reader.interface.peekGreedy(1);
```

When `net.parseRequest` evaluates the incoming bytes, it never copies or clones string data.
Instead, it constructs a `net.Request` struct where the method, path, query parameters, header
names, and cookie values are represented as *Zig string slices* (`[]const u8`) pointing directly
into `raw_req_buf`:

```zig
pub const Request = struct {
    method: Method = .GET,
    path: []const u8 = "/",
    query: []const u8 = "",
    version: []const u8 = "HTTP/1.1",
    headers: [MAX_HEADERS]Header = [_]Header{.{ .name = "", .value = "" }} ** MAX_HEADERS,
    header_count: usize = 0,
    body: []const u8 = "",
    // ...
};
```

Because `headers` is an array with a compile-time bound (`MAX_HEADERS = 32`), parsing a request
incurs zero heap allocations and requires less than *450 nanoseconds* of CPU time. When the
connection closes or advances to the next keep-alive transaction, the stack frame is reclaimed
with zero destructor overhead.

#v(4mm)

= Atomic SpinLocks vs Kernel Mutexes

#objectives([
  Analyze the performance penalties of operating system mutexes (`futex` / `pthread_mutex`),
  derive the atomic compare-and-swap mechanics of `SpinLock`, and explain how 16-shard partitioning
  minimizes lock contention.
])

== The Syscall Tax of Kernel Mutexes

When a Go or C program uses standard mutexes (`sync.Mutex` or `pthread_mutex_t`), uncontented lock
acquisitions are fast. However, as soon as multiple threads contend for the same lock, the operating
system kernel must intervene:
1. The thread executes a `futex` syscall (on Linux) or a kernel trap (on macOS).
2. The operating system deschedules the calling thread, transitioning it to a wait queue.
3. A kernel context switch occurs, invalidating CPU caches and Translation Lookaside Buffers (TLB).
4. When the lock holder releases the lock, another kernel context switch is required to awaken
   the waiting thread.

This context-switch cycle typically consumes between *1,500 and 5,000 nanoseconds* per contention
event.

== Lock-Free Atomic SpinLocks in Zig 0.16

In Sibuna, operations within the active challenge store are extremely brief: finding a slot in an
array and updating a boolean flag takes fewer than *30 CPU instructions* (under 15 nanoseconds).
Under these conditions, entering the operating system kernel to deschedule a thread is an enormous
waste of CPU cycles.

Sibuna implements a pure atomic `SpinLock` using Zig 0.16's atomic primitives:

```zig
pub const SpinLock = struct {
    locked: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn lock(self: *SpinLock) void {
        while (self.locked.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    pub fn unlock(self: *SpinLock) void {
        self.locked.store(false, .release);
    }
};
```

The call to `std.atomic.spinLoopHint()` emits hardware-specific CPU pause instructions (such as
`PAUSE` on x86 or `YIELD` on ARM), signaling to the processor core that it is inside a tight spin
loop and optimizing pipeline power consumption.

== 16-Shard Partitioning

To further reduce contention across CPU cores, Sibuna partitions its in-memory challenge store
into 16 independent shards:

```zig
pub const NUM_SHARDS = 16;
pub const SHARD_CAPACITY = 1024;

pub const ChallengeStore = struct {
    shards: [NUM_SHARDS]Shard = [_]Shard{.{}} ** NUM_SHARDS,

    fn shardIndex(id: []const u8) usize {
        return @as(usize, @intCast(std.hash.Wyhash.hash(0xdead_beef, id) % NUM_SHARDS));
    }
    // ...
};
```

When a thread inserts or verifies a challenge ID, it computes a 64-bit Wyhash modulo 16. Two
concurrent operations will contend for the same spinlock only with probability $P = 1/16 = 6.25%$.
On a 16-core server, lock contention is virtually eradicated.

#exercise([4.1], [
  Suppose a server processes 32,000 challenge operations per second evenly distributed across
  16 shards. If each critical section holds the spinlock for 25 nanoseconds, calculate the
  theoretical probability that an incoming thread will observe a locked shard.
], hint: [Poisson arrival model: average arrival rate per shard $lambda = 2,000$ ops/sec. Service time $T = 25 times 10^(-9)$ seconds. Utilization $rho = lambda times T$.])
