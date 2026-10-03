# paxos-zig

A Paxos library that does no I/O.

**Read the book:**
[The Part-Time Parliament, from paper to library (PDF)](https://insanai.github.io/zxdocs/part-time-parliament.pdf)
-- the learning path, the derivation, the API contract, and the evidence,
rebuilt on every change by the
[zxdocs](https://github.com/insanai/zxdocs) workflow.

## The problem

Suppose you have three computers. You want them to keep the same list of
commands, in the same order, forever. That sounds easy. It is not.

Machines crash and come back with old memories. Messages get lost. Messages
get duplicated. Messages arrive late, or in the wrong order. Two machines may
both believe they are in charge at the same time. And still, no two machines
may ever disagree about what sits in slot 17 of the list.

Leslie Lamport solved this problem and wrote it up as a story about a
parliament on a Greek island. The paper is called *The Part-Time Parliament*.
The algorithm is called Paxos. This library is that algorithm, written in
Zig, and nothing else.

## The trick

Most consensus libraries want to own your process. They open sockets, spawn
threads, read clocks, and write files. Then you spend your time fighting
their runtime instead of understanding the protocol.

This library refuses to do any of that. It is a pure state machine. You hand
it a message. It hands you back a batch of effects: records to write, messages
to send, values that are now committed. It never touches a socket, a thread,
a clock, or a disk. You do. That is the whole deal.

There is one rule, and everything depends on it:

> Persist every `Effects.write` before transmitting any `Effects.message`
> from the same operation.

If you keep that rule, the protocol keeps its promise: no two nodes ever
commit different values for the same slot, even under crashes, loss,
duplication, delay, and reordering. Every build mode enforces the rule,
including ReleaseFast and ReleaseSmall. If you break it, the library stops
the process with a named diagnostic before the network does worse.

Because there is no I/O, everything is deterministic. Because everything is
deterministic, we can simulate thousands of terrible networks and replay any
failure from a single seed. That is not a convenience. It is the reason to
build the library this way.

## Quick facts

- Classic Paxos and Multi-Paxos, following Lamport's paper.
- Zig 0.16. Zero dependencies. No allocator; all memory is bounded up front.
- Tolerates crash/restart, message loss, duplication, delay, and reordering.
- Assumes non-Byzantine nodes and quorum intersection.
- A reconfigurable replicated-log layer: 64-bit global slots that never
  reset, a fixed consensus window with host-licensed reuse, certified log
  trimming, and stop-sign membership changes on one slot line.

## Getting it

Once a release is tagged, let Zig pin the content hash:

```sh
zig fetch --save https://github.com/insanai/paxos-zig/archive/refs/tags/v0.7.0.tar.gz
```

Then expose the module in your `build.zig`:

```zig
const dependency = b.dependency("paxos", .{
    .target = target,
    .optimize = optimize,
});

const application = b.addExecutable(.{
    .name = "my-application",
    .root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "paxos", .module = dependency.module("paxos") },
        },
    }),
});
```

For local development, a path dependency works too:

```zig
.dependencies = .{
    .paxos = .{ .path = "../paxos-zig" },
},
```

## A taste of the API

You instantiate the protocol with your command type and hard bounds. The
library never guesses sizes. You state them.

```zig
const paxos = @import("paxos");

const Command = struct {
    client_id: u128,
    request_id: u64,
    amount: i64,
};

const P = paxos.Protocol(Command, .{
    .max_members = 5,
    .window_slots = 4096,
    .read_quorum_size = 3,
    .write_quorum_size = 3,
});
```

Build the same membership on every node, then campaign:

```zig
var membership: P.Membership = undefined;
try membership.init(&.{ 1, 2, 3 });

var node: P.Node = undefined;
try node.init(1, &membership);
var effects: P.Effects = undefined;
effects.init();

try node.campaign(noop_command, &effects);
```

Your host loop is four steps, in this order, every time:

1. Append `effects.writesSlice()` to stable storage and synchronize it.
2. Call `effects.confirmWritesDurable()`.
3. Send `effects.messagesSlice()` to their recipients.
4. Apply `effects.committedSlice()` in slot order to your state machine.

Feed network input with `node.step(envelope, &effects)`. Once `node.role` is
`.leader`, call `node.propose(command, &effects)`. Call
`node.tick(noop_command, &effects)` at a steady interval; ticks drive
elections, heartbeats, and retransmission. No wall clock is ever read.

For membership changes, use `paxos.ReplicatedLog(Command, options)`. Its
`reconfigure` seals the old configuration with an ordered stop sign, and
`initFromStop` continues the next configuration at the decided stop slot
on the same global slot line.

Hosts that batch several transitions behind one shared storage barrier can
declare their protocol through `paxos.host_managed.Protocol` instead. That
namespace disables the runtime ordering check and transfers the safety
obligation to the host; its doc comment lists the four rules such a host
must keep, and every use should be treated as an audited exception.

The full host-integration contract, recovery rules, and API reference live in
the book (see [insanai/zxdocs](https://github.com/insanai/zxdocs)) and in the
generated API docs (`zig build docs`, then `zig build docs-serve` and open
http://localhost:8000).

## How do we know it works?

Saying "it passed the tests" is not enough for a consensus library. Here is
the actual evidence, and you can rerun all of it.

**A deterministic fault simulator.** `zig build test` runs seeded simulations
that lose, duplicate, reorder, and delay messages, partition the network, and
crash-restart nodes at every host commit point, including a crash after a
durable prefix of writes with no message sent. Agreement, validity,
monotonicity, and convergence oracles are checked at every step. Any failure
prints its seed. Replay it exactly:

```sh
zig build sim -- --seed=N --steps=M --verbose
```

**A model-checked specification.** `specs/Paxos.tla` models the protocol at
the durable-state level. TLC exhaustively checked 85,515,700 states
(3,986,355 distinct) with no violation. `specs/README.md` maps every TLA+
action to the code that implements it.

**A conformance appendix.** The book (in the
[zxdocs repository](https://github.com/insanai/zxdocs)) maps each step of
Lamport's protocol to the code, the simulator's oracles, and the spec, so the
three stay in sync.

## Benchmarks

The benchmark harness runs the same workload matrix against three
implementations:

- this library,
- [OmniPaxos](https://github.com/haraldng/omnipaxos) 0.2.2 (Rust),
- [LibPaxos3](https://bitbucket.org/sciascid/libpaxos) (C, revision `d255f8b`).

The harness code is in [`benchmarks/`](benchmarks/), and every recorded run,
with full environment metadata, is in
[`benchmarks/results/`](benchmarks/results/). Run it yourself:

```sh
zig build benchmark        # all three implementations
zig build benchmark-zig    # this library only
zig build benchmark-durable
sh benchmarks/run-all.sh   # records a JSON result file
```

Numbers below are nanoseconds per committed value, median of seven samples,
in-memory transport, from `benchmarks/results/latest.json`
(Apple M1 MacBook Air, Zig 0.16.0, rustc 1.95.0). Lower is better.

**Three voters, 8-byte values:**

| Commit mode          | paxos-zig | OmniPaxos | LibPaxos3 |
| -------------------- | --------: | --------: | --------: |
| sync, one at a time  |       134 |     4,445 |     1,355 |
| pipeline, window 8   |       136 |       735 |         - |
| pipeline, window 64  |       128 |       236 |         - |

**Five voters, 8-byte values:**

| Commit mode          | paxos-zig | OmniPaxos |
| -------------------- | --------: | --------: |
| sync, one at a time  |       259 |    12,918 |
| pipeline, window 8   |       247 |     1,873 |

**Three voters, 1 KiB values:**

| Commit mode          | paxos-zig | OmniPaxos |
| -------------------- | --------: | --------: |
| sync, one at a time  |     1,523 |     4,945 |
| pipeline, window 8   |     1,668 |     1,283 |

Now, the honest part. The first principle is that you must not fool
yourself, so read these numbers for what they are.

The harness shape decides who looks fast. One value at a time exposes this
library's low per-append overhead. Pipelined windows let OmniPaxos coalesce
many log entries into far fewer envelopes, and the gap narrows; at 1 KiB
payloads with a window of 8, OmniPaxos is faster. This library always sends
six one-value envelopes per value. LibPaxos3 runs a heavier twelve-envelope
path with phase-one pre-execution. These are workload fixtures and regression
signals, not a language contest, and none of them are service latency.

The number that tells you what safety really costs is the durable one. With a
write-ahead journal and an fsync per value, this library commits a value in
about 202,000 ns. Group eight values per fsync and it drops to about
48,000 ns. The disk, not the protocol, is the bill.

## The book

There is a full book about this library, written in Typst: the learning path
from single-decree Paxos to Multi-Paxos, the derivation, the API contract,
the host-integration guide, the evidence audit, and a production checklist.
It lives, together with the zaxonlite book and the design records, in the
separate [insanai/zxdocs](https://github.com/insanai/zxdocs) repository,
which compiles every book to PDF on each change and publishes it at
[insanai.github.io/zxdocs](https://insanai.github.io/zxdocs/). The enforced
source conventions are explained there in the reviewable-code chapter.

## Scope and operational contract

- A `Protocol.Node` has fixed membership. `ReplicatedLog.Node` changes
  membership by deciding a stop sign and starting a new configuration.
- Memory is bounded by `window_slots`. Slots are global and never reset;
  the host licenses window reuse by advancing the memory floor as it
  consumes and journals decided values, and a full window is transient
  backpressure (`error.WindowFull`), not exhaustion.
- `committedSlice()` releases a contiguous prefix during live transitions; it
  is not a recovery feed. Persist the applied slot with your state machine
  and replay missing values explicitly.
- Values are copied into protocol state and messages. Prefer fixed-size
  records or content-addressed IDs.
- Node IDs are non-zero and are never reused for a different logical member.
- Proposals that time out are not known to have failed. Use persistent
  request IDs and deduplicate in the state machine.

## Development

```sh
zig build test       # unit tests + seeded fault simulation
zig build sim -- --seeds=1000 --steps=1024
zig build run        # three-node counter example
zig build fmt        # zig fmt check + the style checker in tools/
```

`zig build fmt` is not just formatting. It also runs
`tools/check-style.sh`, an awk-based checker that walks every Zig source
file and enforces the mechanical rules from the reviewable-code chapter:
lines at or below 100 columns, no tab characters, and functions at or below
70 lines. CI runs the same command, so run it before you push.

See [CONTRIBUTING.md](CONTRIBUTING.md). The style is TigerStyle: safety,
performance, developer experience, in that order.

## Related projects

- [zaxonlite](https://github.com/insanai/zaxonlite): an embedded distributed
  SQL database, built on SQLite and this library.
- [zaxon-cli-ui](https://github.com/insanai/zaxon-cli-ui): the shared
  terminal UI used by the zaxon shell.
- [zxdocs](https://github.com/insanai/zxdocs): the books and design records
  for the whole family.

## License

MIT. Copyright 2026 Vikrant Rathore and Ronak Rathore. See
[LICENSE](LICENSE).
