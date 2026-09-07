#import "theme.typ": *
#import "figures.typ": *

#part_page("V", [High-Throughput Automata & Routing Structures], [
  We examine the algorithms powering Sibuna's sub-microsecond classification: the comptime
  branchless Aho-Corasick automaton and the bitwise IPv4/IPv6 Radix Trie.
])

= Comptime Branchless Aho-Corasick

#objectives([
  By the end of this chapter, you should be able to derive the state transition mechanics of the
  Aho-Corasick automaton, explain how failure transitions allow multi-pattern matching in $O(M)$
  linear time, and understand how compile-time lookup tables eliminate branch mispredictions.
])

== The Limitations of Linear String Scanning

As established in Part II, traditional anti-bot proxies scan User-Agent headers by iterating
through a list of patterns one after another ($O(N times M)$ complexity). If an incoming request
carries a User-Agent of length $M = 150$ and the signature database contains $N = 45$ patterns,
the CPU performs up to 45 sequential string scans.

In 1975, Alfred Aho and Margaret Corasick devised an algorithm that combines a trie of target
keywords with suffix failure transitions, enabling the simultaneous search of an arbitrary number
of keywords in a single linear pass over the input text ($O(M)$ complexity).

#book_figure([State transitions and failure edges in the Aho-Corasick automaton], aho_corasick_graph())

== Transition Construction and Failure Links

The automaton operates in two phases:
1. *Trie Construction:* Every bot signature is inserted character by character into a prefix tree.
2. *Failure Link Generation:* A breadth-first search (BFS) queue computes fallback transitions.
   If a mismatch occurs at state $S$ on character $c$, the automaton follows the longest proper
   suffix of the matched prefix that is also a prefix in the trie.

```zig
pub fn build(self: *Matcher) void {
    var queue: [MAX_STATES]u16 = undefined;
    var head: usize = 0;
    var tail: usize = 0;

    for (0..256) |c| {
        const next = self.transitions[0][c];
        if (next != 0) {
            queue[tail] = next;
            tail += 1;
        }
    }

    while (head < tail) {
        const state = queue[head];
        head += 1;
        const fail_state = self.fail[state];
        if (self.match_id[state] == null) {
            self.match_id[state] = self.match_id[fail_state];
        }
        for (0..256) |c| {
            const next = self.transitions[state][c];
            if (next != 0) {
                self.fail[next] = self.transitions[fail_state][c];
                queue[tail] = next;
                tail += 1;
            } else {
                self.transitions[state][c] = self.transitions[fail_state][c];
            }
        }
    }
}
```

== Branchless Lowercase Conversion

User-Agent headers exhibit unpredictable casing: an automated bot might present `gptbot`,
`GPTBot`, or `GptBot`. In conventional C or Go code, case insensitivity is achieved by calling
`toLower(c)`, which typically compiles into a conditional branch:

```c
// Conventional branching toLower:
if (c >= 'A' && c <= 'Z') return c + 32;
return c;
```

Inside an inner string scanning loop processing millions of characters per second, these branches
routinely induce CPU branch mispredictions.

Sibuna resolves this by computing a 256-byte lookup table entirely at compile time (`comptime`):

```zig
const to_lower_table: [256]u8 = blk: {
    var table: [256]u8 = undefined;
    for (0..256) |i| {
        const c: u8 = @intCast(i);
        table[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
    }
    break :blk table;
};

inline fn toLower(c: u8) u8 {
    return to_lower_table[c];
}
```

Because `to_lower_table` resides entirely in the CPU L1 data cache (256 bytes fits in 4 cache lines),
character normalization is compiled into a single indexed memory load without any conditional
branching.

#v(4mm)

= Bitwise CIDR Radix Trie

#objectives([
  Trace the bitwise prefix traversal of the IPv4 Radix Trie, evaluate the cache efficiency of
  pre-allocated index-based nodes, and contrast its performance against standard Go `net.IPNet`
  slice filtering.
])

== Fast Prefix Matching in $O(k)$

Firewalls must frequently classify client IP addresses against CIDR subnets representing cloud
datacenters (AWS, Google Cloud, Azure), search engine crawler IP pools, or known malicious
autonomous systems.

Linear iteration over a list of CIDR masks requires parsing the IP and computing bitwise AND
operations for every mask in the list.

Sibuna structures its IP policies as a *Bitwise Radix Trie*. Because an IPv4 address is an unsigned
32-bit integer, any IPv4 CIDR prefix of length $L$ corresponds to a unique path of depth $L$ from
the trie root:

```zig
pub const MAX_NODES = 4096;

pub const Trie = struct {
    children: [MAX_NODES][2]?u16 = [_][2]?u16{[_]?u16{ null, null }} ** MAX_NODES,
    actions: [MAX_NODES]?Action = [_]?Action{null} ** MAX_NODES,
    node_count: u16 = 1,

    pub fn match(self: *const Trie, ip: u32) ?Action {
        var current: u16 = 0;
        var best_match: ?Action = self.actions[0];
        var i: u8 = 0;
        while (i < 32) : (i += 1) {
            const shift: u5 = @intCast(31 - i);
            const bit: u1 = @intCast((ip >> shift) & 1);
            if (self.children[current][bit]) |next| {
                current = next;
                if (self.actions[current]) |act| {
                    best_match = act;
                }
            } else {
                break;
            }
        }
        return best_match;
    }
};
```

Notice the critical hardware optimization: *zero pointer indirections*.
The nodes are stored in flat, contiguous pre-allocated arrays indexed by 16-bit integers (`u16`).
Traversing the trie involves sequential array lookups that prefetch cleanly into CPU hardware
caches.

As recorded in our benchmark suite, classifying an IPv4 address across hundreds of CIDR subnets
takes *40.4 nanoseconds* in Sibuna, compared to *380.0 nanoseconds* in Go's slice-based
`net.IPNet` implementation—a *9.4x performance improvement*.
