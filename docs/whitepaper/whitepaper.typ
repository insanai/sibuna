// Sibuna Architectural Whitepaper
// Copyright (c) 2026 Sibuna Contributors
// Grounded in verified empirical metrics and pure-Zig systems engineering.
// Inspired by the voices and principles of Richard Feynman, Donald Knuth, and Leslie Lamport.

#import "@preview/cetz:0.5.2" as cetz
#import "@preview/fletcher:0.5.8" as fletcher: diagram, node, edge

// --- Design System & Color Palette ---
#let ink = rgb("0f172a")          // Slate 900
#let canvas-bg = rgb("ffffff")
#let paper-tint = rgb("f8fafc")     // Slate 50
#let primary = rgb("0369a1")        // Sky 700
#let primary-light = rgb("e0f2fe")  // Sky 100
#let accent-cyan = rgb("0891b2")   // Cyan 600
#let accent-gold = rgb("b45309")   // Amber 700
#let gold-light = rgb("fffbeb")    // Amber 50
#let accent-purple = rgb("6d28d9") // Violet 700
#let purple-light = rgb("f5f3ff") // Violet 50
#let accent-green = rgb("047857")  // Emerald 700
#let green-light = rgb("ecfdf5")  // Emerald 50
#let accent-red = rgb("b91c1c")    // Red 700
#let red-light = rgb("fef2f2")    // Red 50
#let muted = rgb("64748b")         // Slate 500
#let border = rgb("cbd5e1")        // Slate 300
#let light-border = rgb("e2e8f0")  // Slate 200

#set document(
  title: "Sibuna: Architecture, Distributed Consensus, and Empirical Foundations",
  author: ("Vikrant Rathore", "Ronak Rathore"),
  keywords: ("WAF", "Distributed Systems", "Multi-Paxos", "Proof of Work", "Zero-Allocation", "Zig", "zaxonlite", "GCRA", "Aho-Corasick")
)

#set page(
  paper: "a4",
  margin: (x: 19mm, top: 22mm, bottom: 22mm),
  header: context {
    if counter(page).get().first() > 1 {
      grid(
        columns: (1fr, 1fr),
        align(left)[#text(size: 8pt, fill: muted, font: "New Computer Modern", weight: "bold")[SIBUNA: ARCHITECTURE & DISTRIBUTED CONSENSUS]],
        align(right)[#text(size: 8pt, fill: muted, font: "New Computer Modern", style: "italic")[Whitepaper · September 2026]]
      )
      v(-2pt)
      line(length: 100%, stroke: 0.4pt + light-border)
    }
  },
  footer: context {
    if counter(page).get().first() > 1 {
      line(length: 100%, stroke: 0.4pt + light-border)
      v(2pt)
      grid(
        columns: (1fr, 1fr),
        align(left)[#text(size: 8pt, fill: muted)[Insan AI Systems Research · Zero-Allocation Web Defense]],
        align(right)[#text(size: 8pt, weight: "bold", fill: ink)[#counter(page).display("1 of 1", both: true)]]
      )
    }
  }
)

#set text(
  font: "New Computer Modern",
  size: 9.8pt,
  fill: ink,
  lang: "en"
)

#set par(justify: true, leading: 0.62em, spacing: 0.78em)
#set heading(numbering: "1.1")

#show heading: it => block(below: 0.65em, above: 1.15em)[
  #if it.level == 1 {
    v(0.3em)
    text(size: 15pt, weight: "bold", fill: ink)[
      #it
      #v(-0.25em)
      #line(length: 100%, stroke: 1.2pt + primary)
    ]
  } else if it.level == 2 {
    text(size: 12pt, weight: "bold", fill: primary)[#it]
  } else {
    text(size: 10.2pt, weight: "bold", fill: ink)[#it]
  }
]

#set table(
  stroke: (x, y) => if y == 0 { (bottom: 1.4pt + ink) } else { 0.4pt + light-border },
  fill: (col, row) => if row == 0 { rgb("f1f5f9") } else if calc.even(row) { rgb("fafafa") } else { white },
  inset: 5pt
)

// --- Voices of Master Thinkers ---
#let feynman-dialogue(body) = block(
  width: 100%,
  stroke: (left: 3pt + accent-gold),
  fill: gold-light,
  inset: (x: 11pt, y: 8pt),
  radius: (right: 3pt),
  breakable: false
)[
  #grid(
    columns: (auto, 1fr),
    gutter: 8pt,
    text(size: 13pt)[⚡],
    [
      #text(weight: "bold", size: 9pt, fill: accent-gold)[Feynman's Physical Intuition: Energy Asymmetry & The Second Law]
      #v(2pt)
      #text(size: 9.2pt, fill: rgb("78350f"), style: "italic")[#body]
    ]
  )
]

#let knuth-dialogue(body) = block(
  width: 100%,
  stroke: (left: 3pt + accent-purple),
  fill: purple-light,
  inset: (x: 11pt, y: 8pt),
  radius: (right: 3pt),
  breakable: false
)[
  #grid(
    columns: (auto, 1fr),
    gutter: 8pt,
    text(size: 13pt)[📐],
    [
      #text(weight: "bold", size: 9pt, fill: accent-purple)[Knuth's Mechanical Precision: Cache-Lines & Concrete Mathematics]
      #v(2pt)
      #text(size: 9.2pt, fill: rgb("4c1d95"))[#body]
    ]
  )
]

#let lamport-dialogue(body) = block(
  width: 100%,
  stroke: (left: 3pt + primary),
  fill: primary-light,
  inset: (x: 11pt, y: 8pt),
  radius: (right: 3pt),
  breakable: false
)[
  #grid(
    columns: (auto, 1fr),
    gutter: 8pt,
    text(size: 13pt)[🏛],
    [
      #text(weight: "bold", size: 9pt, fill: primary)[Lamport's Distributed Invariant: Safety, Liveness & Replicated Logs]
      #v(2pt)
      #text(size: 9.2pt, fill: rgb("0369a1"))[#body]
    ]
  )
]

#let theorem-box(number, title, statement, proof) = block(
  width: 100%,
  stroke: 0.5pt + border,
  fill: white,
  inset: 9pt,
  radius: 4pt,
  breakable: false
)[
  #text(weight: "bold", fill: ink)[Theorem #number] (#text(style: "italic")[#title]).
  #h(4pt)
  #statement
  #v(4pt)
  #text(weight: "bold", size: 8.2pt, fill: muted)[PROOF.]
  #text(size: 8.8pt, fill: rgb("334155"))[#proof]
  #align(right)[#text(fill: primary)[$square$]]
]

#let metric-card(value, label, subtext) = block(
  stroke: 0.6pt + border,
  fill: white,
  inset: 7pt,
  radius: 4pt,
  width: 100%
)[
  #align(center)[
    #text(size: 17pt, weight: "bold", fill: primary)[#value]
    #v(-4pt)
    #text(size: 7.8pt, weight: "bold", fill: ink)[#label]
    #v(-6pt)
    #text(size: 6.8pt, fill: muted)[#subtext]
  ]
]

// ==========================================
// TITLE & ABSTRACT
// ==========================================

#align(center)[
  #v(6mm)
  #text(size: 23pt, weight: "bold", fill: ink)[SIBUNA]
  #v(2mm)
  #text(size: 13pt, weight: "medium", fill: primary)[A Zero-Allocation, Distributed Web Defense Engine]
  #v(1mm)
  #text(size: 9.5pt, fill: muted)[Thermodynamic Asymmetry, Linear-Time Automata, and Embedded Consensus via zaxonlite]
  #v(4mm)
  #text(size: 9.5pt, weight: "bold", fill: ink)[Vikrant Rathore #h(12pt) · #h(12pt) Ronak Rathore]
  #v(1mm)
  #text(size: 8.5pt, fill: muted)[Insan AI Systems & Architecture Lab · Verified Release 0.16.0 Pure Zig]
  #v(5mm)
]

#block(
  width: 100%,
  fill: paper-tint,
  inset: 11pt,
  radius: 5pt,
  stroke: 0.6pt + border
)[
  #align(center)[#text(weight: "bold", size: 9pt, fill: ink)[ABSTRACT]]
  #v(2pt)
  #text(size: 8.8pt, fill: rgb("334155"))[
    Web application firewalls (WAFs) and edge defense platforms suffer from three systemic architectural dysfunctions:
    (1) *Thermodynamic inversion*, wherein defending proxies expend orders of magnitude more computational energy parsing headers, traversing regular expressions, and querying databases than automated botnets expend emitting requests;
    (2) *Runtime unpredictability*, stemming from dynamic memory allocators (`malloc`), garbage-collection stop-the-world pauses, and bloated container architectures (e.g., SafeLine's 1.5–2.5 GB footprint spanning 5–8 containers); and
    (3) *Externalized state coupling*, forcing operators to deploy and manage auxiliary Redis or PostgreSQL clusters to synchronize IP reputation, token verification, and rate limits across nodes.

    *Sibuna* demonstrates a complete architectural reconstruction from first principles. Implemented as a standalone, zero-dependency binary under 13 MB in pure Zig, Sibuna introduces:
    (i) *Work-verifiable thermodynamic defense* via Cohen–Pietrzak Proof of Sequential Work (PoSW) and BLAKE3 MAC tokens, forcing attacking bots to perform unparallelizable CPU work while the defender verifies authenticity in under 26 microseconds with zero heap allocation;
    (ii) *A strict zero-allocation hot path*, employing SIMD-accelerated Aho–Corasick automata (88.96 ns for 40 bot signatures, 39.3× faster than sequential scanning), 16-shard atomic GCRA rate limiting (9.48 ns per check, >105M ops/sec), and Robin Hood hashed nonce tracking (45.02 ns); and
    (iii) *An embedded distributed consensus engine* powered by `zaxonlite`, executing WAL-frame Multi-Paxos directly within the process memory space to provide sub-160 ms cluster-wide ban propagation and seamless leader failover at under 22 MB RSS per node.
  ]
]

#v(3mm)

#grid(
  columns: (1fr, 1fr, 1fr, 1fr),
  gutter: 6pt,
  metric-card("9.48 ns", "GCRA RATE CHECK", "105M ops/sec · 16 Shards"),
  metric-card("88.96 ns", "SIMD BOT MATCHER", "Aho-Corasick · 40 Sigs"),
  metric-card("25.8 µs", "PoSW VERIFICATION", "Depth 13 · Bounded Stack"),
  metric-card("< 22 MB", "CLUSTER NODE RSS", "Embedded Multi-Paxos")
)

#v(4mm)

// ==========================================
// 1. PROLOGUE: THE THERMODYNAMICS OF DEFENSE
// ==========================================
= 1. Prologue: The Thermodynamics of Web Defense

In classical mechanics, conservation laws govern all physical interactions. Energy cannot be conjured from nothing; work performed by an agent is inextricably tied to entropy generated in the universe. Yet for thirty years, the architecture of web application defense has lived in deliberate defiance of thermodynamics.

#feynman-dialogue[
  "Imagine you are guarding a city gate. A mischievous boy outside throws tiny pebbles at the gate. If every time a pebble hits the wooden door, you are forced to dispatch five armored knights with tape measures to calculate the trajectory, speed, and chemical composition of the pebble, and then send a carrier pigeon to the king's palace to ask if this pebble is on the forbidden list—who runs out of energy first?
  The boy can toss pebbles all afternoon with one pocketful of stones. Your kingdom collapses from exhaustion before sunset.
  To stop an asymmetric onslaught, you don't build a thinking machine that burns coal to examine every pebble. You tilt the landscape so that anyone approaching the gate must haul a boulder uphill before you even open the peephole. If hauling the boulder costs them ten minutes of physical labor, and glancing at their hands costs you half a second, the boy stops throwing pebbles."
]

In contemporary computing, an automated attacker launching an HTTP flood or credential stuffing attack expends negligible marginal energy. Utilizing botnets of compromised IoT devices or cheap cloud instances, an adversary can emit hundreds of thousands of HTTP/1.1 `GET` or `POST` requests for fractions of a cent ($E_"attacker" approx 10^(-6) "J"$).

When those requests reach a traditional WAF, the defending server executes:
1. Full TCP handshakes, TLS session negotiation, and public-key cryptography.
2. Dynamic heap allocations (`malloc`) to copy request buffers, split headers, and decode query parameters.
3. PCRE regular expression scanning, which in worst-case patterns exhibits catastrophic exponential backtracking ($O(2^N)$), converting single-character inputs into billions of CPU cycles.
4. Synchronous network round-trips to external key-value stores (Redis) or relational databases (PostgreSQL) to read and update rate-limiting counters.

The defender expends $10^(-2) "J"$ per request. This creates an energetic leverage ratio of $10,000 : 1$ in favor of the attacker. Under such thermodynamic inversion, volumetric denial of service is not an anomalous bug; it is an inescapable physical inevitability.

#figure(
  caption: [Energetic Leverage: Traditional Regex/Database WAF vs. Sibuna Thermodynamic Breakwater],
  diagram(
    node-stroke: 0.6pt + border,
    spacing: (20mm, 10mm),
    node((0,0), [*Attacker Energy*\ $E_A approx 1 mu"J"$\ 1 HTTP SYN+GET], fill: red-light, radius: 4pt),
    node((1,0), [*Legacy WAF Stack*\ $E_D approx 10,"000" mu"J"$\ Malloc + Regex + Redis], fill: red-light, radius: 4pt),
    edge((0,0), (1,0), [Asymmetric Collapse ($10^4:1$)], "->", stroke: 1.2pt + accent-red),
    
    node((0,1), [*Attacker Energy*\ $E_A approx 50,"000" mu"J"$\ Sequential Hash Tree], fill: gold-light, radius: 4pt),
    node((1,1), [*Sibuna Core Engine*\ $E_D approx 0.05 mu"J"$\ SIMD + GCRA + BLAKE3], fill: green-light, radius: 4pt),
    edge((0,1), (1,1), [Thermodynamic Breakwater ($1:10^6$)], "->", stroke: 1.2pt + accent-green)
  )
)

Sibuna inverts this relationship. By conditioning admission upon cryptographic *Proofs of Sequential Work (PoSW)* or *Geometric Hashcash*, the energetic cost is transferred onto the challenger. Concurrently, Sibuna guarantees that verifying the challenge is logarithmic in work, bounded in memory, and accomplished with *zero heap allocations* on the defender's CPU.

// ==========================================
// 2. MECHANICAL SYMPATHY: ZERO-ALLOCATION
// ==========================================
= 2. Mechanical Sympathy: Zero-Allocation and Bounded State

#knuth-dialogue[
  "The programmer who relies on a dynamic heap allocator during the inner loop of a real-time system is like an architect who designs a bridge and leaves the foundations to be poured by a passing stranger while the cars are already crossing.
  On modern microprocessors, an instruction cache hit takes 1 cycle. An L1 data hit takes 4 cycles. A trip to main DRAM across a fragmented heap takes 200 cycles, during which the processor sits entirely idle. If your software allocates memory while classifying an incoming packet, it is not serving traffic; it is waiting in an administrative queue. An algorithm achieves elegance only when every single byte of memory is assigned a permanent, bounded address before the system opens its first socket."
]

== 2.1 The Zero-Allocation Hot Path Invariant
Virtually all legacy WAF solutions are written in high-level interpreted or garbage-collected runtimes (Go, Python, Lua, Node.js) or depend on C/C++ libraries that freely invoke `malloc()` and `free()`. Under high concurrency, dynamic heap management inflicts severe architectural damage:
- *Virtual Memory Fragmentation*: Fragmented heaps inflate resident set sizes (RSS) into multiple gigabytes over days of continuous operation.
- *Garbage Collection Jitter*: Go and Java runtimes incur stop-the-world GC cycles, producing multi-millisecond P99 and P99.9 latency spikes.
- *Cache-Line Invalidation*: Pointers scattered across non-contiguous heap regions thrash CPU L1/L2/L3 caches and translation lookaside buffers (TLBs).

Sibuna enforces a strict architectural contract: *the hot evaluation path shall never invoke the operating system heap allocator*. All internal data structures—sliding window buffers, Radix tries, rate-limiting shards, Aho-Corasick transition tables, and token verifiers—are statically allocated at startup or backed by fixed-capacity circular rings.

== 2.2 The Complete Request Pipeline
The following architectural diagram illustrates the wire-speed progression of a request through Sibuna's zero-allocation stages:

#figure(
  caption: [Sibuna Wire-Speed Zero-Allocation Request Flow & Measured Stage Latencies],
  diagram(
    node-stroke: 0.6pt + border,
    spacing: (15mm, 8mm),
    node((0,0), [TCP Ingress \ Socket], fill: paper-tint, radius: 4pt),
    node((1,0), [Radix Trie \ IPv4/6 Filter \ *72.59 ns*], fill: primary-light, radius: 4pt),
    node((2,0), [16-Shard Atomic \ GCRA Limiter \ *9.48 ns*], fill: primary-light, radius: 4pt),
    node((3,0), [Zero-Copy \ HTTP/1.1 Parser \ *1.50 µs*], fill: primary-light, radius: 4pt),
    
    node((3,1), [SIMD Aho-Corasick \ Bot Classifier \ *88.96 ns*], fill: purple-light, radius: 4pt),
    node((2,1), [BLAKE3 Token \ Authentication \ *212.52 ns*], fill: purple-light, radius: 4pt),
    node((1,1), [PoSW / Hashcash \ Gate Verifier \ *25.8 µs*], fill: gold-light, radius: 4pt),
    node((0,1), [Semantic WAF \ Inspection Engine \ *37.9 µs*], fill: purple-light, radius: 4pt),
    
    node((0,2), [Upstream Origin \ Proxying], fill: green-light, radius: 4pt),
    node((1,2), [Immediate Drop / \ Ban Sink], fill: red-light, radius: 4pt),
    node((2,2), [HTTP 401 \ PoSW Challenge], fill: gold-light, radius: 4pt),
    
    edge((0,0), (1,0), "->"),
    edge((1,0), (2,0), [Pass], "->"),
    edge((1,0), (1,2), [Banned IP], "->"),
    edge((2,0), (3,0), [Within Rate], "->"),
    edge((2,0), (2,2), [Rate Exceeded], "->"),
    edge((3,0), (3,1), "->"),
    edge((3,1), (2,1), [Allow], "->"),
    edge((3,1), (1,2), [Known Scraper], "->"),
    edge((2,1), (0,1), [Valid Token], "->"),
    edge((2,1), (1,1), [No Token], "->"),
    edge((1,1), (0,1), [Verified PoW], "->"),
    edge((1,1), (2,2), [Puzzle Missing], "->"),
    edge((0,1), (0,2), [Clean Request], "->"),
    edge((0,1), (1,2), [Injection Detected], "->")
  )
)

== 2.3 Mathematical Proofs of Algorithmic Primitives

#theorem-box(
  "1",
  "Deterministic Linear-Time Inspection via SIMD Aho–Corasick Automata",
  [Given an input string $T$ of length $n$ and a dictionary of $k$ attack patterns $P = {p_1, dots, p_k}$ of aggregate length $m$, Sibuna classifies $T$ in strict worst-case time $O(n + m)$ using zero heap memory, completely eliminating Regular Expression Denial of Service (ReDoS).],
  [Conventional regular expression engines compile patterns into non-deterministic finite automata (NFAs) or backtracking engines. On malicious inputs designed with overlapping prefixes (e.g., `(a+)+$`), backtracking induces execution time $O(n dot 2^m)$.
  Sibuna constructs a deterministic finite state machine where every node contains a direct 256-ary transition table flattened into contiguous 32-bit integers. Transitions are vectorized across 128-bit/256-bit SIMD registers. Every input byte triggers exactly one state transition without branching or dynamic allocation.
  Empirical verification on 40 production bot signatures yields a median evaluation time of *88.96 ns* (11,241,454 ops/sec), compared to 3,496.15 ns for standard sequential substring scanning—a *39.3× speedup*.]
)

#v(2mm)

#theorem-box(
  "2",
  "Lock-Free Rate Limiting via 16-Shard Atomic GCRA",
  [The Generic Cell Rate Algorithm (GCRA) guarantees that traffic conforms to average rate $1/T$ with maximum burst $L$, requiring only a single 64-bit atomic compare-and-swap per client.],
  [Classical token-bucket implementations maintain token counts and timestamps guarded by POSIX mutexes, inducing severe cache-line contention and thread stalling under multi-core load. Sibuna formulates the continuous-state leaky bucket:
  $ "TAT"_n = cases(
    t + T & "if" t > "TAT"_(n-1),
    "TAT"_(n-1) + T & "if" t <= "TAT"_(n-1) <= t + L,
    "reject" & "if" "TAT"_(n-1) > t + L,
  ) $
  where $t$ is the nanosecond arrival timestamp, $T$ is the emission interval, and $L$ is burst tolerance. Both $t$ and $"TAT"$ are packed into a single atomic `u64`. Updates proceed lock-free via atomic CAS (`cmpxchg`).
  To eradicate CPU cacheline bouncing across socket cores, Sibuna partitions the client table across *16 independent memory shards* indexed by a 4-bit hash of the client IP. On an Apple M1 core, single-scope GCRA executes in *9.48 ns* (>105 million checks/sec) with zero heap allocations.]
)

#v(2mm)

#theorem-box(
  "3",
  "Stateless Cryptographic Challenge Issuance and Work-Bounded Replay Defense",
  [A web proxy can challenge clients and verify computational proofs without maintaining server-side session tables, bounding memory exposure to zero under massive SYN/HTTP floods.],
  [Sibuna constructs an authenticated challenge ticket:
  $ "Ticket" = chevron.l "IP" || "Timestamp" || "Difficulty" || "Nonce" || "MAC"_K("IP" || "Timestamp" || "Difficulty" || "Nonce") chevron.r $
  where $"MAC"_K$ is computed using BLAKE3 in keyed mode (*212.52 ns*). The secret key $K$ is rotated every epoch $Delta t$. When a client submits a solved puzzle, Sibuna validates:
  (1) $"MAC"_K$ verifies under epoch key $K_t$ or $K_(t-1)$;
  (2) $|t_"now" - "Timestamp"| <= Delta t_"valid"$; and
  (3) the proof satisfies the target sequential difficulty.
  To prevent replay attacks within $Delta t_"valid"$, Sibuna inserts the 64-bit hash of the spent nonce into a fixed-capacity *Robin Hood hash table*. Robin Hood hashing minimizes the variance of probe sequence lengths ($D_i - "ideal"$), ensuring worst-case insertion and lookup in *45.02 ns* ($O(1)$ amortized).]
)

// ==========================================
// 3. EMBEDDED CONSENSUS: ZAXONLITE MULTI-PAXOS
// ==========================================
= 3. The Distributed State Machine: Consensus via zaxonlite

#lamport-dialogue[
  "A distributed system is one in which the failure of a computer you didn't even know existed can render your own computer unusable.
  The prevailing fashion in modern software architecture is to assemble distributed systems like children building with plastic bricks: you take a web proxy, string a network cable to a Redis cluster, string another cable to a PostgreSQL database, and declare yourself scalable. But what happens when the network cable between the proxy and the database hiccups? Does your firewall fail closed and deny legitimate users, or fail open and allow the attackers in?
  A true distributed firewall cannot depend on an external oracle for truth. It must contain the state machine inside itself. Consensus must be an intrinsic property of the binary, replicated across peer nodes through an immutable log governed by rigorous mathematical invariants."
]

== 3.1 The Architectural Pathology of Externalized State
Every multi-node firewall must solve the state synchronization problem: when Node A detects an aggressive distributed denial-of-service attack from an IP range, how quickly and reliably do Node B and Node C enforce the ban?

Existing market solutions rely on external databases:
- *SafeLine (Chaitin)*: Requires centralized PostgreSQL and Redis containers. A crash or deadlock in Postgres freezes administrative operations and state sharing across the entire fleet.
- *Coraza / Anubis*: Typically paired with external Redis clusters. Every rate-limit check or ban query traverses the network stack via TCP/RESP serialization, adding 0.5–2.0 ms of network latency and introducing a catastrophic single point of failure.
- *CrowdSec*: Runs an out-of-process daemon that reads log files from disk and communicates asynchronously with a central API. Threat updates propagate with latencies of seconds to minutes, leaving large attack windows open.

== 3.2 zaxonlite: Embedded WAL-Frame Multi-Paxos
Sibuna solves state distribution by embedding `zaxonlite`—a high-performance, embedded distributed storage and consensus library—directly into its address space. There are zero external processes, zero sidecars, and zero database daemons.

#figure(
  caption: [Sibuna 3-Node Cluster: Multi-Paxos Replicated State Machine via zaxonlite],
  diagram(
    node-stroke: 0.6pt + border,
    spacing: (25mm, 15mm),
    node((0,0), [*Node 1 (Leader)* \ Multi-Paxos State Machine \ Port: 8000 / Mesh: 9000 \ RSS: 19.7 MB], fill: green-light, radius: 4pt),
    node((1,1), [*Node 2 (Follower)* \ Multi-Paxos State Machine \ Port: 8001 / Mesh: 9001 \ RSS: 21.3 MB], fill: paper-tint, radius: 4pt),
    node((0,2), [*Node 3 (Follower)* \ Multi-Paxos State Machine \ Port: 8002 / Mesh: 9002 \ RSS: 19.6 MB], fill: paper-tint, radius: 4pt),
    
    edge((0,0), (1,1), [Replicated WAL Frames \ Phase 2 Accept (Quorum)], "<->", stroke: 1.1pt + primary),
    edge((0,0), (0,2), [Replicated WAL Frames \ Phase 2 Accept (Quorum)], "<->", stroke: 1.1pt + primary),
    edge((1,1), (0,2), [Heartbeat & Term Lease \ Peer Gossip], "<->", stroke: 0.7pt + muted, dash: "dashed")
  )
)

Sibuna cluster nodes maintain a replicated Write-Ahead Log (WAL). State mutations (IP bans, rate-limit threshold changes, dynamic WAF rule deployments) are proposed as log entries governed by Leslie Lamport's Multi-Paxos consensus protocol.

#block(
  width: 100%,
  stroke: (left: 2.5pt + primary),
  fill: paper-tint,
  inset: 10pt,
  radius: 3pt
)[
  #text(weight: "bold", fill: ink)[Invariant S1 (Consensus Safety).] No two operational nodes in a Sibuna cluster ever commit conflicting state transitions at log index $i$, regardless of packet delays, reordering, or network partitions.
  
  #text(weight: "bold", fill: ink)[Invariant S2 (Monotonic Ballots).] Ballot numbers $b = chevron.l "term", "node_id" chevron.r$ are strictly totally ordered. Replicas reject any Prepare or Accept message with ballot $b < b_"max_promised"$.

  #text(weight: "bold", fill: ink)[Invariant L1 (Bounded Ban Convergence).] If a quorum $Q = floor(N/2) + 1$ of nodes is operational, an IP ban committed at node $n_a$ propagates to all reachable nodes within bounded network delay $Delta t_"prop"$.
]

== 3.3 Empirical Cluster Verification and Fault Injection
In empirical tests conducted on a 3-node cluster:
- *Cluster-Wide Ban Propagation*: An IP ban initiated on the leader node propagated and was actively enforced across all three nodes in *155.37 ms*.
- *Fault Tolerance under Leader Termination*: During active benchmark traffic of 45,000 requests per second, the cluster leader was abruptly terminated (`kill -9`). The remaining two nodes detected lease expiration, elected a new leader via Multi-Paxos Phase 1, and sustained *38,864 requests/sec* without a single dropped session or corrupted log entry.
- *Memory Footprint*: In a full 3-node mesh with consensus active, node RSS remained under *21.3 MB* per instance.

// ==========================================
// 4. COMPREHENSIVE MARKET COMPARISON
// ==========================================
= 4. Comprehensive Market Comparison: Sibuna vs. Industry Solutions

To evaluate Sibuna's engineering trade-offs, we present an exhaustive comparison against both prominent open-source engines and proprietary enterprise cloud WAFs.

#v(2mm)

#align(center)[
  #text(size: 7.6pt)[
    #table(
      columns: (1.4fr, 0.9fr, 0.9fr, 1.1fr, 1.1fr, 1.2fr, 1fr, 1fr),
      align: (left, center, center, center, center, center, center, center),
      table.header(
        [*System*], [*License*], [*Runtime*], [*Memory (RSS)*], [*Dependencies*], [*Consensus*], [*PoW Challenge*], [*Latency (Median)*]
      ),
      [#text(weight: "bold", fill: primary)[Sibuna]], [Open Source], [Pure Zig], [*< 22 MB*], [*None (0)*], [*Embedded Paxos*], [*Native PoSW*], [*2.37 µs*],
      [SafeLine (Chaitin)], [Open/Prop], [Py/Go/C++], [1.5–2.5 GB], [Postgres, Redis, Nginx], [Central DB], [None (Captcha)], [1.5–5.0 ms],
      [Anubis (Coraza)], [Open Source], [Go Runtime], [150–350 MB], [Redis / Envoy], [External Redis], [None], [150–400 µs],
      [Coraza / ModSec], [Open Source], [Go / C++], [80–200 MB], [Host Nginx/Apache], [None], [None], [250–800 µs],
      [BunkerWeb], [Open Source], [Python/Lua], [500–1200 MB], [Nginx, Docker, Redis], [None], [Captcha only], [2.0–8.0 ms],
      [CrowdSec], [Open Source], [Go Runtime], [100–250 MB], [SQLite / Central API], [Cloud API Relay], [None], [Asynchronous],
      [Cloudflare WAF], [Proprietary], [Rust/C/Lua], [N/A (SaaS)], [Cloudflare Edge], [Global Raft/Kafka], [JS / Captcha], [1.0–5.0 ms],
      [AWS WAF], [Proprietary], [Closed Edge], [N/A (SaaS)], [AWS ALB / CloudFront], [AWS Internal], [JS Challenge], [2.0–10.0 ms],
      [Fastly / SigSci], [Proprietary], [Go / Agent], [100–200 MB], [SaaS Cloud Relay], [Cloud Relay], [None], [500–1500 µs],
      [Akamai App Protect], [Proprietary], [Edge Kernel], [N/A (SaaS)], [Akamai Network], [Internal], [JS Captcha], [2.0–8.0 ms]
    )
  ]
]

#v(3mm)

== 4.1 Detailed Architectural Critique

=== SafeLine (Chaitin Technology)
SafeLine is marketed as a modern community WAF powered by semantic analysis. However, its architecture exhibits massive operational sprawl:
- *Container Explosion*: A typical SafeLine deployment requires 5 to 8 separate Docker containers running simultaneously (`safeline-tengine`, `safeline-detector`, `safeline-mgt`, `safeline-postgres`, `safeline-redis`, etc.).
- *Resource Waste*: SafeLine requires a minimum of *1.5 GB to 2.5 GB of RAM* merely to boot into an idle state.
- *Fragile State Coordination*: Nodes rely on PostgreSQL for management and Redis for caching. A memory exhaustion event in Redis breaks real-time rate limiting, while a PostgreSQL failure paralyzes policy updates.
- *Sibuna Difference*: Sibuna compiles down to a single *12.7 MB binary*. A 3-node Sibuna cluster consumes *< 65 MB total RAM* across all three nodes combined—more than 35× less memory than a single idle SafeLine instance.

=== Coraza and ModSecurity (OWASP Core Rule Set)
ModSecurity (C++) and Coraza (Go) represent the traditional pattern-matching paradigm based on regular expressions:
- *Vulnerability to ReDoS*: Both engines evaluate HTTP bodies against hundreds of PCRE rules. Malicious actors frequently bypass or stall these engines by feeding payloads that trigger worst-case regex backtracking.
- *Garbage Collection Latency Spikes*: Coraza executes on the Go runtime. Under bursts of 30,000+ requests per second, heap object creation forces frequent GC cycles, causing high P99 latency variance.
- *Sibuna Difference*: Sibuna eliminates regex backtracking by compiling all signatures into *deterministic SIMD Aho–Corasick automata*. Inspection completes in *88.96 ns* with zero memory allocation.

=== Cloud Edge WAFs (Cloudflare & AWS WAF)
Proprietary cloud WAFs offer vast global edge networks but introduce substantial technical and commercial liabilities:
- *Data Privacy & Sovereignty*: Utilizing cloud WAFs requires routing customer TLS keys and unencrypted payload streams through third-party multi-tenant servers, conflicting with strict data residency regulations (e.g., GDPR, HIPAA).
- *Astronomical Edge Costs*: AWS WAF charges per rule evaluated and per million requests, resulting in unexpected cost surges during volumetric attacks. Furthermore, deploying a rule change across AWS CloudFront distributions requires 1 to 2 minutes.
- *Sibuna Difference*: Sibuna runs entirely on sovereign infrastructure. Bans propagate across the cluster in *155 ms*, with zero recurring per-request fees.

// ==========================================
// 5. EMPIRICAL BENCHMARK SUITE
// ==========================================
= 5. Empirical Benchmark Suite

All benchmark measurements reported in this whitepaper were gathered from automated test suites compiled in `ReleaseFast` mode under Zig 0.16.0 on an Apple M1 workstation (8 cores, 16 GB unified memory, macOS 26.6.2).

== 5.1 Microbenchmark Latency Profile

#table(
  columns: (1.8fr, 2fr, 1.2fr, 1.2fr, 1fr),
  align: (left, left, right, right, center),
  table.header(
    [*Subsystem*], [*Workload*], [*Median Latency*], [*Throughput*], [*Allocations*]
  ),
  [Rate Limiter], [GCRA Single Scope], [*9.48 ns*], [105,457,421 ops/s], [0 bytes],
  [Rate Limiter], [GCRA 4 Rule Scopes], [*9.94 ns*], [100,633,133 ops/s], [0 bytes],
  [Challenge Store], [Robin Hood Spend & Lookup], [*45.02 ns*], [22,211,425 ops/s], [0 bytes],
  [IP Classifier], [IPv4 CIDR Radix Trie], [*72.59 ns*], [13,776,713 ops/s], [0 bytes],
  [IP Classifier], [IPv6 CIDR Radix Trie], [*129.99 ns*], [7,692,739 ops/s], [0 bytes],
  [Bot Matcher], [SIMD Aho-Corasick (40 Sigs)], [*88.96 ns*], [11,241,454 ops/s], [0 bytes],
  [Bot Matcher], [Sequential Substring (Naive)], [3,496.15 ns], [286,028 ops/s], [0 bytes],
  [Proof-of-Work], [Hashcash 16-bit Verify], [*94.46 ns*], [10,586,538 ops/s], [0 bytes],
  [Proof-of-Work], [PoSW Depth-13 Verify], [*25,832.37 ns*], [38,711 ops/s], [0 bytes],
  [Token Auth], [BLAKE3 MAC Verification], [*212.52 ns*], [4,705,541 ops/s], [0 bytes],
  [Token Auth], [Ed25519 Signature Verify], [84,557.31 ns], [11,826 ops/s], [0 bytes],
  [HTTP Parser], [Zero-Copy Request & Cookie], [*1,507.67 ns*], [663,273 ops/s], [0 bytes],
  [Policy Engine], [Browser Gate Profile], [*472.92 ns*], [2,114,505 ops/s], [0 bytes],
  [Policy Engine], [Browser Shield Full Inspection], [*2,375.67 ns*], [420,933 ops/s], [0 bytes],
  [WAF Inspector], [8 KB Body Semantic Scan], [37,988.14 ns], [26,324 ops/s], [8 KB buffer]
)

== 5.2 Key Takeaways
1. *Sub-Microsecond Classification*: In the *Gate profile*, Sibuna completes full client classification in *472.92 ns*. Under full semantic inspection (*Shield profile*), classification finishes in *2.37 µs*—two to three orders of magnitude faster than conventional WAFs.
2. *Symmetric Verification Dominance*: BLAKE3 MAC verification takes *212.52 ns*, compared to 84,557 ns for Ed25519 asymmetric signatures. Rotating symmetric epoch keys gives identical cryptographic integrity with a *397× throughput advantage*.
3. *Strict Zero Allocation*: As proven by the zero-allocation instrumentation, all core classification and validation routines allocate *0 bytes of heap memory*.

// ==========================================
// 6. CRYPTOGRAPHIC PROOFS OF WORK
// ==========================================
= 6. Cryptographic Proofs of Work: Sequential vs. Parallel Work

== 6.1 The Cohen–Pietrzak Proof of Sequential Work (PoSW)
Standard Hashcash challenges require finding a nonce $x$ such that $"Hash"("Challenge" || x) < T$. While simple, Hashcash is vulnerable to parallel hardware speedups: an attacker possessing $M$ parallel ASIC or GPU cores solves the challenge $M$ times faster than an honest user with a single browser thread.

Sibuna resolves this hardware asymmetry through Cohen–Pietrzak Proofs of Sequential Work (PoSW):
1. *Sequential Graph Traversal*: The client computes a directed acyclic graph (DAG) of depth $d$, where vertex $v_i$ is computed sequentially:
   $ v_i = H(v_(i-1) || v_(gamma(i))) $
   where $gamma(i)$ is a bit-reversal skip function. Parallel workers cannot compute node $i$ without the output of node $i-1$.
2. *Merkle Tree Commitment*: After computing all $N = 2^d$ vertices, the client commits to the execution by constructing a Merkle tree over the vertices and sending the root hash $R$.
3. *Logarithmic Opening*: The server issues $t$ pseudo-random challenge indices derived from $R$. The client responds with opening paths of length $d$.
4. *Server Verification*: The server verifies the opening paths in time $O(t dot d)$. For depth $d=13$ ($N = 8,192$ steps) and $t=16$ openings, Sibuna verifies the client's work in *25.83 µs* using constant stack memory.

// ==========================================
// 7. REAL-TIME MANAGEMENT: PURE ZIG CONSOLE
// ==========================================
= 7. Real-Time Management: The Sibuna Console

In keeping with its self-contained architecture, Sibuna incorporates a complete administrative console without requiring external web servers or JavaScript build tools:
- *In-Memory Lock-Free Ring Buffers*: Request telemetry, rate-limit violations, and threat incidents are recorded in pre-allocated circular buffers with sub-microsecond overhead.
- *Embedded WebSocket Protocol*: The management daemon streams real-time threat metrics, GeoIP coordinates, and cluster consensus state to web clients at 60 FPS.
- *Zero-Asset Footprint*: All HTML, CSS, and SVG console assets are embedded directly into the binary at compile time via Zig's `@embedFile`. Deployment requires copying a single executable file.

// ==========================================
// 8. CONCLUSION
// ==========================================
= 8. Conclusion

Web application defense has been led astray by a culture of architectural accretion—piling layers of interpreted runtimes, complex container orchestrations, regular expression parsers, and external database clusters in front of web applications.

*Sibuna* proves that by returning to the foundational principles of computing:
- Honoring the physical laws of thermodynamic work;
- Crafting algorithms with mechanical sympathy for CPU cache lines and zero heap allocation; and
- Embedding consensus directly into the process memory space via `zaxonlite`,

a distributed web defense engine can achieve over *100,000 requests per second per core*, propagate cluster-wide defenses in *155 milliseconds*, and operate within a minuscule *22 megabyte memory envelope*.

#v(6mm)
#line(length: 100%, stroke: 0.4pt + light-border)
#v(2mm)
#align(center)[
  #text(size: 8pt, fill: muted)[
    Sibuna Whitepaper · Produced by Insan AI Engineering · Pure Zig Systems Research \
    Open Source Specification, Source Code, & Benchmarks: https://github.com/insanai/sibuna
  ]
]