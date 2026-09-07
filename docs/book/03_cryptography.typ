#import "theme.typ": *
#import "figures.typ": *

#part_page("III", [Foundations from Cryptography Research], [
  We derive the cost models behind Sibuna's two proof-of-work tiers, present the Cohen–Pietrzak
  Proof of Sequential Work with its security argument, and justify keyed-hash authentication
  for challenges and sessions. Full proofs live in SID 0006.
])

= Hashcash: The Mathematics of Tier One

#objectives([
  By the end of this chapter, you should be able to state the expected work, variance, and tail
  probability of a bit-level Hashcash puzzle, explain why the server's verification cost bounds
  the attacker's advantage, and describe the two limits that motivate a second tier.
])

== Definition and Cost

Sibuna's Tier One puzzle for challenge string $C$ and difficulty $b$ bits is: find $N in NN$
such that $"SHA-256"(C || ":" || "dec"(N))$ has $b$ leading zero bits. The decimal rendering of
the nonce is deliberate; it keeps the wire format identical between the WebAssembly solver, the
JavaScript fallback, and the native verifier without a binary encoding step.

#definition([Work-bit contract], [
  A difficulty of $b$ *work bits* denotes $2^b$ expected SHA-256 compressions for the honest
  client. Both tiers are calibrated to this unit so an operator's `--difficulty 16` means the same
  wall-clock order of magnitude whichever algorithm is selected.
])

Let $X$ be the number of trials. Since each digest is uniform and independent, $X ~ "Geometric"(2^(-b))$:

$ E[X] = 2^b, quad "median"(X) = 2^b ln 2 approx 0.69 dot 2^b, quad P[X > k 2^b] = (1 - 2^(-b))^(k 2^b) approx e^(-k). $

#callout([Lemma 1 (Verification bound)], [
  The verifier computes one compression, so for any adversary $cal(A)$ producing a valid
  solution, $E["work"(cal(A))] >= 2^b$ compressions in the random-oracle model, and the server's
  cost per accepted solution is exactly one compression regardless of $cal(A)$. The asymmetry
  ratio is therefore at least $2^b$ and is independent of the attacker's parallelism.
])

The lemma is the whole reason Tier One exists: 62.6 ns per verification on the reference host
means submission floods are absorbed at sixteen million per second per core.

== Two Limits of Tier One

1. *Variance.* The geometric tail means one client in twenty does three times the expected
   work, and one in a hundred does 4.6 times. On a phone that is the difference between a
   pleasant interstitial and a page that seems hung.
2. *Parallelism.* A hash search parallelises perfectly. A GPU computes on the order of
   $10^9$ SHA-256 per second; at $b = 16$ it solves a puzzle in 65 µs. The per-request cost to a
   well-equipped fleet is far below the cost to a human's laptop.

Both limits are addressed by requiring the work to be *sequential*.

#exercise([3.1], [
  Show that for a geometric variable with mean $2^b$, the probability of needing more than
  $4.6 dot 2^b$ trials is about $1%$, and derive the difficulty $b'$ at which the *median* solve
  time equals the *mean* solve time at $b$.
], hint: [$P[X > k 2^b] approx e^(-k)$; the median is $2^b ln 2$.])

#v(4mm)

= Proof of Sequential Work: Tier Two

#objectives([
  Understand the Cohen–Pietrzak labelling, why it forces sequential computation, what the
  verifier checks, the soundness bound $(1 - alpha)^t$ and why cheating never pays for $t >= 2$,
  the post-quantum result, the prover's memory bound, and the calibration data behind the
  work-bit mapping.
])

== Why Sequential Work

A *proof of sequential work* (PoSW) is a puzzle whose solution requires $N$ *sequential* hash
evaluations: no amount of parallel hardware finishes it faster than the latency of $N$ dependent
hashes. Mahmoody, Moran and Vadhan introduced the notion in 2013; Cohen and Pietrzak gave the
construction Sibuna implements at EUROCRYPT 2018 ("Simple Proofs of Sequential Work"); Blocki,
Lee and Zhou proved it secure against quantum adversaries at ITC 2021. Three consequences matter
for a firewall:

- The solve time is *deterministic*: exactly $2^(n+1) - 1$ hashes for depth $n$. No tail.
- A fleet gains nothing from parallelism within a puzzle; its advantage is bounded by the
  ratio of single-hash latencies between its hardware and a browser, typically a small
  constant, rather than by core count.
- Grover's algorithm gives a quadratic speedup for search puzzles like Hashcash. For the
  sequential construction the quantum lower bound of Blocki, Lee and Zhou still requires
  $Omega(N)$ sequential steps.

== The Construction

Let $n$ be the depth and consider the complete binary tree with nodes named by binary strings of
length at most $n$ (root $epsilon$, children $v 0$ and $v 1$, leaves of length $n$). Each node $v$
carries a 32-byte label $ell_v = H(chi, v, "parents"(v))$, where $chi$ is the challenge statement
and $H$ is SHA-256 with $chi$ absorbed once (the same prefix trick as the Hashcash solver):

- an internal node hashes its two children: $ell_v = H(chi, v, ell_(v 0), ell_(v 1))$;
- a leaf $u = u_1 dots u_n$ hashes the *left siblings of its ancestors* wherever the root path
  turned right: $ell_u = H(chi, u, {ell_(u_1 dots u_(i-1) 0) : u_i = 1})$.

#book_figure([The depth-3 tree: an opening of leaf 3.5 sends the leaf label and the three
sibling labels; the dashed edges are the left-sibling dependencies that make labelling sequential],
posw_tree())

The left-sibling edges are what make the computation sequential: leaf $u$ cannot be labelled
until every subtree to its left is complete, so a depth-first post-order traversal is forced and
the root label $phi = ell_epsilon$ depends on all $2^(n+1) - 1$ labels in sequence.

*Openings.* After computing $phi$, the prover derives $t$ leaves by Fiat–Shamir,
$gamma_i = H(chi || phi || i) mod 2^n$, and for each sends the leaf label and the $n$ sibling labels
along its root path. The verifier recomputes the leaf from the siblings that are its parents,
hashes upward through the path, and checks that it arrives at $phi$. The verifier's cost is
$t (n + 1)$ compressions and constant memory.

#api_anchor([`posw.verifyOpening`], [
  Recomputes one opened leaf from its sibling labels and walks the path to the root.
], source: "libs/crypto/src/posw.zig")

```zig
fn verifyOpening(base: *const Sha256, n: u8, phi: *const Label, gamma: u32, opening: []const u8) bool {
    const leaf: *const Label = opening[0..label_len];
    var h = nodeHasher(base, n, gamma);
    var d: u8 = 1;
    while (d <= n) : (d += 1) {
        if (pathBit(gamma, n, d) == 1) h.update(siblingAt(opening, n, d));
    }
    var computed: Label = undefined;
    h.final(&computed);
    if (!std.mem.eql(u8, &computed, leaf)) return false;

    var cur = leaf.*;
    d = n;
    while (d >= 1) : (d -= 1) {
        const sib = siblingAt(opening, n, d);
        var parent = nodeHasher(base, d - 1, gamma >> @intCast(n - d + 1));
        if (pathBit(gamma, n, d) == 0) { parent.update(&cur); parent.update(sib); }
        else { parent.update(sib); parent.update(&cur); }
        parent.final(&cur);
    }
    return std.mem.eql(u8, &cur, phi);
}
```

== Soundness, and Why Cheating Never Pays

Cohen and Pietrzak prove that a prover which computes fewer than $(1 - alpha) N$ labels
consistently is caught by each random opening with probability at least $alpha$, so it passes
$t$ openings with probability at most $(1 - alpha)^t$ (plus a negligible term in the hash output
length). Sibuna adds one observation that makes the parameter choice simple:

#callout([Lemma 2 (Cheating is never cheaper)], [
  Let a dishonest prover skip a fraction $alpha in (0, 1)$ of the work and retry until accepted.
  Its expected cost per accepted proof is
  $ frac((1 - alpha) N, (1 - alpha)^t) = N (1 - alpha)^(1 - t) >= N quad "for all" t >= 2. $
  Hence for two or more openings the honest strategy is optimal in expectation; larger $t$ only
  steepens the penalty. Sibuna uses $t = 16$, at which skipping a tenth of the work costs
  $1.1^(15) approx 4.2$ times the honest work per success.
])

== Prover Memory

A naive prover stores every label ($2^(n+1) - 1$ of them). Sibuna's prover keeps a stack of the
current path's left-sibling labels ($n + 1$ labels) during the first pass and retains only the
top $m = min(n, 10)$ levels ($2^(m+1) - 1$ labels, at most 64 KB). To open a leaf it recomputes
the subtree of the leaf's depth-$m$ ancestor, $2^(n - m + 1) - 1$ hashes, seeding the stack from the
retained levels. Total prover cost is $2^(n+1) - 1 + t (2^(n - m + 1) - 1)$ hashes and the whole
workspace, including the output proof, is under 100 KB: a browser tab and a native test share the
same `Workspace` type.

== Calibration and the Work-Bit Mapping

#table(
  columns: (0.8fr, 1.3fr, 1.3fr, 1.3fr),
  table.header([*Depth $n$*], [*Native solve (M1)*], [*Native verify (t = 16)*], [*V8 WebAssembly solve*]),
  [12], [2.2 ms], [40 µs], [17.8 ms],
  [13], [5.0 ms], [34 µs], [15.4 ms],
  [14], [8.3 ms], [30 µs], [32.0 ms],
  [15], [13.3 ms], [25 µs], [66.4 ms],
  [16], [20.8 ms], [20 µs], [137.9 ms],
  [17], [33.9 ms], [18 µs], [285.1 ms],
  [18], [65.4 ms], [18 µs], [-],
)

A leaf hashes about $n / 2$ parent labels on average, several SHA-256 blocks, so a depth-$n$ tree
costs roughly $2^(n + 3)$ compressions; Hashcash at $b$ bits costs $2^b$. Sibuna therefore maps
work bits to depth as $n = b - 3$ (clamped to $[4, 24]$), and the measured V8 numbers confirm it:
16 work bits is 20 ms of Hashcash or 15 ms of sequential work at depth 13. Proof size is
$32 (1 + t (n + 1))$ bytes: 7.2 KB at depth 13 with sixteen openings.

== Why Not the Alternatives

#table(
  columns: (1fr, 2.2fr, 1.6fr),
  table.header([*Candidate*], [*Assessment*], [*Verdict*]),
  [Argon2id / scrypt puzzles], [Memory-hard with strong results (Alwen et al. proved scrypt maximally memory-hard), but verification recomputes the full function: 16 MB and milliseconds per submission. A server-verified puzzle that costs the verifier as much as the prover is a denial-of-service amplifier.], [Rejected for verification cost],
  [Equihash (generalised birthday)], [Asymmetric and memory-hard, published at NDSS 2016, but the solver needs 10–15 MB of browser memory, Wagner's algorithm parallelises across instances, and the $k$-XOR problem has known quantum speedups (Grassi, Naya-Plasencia, Schrottenloher 2018).], [Not adopted; may return as an optional tier],
  [HashX (Tor)], [ASIC-resistant program generation; verification needs a program compiler or interpreter on the server and has no sequentiality proof.], [Rejected],
  [Time-lock puzzles / VDFs in RSA or class groups], [Sequential with instant trapdoor verification, but the groups are broken by Shor's algorithm and require big-integer arithmetic on both sides.], [Rejected for post-quantum reasons],
  [Cohen–Pietrzak PoSW], [Hash-based, proven sequential, proven post-quantum, $O(log N)$ prover memory, $O(t log N)$ verification.], [*Adopted as Tier Two*],
)

#exercise([3.2], [
  With $t = 16$ openings, compute the expected cost multiplier $ (1 - alpha)^(1 - t)$ for a
  prover that skips $alpha = 0.02$, $0.1$, and $0.5$ of the labels. At what $t$ does skipping
  half the work first cost more than $10 N$?
])

#teach_back([
  Explain, without formulas, why the left-sibling edges prevent a thousand-core machine from
  labelling the tree faster than a single core, and why opening random leaves catches a prover
  that skipped part of the tree.
])

#v(4mm)

= Symmetric Authentication: Challenges and Sessions

#objectives([
  Explain why a keyed pseudorandom function is the correct primitive when issuer and verifier
  are the same trust domain, state the forgery bound for a 128-bit tag, describe the stateless
  challenge record and the spent-set bound, and read the key schedule.
])

== Issuer Equals Verifier

A digital signature lets *anyone* holding the public key verify, which is the right tool when
verifiers must not be able to mint. Sibuna's verifier *is* the issuer (or a cluster sharing one
seed), so the extra property is paid for but never used, at a cost of about 52.8 µs per Ed25519
verification. A message authentication code built from a pseudorandom function gives exactly the
property needed, unforgeability under chosen-message attack, in one BLAKE3 compression: 134 ns.

#callout([Lemma 3 (Forgery bound)], [
  With BLAKE3 in keyed mode modelled as a PRF and a 16-byte tag, an adversary making $q$
  verification queries forges a valid token with probability at most $q dot 2^(-128) + epsilon_"PRF"$.
  At a million queries per second that is $2^(-108)$ per second.
])

A second consequence matters for the long term: Ed25519 rests on discrete logarithms in an
elliptic-curve group, which Shor's algorithm breaks; a keyed hash rests only on the hash
function, against which quantum algorithms give at most a quadratic speedup. Sibuna keeps
Ed25519 as an option (`--token-scheme ed25519`) for deployments that need non-minting verifiers.

== The Key Schedule

One 32-byte master seed (from `--secret-file`, `SIBUNA_SECRET`, or a fresh random value)
derives every purpose key with keyed BLAKE3 and a domain string:

```zig
pub fn derive(seed: *const [32]u8) Keys {
    return .{
        .token = subkey(seed, "sibuna/token/v1"),
        .challenge = subkey(seed, "sibuna/challenge/v1"),
        .ed25519_seed = subkey(seed, "sibuna/ed25519/v1"),
        .fingerprint = subkey(seed, "sibuna/fingerprint/v1"),
    };
}
```

Domain separation means a compromise of one purpose never touches another, and a cluster only
has to agree on one seed.

== Stateless Challenges

#book_figure([Wire formats of the challenge identifier and the session token], wire_formats())

A challenge identifier is a self-authenticating record: version, algorithm, difficulty, opening
count, issue time, the client's keyed fingerprint, a PRF-derived nonce, and the hash of the
policy rule that demanded the challenge, followed by a 16-byte tag under the challenge key.
Issuing one writes nothing. Verification decodes the record, checks the tag in constant time,
checks the age against the challenge TTL, checks the fingerprint against the submitting client,
and only then examines the proof.

#callout([Lemma 4 (State grows only with paid work)], [
  Let $S$ be the set of challenge tags the daemon remembers. A tag enters $S$ only after a valid
  proof for it was accepted, and it leaves after the challenge TTL. Hence $|S| <= r dot "TTL"$
  where $r$ is the rate of *solved* challenges, and an adversary that wants to occupy $k$
  entries must perform $k$ full proofs of work. Memory cannot be exhausted by free challenge
  fetches.
])

The spent set is 16 shards of Robin Hood open addressing over the 16-byte tags (Part V). The
fingerprint is a keyed hash of the client address and User-Agent, length-separated so no two
inputs collide by concatenation, and keyed so fingerprints of other clients cannot be computed
offline.

#exercise([3.3], [
  A token payload carries `timestamp`, `expiry`, `rule_hash`, and `fingerprint`. Explain what
  each field prevents if it were removed, and why the tag must cover all four.
])

#teach_back([
  A colleague proposes switching all tokens to Ed25519 "because it is stronger". Explain the
  trust-domain argument, the cost difference, and the post-quantum consideration.
])
