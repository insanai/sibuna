#import "theme.typ": *
#import "figures.typ": *

#part_page("III", [Foundations from Cryptography Research], [
  We derive the cost models behind Sibuna's two proof-of-work tiers, present the Cohen–Pietrzak
  Proof of Sequential Work with its security argument, and justify keyed-hash authentication
  for challenges and sessions. SID 0006 records the assumptions and references.
])

== Hashcash: The Mathematics of Tier One

#objectives([
  By the end of this chapter, you should be able to state a Hashcash puzzle's expected work,
  variance and tail probability. You should also be able to explain why checking a solution
  costs less than searching for one, and describe the two limits that motivate a second tier.
])

=== Definition and Cost

Sibuna's Tier One puzzle for challenge string $C$ and difficulty $b$ bits is: find $N in NN$
such that $"SHA-256"(C || ":" || "dec"(N))$ has $b$ leading zero bits. The nonce $N$ is written
in decimal. This gives the WebAssembly solver, JavaScript fallback and native verifier the
same bytes to hash.

The unit of difficulty is an expected *hash trial*, not a compression function call.
An input can occupy several SHA-256 blocks. Prefix precomputation can also change the work
per nonce. The wire rule remains the digest predicate; implementations must agree on the
statement and nonce encoding, not on an estimated CPU cost.

For independent ideal digests, the trial count $X$ is geometric with $p=2^(-b)$ and
$E[X]=2^b$. Its median is $ceil(ln(1/2)/ln(1-p))$, approximately $2^b ln 2$ for small $p$.
Its variance is $(1-p)/p^2$.

The requester searches; the verifier checks one candidate digest. At $b=16$, that is an
average of 65,536 candidate trials to create a proof and one to check it. This difference is
the intended admission cost balance. It is not a ratio of elapsed time or electrical energy.
The server also parses the request, authenticates the challenge, checks its fingerprint,
records a solved challenge and sends a response. Those costs belong in a capacity measurement.

=== Two Limits of Search

The first is variance: a long search is not necessarily a broken worker. The second is
parallelism: independent nonce trials can run concurrently. More cores reduce elapsed search
time even when the expected aggregate trial count remains the same. Hardware throughput
therefore matters to the admission policy. Neither a claimed hash rate nor a single benchmark
can bound every requester's advantage.

#exercise("3.0", [Using the geometric tail, estimate the probability of needing more than
$4.6 times 2^b$ trials. Why is the expected trial count unchanged by dividing the nonce space
among several workers?], hint: [Count aggregate trials, not elapsed seconds.])

== Proof of Sequential Work: Tier Two

#objectives([
  Understand the Cohen–Pietrzak labelling, why it forces sequential computation, what the
  verifier checks, the conditional sampling bound $(1 - alpha)^t$ and its limitations,
  the post-quantum result, the prover's memory bound, and the calibration data behind the
  work-bit mapping.
])

=== Why Sequential Work

A sequential-work construction makes a later calculation depend on an earlier result.
It therefore constrains the depth of the computation as well as its total work. Independent
puzzles can still run in parallel, and the time taken by one hash still depends on hardware.

Sibuna follows the hash-based construction described by Cohen and Pietrzak. Its graph has
$2^(n+1)-1$ labels at depth $n$. This fixes a count of calculations, not a browser completion
time. A label can span several compression blocks, proof openings may recompute subtrees,
and browser scheduling adds variation. The security analysis also has assumptions. They must
be checked when applying the construction to a concrete implementation.

=== The Construction

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

*Openings.* After computing $phi$, the prover derives $t$ leaves by Fiat–Shamir: hashing the
statement and commitment determines which leaves the verifier will check. The selected leaf
is $gamma_i = H(chi || phi || i) mod 2^n$. For each leaf, the prover sends its label and the
$n$ sibling labels along its root path. The verifier recomputes the leaf from the siblings that are its parents,
hashes upward through the path, and checks that it arrives at $phi$. The verifier's cost is
$O(t n)$ label computations with bounded workspace. A label computation may span multiple
hash blocks; counting labels is not counting compression calls.

#api_anchor([`posw.verifyOpening`], [
  Recomputes one opened leaf from its sibling labels and walks the path to the root.
], source: "libs/crypto/src/posw.zig")

```zig
fn verifyOpening(base: *const Sha256, n: u8, phi: *const Label, gamma: u32,
    opening: []const u8) bool {
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

=== Sampling, Soundness, and Their Limits

Consider a fixed commitment with an independently detectable bad fraction $alpha$. If each
opening samples uniformly and independently, the chance of missing every bad location in $t$
openings is $(1-alpha)^t$. This elementary calculation explains why more openings help. It is
not, by itself, a security proof for a sequential-work protocol.

#definition([Worked example: a conditional sampling bound], [
  With a fixed bad fraction $alpha=0.1$ and $t=16$ independent openings, the chance of missing
  every bad location is $0.9^16 approx 0.185$. With 32 openings it is about 0.034. The premise
  fixes the commitment before the samples are chosen. If a prover can grind many roots, choose
  which commitment to reveal, or correlate failures, this calculation does not account for
  that strategy.
])

The referenced sequential-work construction has a security analysis in an oracle model.
Sibuna's domain separation, parameter mapping, truncation, and implementation must still be
checked against the construction's assumptions. Fiat–Shamir sampling makes openings
reproducible from a commitment; reproducibility alone does not prove resistance to grinding.
The construction's assumptions limit the security claim.

#exercise("3.1", [If an attacker tries $g$ independent commitments, each accepted with
probability $q$, derive the probability that at least one is accepted. Which costs are missing
from that expression?], hint: [First calculate the probability that all $g$ fail.])

=== Prover Memory

A naive prover stores every label ($2^(n+1) - 1$ of them). Sibuna's prover keeps a stack of the
current path's left-sibling labels ($n + 1$ labels) during the first pass and retains only the
top $m = min(n, 10)$ levels ($2^(m+1) - 1$ labels, at most 64 KB).

To open a leaf, it recomputes the subtree of the leaf's depth-$m$ ancestor. This takes
$2^(n - m + 1) - 1$ label calculations, using the retained levels to seed the stack. Total
prover cost is $2^(n+1) - 1 + t (2^(n - m + 1) - 1)$ label calculations. The whole workspace,
including the output proof, is under 100 KB. Browser and native tests share the same
`Workspace` type.

=== Parameters Are Not Timings

Sibuna maps work bits to depth using $n=b-3$, clamped to the supported interval $[4,24]$.
This is a work-scale convention, not a guarantee of equal wall-clock time between algorithms.
A leaf can hash several parent labels, while Hashcash repeatedly tests a nonce. Compiler,
browser, processor, and parameter choices all affect their relative costs. The committed
primitive benchmark measures verification; it does not establish browser solve latency.

Proof size is $32(1+t(n+1))$ bytes. At depth 13 with sixteen openings, this is
$32(1+16 times 14)=7200$ bytes. Raising the opening count increases both the proof and the
verifier's work, even if the dominant cost of constructing the tree stays the same.

#exercise("3.2", [Compute the proof size at depth 17 with 16 openings. Then double the
opening count. Which term doubles and which term remains fixed?])

=== Choosing a Construction

The relevant comparison is a resource budget, not an algorithm's reputation. Record the
prover's memory, the verifier's worst-case work, the proof bytes, and the assumptions needed
for the claimed property. Memory-hard search can be useful, but a verifier that must repeat
expensive work gives an attacker another place to spend the server's resources. Publicly
verifiable delay constructions serve a different trust model from a shared-secret gate.

Sibuna retains cheap hash verification and a hash-based sequential-work option. The latter
requires more proof bytes and more careful parameter analysis. Neither choice removes the
need to reject malformed proofs before entering expensive verification.

#teach_back([Explain the distinction between an authentication tree, which proves that a
label belongs to a commitment, and dependency edges, which constrain how labels are computed.])

== Symmetric Authentication: Challenges and Sessions

#objectives([
  Explain why a keyed pseudorandom function is the correct primitive when issuer and verifier
  are the same trust domain, state the forgery bound for a 128-bit tag, describe the stateless
  challenge record and the spent-set bound, and read the key schedule.
])

=== Issuer Equals Verifier

A digital signature lets a public-key holder verify a token without issuing one. That is
useful when verifiers must not be able to mint tokens. Sibuna's verifier is also the issuer,
or a cluster member sharing the same seed.

A message authentication code (MAC) authenticates tokens within this shared trust domain.
It uses a pseudorandom function (PRF), whose output is modelled as unpredictable to someone
without the key. Every holder of the MAC key can mint tokens as well as verify them. Part VIII compares
the implemented token operations.

#callout([Lemma 3 (Forgery bound)], [
  With BLAKE3 in keyed mode modelled as a PRF and a 16-byte tag, an adversary making $q$
  verification queries forges a valid token with probability at most $q dot 2^(-128) + epsilon_"PRF"$.
  At a million queries per second that is $2^(-108)$ per second.
])

The assumptions also differ under quantum computation. Ed25519 relies on elliptic-curve
discrete logarithms, which Shor's algorithm breaks. Generic quantum search gives a quadratic
speedup against ideal keyed-hash search. Sibuna retains Ed25519 as an option
(`--token-scheme ed25519`) for deployments whose verifiers must not mint tokens.

=== The Key Schedule

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

Each domain string gives the derived key a separate purpose. Compromising the master seed
compromises every derived key. Cluster members must agree on the seed.

=== Stateless Challenges

#book_figure([Wire formats of the challenge identifier and the session token], wire_formats())

A challenge identifier is a self-authenticating record: version, algorithm, difficulty, opening
count, issue time, the client's keyed fingerprint, a PRF-derived nonce, and the hash of the
policy rule that demanded the challenge, followed by a 16-byte tag under the challenge key.
Issuing one writes nothing. Verification decodes the record and checks its tag with a
constant-time comparison. It then checks the age against the challenge lifetime (TTL) and
the fingerprint against the submitting client. Proof verification follows these cheap checks.

#callout([Lemma 4 (State grows only with paid work)], [
  Let $S$ be the set of challenge tags the daemon remembers. A tag enters $S$ only after a valid
  proof for it was accepted, and it leaves after the challenge TTL. Hence $|S| <= r dot "TTL"$
  when $r$ bounds the rate of accepted distinct solutions over that interval. A tag is not
  allocated on a free challenge fetch. The implementation also has a fixed capacity and can
  reject a valid solution when saturated. This is a state bound, not a lower bound on every
  adversary's computational strategy.
])

The spent set is 16 shards of Robin Hood open addressing over the 16-byte tags (chapter 5). The
fingerprint is a keyed hash of the client address and User-Agent. Their lengths are encoded
separately, so different field boundaries cannot produce the same concatenated input.
The key prevents computing another client's fingerprint offline without the secret.

#exercise([3.3], [
  A token payload carries a work level, `timestamp`, `expiry`, `rule_hash`, and `fingerprint`.
  Explain what each field prevents if it were removed, and why the tag must cover all five.
])

#teach_back([
  A colleague proposes switching all tokens to Ed25519 "because it is stronger". Explain the
  trust-domain argument, the cost difference, and the post-quantum consideration.
])
