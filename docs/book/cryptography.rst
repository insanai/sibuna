Part III: Foundations from Cryptography Research
================================================

We derive the cost models behind Sibuna's two proof-of-work tiers, present the Cohen-Pietrzak Proof of Sequential Work with its security argument, and justify keyed-hash authentication for challenges and sessions. SID 0006 records the assumptions and references.

Hashcash: The Mathematics of Tier One
-------------------------------------

.. admonition:: Objectives

   By the end of this chapter, we should be able to state the expected work, variance, and tail probability of a bit-level Hashcash puzzle, explain why the server's verification cost bounds the attacker's advantage, and describe the two limits that motivate a second tier.

Definition and Cost
~~~~~~~~~~~~~~~~~~~

Sibuna's Tier One puzzle for challenge string :math:`C` and difficulty :math:`b` bits is: find :math:`N \in \mathbb{N}` such that :math:`\text{SHA-256}(C \parallel \text{":"} \parallel \mathrm{dec}(N))` has :math:`b` leading zero bits. The decimal rendering of the nonce is deliberate; it keeps the wire format identical between the WebAssembly solver, the JavaScript fallback, and the native verifier without a binary encoding step.

The unit of difficulty is an expected *hash trial*, not a compression function call. An input can occupy several SHA-256 blocks. Prefix precomputation can also change the work per nonce. The wire rule remains the digest predicate; implementations must agree on the statement and nonce encoding, not on an estimated CPU cost.

For independent ideal digests, the trial count :math:`X` is geometric with :math:`p = 2^{-b}`. Its median is :math:`\left\lceil \ln(1/2) / \ln(1-p) \right\rceil`, approximately :math:`2^b \ln 2` for small :math:`p`, and its variance is :math:`(1-p)/p^2`. The verifier checks one candidate digest rather than performing the search. Parsing, challenge authentication, fingerprint checks, spent-state insertion, and the response are additional work. A primitive timing cannot be inverted into a server's flood capacity.

Two Limits of Search
~~~~~~~~~~~~~~~~~~~~

The first is variance: a long search is not necessarily a broken worker. The second is parallelism: independent nonce trials can run concurrently. More cores reduce elapsed search time even when the expected aggregate trial count remains the same. Hardware throughput therefore matters to the admission policy. Neither a claimed hash rate nor a single benchmark can bound every requester's advantage.

.. admonition:: Exercise 3.0

   Using the geometric tail, estimate the probability of needing more than :math:`4.6 \times 2^b` trials. Why is the expected trial count unchanged by dividing the nonce space among several workers?

   *Hint:* Count aggregate trials, not elapsed seconds.

Proof of Sequential Work: Tier Two
----------------------------------

.. admonition:: Objectives

   Understand the Cohen-Pietrzak labelling, why it forces sequential computation, what the verifier checks, the conditional sampling bound :math:`(1 - \alpha)^t` and its limitations, the post-quantum result, the prover's memory bound, and the calibration data behind the work-bit mapping.

Why Sequential Work
~~~~~~~~~~~~~~~~~~~

A sequential-work construction introduces dependencies between computations: a later label needs a value produced earlier. This addresses a different quantity from aggregate work, namely the depth of the computation. Independent puzzles can still run in parallel, and hardware hash latency still matters.

Sibuna follows the hash-based construction described by Cohen and Pietrzak. Its graph has :math:`2^{n+1}-1` labels at depth :math:`n`, but a fixed label count is not a deterministic browser latency: labels can span several compression blocks, openings may recompute subtrees, and scheduling adds variation. Security statements from oracle-model analyses must not be turned into an unqualified claim about every concrete implementation or adversary.

The Construction
~~~~~~~~~~~~~~~~

Let :math:`n` be the depth and consider the complete binary tree with nodes named by binary strings of length at most :math:`n` (root :math:`\varepsilon`, children :math:`v0` and :math:`v1`, leaves of length :math:`n`). Each node :math:`v` carries a 32-byte label :math:`\ell_v = H(\chi, v, \mathrm{parents}(v))`, where :math:`\chi` is the challenge statement and :math:`H` is SHA-256 with :math:`\chi` absorbed once (the same prefix trick as the Hashcash solver):

- an internal node hashes its two children: :math:`\ell_v = H(\chi, v, \ell_{v0}, \ell_{v1})`;
- a leaf :math:`u = u_1 \dots u_n` hashes the *left siblings of its ancestors* wherever the root path turned right: :math:`\ell_u = H(\chi, u, \{\ell_{u_1 \dots u_{i-1} 0} : u_i = 1\})`.

.. graphviz::
   :caption: The depth-3 tree: an opening of leaf 3.5 sends the leaf label and the three sibling labels; the dashed edges are the left-sibling dependencies that make labelling sequential. Amber nodes form the path of leaf 3.5, green nodes are the siblings sent in the opening, and the dashed red edges are the left-sibling edges hashed into the leaf.
   :alt: A complete binary tree of depth 3 with nodes named depth.index. The root path of leaf 3.5 (nodes 0.0, 1.1, 2.2, 3.5) is highlighted in amber, the siblings 1.0, 2.3 and 3.4 sent in its opening are green, and dashed red edges run from 1.0 and 3.4 into leaf 3.5.

   digraph posw_tree {
     graph [rankdir=TB, bgcolor="transparent", nodesep=0.25, ranksep=0.5, ordering=out];
     node [shape=circle, fixedsize=true, width=0.5, fontname="Helvetica", fontsize=10, style=filled, fillcolor="#ffffff", color="#1e40af", fontcolor="#172033"];
     edge [color="#64748b", arrowhead=none];

     "0.0" [fillcolor="#fffbeb", color="#b45309", penwidth=1.5, xlabel=<<font color="#64748b">root &phi;</font>>];
     "1.1" [fillcolor="#fffbeb", color="#b45309", penwidth=1.5];
     "2.2" [fillcolor="#fffbeb", color="#b45309", penwidth=1.5];
     "3.5" [fillcolor="#fffbeb", color="#b45309", penwidth=1.5];
     "1.0" [fillcolor="#f0fdf4", color="#15803d", penwidth=1.5];
     "2.3" [fillcolor="#f0fdf4", color="#15803d", penwidth=1.5];
     "3.4" [fillcolor="#f0fdf4", color="#15803d", penwidth=1.5];

     "0.0" -> "1.0"; "0.0" -> "1.1";
     "1.0" -> "2.0"; "1.0" -> "2.1"; "1.1" -> "2.2"; "1.1" -> "2.3";
     "2.0" -> "3.0"; "2.0" -> "3.1"; "2.1" -> "3.2"; "2.1" -> "3.3";
     "2.2" -> "3.4"; "2.2" -> "3.5"; "2.3" -> "3.6"; "2.3" -> "3.7";

     "3.5" -> "1.0" [style=dashed, color="#b91c1c", dir=back, arrowtail=normal, constraint=false];
     "3.5" -> "3.4" [style=dashed, color="#b91c1c", dir=back, arrowtail=normal, constraint=false];
   }

The left-sibling edges are what make the computation sequential: leaf :math:`u` cannot be labelled until every subtree to its left is complete, so a depth-first post-order traversal is forced and the root label :math:`\varphi = \ell_\varepsilon` depends on all :math:`2^{n+1} - 1` labels in sequence.

**Openings.** After computing :math:`\varphi`, the prover derives :math:`t` leaves by Fiat-Shamir, :math:`\gamma_i = H(\chi \parallel \varphi \parallel i) \bmod 2^n`, and for each sends the leaf label and the :math:`n` sibling labels along its root path. The verifier recomputes the leaf from the siblings that are its parents, hashes upward through the path, and checks that it arrives at :math:`\varphi`. The verifier's cost is :math:`O(tn)` label computations with bounded workspace. A label computation may span multiple hash blocks; counting labels is not counting compression calls.

.. admonition:: Implementation: ``posw::verify_opening``

   Recomputes one opened leaf from its sibling labels and walks the path to the root. In ``crates/pow/src/posw.rs`` (crate ``sibuna-pow``).

.. code-block:: rust

   fn verify_opening(base: &Sha256, n: u8, phi: &Label, gamma: u32, opening: &[Label]) -> bool {
       let Some((leaf, siblings)) = opening.split_first() else {
           return false;
       };
       // `siblings` runs from depth n up to depth 1; reversed, it pairs with depths 1..=n.
       let mut hasher = node_hasher(base, n, gamma);
       for (d, sibling) in (1..=n).zip(siblings.iter().rev()) {
           if turns_right(gamma, n, d) {
               hasher.update(sibling);
           }
       }
       if hasher.finalize() != *leaf {
           return false;
       }
       let mut current = *leaf;
       for (d, sibling) in (1..=n).rev().zip(siblings) {
           let mut parent = node_hasher(base, d - 1, gamma >> (n - d + 1));
           if turns_right(gamma, n, d) {
               parent.update(sibling);
               parent.update(&current);
           } else {
               parent.update(&current);
               parent.update(sibling);
           }
           current = parent.finalize();
       }
       current == *phi
   }

Sampling, Soundness, and Their Limits
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Consider a fixed commitment with an independently detectable bad fraction :math:`\alpha`. If each opening samples uniformly and independently, the chance of missing every bad location in :math:`t` openings is :math:`(1-\alpha)^t`. This elementary calculation explains why more openings help. It is not, by itself, a security proof for a sequential-work protocol.

.. admonition:: Worked example: a conditional sampling bound

   With a fixed bad fraction :math:`\alpha = 0.1` and :math:`t = 16` independent openings, the chance of missing every bad location is :math:`0.9^{16} \approx 0.185`. With 32 openings it is about 0.034. The premise fixes the commitment before the samples are chosen. If a prover can grind many roots, choose which commitment to reveal, or correlate failures, this calculation does not account for that strategy.

The referenced sequential-work construction has a security analysis in an oracle model. Sibuna's domain separation, parameter mapping, truncation, and implementation must still be checked against the construction's assumptions. Fiat-Shamir sampling makes openings reproducible from a commitment; reproducibility alone does not prove resistance to grinding. We make no unconditional claim that cheating is never cheaper.

.. admonition:: Exercise 3.1

   If an attacker tries :math:`g` independent commitments, each accepted with probability :math:`q`, derive the probability that at least one is accepted. Which costs are missing from that expression?

   *Hint:* First calculate the probability that all :math:`g` fail.

Prover Memory
~~~~~~~~~~~~~

A naive prover stores every label (:math:`2^{n+1} - 1` of them). Sibuna's prover keeps a stack of the current path's left-sibling labels (:math:`n + 1` labels) during the first pass and retains only the top :math:`m = \min(n, 10)` levels (:math:`2^{m+1} - 1` labels, at most 64 KB). To open a leaf it recomputes the subtree of the leaf's depth-:math:`m` ancestor, :math:`2^{n-m+1} - 1` hashes, seeding the stack from the retained levels. Total prover cost is :math:`2^{n+1} - 1 + t\,(2^{n-m+1} - 1)` hashes and the whole workspace, including the output proof, is under 100 KB: a browser tab and a native test share the same ``Workspace`` type (``sibuna_pow::posw::Workspace``).

Parameters Are Not Timings
~~~~~~~~~~~~~~~~~~~~~~~~~~

Sibuna maps work bits to depth using :math:`n = b - 3`, clamped to the supported interval :math:`[4, 24]`. This is a work-scale convention, not a guarantee of equal wall-clock time between algorithms. A leaf can hash several parent labels, while Hashcash repeatedly tests a nonce. Compiler, browser, processor, and parameter choices all affect their relative costs. The committed primitive benchmark measures verification; it does not establish browser solve latency.

Proof size is :math:`32(1 + t(n+1))` bytes. At depth 13 with sixteen openings, this is :math:`32(1 + 16 \times 14) = 7200` bytes. Raising the opening count increases both the proof and the verifier's work, even if the dominant cost of constructing the tree stays the same.

.. admonition:: Exercise 3.2

   Compute the proof size at depth 17 with 16 openings. Then double the opening count. Which term doubles and which term remains fixed?

Choosing a Construction
~~~~~~~~~~~~~~~~~~~~~~~

The relevant comparison is a resource budget, not an algorithm's reputation. Record the prover's memory, the verifier's worst-case work, the proof bytes, and the assumptions needed for the claimed property. Memory-hard search can be useful, but a verifier that must repeat expensive work gives an attacker another place to spend the server's resources. Publicly verifiable delay constructions serve a different trust model from a shared-secret gate.

Sibuna retains cheap hash verification and a hash-based sequential-work option. The latter requires more proof bytes and more careful parameter analysis. Neither choice removes the need to reject malformed proofs before entering expensive verification.

.. admonition:: Explain the invariant

   Explain the distinction between an authentication tree, which proves that a label belongs to a commitment, and dependency edges, which constrain how labels are computed.

Symmetric Authentication: Challenges and Sessions
-------------------------------------------------

.. admonition:: Objectives

   Explain why a keyed pseudorandom function is the correct primitive when issuer and verifier are the same trust domain, state the forgery bound for a 128-bit tag, describe the stateless challenge record and the spent-set bound, and read the key schedule.

Issuer Equals Verifier
~~~~~~~~~~~~~~~~~~~~~~

A digital signature lets *anyone* holding the public key verify, which is the right tool when verifiers must not be able to mint. Sibuna's verifier *is* the issuer (or a cluster sharing one seed). A message authentication code built from a pseudorandom function supplies authentication within that trust domain. It does not supply public verification: anyone holding the MAC key can also mint tokens. The benchmark chapter compares the implemented token operations.

.. admonition:: Lemma 3 (Forgery bound)

   With BLAKE3 in keyed mode modelled as a PRF and a 16-byte tag, an adversary making :math:`q` verification queries forges a valid token with probability at most :math:`q \cdot 2^{-128} + \varepsilon_{\mathrm{PRF}}`. At a million queries per second that is :math:`2^{-108}` per second.

A second consequence matters for the long term: Ed25519 rests on discrete logarithms in an elliptic-curve group, which Shor's algorithm breaks; a keyed hash rests only on the hash function, against which quantum algorithms give at most a quadratic speedup. Sibuna keeps Ed25519 as an option (``--token-scheme ed25519``) for deployments that need non-minting verifiers.

The Key Schedule
~~~~~~~~~~~~~~~~

One 32-byte master seed (from ``--secret-file``, ``SIBUNA_SECRET``, or a fresh random value) derives every purpose key with keyed BLAKE3 and a domain string. The key schedule belongs to the ``sibuna-challenge`` crate.

.. note::

   The ``sibuna-challenge`` crate is still being ported. Until it lands, we show its code in the Zig original, which SID 0010 makes the specification of the crate's behaviour. The domain strings and the byte layouts are identical in both.

.. code-block:: zig

   pub fn derive(seed: *const [32]u8) Keys {
       return .{
           .token = subkey(seed, "sibuna/token/v1"),
           .challenge = subkey(seed, "sibuna/challenge/v1"),
           .ed25519_seed = subkey(seed, "sibuna/ed25519/v1"),
           .fingerprint = subkey(seed, "sibuna/fingerprint/v1"),
       };
   }

Domain separation prevents accidental reuse across purposes; compromise of the master seed compromises every derived key. A cluster only has to agree on one seed.

Stateless Challenges
~~~~~~~~~~~~~~~~~~~~

.. code-block:: text
   :caption: Wire formats of the challenge identifier and the session token (field widths in bytes).

   Challenge identifier
   +-----+-----+------+---+-----------+-------------+---------+-----------+----------------+
   | ver | alg | diff | t | issued_at | fingerprint | nonce   | rule_hash | BLAKE3 tag     |
   |  1  |  1  |  1   | 1 |     8     |      8      |    8    |     8     |       16       |
   +-----+-----+------+---+-----------+-------------+---------+-----------+----------------+
   |<----------------------- 36-byte payload ---------------------------->|<-- keyed tag ->|
   36-byte payload + 16-byte keyed tag = 52 bytes, 70 URL-safe base64 characters

   Session token
   +-----+-----+------+-----+-----------+--------+-----------+-------------+----------------+
   | ver | alg | bits | res | timestamp | expiry | rule_hash | fingerprint | BLAKE3 tag     |
   |  1  |  1  |  1   |  5  |     8     |   8    |     8     |      8      |       16       |
   +-----+-----+------+-----+-----------+--------+-----------+-------------+----------------+
   |<------------------------ 40-byte payload ---------------------------->|<-- keyed tag ->|
   40-byte payload + 16-byte keyed tag = 56 bytes, 75 URL-safe base64 characters

A challenge identifier is a self-authenticating record: version, algorithm, difficulty, opening count, issue time, the client's keyed fingerprint, a PRF-derived nonce, and the hash of the policy rule that demanded the challenge, followed by a 16-byte tag under the challenge key. Issuing one writes nothing. Verification decodes the record, checks the tag in constant time, checks the age against the challenge TTL, checks the fingerprint against the submitting client, and only then examines the proof.

.. admonition:: Lemma 4 (State grows only with paid work)

   Let :math:`S` be the set of challenge tags the daemon remembers. A tag enters :math:`S` only after a valid proof for it was accepted, and it leaves after the challenge TTL. Hence :math:`|S| \le r \cdot \mathrm{TTL}` when :math:`r` bounds the rate of accepted distinct solutions over that interval. A tag is not allocated on a free challenge fetch. The implementation also has a fixed capacity and can reject a valid solution when saturated. This is a state bound, not a lower bound on every adversary's computational strategy.

The spent set is 16 shards of Robin Hood open addressing over the 16-byte tags (Part V). The fingerprint is a keyed hash of the client address and User-Agent, length-separated so no two inputs collide by concatenation, and keyed so fingerprints of other clients cannot be computed offline.

.. admonition:: Exercise 3.3

   A token payload carries a work level, ``timestamp``, ``expiry``, ``rule_hash``, and ``fingerprint``. Explain what each field prevents if it were removed, and why the tag must cover all five.

.. admonition:: Explain the invariant

   A colleague proposes switching all tokens to Ed25519 "because it is stronger". Explain the trust-domain argument, the cost difference, and the post-quantum consideration.
