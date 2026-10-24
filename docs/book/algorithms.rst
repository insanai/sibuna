Part VI: Automata, Tries, and the Semantic Firewall
===================================================

We examine the algorithms behind sub-microsecond classification: the tagged Aho-Corasick automaton, the IPv4/IPv6 radix trie, the byte-class tokenizers of the semantic WAF, and the declarative policy engine with WEIGH scoring.

Single-Pass Multi-Pattern Matching
----------------------------------

.. admonition:: Objectives

   By the end of this chapter, we should be able to derive the Aho-Corasick automaton's linear-time guarantee, explain the dense-table layout and case folding through byte classes, and argue why a SIMD literal engine was not adopted.

Aho-Corasick as a Dense DFA
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sibuna has two literal-pattern sets: about forty bot signatures and about a hundred attack signatures. Scanning a field against :math:`N` patterns one at a time is :math:`O(NM)`; the automaton of Aho and Corasick (1975) scans it once in :math:`O(M)` after building a trie with failure links. Sibuna folds the failure links into the transition table at build time, so scanning is one table load per input byte with no branches on the pattern set. The automaton lives in the ``sibuna-patterns`` crate:

.. code-block:: rust

   /// Advances from `state` (a row offset) over `byte`.
   fn step(&self, state: usize, byte: u8) -> usize {
       self.table[state + usize::from(self.classes[usize::from(byte)])] as usize
   }

   pub fn find_first(&self, haystack: &[u8]) -> Option<Match> {
       let mut state = 0;
       for (index, &byte) in haystack.iter().enumerate() {
           state = self.step(state, byte);
           if state >= self.first_match {
               let id = self.first_output_in(self.match_state(state), self.all_tags)?;
               return Some(self.report(id, index + 1));
           }
       }
       None
   }

A state is stored as its row offset in one flat table, so a step is one add and one load. States are numbered so that every match state comes after every other state; detecting a match is then one comparison against ``first_match``, with no second table to load in the inner loop.

.. graphviz::
   :caption: Trie states and failure edges for two signatures
   :alt: A trie from the root through G and GP to the GPTBot match state, and through C and Cl to the ClaudeBot match state; dashed failure edges lead from GP and Cl back to the root.

   digraph aho_corasick {
     graph [rankdir=LR, bgcolor="transparent", nodesep=0.55, ranksep=0.5, pad=0.12];
     node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10, fontcolor="#172033", color="#1e40af", fillcolor="#eff6ff", penwidth=1.1, height=0.4, margin="0.12,0.05"];
     edge [fontname="Courier-Bold", fontsize=10, fontcolor="#1e40af", color="#64748b", arrowsize=0.65, penwidth=1.1];
     root [label="Root (0)", fillcolor="#ffffff", color="#172033", penwidth=1.4];
     g [label="G", group=top];
     gp [label="GP", group=top];
     gptbot [label="GPTBot", group=top, fillcolor="#fef2f2", color="#b91c1c", peripheries=2];
     c [label="C", group=bottom];
     cl [label="Cl", group=bottom];
     claudebot [label="ClaudeBot", group=bottom, fillcolor="#fef2f2", color="#b91c1c", peripheries=2];
     root -> g [label="g"];
     g -> gp [label="p"];
     gp -> gptbot [label="tbot"];
     root -> c [label="c"];
     c -> cl [label="l"];
     cl -> claudebot [label="audebot"];
     root:n -> gp:n [dir=back, label="fail", style=dashed, color="#d97706", fontcolor="#b45309", fontname="Helvetica", fontsize=8.5];
     root:s -> cl:s [dir=back, label="fail", style=dashed, color="#d97706", fontcolor="#b45309", fontname="Helvetica", fontsize=8.5];
   }

The automaton's state budget is a run-time option. The policy engine reserves at most one root plus the sum of all signature lengths, a safe upper bound on trie states. This avoids historically oversized fixed tables while retaining a dense transition for every byte class. Each pattern carries a small category tag (0 to 63, so a set of tags is one 64-bit word). Case folding uses a 256-entry byte-class table built with the automaton: both cases of a letter share a class, and bytes that occur in no pattern share one class, so a table row is as wide as the number of distinct pattern bytes plus one rather than 256. Exact engine sizes and the comparison with sequential substring search are recorded in Part VIII. The latter uses the same patterns and any-match semantics.

Regular Expressions, SIMD Engines, and the Choice
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Three families were weighed for the signature stage:

- *Backtracking regular expressions* (a backtracking rule-set style) run hundreds of patterns per request and allocate per match; they are the slowest option and the most prone to false positives.
- *SIMD literal engines* (Hyperscan, Vectorscan) prefilter blocks of 16 to 32 bytes with shuffle-based nibble masks (the "Teddy" algorithm) and verify candidates with automata. They excel on long inputs with large literal sets. The cost is a multi-megabyte C++ dependency, a compile-time pattern database, no WebAssembly target, and, for inputs of a hundred bytes, no advantage: the whole field scans in less time than one cache miss.
- *Dense Aho-Corasick plus small structural tokenizers*, the libinjection lineage, gives exact linear-time behaviour in a fixed table and needs nothing outside the binary.

Sibuna's fields are short, so the third family wins on both memory and speed; Part VIII records about 1.56 ns per byte on an 8 KiB body (the semantic scan takes 12,784.3 ns, ``8kb_body_semantic_scan`` in ``benchmarks/results/primitives-latest.md``). That is the one workload where a SIMD prefilter would pay, and SID 0006 keeps it as an open item.

The Radix Trie for IPv4 and IPv6
--------------------------------

.. admonition:: Objectives

   Trace a longest-prefix lookup through the 128-bit trie, explain the IPv4 root shortcut, and see how the trie doubles as the reputation store fed by the cluster.

One binary trie over 128-bit keys serves both families: IPv6 prefixes are inserted as-is, IPv4 prefixes are mapped into ``::ffff:0:0/96`` so a ``/24`` becomes a depth-120 path. Nodes live in one flat ``Vec`` indexed by ``u32`` with index zero as both root and "no child", so a lookup is at most 128 dependent loads with no pointer chasing. The trie is the ``PrefixTrie`` of the ``sibuna-cidr`` crate.

Walking the 96 mapped-prefix levels for every IPv4 lookup would cost 96 dependent loads before it reached the first bit of the IPv4 address. So the trie records the node at depth 96 at initialisation and starts IPv4 lookups there:

.. code-block:: rust

   let (mut node, mut depth, mut best) = if is_ipv4_mapped(key) {
       let start = self.ipv4_root;
       let value = self.nodes[start as usize].value.as_ref();
       (start, IPV4_DEPTH, value.or(self.nodes[0].value.as_ref()))
   } else {
       (0, 0, self.nodes[0].value.as_ref())
   };

Classifying an IPv4 address costs 32.0 ns and an IPv6 address 79.3 ns (``ipv4_cidr_classification`` and ``ipv6_cidr_classification`` in ``benchmarks/results/primitives-latest.md``). The engine consults the trie twice: terminal ``allow``/``deny`` verdicts before the rule table, so a cluster-wide ban beats every rule, and ``challenge`` verdicts after it.

The Semantic Firewall
---------------------

.. admonition:: Objectives

   Understand the byte-class pre-scan, the tagged signature automaton, the SQL tokenizer with tautology detection, the HTML and shell structure checks, canonicalisation, and the false-positive discipline that a real browser request must pass untouched.

A Lesson in False Positives
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The first version of the WAF matched a flat substring list against every header. The list contained ``/*``, and every browser sends ``Accept: text/html,...,*/*;q=0.8``. Every real browser was classified as SQL injection and received ``403``. The lesson shaped the design: a detector may fire only on *structure*, and the test suite now passes a complete Chrome request, including a comment body containing ``select``, ``--``, and an apostrophe, through the engine and asserts it comes out clean.

Byte Classes in One Pass
~~~~~~~~~~~~~~~~~~~~~~~~

Each inspected field is scanned once to collect which byte classes occur: quotes, ``=``, ``<``, shell separators, ``%``, NUL, canonicalisation triggers, and double spaces. Every detector consults the classes instead of rescanning, and the canonicalised second pass runs only when a trigger was seen. The scan is a 256-entry table lookup per byte, from the WAF module of ``sibuna-policy``. Four accumulators keep the OR chains short, and the two byte pairs (``/*`` and two adjacent spaces) are searched for only when no single byte has already demanded canonicalisation:

.. code-block:: rust

   pub(crate) fn scan(text: &[u8]) -> Classes {
       let (chunks, remainder) = text.as_chunks::<8>();
       // Four accumulators keep the OR chains short so the loads can issue back to back.
       let mut lanes = [0u16; 4];
       for chunk in chunks {
           lanes[0] |= TABLE[usize::from(chunk[0])] | TABLE[usize::from(chunk[4])];
           lanes[1] |= TABLE[usize::from(chunk[1])] | TABLE[usize::from(chunk[5])];
           lanes[2] |= TABLE[usize::from(chunk[2])] | TABLE[usize::from(chunk[6])];
           lanes[3] |= TABLE[usize::from(chunk[3])] | TABLE[usize::from(chunk[7])];
       }
       let mut bits = lanes[0] | lanes[1] | lanes[2] | lanes[3];
       for &byte in remainder {
           bits |= TABLE[usize::from(byte)];
       }
       // The pairs matter only while no single byte has demanded canonicalisation yet.
       if bits & CANONICAL == 0
           && ((bits & SPACE != 0 && has_pair(text, b' ', b' '))
               || (bits & (SLASH | STAR) == SLASH | STAR && has_pair(text, b'/', b'*')))
       {
           bits |= CANONICAL;
       }
       Classes { bits }
   }

Detectors
~~~~~~~~~

- *Signatures.* All strong signatures of every category live in one tagged automaton; a hit is a terminal ``deny`` named ``waf:sqli``, ``waf:xss``, ``waf:path-traversal``, or ``waf:rce``.
- *SQL injection.* A single-pass word scanner looks up each alphanumeric word (at most seven bytes) in the keyword table and, on ``or`` / ``and``, checks for a ``literal = literal`` tautology; ``id=1 or 1=1`` is terminal. Otherwise a quote byte is mandatory and the evidence must score at least 4 out of: quote (1), up to two keywords (2), a comment marker (1), an ``=`` (1). ``admin'--`` is terminal by itself. "it's a group order from the shop" scores 3 and passes.
- *Cross-site scripting.* Requires ``<``; fires when a tag that can host script co-occurs with an ``on<event>=`` attribute in attribute position. ``onboarding=1`` does not count.
- *Command injection.* Requires a separator; fires when ``;``, ``|``, ``&&``, ``$(``, a backtick, or a newline is followed by a known command name. ``status ok; done | next`` passes.
- *Path traversal.* Signatures (``../``, ``..%2f``, ``/etc/passwd``, ``id_rsa``, ...) plus NUL and ``%00``.

Structural headers whose grammar legitimately contains quotes and stars (``Accept*``, ``Content-Type``, ``Sec-*``, ``If-*``, ...) are skipped; the path, query, User-Agent, other headers, and the first 8 KB of the body are inspected, and fields with percent escapes, plus signs, comment openers, or collapsible whitespace are canonicalised into an 8 KB stack buffer and inspected again, so ``1%27/**/UnIoN/**/SeLeCt`` and ``%252e%252e/`` collapse onto the raw signatures.

Cost
~~~~

The inspection cost depends on the fields and bytes presented to the engine, not just the number of requests. The benchmark chapter reports separate Gate, Shield, and 8 KB body cases. The 8 KB bound is an inspection limit, not a claim that the rest of an upload is safe. An ingress using forward-auth must pass the relevant request information; omitted bytes cannot be inspected by this process.

The Declarative Policy Engine
-----------------------------

.. admonition:: Objectives

   Read the rule model, the evaluation order, WEIGH scoring with thresholds, and the JSON policy grammar.

A rule is a conjunction of optional criteria (path pattern, User-Agent pattern, up to four headers, up to eight IPv4/IPv6 CIDR blocks, one JA4 fingerprint or prefix) with an action ``ALLOW``, ``DENY``, ``CHALLENGE``, or ``WEIGH``, optional per-rule difficulty in work bits and algorithm, and a signed ``weight``. Evaluation order:

1. Semantic WAF (Shield only): violation is a terminal ``deny``.
2. Reputation trie: ``deny`` or ``allow`` prefixes are terminal.
3. Rules in order: the first terminal match returns; ``WEIGH`` matches accumulate.
4. Score: negative totals ``allow``; totals :math:`\geq 40` ``deny``; totals :math:`\geq 10` ``challenge`` with one extra work bit per 5 points above the threshold, capped at six.
5. Static bypass paths, then trie ``challenge`` verdicts, then the bot automaton.
6. Default action, ``challenge`` unless the policy file says otherwise.

Built-in rules allow ``/.well-known/*``, ``/favicon.ico``, ``/robots.txt``, and ``/__sibuna/*``, deny ``CF-Worker`` clients and ``Amazonbot``, and challenge every ``Mozilla`` User-Agent: a browser string is free to forge, so admitting it would make the gate decorative.

.. code-block:: json

   {
     "default_action": "CHALLENGE",
     "waf": true,
     "thresholds": { "challenge_at": 10, "deny_at": 40, "bits_step": 5 },
     "ip_rules": { "10.0.0.0/8": "ALLOW", "2001:db8::/32": "DENY" },
     "rules": [
       { "name": "internal-api", "path": "/api/*", "headers": { "X-Api-Key": ".*" },
       "action": "ALLOW" },
       { "name": "checkout", "path": "/checkout/*", "action": "CHALLENGE",
         "challenge": { "difficulty": 20, "algorithm": "posw" } },
       { "name": "headless", "user_agent": "Headless", "action": "WEIGH", "weight": 30 },
       { "name": "no-language", "headers": { "Accept-Language": "" },
       "action": "WEIGH", "weight": -5 }
     ]
   }

Worked Trace: an Encoded Attack with a Valid Session
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Consider ``GET /search?q=%2527%2520OR%25201%253D1`` from a client holding a valid session. First the HTTP parser separates the path and query without copying their bytes. Local limits run, then Shield inspects the request. The percent sign marks the field for canonicalization. One decoding pass exposes ``%27%20OR%201%3D1``; a second exposes ``' OR 1=1``.

The tokenizer now sees a quote, the keyword ``OR``, and equal literal operands. A denial is a terminal policy result. The valid session does not turn it into an allow: the session check only resolves a challenge decision. The storage hook copies a bounded incident record; SQL runs later. The response path need not hold the engine snapshot while an origin connection is idle.

.. admonition:: Exercise 6.1

   Replace the payload with ``O'Reilly`` and then with ``order=1``. Why should neither alone establish SQL injection? Give an example of a false positive a substring-only detector could produce.

.. admonition:: Exercise 6.2

   Write the byte-class table entries needed to add a detector for LDAP injection (patterns such as ``)(|(``), and explain which existing class bits it can reuse.

.. admonition:: Explain the invariant

   Explain to a reviewer why ``Accept: */*`` was a false positive, what structural property the new SQL detector requires, and how the automaton and the tokenizer divide the work.
