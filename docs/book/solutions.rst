Selected Solutions
==================

These solutions are checks on the argument, not substitutes for the exercises. If a result differs, we first compare assumptions: endpoints of time intervals, what is counted as work, and whether a write has committed are common sources of disagreement.

Part I: Cost and Probability
----------------------------

**1.1.** One million trials divided among 100 requests is 10,000 trials per request. Sharing a session does not change that arithmetic if the aggregate request count stays 100. The actual system must decide whether a second process can satisfy the fingerprint and routing bindings; those conditions are outside the amortization equation.

**1.2.** The excess is :math:`1000 - 600 = 400` records/s. An empty queue of 512 records buys :math:`512/400 = 1.28` seconds in the fluid model. Real producers arrive in bursts and the consumer commits batches, so the exact first drop depends on arrival and commit times.

Part II: Prior Art
------------------

**2.1.** One source compiled twice cannot disagree with itself about the statement, the nonce encoding, the tree shape, or the opening layout; drift would require a compiler bug. It says nothing about whether the construction is sound (cryptographic review), whether the browser runtime executes it correctly (a byte-identical comparison between the WebAssembly and JavaScript provers covers that), or whether the parameters are calibrated (measurement).

**2.2.** (a) Sibuna Gate or Anubis, one binary; (b) Sibuna Shield, SafeLine, or Cloudflare (Pro plan or above); (c) Sibuna Edge with a shared PostgreSQL database (``--database-url``), Anubis with a shared Valkey store (for state, not for bans), or Cloudflare. The only single product meeting all three without a Docker host or a subscription is Sibuna Shield with its nodes sharing one PostgreSQL database (``--database-url`` and ``--cluster-node``); the "runs as", "inspection", and "multi-node" rows decide it.

Part III: Cryptography
----------------------

**3.0.** The tail estimate is :math:`e^{-4.6} \approx 0.010`. Dividing the nonce space changes the rate at which trials are completed, not the success probability of each independent trial. Duplicate trials or coordination work can make a real parallel implementation less efficient.

**3.1.** If each commitment succeeds with probability :math:`q`, all :math:`g` fail with probability :math:`(1-q)^g`. At least one succeeds with probability :math:`1-(1-q)^g`. The formula does not count commitment construction, query budgets, dependencies between trials, or the work needed to find a commitment with a particular acceptance probability.

**3.2.** At depth 17 and 16 openings, the proof has :math:`32(1 + 16 \times 18) = 9248` bytes. At 32 openings it has :math:`32(1 + 32 \times 18) = 18464` bytes. The opening bytes double; the 32-byte root is still sent once.

**3.3.** Without the work level a session earned on a cheap route would admit a request to an expensive one that demanded more work; without ``timestamp`` a token could be minted "in the future" and outlive its policy; without ``expiry`` it would never die; without ``rule_hash`` the upstream could not learn which rule admitted the client; without ``fingerprint`` a cookie copied to another machine would be accepted. The tag must cover all five because any field left outside it could be edited freely, and the verifier could not tell.

Part IV: Protocol
-----------------

**4.1.** Both browsers share the address and User-Agent, so they share the fingerprint, the rate-limit cell, and the ban slot. They do not share the challenge (each fetches its own record with its own nonce), the spent-set entry, or the cookie. To reuse the other browser's cookie an attacker on the NAT would need to read it from the other machine: the fingerprint would then match, which is why ``HttpOnly`` and ``SameSite`` matter more than the binding on a shared address.

Part V: State and Ordering
--------------------------

**5.1.** The head and the first part of the body (up to what fits after the head in 64 KB) are in the connection buffer and are sent with ``write_all(request.body)``. The remaining bytes never enter the buffer whole: ``relay_body`` reads them in 16 KB pieces from the client reader and writes each to the origin. The head must go first because the origin needs ``Content-Length`` before the body, and because the audit headers are part of the head.

**5.2.** The emission interval is 100 ms and burst tolerance is 9,900 ms. An idle client may send 100 requests immediately, then one per 100 ms. Through the inclusive endpoint at 3,000 ms, the bound is 130. A fixed 10-second counter would allow 100 in the first window and 100 more the instant the window rolls over; a sliding log would allow exactly 100 in any 10 seconds but must store 100 timestamps per client.

Part VI: Algorithms
-------------------

**6.1.** An apostrophe in a name and an ordinary parameter named ``order`` do not establish an SQL expression. A substring detector could mistake either for syntax. The structural detector looks for additional evidence, including operators and literal relations. It remains bounded inspection, not a parser for every application language.

**6.2.** LDAP filters are built from parentheses, ``|``, ``&``, ``!``, and ``=``. The detector needs a byte class for ``(`` and ``)`` (new) and can reuse the existing ``=`` and shell-separator classes for ``|`` and ``&``. It should fire on a *sequence* such as ``)(`` or ``(|(``, not on a single parenthesis, for the same reason the SQL detector requires a quote or a tautology.

Part VII: Browser Engine
------------------------

**7.1.** At the default 16 work bits (depth 13 with 16 openings), the supposed 20 ms in WebAssembly become :math:`50 \times 20 = 1000` ms, one second, in JavaScript on the laptop, and four seconds on the slower phone. The figures are suppositions; we measure our own clients' devices before we set a policy. A sensible policy: let the page forward the ``fallback`` message, log it server-side as a metric, and lower the difficulty for a rule that matches clients known to block WebAssembly rather than for everyone.

Part VIII: The Edge Load Balancer
---------------------------------

**8.1.** Under modulo hashing, a step from 10 to 9 servers keeps a flow only when :math:`h \bmod 10` and :math:`h \bmod 9` name the same survivor. By the Chinese remainder theorem each of the 90 pairs has probability :math:`1/90`, and each of the 9 survivors owns one matching pair, so :math:`9/90 = 10\%` stay and 90% move. Under rendezvous hashing only the departed server's clients move: 10%. In the run reported in the chapter, Sibuna's Maglev table moved the departed server's 10.0% of the slots and 0.18% to 0.28% more. When a fifth server joins four, modulo hashing keeps the flows whose pair :math:`(h \bmod 4, h \bmod 5)` names one of the four old servers at both positions, :math:`4/20 = 20\%`, and moves 80%. Rendezvous hashing moves only the clients for which the newcomer is nearer than their old server: 20% of them, all to the newcomer.

**8.2.** :math:`W = 4` and :math:`L + 1 = 20`. The bound of ``a`` is :math:`\lceil 1.25 \times 20 \times 2/4 \rceil = \lceil 12.5 \rceil = 13`; that of ``b`` and ``c`` is :math:`\lceil 6.25 \rceil = 7`. ``b`` holds 7, which is not below 7, so the primary refuses. Least connections compares flows per unit of weight: ``a`` has :math:`9/2 = 4.5`, ``b`` has 7 and ``c`` has 3, so the flow goes to ``c``, which then holds 4, within its bound of 7. Some server is always below its bound: if every server :math:`i` held at least :math:`1.25 \times 20\, w_i / 4` flows, the three would hold at least :math:`1.25 \times 20 = 25` flows, but they hold 19.

**8.3.** With the tenant field, ``tenant`` admits. If ``score`` denies or challenges, the chain ends there; suppose it admits, by its verdict or, when it fails, by its written ``on_failure: "admit"``. ``authz`` fails with ``unavailable``, and its default ``on_failure`` is ``deny``, so the chain ends in a denial: 403 with the reason ``hook:authz``. Without the field, ``tenant`` denies, the chain ends there with ``hook:tenant``, and the agent is never asked. An open breaker refuses without a system call, so a request costs the worker nothing for the agent; each worker sends one probe per ``open`` interval, which costs at most one ``deadline``. With ``authz`` written ``on_failure: "admit"`` the request with the field is admitted, and the failed agent adds no fields. The hook is then advisory: anyone who can make it fail passes it.

**8.4.** The mapping received 1,200 bytes, so before validation it sends at most 3,600 bytes to the client: three of the eight replies. The edge learns the source connection ID of the first long-header reply whose version is not zero and whose ID has at least 8 bytes and differs from the IDs of the Initial. The client's next datagram that carries this ID as its destination validates the mapping. The reply that carried the ID went only to the claimed address, so a sender that spoofs that address never sees it and must guess at least 64 bits, one datagram per guess. A Version Negotiation packet has version zero and repeats the IDs that the client sent; a spoofing sender knows those IDs, and if the edge learned from that packet, the sender could validate itself and lift the bound that prevents reflection.

Part IX: A Cluster of Edges
---------------------------

**9.1.** C sends the lift :math:`\max(1300, 900 + 60) = 1300`: the end of the ban it knows, and at least 60 seconds ahead. Every node that hears it admits the client and forgets A's ban. D's ban until 1,200 ends before the lift, so every node ignores it: the cut-off node cannot bring the ban back. B's new ban until 1,250 also ends before the lift. B's own firewall bans the client, but its peers ignore the datagram, so the ban holds on B only. This is the first known gap of SID 0022: a ban issued after a lift holds everywhere only when it ends after the lifted ban would have. A ban of the same length as A's, issued at second 1,000, would have ended after 1,300 and held on every node.

**9.2.** The two entries have the same end, so the server decides: ``0x91...`` is the larger hash, and B's entry wins on every node, A included, whatever the order in which the datagrams arrive. No flow moves. The flow that A placed holds a reservation on its server and never reads the table again. Only the next new flow of the client, on any node, goes to the server ``0x91...``, and only while that server is eligible. Without the server in the order, A and B would each keep their own entry forever, because neither end is later.

**9.3.** :math:`\lfloor 10/4 \rfloor = 2` with remainder 2, so A and B have base 3 and C and D base 2. D has :math:`f = 0` and :math:`r = \max(1, \lceil 2/4 \rceil) = 1`, so it wants 1, with the flag. A has share 3, :math:`f = 3`, surplus 2, and gives :math:`\min(1, \max(2, \lceil 3/2 \rceil)) = 1`; B gives 1 likewise; C has :math:`f = 2`, surplus 1, and gives 1. Every peer serves the want it heard, so D receives 3 and holds a share of 5, beside 2, 2 and 1: the sum is 10. When A stops for good, its share of 2 is stranded: D still counts the 1 that A gave, and the cluster can hold at most 8 flows on the server. Nothing returns the 2 by itself. The operator removes A from ``mesh.nodes`` in every file and restarts the nodes. The new roster makes a new ledger, under a new key, with bases 4, 3 and 3; it starts unsynchronised, so new flows on the server are refused until the nodes have exchanged one status, about a second.

**9.4.** (a) Each client moves with probability :math:`1/5`, so about 200 of 1,000 move, all of them to the new node. (b) Only B's clients, about 250, move. Each goes to the node with its second largest score among A, C and D, so each of the three receives about 83. (c) A client stays when :math:`h \bmod 4 = h \bmod 5`. Both residues are fixed by :math:`h \bmod 20`, and they agree only for :math:`h \bmod 20 \in \{0, 1, 2, 3\}`, four residues of twenty. So about 800 clients move, against 200 under rendezvous hashing.

**9.5.** With eight counters for each slot, :math:`m = 8S`. At the middle of the window :math:`N = 2S` and :math:`\lambda \le 4 \cdot 2S / 8S = 1`. Then :math:`P(X \ge 4) = 1 - e^{-1}(1 + 1 + \tfrac{1}{2} + \tfrac{1}{6}) \approx 1 - 0.3679 \times 2.667 \approx 0.019`, and for all four counters :math:`0.019^4 \approx 1.3 \times 10^{-7}`. At the end of the window :math:`N = 4S` and :math:`\lambda \le 2`, which gives the :math:`4.2 \times 10^{-4}` of the worked example. Doubling the counters halves :math:`\lambda` and lowers the probability by more than three orders of magnitude, which is why the code asks for eight counters for each slot.

**9.6.** Both commands read head 7 and commit with the expected revision 7. The transaction that first takes the row lock of ``edge_head`` sets the head to 8 and inserts revision 8. The other waits for the lock, then finds the head at 8; its ``UPDATE`` changes no row, and the command fails with ``DBA002 REVISION CONFLICT`` and commits nothing. The database holds revision 8 with the first change only. The second operator runs ``diff`` again: because a revision is a whole document, the difference now shows that the second source would also undo the first change. The operator merges both changes into the source and applies against revision 8. A commit conditioned on the head at the time of the commit would have succeeded on 8 and silently removed the first operator's change: a lost update that nobody saw.

Part X: Evaluation
------------------

**10.2.** For Gate's ``admitted`` row, :math:`11.84 \times 211{,}345 / 10^6 \approx 2.50` cores busy out of four, so the daemon was not CPU bound and the load generator set the limit. The 11.84 us of CPU per request is far above the sub-microsecond classification cost because a product row also contains the kernel's socket read and write, the parser, the session tag check, the metrics increments, the response formatting, the writer flush, and the scheduler's hand-off between the load generator and the connection thread. The primitive suite times none of those.

Part XI: Operations
-------------------

**11.1.** If the data commits before a separate receipt update, a crash between them leaves the old receipt and a retry can apply the effect again. If the receipt commits first, a crash before the data write can cause the retry to skip data that never existed. One atomic transaction removes both gaps. Losing the transaction's acknowledgement still requires the retained retry.

**11.2.** ``ip_rules: {"10.20.0.0/16": "ALLOW"}`` (or an ``ip_reputation`` row with score 100) admits staging; a rule ``{"name": "admin", "path": "/admin/*", "action": "CHALLENGE", "challenge": {"difficulty": 20, "algorithm": "posw"}}`` demands the work; a rule matching ``headers: {"X-Partner-Key": ".*"}`` with ``ALLOW`` and ``"limits": {"rate": 30, "window_seconds": 10}`` admits the partner at 30 requests per 10 seconds. The rule's quota is checked for every request it matches, after the per-client daemon limit (``--rate-limit``, ``--rate-window``), which must therefore be at least as generous.

Part XII: Reference
-------------------

**12.1.** The challenge record carries the keyed fingerprint of the address that fetched it; the solution arrives from a new address, so ``verify_and_mint`` returns ``FingerprintMismatch`` before looking at the proof. The smallest recovery is in the interstitial: on a ``400`` whose title is ``CLIENT FINGERPRINT MISMATCH``, fetch a fresh challenge and solve again instead of showing the error, since the work already done cannot be transferred.

Continue the Investigation
--------------------------

Change one invariant at a time in a disposable test. Remove the snapshot recheck, omit the incident receipt, or round the rate interval downward. Predict a failure schedule before we run the test. A useful regression does more than assert the happy-path output: it demonstrates why the omitted condition is necessary.
