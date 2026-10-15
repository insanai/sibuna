Part I: The Cost of a Request
=============================

Before choosing an algorithm, identify the resource it is meant to protect. This chapter builds the small models that every later design decision is measured against: origin work, puzzle work, session amortisation, and the memory an untrusted client can make a server hold.

.. admonition:: Objectives

   By the end of this chapter, we should be able to write the inequality that decides whether a gate pays for itself, state what a proof of work does and does not establish, derive the expectation and tail of hash search, explain how sessions amortise work, and list the five invariants the rest of the book maintains.

Admission Is an Economic Decision
---------------------------------

Suppose an origin performs a database lookup and renders a page for each admitted request. Let :math:`c_o` be that work, :math:`c_g` the gate's work per request, and :math:`r` the arrival rate. With no gate, the origin must sustain :math:`r c_o` units of work per second. A gate that admits fraction :math:`a` changes that demand to :math:`r a c_o`, while spending :math:`r c_g` itself. The gate is useful only when the saved origin work exceeds its own cost and the cost it imposes on legitimate visitors.

.. math::

   r c_g + r a c_o < r c_o \quad \Leftrightarrow \quad c_g < (1-a) c_o.

This is a capacity model, not a measurement. It omits bandwidth, connection state, storage, and client delay. Its value is that every missing term is visible. A cache hit may make :math:`c_o` small; a costly query may make it large. There is no universal requester-to-server cost ratio.

.. admonition:: Worked example: when a gate pays for itself

   Choose :math:`c_o = 100` work units and :math:`c_g = 1`. If half the requests are rejected, the gated system spends :math:`1 + 0.5 \times 100 = 51` units per arrival instead of 100. If only one in a thousand is rejected, it spends :math:`100.9`: the gate costs more than it saves in this model. These selected numbers are not timings. They show why the workload belongs in every performance claim.

What a Proof of Work Establishes
--------------------------------

A client puzzle establishes that somebody found an input satisfying a public verification rule. It does not establish humanity, identity, or good intent. A requester can rent compute, reuse a valid session within its lifetime, or distribute work across machines. The puzzle changes the admission cost; policy and inspection still decide what admitted requests may do.

Address-based limits are complementary. They constrain one address, but shared addresses can represent many people and one requester can use many addresses. Neither a puzzle nor an address is an identity oracle. Sibuna therefore keeps admission, inspection, and reputation as distinct decisions.

Hash Search as a Random Variable
--------------------------------

For an ideal 256-bit digest, requiring :math:`b` leading zero bits gives success probability :math:`p = 2^{-b}` for each independent trial. Let :math:`K` count trials through the first success. Then

.. math::

   P(K=k) = (1-p)^{k-1} p, \quad P(K>k) = (1-p)^k, \quad E[K] = 1/p = 2^b.

The expectation follows from the tail sum:

.. math::

   E[K] = \sum_{k=0}^{\infty} P(K>k) = \sum_{k=0}^{\infty} (1-p)^k = 1/p.

A difficulty step doubles expected trials. It does not promise that every puzzle takes twice as long. Some succeed on the first trial; some take far longer than the mean. A client that measures only one solve has mostly measured this randomness.

.. code-block:: text
   :caption: Survival probability of hash search. The horizontal axis is trials divided by expected trials; the curve uses the large-work approximation P(K > x/p) ~ e^(-x). The point o marks x = 1, where the probability of still searching is e^(-1) = 0.368.

   P(K > x E[K])
   1.0 |*
       | *
       |  *
       |   **
       |     *
   0.5 |      **
       |        **o
       |           ***
       |              *****
       |                   ***********
   0.0 |                              ***********
       +-----------------------------------------
        0         1         2         3         4
                 trials / expected trials (x)

.. admonition:: Worked example: expectation is not a deadline

   At :math:`b = 16`, the expected work is 65,536 hashes. The probability of still searching after that many trials is approximately :math:`e^{-1} = 0.368`. The 95th-percentile trial count is :math:`\lceil \ln(0.05) / \ln(1 - 2^{-16}) \rceil \approx 196327`, nearly three times the mean. A user interface should tolerate that spread rather than announcing failure at the expected completion time.

Sessions Amortise Work
----------------------

Suppose a session permits :math:`m` requests before expiry, a puzzle costs :math:`c_p`, verification costs :math:`c_v`, and a session check costs :math:`c_s`. Ignoring unsuccessful attempts, the amortized gate cost per request is :math:`c_v/m + c_s`, while the client's puzzle cost is :math:`c_p/m`. Increasing the session lifetime helps people and automated clients alike. Choosing it is a policy decision, not a cryptographic optimization.

.. admonition:: Exercise 1.1

   A client gets 100 requests per session and performs a puzzle costing one million trials. What is the amortized work per request? What changes if it shares the session with a second process?

   Hint: Distinguish the accounting model from the token's actual bindings.

Bounded State Is a Second Budget
--------------------------------

Moving work off the request path does not make it disappear. Let incidents arrive at rate :math:`\lambda`, let the storage thread persist them at average rate :math:`\mu`, and let the queue hold :math:`Q` records. When :math:`\lambda > \mu`, a fluid approximation gives

.. math::

   t_{\mathrm{fill}} \approx \frac{Q}{\lambda - \mu}.

A larger queue buys time; it does not create throughput. Batching amortizes transaction cost, but retained records still need memory and eventual service. Under overload Sibuna drops new incident records and counts them. It continues making request decisions from in-memory state. The operator must monitor the lost evidence as well as the HTTP success rate.

.. admonition:: Exercise 1.2

   A queue holds 512 records. Arrival rate is 1,000/s and drain rate is 600/s. How long can an initially empty queue absorb the excess? Why is the answer only an approximation?

   Hint: Use the difference of rates, then consider bursts and batch commits.

The Invariants We Will Carry Forward
------------------------------------

1. Untrusted requests cannot create unbounded server state.
2. A valid admission token does not bypass an application denial.
3. A buffer remains alive for every slice borrowed from it.
4. A durable retry cannot multiply an incident or its reputation effect.
5. A published policy snapshot is immutable until its last reader releases it.

The rest of the book derives the mechanisms that make these statements true, and the tests that would reveal a violation. A fast path is useful only while those statements remain true.

.. admonition:: Explain the invariant

   State the gate inequality :math:`c_g < (1-a) c_o` in words, then explain why a measured verification latency alone cannot tell an operator whether the gate is worth running.
