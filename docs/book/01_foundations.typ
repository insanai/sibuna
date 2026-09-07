#import "theme.typ": *
#import "figures.typ": *

#part_page("I", [The cost of a request], [
  Before choosing an algorithm, identify the resource it is meant to protect.
])

== Admission is an economic decision

Suppose an origin performs a database lookup and renders a page for each admitted request.
Let $c_o$ be that work, $c_g$ the gate's work per request, and $r$ the arrival rate. With no gate,
the origin must sustain $r c_o$ units of work per second. A gate that admits fraction $a$ changes
that demand to $r a c_o$, while spending $r c_g$ itself. The gate is useful only when the saved
origin work exceeds its own cost and the cost it imposes on legitimate visitors.

$ r c_g + r a c_o < r c_o quad arrow.l.r.double quad c_g < (1-a)c_o. $

This is a capacity model, not a measurement. It omits bandwidth, connection state, storage,
and client delay. Its value is that every missing term is visible. A cache hit may make $c_o$
small; a costly query may make it large. There is no universal requester-to-server cost ratio.

#definition([Worked example: when a gate pays for itself], [
  Choose $c_o=100$ work units and $c_g=1$. If half the requests are rejected, the gated system
  spends $1+0.5 times 100=51$ units per arrival instead of 100. If only one in a thousand is
  rejected, it spends $100.9$: the gate costs more than it saves in this model. These selected
  numbers are not timings. They show why the workload belongs in every performance claim.
])

== What a proof of work establishes

A client puzzle establishes that somebody found an input satisfying a public verification
rule. It does not establish humanity, identity, or good intent. A requester can rent compute,
reuse a valid session within its lifetime, or distribute work across machines. The puzzle
changes the admission cost; policy and inspection still decide what admitted requests may do.

Address-based limits are complementary. They constrain one address, but shared addresses can
represent many people and one requester can use many addresses. Neither a puzzle nor an
address is an identity oracle. Sibuna therefore keeps admission, inspection, and reputation
as distinct decisions.

== Hash search as a random variable

For an ideal 256-bit digest, requiring $b$ leading zero bits gives success probability
$p=2^(-b)$ for each independent trial. Let $K$ count trials through the first success. Then

$ P(K=k)=(1-p)^(k-1)p, quad P(K>k)=(1-p)^k, quad E[K]=1/p=2^b. $

The expectation follows from the tail sum:
$ E[K]=sum_(k=0)^infinity P(K>k)=sum_(k=0)^infinity (1-p)^k=1/p. $

A difficulty step doubles expected trials. It does not promise that every puzzle takes twice
as long. Some succeed on the first trial; some take far longer than the mean. A client that
measures only one solve has mostly measured this randomness.

#book_figure([Survival probability of hash search. The horizontal axis is trials divided by
expected trials; the continuous curves use the large-work approximation $P(K>x/p) approx e^(-x)$.], probability_contours())

#definition([Worked example: expectation is not a deadline], [
  At $b=16$, the expected work is 65,536 hashes. The probability of still searching after that
  many trials is approximately $e^(-1)=0.368$. The 95th-percentile trial count is
  $ceil(ln(0.05)/ln(1-2^(-16))) approx 196327$, nearly three times the mean. A user interface
  should tolerate that spread rather than announcing failure at the expected completion time.
])

== Sessions amortize work

Suppose a session permits $m$ requests before expiry, a puzzle costs $c_p$, verification costs
$c_v$, and a session check costs $c_s$. Ignoring unsuccessful attempts, the amortized gate cost
per request is $c_v/m+c_s$, while the client's puzzle cost is $c_p/m$. Increasing the session
lifetime helps people and automated clients alike. Choosing it is a policy decision, not a
cryptographic optimization.

#exercise("1.1", [A client gets 100 requests per session and performs a puzzle costing
one million trials. What is the amortized work per request? What changes if it shares the
session with a second process?], hint: [Distinguish the accounting model from the token's actual bindings.])

== Bounded state is a second budget

Moving work off the request path does not make it disappear. Let incidents arrive at rate
$lambda$, let the storage thread persist them at average rate $mu$, and let the queue hold
$Q$ records. When $lambda>mu$, a fluid approximation gives

$ t_"fill" approx Q/(lambda-mu). $

A larger queue buys time; it does not create throughput. Batching amortizes transaction cost,
but retained records still need memory and eventual service. Under overload Sibuna drops new
incident records and counts them. It continues making request decisions from in-memory state.
The operator must monitor the lost evidence as well as the HTTP success rate.

#exercise("1.2", [A queue holds 512 records. Arrival rate is 1,000/s and drain rate is 600/s.
How long can an initially empty queue absorb the excess? Why is the answer only an approximation?],
  hint: [Use the difference of rates, then consider bursts and batch commits.])

== The invariants we will carry forward

1. Untrusted requests cannot create unbounded server state.
2. A valid admission token does not bypass an application denial.
3. A buffer remains alive for every slice borrowed from it.
4. A durable retry cannot multiply an incident or its reputation effect.
5. A published policy snapshot is immutable until its last reader releases it.

The rest of the book derives the mechanisms that make these statements true, and the tests
that would reveal a violation. A fast path is useful only while those statements remain true.
