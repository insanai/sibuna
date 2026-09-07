#import "theme.typ": *

#heading(numbering: none)[Selected solutions]

These solutions are checks on the argument, not substitutes for the exercises. If your result
differs, first compare assumptions: endpoints of time intervals, what is counted as work, and
whether a write has committed are common sources of disagreement.

== Cost and probability

*1.1.* One million trials divided among 100 requests is 10,000 trials per request. Sharing a
session does not change that arithmetic if the aggregate request count stays 100. The actual
system must decide whether a second process can satisfy the fingerprint and routing bindings;
those conditions are outside the amortization equation.

*1.2.* The excess is $1000-600=400$ records/s. An empty queue of 512 records buys
$512/400=1.28$ seconds in the fluid model. Real producers arrive in bursts and the consumer
commits batches, so the exact first drop depends on arrival and commit times.

*3.0.* The tail estimate is $e^(-4.6) approx 0.010$. Dividing the nonce space changes the rate
at which trials are completed, not the success probability of each independent trial. Duplicate
trials or coordination work can make a real parallel implementation less efficient.

*3.1.* If each commitment succeeds with probability $q$, all $g$ fail with probability
$(1-q)^g$. At least one succeeds with probability $1-(1-q)^g$. The formula does not count
commitment construction, query budgets, dependencies between trials, or the work needed to
find a commitment with a particular acceptance probability.

*3.2.* At depth 17 and 16 openings, the proof has $32(1+16 times 18)=9248$ bytes. At 32
openings it has $32(1+32 times 18)=18464$ bytes. The opening bytes double; the 32-byte root
is still sent once.

== State and ordering

*5.2.* The emission interval is 100 ms and burst tolerance is 9,900 ms. An idle client may
send 100 requests immediately, then one per 100 ms. Through the inclusive endpoint at 3,000 ms,
the bound is 130. The interval convention matters when an arrival lands exactly on an endpoint.

*6.1.* An apostrophe in a name and an ordinary parameter named `order` do not establish an SQL
expression. A substring detector could mistake either for syntax. The structural detector
looks for additional evidence, including operators and literal relations. It remains bounded
inspection, not a parser for every application language.

*9.1.* If the data commits before a separate receipt update, a crash between them leaves the
old receipt and a retry can apply the effect again. If the receipt commits first, a crash before
the data write can cause the retry to skip data that never existed. One atomic transaction
removes both gaps. Losing the transaction's acknowledgement still requires the retained retry.

== Continue the investigation

Change one invariant at a time in a disposable test. Remove the snapshot recheck, omit the
incident receipt, or round the rate interval downward. Predict a failure schedule before you
run the test. A useful regression does more than assert the happy-path output: it demonstrates
why the omitted condition is necessary.
