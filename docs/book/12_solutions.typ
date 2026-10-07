#import "theme.typ": *

#heading(numbering: none)[Selected Solutions]

Use these solutions to check your reasoning after trying the exercises. If a result
differs, compare assumptions first. Interval endpoints, the definition of work and the
point at which a write commits often explain the difference.

== Part I: Cost and Probability

*1.1.* One million trials divided among 100 requests is 10,000 trials per request. Sharing a
session does not change that arithmetic if the aggregate request count stays 100. The actual
system must decide whether a second process can satisfy the fingerprint and routing bindings;
those conditions are outside the amortization equation.

*1.2.* The excess is $1000-600=400$ records/s. An empty queue of 512 records buys
$512/400=1.28$ seconds in the fluid model. Real producers arrive in bursts and the consumer
commits batches, so the exact first drop depends on arrival and commit times.

== Part II: Prior Art

*2.1.* Sharing the source keeps the statement, nonce encoding, tree shape and opening layout
in one place. Separate implementations can drift when one changes without the other.
Compiler and runtime defects are still possible. Cryptographic review must establish the
construction's security, WebAssembly/JavaScript comparisons check compatible output, and
measurements guide parameter choices.

*2.2.* Several deployments can meet these requirements. Use Part II's capability table to
compare installation needs, inspection and shared state. For Sibuna, Gate supplies admission,
Shield adds the lightweight inspector, and `--data-dir` with a cluster build adds persistent
policies and replicated reputation. Choose a deployment around the application's needs;
the examples do not establish one product as the best choice for every site.

== Part III: Cryptography

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

*3.3.* The work level prevents a session earned on a cheap route from satisfying a route
that demands more work. `timestamp` allows the verifier to reject future-dated tokens;
`expiry` bounds their lifetime. `rule_hash` tells the upstream which rule admitted the client.
The `fingerprint` binds the cookie to an address and User-Agent, although clients sharing
both already share that binding. The tag covers all five fields so an edit is detected.

== Part IV: Protocol

*4.1.* Both browsers share the address and User-Agent, so they share the fingerprint, the
rate-limit cell, and the ban slot. They do not share the challenge (each fetches its own
record with its own nonce), the spent-set entry, or the cookie. To reuse the other browser's
cookie an attacker on the NAT would need to read it from the other machine: the fingerprint
would then match, which is why `HttpOnly` and `SameSite` matter more than the binding on a
shared address.

== Part V: State and Ordering

*5.1.* The 64 KiB connection buffer holds the head and the start of the body. The relay
forwards those buffered body bytes, then reads and forwards the remainder in bounded pieces.
It preserves the head until evidence and telemetry have consumed it. The origin needs the
head first to interpret the body's framing and the added audit headers. Content-Length and
chunked uploads use their respective forwarding paths.

*5.2.* The emission interval is 100 ms and burst tolerance is 9,900 ms. An idle client may
send 100 requests immediately, then one per 100 ms. Through the inclusive endpoint at 3,000 ms,
the bound is 130. A fixed 10-second counter would allow 100 in the first window and 100 more
the instant the window rolls over; a sliding log would allow exactly 100 in any 10 seconds but
must store 100 timestamps per client.

== Part VI: Algorithms

*6.1.* An apostrophe in a name and an ordinary parameter named `order` do not establish an SQL
expression. A substring detector could mistake either for syntax. The structural detector
looks for additional evidence, including operators and literal relations. It remains bounded
inspection, not a parser for every application language.

*6.2.* LDAP filters are built from parentheses, `|`, `&`, `!`, and `=`. The detector needs a
byte class for `(` and `)` (new) and can reuse the existing `=` and shell-separator classes for
`|` and `&`. It should fire on a *sequence* such as `)(` or `(|(`, not on a single parenthesis,
for the same reason the SQL detector requires a quote or a tautology.

== Part VII: Browser Engine

*7.1.* At the default 16 work bits, depth 13 with 16 openings, the WebAssembly prover on a
laptop-class V8 takes on the order of 15 ms, so the JavaScript fallback takes on the order of
one second; on a slow phone several seconds. A sensible policy: let the page forward the
`fallback` message, log it server-side as a metric, and lower the difficulty for a rule that
matches clients known to block WebAssembly rather than for everyone.

== Part VIII: Evaluation

*8.2.* Dividing CPU microseconds per request by busy cores estimates amortized wall time per
completed request. Concurrent requests can wait or overlap, so this ratio is not an
individual request's latency. The complete product also pays for socket reads and writes,
parsing, session checks, metrics, response formatting, writer flushes and scheduling.
The primitive classification timing excludes those costs.

== Part IX: Operations

*9.1.* If the data commits before a separate receipt update, a crash between them leaves the
old receipt and a retry can apply the effect again. If the receipt commits first, a crash before
the data write can cause the retry to skip data that never existed. One atomic transaction
removes both gaps. Losing the transaction's acknowledgement still requires the retained retry.

*9.2.* `ip_rules: {"10.20.0.0/16": "ALLOW"}` (or an `ip_reputation` row with score 100) admits
staging; a rule `{"name": "admin", "path": "/admin/*", "action": "CHALLENGE", "challenge":
{"difficulty": 20, "algorithm": "posw"}}` demands the work; a rule matching
`headers: {"X-Partner-Key": ".*"}` with `ALLOW` admits the partner. The 30-per-10-seconds
limit is a daemon flag (`--rate-limit 30 --rate-window 10`) and applies to every client, so
either accept that or place the partner behind its own Sibuna instance.

== Part X: Reference

*10.1.* The challenge record carries the keyed fingerprint of the address that fetched it; the
solution arrives from a new address, so `verifyAndMint` returns `FingerprintMismatch` before
looking at the proof. The smallest recovery is in the interstitial: on a `400` whose title is
`CLIENT FINGERPRINT MISMATCH`, fetch a fresh challenge and solve again instead of showing the
error, since the work already done cannot be transferred.

== Continue the Investigation

Change one invariant at a time in a disposable test. Remove the snapshot recheck, omit the
incident receipt, or round the rate interval downward. Predict a failure schedule before you
run the test. A useful regression does more than assert the happy-path output: it demonstrates
why the omitted condition is necessary.
