#import "theme.typ": *

#title_page()
#pagebreak()
#heading(numbering: none)[Preface]

A request arrives with a method, a path, some headers, and a claim to the server's attention.
None of those bytes establishes that serving it is worthwhile. Sibuna places a decision
between the request and the origin: admit it, refuse it, or ask its sender to do verifiable work.
This book follows that decision from its mathematical model to the bytes in memory.

The system has two surfaces. *Gate* provides proof-of-work admission and local flood controls.
*Shield* adds application inspection and policy decisions. Either can use replicated storage
for policy, reputation, and incident history; we call that deployment *Edge*. A valid session
establishes admission; it does not exempt the request from inspection. Replication distributes
durable state; it does not turn a local rate counter into a global quota.

The central engineering question is not whether a hash is fast. It is whether the complete
path remains bounded when an untrusted client chooses the input. How many bytes can a parser
inspect? How much memory can a challenge consume? How many connections can a client hold
open? Which writes may be retried? What remains available after a leader disappears? Each
answer must name both an invariant and its boundary.

The mathematics serves the same purpose. An expected cost is not a latency guarantee. A
sampling argument for a fixed commitment is not a proof against every adaptive prover. A
queue absorbs a burst; it cannot compensate for a permanently slower consumer. We derive
small models, work examples by hand, and then ask where the implementation departs from them.

The book is written to be used three ways. Read in order, Parts I to VII are a course: each
chapter opens with what you should be able to do afterwards, works an example by hand, and
closes with an exercise and an invariant to explain in your own words; selected solutions are
at the back. Parts VIII to X are the reference: measurements with their provenance, every flag
and topology, every endpoint, status, error, and table. Part XI is a two-page card for the
terminal. A glossary and a bibliography close the book.

Part II places Sibuna beside Anubis, SafeLine, and the Cloudflare WAF, feature by feature,
and Part VIII measures Sibuna and Anubis as whole products under the same load generator.
Both are written so the reader can check the claims: the comparison names its sources and the
measurements are rendered from committed result files.

The reader should know basic programming, logarithms, and conditional probability. Zig is
introduced through ownership and data layout rather than a language survey. The chapters can
be read in order: the cost model motivates the protocol, the protocol determines the state,
and the state determines the concurrency and storage design. Later chapters turn those
invariants into measurements and operating procedures.

This is an implementation book, not a claim that computational puzzles eliminate automated
traffic. Clients can buy compute, addresses can be shared, and application syntax is richer
than a bounded detector. The useful result is a system whose costs and limitations can be
examined, tested, and changed without hiding them behind a slogan.

#v(5mm)
#text(size: 9pt, fill: gray)[
  Edition 0.3 · September 2026 #linebreak()
  Sources, exercises, and reproducible measurements accompany the Sibuna repository.
]
