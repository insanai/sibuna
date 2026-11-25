Preface
=======

A request arrives with a method, a path, some headers, and a claim to the server's attention. None of those bytes establishes that serving it is worthwhile. Sibuna places a decision between the request and the origin: admit it, refuse it, or ask its sender to do verifiable work. When there is more than one origin, it also decides which one serves. This book follows both decisions from their mathematical models to the bytes in memory.

The system has two surfaces. *Gate* provides proof-of-work admission and local flood controls. *Shield* adds application inspection and policy decisions. Either can use persistent storage for policy, reputation, and incident history, local to one node or shared by a cluster. The *edge* is the load balancer around them: it accepts TCP, UDP and HTTP, terminates TLS, chooses a server from a pool, and runs as one node or as a mesh of nodes that share their state. A valid session establishes admission; it does not exempt the request from inspection. Sharing durable state across a cluster distributes it; it does not turn a local rate counter into a global quota.

The central engineering question is not whether a hash is fast. It is whether the complete path remains bounded when an untrusted client chooses the input. How many bytes can a parser inspect? How much memory can a challenge consume? How many connections can a client hold open? Which writes may be retried? What remains available after a node or the database disappears? Each answer must name both an invariant and its boundary.

The mathematics serves the same purpose. An expected cost is not a latency guarantee. A sampling argument for a fixed commitment is not a proof against every adaptive prover. A queue absorbs a burst; it cannot compensate for a permanently slower consumer. We derive small models, work examples by hand, and then ask where the implementation departs from them.

The book is written to be used three ways. Read in order, Parts I to IX are a course: each chapter opens with what we should be able to do afterwards, works an example by hand, and closes with an exercise and an invariant to explain in our own words; selected solutions are at the back. Parts X to XII are the reference: measurements with their provenance, every flag and topology, every endpoint, status, error, and table. Part XIII is a two-page card for the terminal. A glossary and a bibliography close the book.

Parts I to VII build the admission decision. Parts VIII and IX build the load balancer: one node, then a cluster. Part II places Sibuna beside Anubis, SafeLine, and the Cloudflare WAF, and beside HAProxy and Envoy, feature by feature, and Part X presents Sibuna's own measurements, from single primitives to whole-product runs, and compares Sibuna with Anubis and with HAProxy under the same load generator. Both are written so the reader can check the claims: the comparison names its sources, and every measurement names the committed result file it is copied from.

The reader should know basic programming, logarithms, and conditional probability. Rust is introduced through ownership and data layout rather than a language survey. The chapters can be read in order: the cost model motivates the protocol, the protocol determines the state, and the state determines the concurrency and storage design. The load balancer reuses that design: a flow is owned by one worker, and what nodes share is merged by rules that converge. Later chapters turn those invariants into measurements and operating procedures.

This is an implementation book, not a claim that computational puzzles eliminate automated traffic, nor that a new load balancer has the record of an old one. Clients can buy compute, addresses can be shared, and application syntax is richer than a bounded detector. A load balancer earns trust through years of production traffic, and ours has not had them yet. The useful result is a system whose costs and limitations can be examined, tested, and changed without hiding them behind a slogan.

.. rubric:: Edition for the Sibuna source tree after 1.0.0-beta.3, November 2026

Sources, exercises, and reproducible measurements accompany the Sibuna repository.
