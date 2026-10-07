#import "theme.typ": *

#title_page()
#pagebreak()
#heading(numbering: none)[Preface]

Every request asks a server to spend resources. Its method, path and headers describe what
the sender wants; they do not establish that the sender should receive it. Sibuna decides
whether to admit the request, refuse it, or ask its sender to do verifiable work before it
reaches the origin.
This book follows that decision from its mathematical model to the bytes in memory.

The aim is to protect the site's resources by asking a requester to do more work to create
a proof than the server needs to check it. A successful proof buys admission for a session;
later requests can reuse that session. Local limits and application inspection still apply.
The difficulty, client hardware and session lifetime determine how useful that cost balance
is for a particular site.

*Gate* provides proof-of-work admission and local flood controls. *Shield* adds application
inspection. Either can use replicated policy, reputation and incident storage; we call that
deployment *Edge*. A session does not bypass inspection, and replication does not turn a
local rate counter into a global quota.

The engineering problem is to bound the request path when an untrusted client chooses the
input. We ask how much data a parser can inspect, how much state a client can occupy, which
writes can be retried, and what survives a leader's loss. Each answer states a guarantee and
its limits.

The mathematics helps explain those limits. An average cost is not a deadline. Sampling a
fixed commitment is not a proof against an adaptive prover. A queue absorbs bursts but cannot
make a slow consumer faster. Worked examples connect these models to the implementation.

Parts I to VII form a course, with worked examples, exercises and selected solutions.
Parts VIII to X cover measurements, deployment and the API. Part XI is a reference card for
the terminal. A glossary and bibliography close the book.

Part II compares Sibuna with Anubis, SafeLine and the Cloudflare WAF. Part VIII measures
complete processes under documented workloads. Sources and committed result files let
readers check the claims.

The reader should know basic programming, logarithms and conditional probability. Zig is
introduced through ownership and data layout. Later chapters turn the design's invariants
into measurements and operating procedures.

Computational puzzles do not eliminate automated traffic. Clients can buy computing power,
addresses can be shared, and a bounded detector cannot understand every application.
This book explains an implementation whose costs and limitations can be examined, tested
and changed.

#v(5mm)
#text(size: 9pt, fill: gray)[
  Edition 0.3 · September 2026 #linebreak()
  Sources, exercises, and reproducible measurements accompany the Sibuna repository.
]
