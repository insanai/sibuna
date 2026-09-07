#import "theme.typ": *

#pagebreak()
#{
  set text(size: 9pt)
  set par(leading: 0.28em, spacing: 0.1em)
  outline(title: [Contents], depth: 2, indent: 1em)
}
#pagebreak()
#heading(numbering: none)[How to read this book]

Begin with a single question: what is the cheapest safe decision the server can make now?
Keep that question beside you through the protocol and implementation chapters. A cheap
operation that admits the wrong request is a defect; a correct operation with unbounded
cost is another kind of defect.

For a first reading, follow chapters 1–4, then trace the worked request in chapter 6.
Return to chapter 5 when the trace reaches a shared table or a borrowed slice. Operators can
then read chapters 8–10, while implementers should include the browser engine in chapter 7.

#table(columns: (1fr, 2.5fr),
  table.header([Question], [Where the answer develops]),
  [What does a puzzle buy?], [Chapters 1–3: cost, probability, and the limits of proof.],
  [What does a session mean?], [Chapter 4: bindings, verification order, expiry, and replay.],
  [Where does the memory go?], [Chapters 5–6: buffers, tables, automata, and publication.],
  [How does the browser solve?], [Chapter 7: worker messages, memory, and calibration.],
  [How do we know it works?], [Chapters 8–10: experiments, deployment, and diagnostics.],
)

A *worked example* shows the intermediate states, not just the answer. An *exercise* asks you
to change one assumption. Hints suggest a first step; selected solutions at the end of the book
make the reasoning checkable. Diagrams distinguish the request path from background work.
A source anchor names the implementation to inspect when prose and code appear to disagree.

In equations, $b$ is Hashcash difficulty in bits, $p$ is success probability per trial, $K$ is
the number of trials, $T$ is a rate limiter's emission interval, and $Q$ is a queue capacity.
A symbol is local to its section unless stated otherwise. Nanoseconds in the benchmark chapter
are measurements from a named run. Numbers in worked examples are chosen inputs, not benchmark
claims. Statistical models state their assumptions before drawing conclusions.
