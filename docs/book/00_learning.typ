#import "theme.typ": *

#pagebreak()
#{
  set text(size: 9pt)
  set par(leading: 0.28em, spacing: 0.1em)
  outline(title: [Contents], depth: 2, indent: 1em)
}
#pagebreak()
#heading(numbering: none)[How to Read This Book]

Begin with a question: what is the cheapest safe decision the server can make now?
Keep it in mind through the protocol and implementation chapters. An operation must make
the right decision and have a bounded cost. Either failure leaves the server vulnerable.

#table(columns: (1fr, 2.5fr),
  table.header([Question], [Where the answer develops]),
  [What does a puzzle buy?], [Parts I–III: cost, probability, and the limits of proof.],
  [How does Sibuna compare?], [Part II: lineage and the feature table; Part VIII: measurements.],
  [What does a session mean?], [Part IV: bindings, verification order, expiry, and replay.],
  [Where does the memory go?], [Parts V–VI: buffers, threads, tables, automata, and publication.],
  [How does the browser solve?], [Part VII: worker messages, memory, and calibration.],
  [How do we know it works?], [Part VIII: four harnesses and what each excludes.],
  [How do I run it?], [Part IX: flags, topologies, policy, storage, clustering, packaging.],
  [What was that error?], [Part X: endpoints, statuses, errors, schema; Part XI: the card.],
)

=== Three Reading Paths

- *Learning the design.* Parts I–IV in order, then the worked trace in Part VI, then Part VII.
  Do the exercises; compare with the solutions at the back only afterwards. Return to Part V
  when a trace reaches a shared table or a borrowed slice.
- *Operating a deployment.* Part IX, then Part XI, with Part X open for lookups. Read the
  "Feature Comparison" in Part II before choosing a surface, and the "Whole-Product
  Comparison" in Part VIII before choosing worker and connection limits.
- *Changing the code.* Parts V and VI, the source anchors in every chapter, and the SID
  records they cite. Part VIII explains which test harness to use for the subsystem you
  change. Part II lists the constraints that the change must preserve.

=== Conventions

A *worked example* shows the intermediate states, not just the answer. An *exercise* asks you
to change one assumption. Hints suggest a first step; selected solutions at the end of the book
show how to check the reasoning. Diagrams distinguish the request path from background work.
A source anchor points to the implementation discussed in the text.
Boxes headed "Implementation" name a function and its file; boxes headed "Explain the
invariant" ask you to teach the idea back.

In equations, $b$ is Hashcash difficulty in bits, $n$ is sequential-work depth, $t$ is the
number of openings, $p$ is success probability per trial, $K$ is the number of trials, $T$ is
a rate limiter's interval between admitted requests, $tau$ its burst tolerance, and $Q$ is a
queue capacity.
A symbol is local to its section unless stated otherwise. Nanoseconds and requests per second
in Part VIII are measurements from a named run. Numbers in worked examples are chosen inputs,
not benchmark claims. Statistical models state their assumptions before drawing conclusions.
