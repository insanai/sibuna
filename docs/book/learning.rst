How to Read This Book
=====================

We begin with a single question: what is the cheapest safe decision the server can make now? We keep that question beside us through the protocol and implementation chapters. A cheap operation that admits the wrong request is a defect; a correct operation with unbounded cost is another kind of defect.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Question
     - Where the answer develops
   * - What does a puzzle buy?
     - Parts I to III: cost, probability, and the limits of proof.
   * - How does Sibuna compare?
     - Part II: lineage and the feature table; Part VIII: measurements.
   * - What does a session mean?
     - Part IV: bindings, verification order, expiry, and replay.
   * - Where does the memory go?
     - Parts V and VI: buffers, threads, tables, automata, and publication.
   * - How does the browser solve?
     - Part VII: worker messages, memory, and calibration.
   * - How do we know it works?
     - Part VIII: four harnesses and what each excludes.
   * - How do we run it?
     - Part IX: flags, topologies, policy, storage, clustering, packaging.
   * - What was that error?
     - Part X: endpoints, statuses, errors, schema; Part XI: the card.

Three Reading Paths
-------------------

- *Learning the design.* Parts I to IV in order, then the worked trace in Part VI, then Part VII. Do the exercises; compare with the solutions at the back only afterwards. Return to Part V when a trace reaches a shared table or a borrowed slice.
- *Operating a deployment.* Part IX, then Part XI, with Part X open for lookups. Read the "Feature Comparison" in Part II before choosing a surface, and the "Whole-Product Comparison" in Part VIII before choosing worker and connection limits.
- *Changing the code.* Parts V and VI, the source anchors in every chapter, and the SID records they cite. Part VIII explains which harness will catch a regression in what we touched; Part II lists the constraints a change must keep.

Conventions
-----------

A *worked example* shows the intermediate states, not just the answer. An *exercise* asks us to change one assumption. Hints suggest a first step; selected solutions at the end of the book make the reasoning checkable. Diagrams distinguish the request path from background work. A source anchor names the implementation to inspect when prose and code appear to disagree. Boxes headed "Implementation" name a function and its file; boxes headed "Explain the invariant" ask us to teach the idea back.

In equations, :math:`b` is Hashcash difficulty in bits, :math:`n` is sequential-work depth, :math:`t` is the number of openings, :math:`p` is success probability per trial, :math:`K` is the number of trials, :math:`T` is a rate limiter's emission interval, :math:`\tau` its burst tolerance, and :math:`Q` is a queue capacity. A symbol is local to its section unless stated otherwise. Nanoseconds and requests per second in Part VIII are measurements from a named run. Numbers in worked examples are chosen inputs, not benchmark claims. Statistical models state their assumptions before drawing conclusions.
