How to Read This Book
=====================

The timetable example gives us two questions to carry into the design chapters. Which requests does the edge admit, and which server handles an admitted request? The first chapters develop the cost and correctness of admission. Later chapters show how a single edge selects a server and how multiple edges cooperate.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Question
     - Where the answer develops
   * - What does a puzzle buy?
     - Parts I to III: cost, probability, and the limits of proof.
   * - How does Sibuna compare?
     - Part II: lineage and the feature tables; Part X: measurements beside Anubis and HAProxy.
   * - What does a session mean?
     - Part IV: bindings, verification order, expiry, and replay.
   * - Where does the memory go?
     - Parts V and VI: buffers, threads, tables, automata, and publication.
   * - How does the browser solve?
     - Part VII: worker messages, memory, and calibration.
   * - How does one node balance load?
     - Part VIII: flows, workers, choosing a server, admission at the socket, hooks.
   * - How do several nodes act as one?
     - Part IX: the mesh, shared affinity, fleet caps, forwarding, handoff.
   * - How do we know it works?
     - Part X: three harnesses and what each excludes.
   * - How do we run it?
     - Part XI: flags, the edge topology, certificates, policy, storage, clustering, packaging.
   * - What was that error?
     - Part XII: endpoints, statuses, errors, schema; Part XIII: the card.

Three Reading Paths
-------------------

- *Learning the design.* Parts I to IV in order, then the worked trace in Part VI, then Part VII. For the load balancer, Part VIII and then Part IX; they need only Part I and the ownership ideas of Part V. Do the exercises; compare with the solutions at the back only afterwards. Return to Part V when a trace reaches a shared table or a borrowed slice.
- For a first deployment, we work through :doc:`jlavi` after meeting frontends, routes and pools in :doc:`introduction`. Part XI then explains how to install, observe and reload the running system. Parts XII and XIII provide the reference and the command summary.
- *Changing the code.* Parts V and VI, the source anchors in every chapter, and the SID records they cite. Part X explains which harness will catch a regression in what we touched; Part II lists the constraints a change must keep.

Conventions
-----------

A *worked example* shows the intermediate states, not just the answer. An *exercise* asks us to change one assumption. Hints suggest a first step; selected solutions at the end of the book make the reasoning checkable. Diagrams distinguish the request path from background work. A source anchor names the implementation to inspect when prose and code appear to disagree. Boxes headed "Implementation" name a function and its file; boxes headed "Explain the invariant" ask us to teach the idea back.

In equations, :math:`b` is Hashcash difficulty in bits, :math:`n` is sequential-work depth, :math:`t` is the number of openings, :math:`p` is success probability per trial, :math:`K` is the number of trials, :math:`T` is a rate limiter's emission interval, :math:`\tau` its burst tolerance, and :math:`Q` is a queue capacity. In Parts VIII and IX, :math:`n` is the number of servers or nodes and :math:`c` the bound of a bounded load. A symbol is local to its section unless stated otherwise. Nanoseconds and requests per second in Part X are measurements from a named run. Numbers in worked examples are chosen inputs, not benchmark claims. Statistical models state their assumptions before drawing conclusions.
