:sid-number: 0001
:sid-title: Sibuna Discussions Process
:sid-state: published
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-10-15
:sid-updated: 2026-10-15
:sid-discussion: No external discussion URL assigned
:sid-labels: ["process"]

Sibuna Discussions Process
==========================

Abstract
--------

This draft says how Sibuna Discussions proposes, reviews, and records decisions.
It is a starting point for the maintainers to edit. It is not yet accepted.

Lifecycle and numbering
-----------------------

A draft starts with the number ``XXXXX`` and the state ``prediscussion``.
Promotion gives it the next number, from 1, with at least 4 digits (0007), and
moves it to ``discussion``. A state change needs a reason.

.. list-table:: The states and the moves between them
   :header-rows: 1
   :widths: 30 70

   * - State
     - May move to
   * - ``prediscussion``
     - discussion (by promotion), abandoned
   * - ``discussion``
     - accepted, published, abandoned
   * - ``accepted``
     - published, committed, abandoned
   * - ``published``
     - committed, abandoned
   * - ``committed``
     - none: the record is closed; moving here needs evidence
   * - ``abandoned``
     - none: the record is closed

.. graphviz::
   :caption: The moves this catalog allows.
   :alt: The lifecycle states of a record and the moves between them.

   digraph lifecycle {
     graph [rankdir=TB, bgcolor="transparent"];
     node [shape=box, fontname="Helvetica"];
     "prediscussion" -> "discussion" [label="promote"];
     "prediscussion" -> "abandoned";
     "discussion" -> "accepted";
     "discussion" -> "published";
     "discussion" -> "abandoned";
     "accepted" -> "published";
     "accepted" -> "committed" [label="evidence"];
     "accepted" -> "abandoned";
     "published" -> "committed" [label="evidence"];
     "published" -> "abandoned";
   }

Closed records are kept, and numbers are never reused. The tool records decisions;
the maintainers' review makes them. ``discussion.toml`` sets these states and moves.

Writing and review
------------------

Start from ``template/rfc-template.rst``. Explain the problem before the solution.
Name the terms, the behavior a reader will see, the alternatives, compatibility,
security, and operations. Keep the implementation status separate from the proposal.
Every record needs an Abstract and a References section.
A number is not an approval.

Operations and recovery
-----------------------

Commands that change records hold a lock. Each file is replaced whole, and a journal
makes an update of several files recoverable. ``--dry-run`` shows a change without
making it. After an interruption, run ``recover --rollback``; it refuses to overwrite
a later edit. Keep the records in version control.

References
----------

* :doc:`../workflow`, the commands of this catalog.
* Guidedog, which builds the HTML and PDF editions.

.. rubric:: Lifecycle event

::

   2026-10-15: prediscussion -> discussion. Ported from the Zig repository's
   Typst record

.. rubric:: Lifecycle event

::

   2026-10-15: discussion -> published. State carried over from the Zig
   repository's registry
