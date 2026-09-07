#import "theme.typ": *

= Learning Paths and Reading Guide

#objectives([
  By the end of this introductory chapter, you should be able to identify which reading
  path aligns with your technical background, understand how code anchors connect to the
  monorepo source files, and anticipate the empirical evaluation criteria applied in Part VIII.
])

The book is organized into ten sequential parts. Depending on your primary engineering focus,
you may navigate the material through one of five specialized routes.

#v(4mm)

== Five Reader Routes

#table(
  columns: (1.1fr, 1.3fr, 1.8fr),
  table.header([*Role*], [*Primary Parts*], [*Key Takeaways*]),
  [Cryptography Researcher],
  [Parts I, III, IV, VIII],
  [Cost models of Hashcash and sequential work, the soundness argument, why symmetric MACs replace signatures, the spent-set bound, calibration data.],

  [Security Architect],
  [Parts I, III, IV, VI, IX],
  [Challenge binding and replay resistance, the semantic WAF's detector structure and its false-positive discipline, reputation and bans, cluster-wide propagation.],

  [Systems Engineer],
  [Parts V, VI, VII, VIII],
  [The 64 KB connection buffer, byte-class scanning, Robin Hood hashing, GCRA, lock-free rings, read-copy-update slots, memory residency.],

  [Reverse Proxy Operator],
  [Parts I, IX, X],
  [Surfaces and flags, forward-auth recipes for Nginx and Caddy, policy JSON, storage and cluster deployment, diagnostics.],

  [Web / Frontend Engineer],
  [Parts IV, VII, X],
  [The 8.8 KB WebAssembly module, the Web Worker protocol, the JavaScript fallback provers, the interstitial page.],
)

== Visual and Typographical Conventions

Throughout the book, specific pedagogical callouts highlight critical insights, trade-offs,
and exercises:

- *Learning Contracts (#text(fill: green)[Green]):* Concrete objectives stated at the beginning
  of every part and chapter.
- *Warnings (#text(fill: red)[Red]):* Security hazards, denial-of-service vulnerabilities, and
  common operational anti-patterns.
- *Exercises (#text(fill: amber)[Amber]):* Conceptual puzzles, mathematical derivations, and code
  modifications with hints.
- *API Anchors:* Explicit cross-references linking textual discussions directly to source code
  symbols within the `apps/` and `libs/` directories.
- *Teach It Back:* Formative assessment prompts challenging you to explain an invariant or
  algorithmic decision in your own words before advancing.

Code excerpts are copied from the repository at the revision named in Part VIII. When a listing
has been shortened for the page, the omission is marked with an ellipsis comment.

#callout([Empirical Integrity Rule], [
  This book does not cite unmeasured figures as measurements. Every performance number in
  Part VIII is rendered at compile time from the committed result file
  `benchmarks/results/latest.json`, which records the host, CPU, revision, and the spread across
  seven batches. Reference values for other systems are labelled as models wherever they appear.
])
