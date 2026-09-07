#import "theme.typ": *

= Learning Paths and Reading Guide

#objectives([
  By the end of this introductory chapter, you should be able to identify which reading
  path aligns with your technical background, understand how code anchors connect to the
  monorepo source files, and anticipate the empirical evaluation criteria applied in Part VII.
])

The book is organized into nine sequential parts. Depending on your primary engineering focus,
you may navigate the material through one of four specialized routes.

#v(4mm)

== Four Reader Routes

#table(
  columns: (1.1fr, 1.3fr, 1.8fr),
  table.header([*Role*], [*Primary Parts*], [*Key Takeaways*]),
  [Security Architect],
  [Parts I, III, VII, VIII],
  [Mathematical Proof-of-Work cost models, anti-cookie-theft fingerprinting, and dynamic difficulty tuning under attack.],

  [Systems Engineer],
  [Parts II, IV, V, VII],
  [Zero-allocation hot path design, cache-line aligned spinlocks, SIMD automata, and memory residency optimization.],

  [Reverse Proxy Operator],
  [Parts I, VII, VIII, IX],
  [Autonomous reverse proxy configuration, forward-auth integration with Nginx/Caddy/Traefik, and container sidecars.],

  [Web / Frontend Engineer],
  [Parts III, VI, IX],
  [The 6.9 KB freestanding WebAssembly solver, background Web Worker lifecycles, and cyber interstitial UI integration.],
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

#callout([Empirical Integrity Rule], [
  This book does not cite hypothetical or unmeasured benchmark figures. Every performance
  metric in Part VII is rendered dynamically at compile time from the committed result file
  `benchmarks/results/latest.json`. When numbers change across hardware architectures or
  optimization passes, the table and accompanying analysis adapt deterministically.
])
