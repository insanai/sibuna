#import "theme.typ": *
#import "figures.typ": *

#part_page("I", [Foundations of Asymmetric Web Defense], [
  We explore the economics of automated web scraping, explain why the traditional
  defensive boundaries fail, and establish verifiable computation as the friction that
  restores the balance between requester and server.
])

= The AI Scraping Arms Race

#objectives([
  By the end of this chapter, you should be able to quantify the economic asymmetry between web
  scrapers and origin servers, articulate why IP reputation lists cannot stop distributed
  harvesting, and explain why cognitive tests such as CAPTCHAs no longer separate humans from
  machines.
])

== The Economics of Automated Data Extraction

The demand for training text, code, and media has turned the public web into a quarry. Model
builders, data brokers, and autonomous agents run extraction pipelines against every reachable
site, continuously. Under ordinary HTTP the cost of an interaction falls almost entirely on the
*server*:

#table(
  columns: (1fr, 1.2fr, 1.2fr),
  table.header([*Actor*], [*Action*], [*Computational Cost*]),
  [Scraper Client],
  [Emits HTTP GET over an existing TCP connection],
  [$approx 0.0001$ ms CPU time],

  [Origin Web Server],
  [Accepts socket, TLS termination, routing, database query, template rendering, response serialization],
  [$5$ to $50$ ms CPU time, plus database I/O and bandwidth],
)

The asymmetry favours the requester by at least $10,000 : 1$. A bot on a five-dollar virtual
machine can saturate an origin backed by a fleet of database replicas.

== The Collapse of Legacy Defenses

#warning([The Failure of Convention], [
  Relying on `robots.txt` against a harvesting fleet is locking a vault with a paper ribbon.
  Commercial scrapers disguise their User-Agent, present browser headers, and ignore crawling
  directives entirely.
])

=== The Residential Proxy Revolution

Firewalls used to block crawlers with IP reputation lists and per-address rate limits.
Residential proxy pools defeated both: traffic is routed through millions of consumer routers
and devices so that a fleet can issue a hundred thousand requests a minute, each from a fresh,
previously unseen address. A token bucket keyed by client address sees one request per bucket.

=== The Death of the CAPTCHA

CAPTCHAs replaced identity with cognition: distorted letters, audio puzzles, image grids.
Multimodal models now solve them faster and more reliably than people, while users with visual
impairments or small screens fail them at rates between $15%$ and $30%$. The test punishes the
humans and admits the machines.

== What Remains: Verifiable Cost

The one resource a requester cannot borrow from a proxy pool is *its own computation*. If
admission requires a proof that a known amount of work was done, and the server can check that
proof in nanoseconds, the economics invert. The idea is old, Dwork and Naor proposed "pricing via
processing" in 1992 and Back's Hashcash followed in 1997, but the engineering that makes it usable
at the edge is recent: hardware hash instructions, WebAssembly in every browser, and constructions
with proofs of sequentiality. Sibuna is built on that engineering.

#v(4mm)

= Proof of Work as a Thermodynamic Barrier

#objectives([
  Derive the mechanics of a bit-level Hashcash puzzle, calculate expected work as a function of
  difficulty, and see how computational friction removes the profit from mass scraping while
  staying imperceptible to a person.
])

== The Hashcash Paradigm

Given a server-issued challenge string $C$ and a difficulty $b$ in *bits*, the client must find
a nonce $N$ such that

$ "SHA-256"(C || ":" || N) < 2^(256 - b), $

that is, the digest begins with $b$ zero bits. Sibuna measures difficulty in bits rather than in
hexadecimal digits so that each step doubles the work instead of multiplying it by sixteen; the
operational difference is the gap between a 20 ms and a 320 ms interstitial on a phone.

=== Probability and Geometric Distribution

SHA-256 behaves as a random oracle, so each trial succeeds independently with probability
$p = 2^(-b)$. The number of trials $X$ is geometric:

$ E[X] = 2^b, quad "Var"[X] = (1 - p) / p^2 approx 2^(2b), quad P[X > k dot 2^b] approx e^(-k). $

The distribution has a long tail: one client in twenty needs three times the expected work. Part
III shows how the sequential-work tier removes this variance entirely.

#table(
  columns: (0.8fr, 1.2fr, 1.4fr, 1.4fr),
  table.header([*Bits $b$*], [*Expected hashes*], [*V8 WebAssembly (0.3 µs/hash)*], [*Native, hardware SHA (52 ns/hash)*]),
  [12], [4,096], [$approx 1$ ms], [$approx 0.2$ ms],
  [16], [65,536], [$approx 20$ ms], [$approx 3.4$ ms],
  [18], [262,144], [$approx 80$ ms], [$approx 14$ ms],
  [20], [1,048,576], [$approx 320$ ms], [$approx 55$ ms],
)

The WebAssembly column is measured with the shipped solver under V8 on an Apple M1; the native
column is the same solver compiled for the host.

== Reversing the Asymmetry

The server verifies a solution with exactly one SHA-256 evaluation, 62.6 ns on the reference
host. At $b = 16$ the asymmetry is therefore

$ "Asymmetry" = frac(E["Hashes"_"client"], 1) = 65,536 : 1, $

and a single core verifies sixteen million solutions per second. No submission flood can outpace
verification; the attacker's cost is bounded below by the honest client's cost, which Part III
makes precise.

#exercise([1.1], [
  A crawler botnet attempts to scrape 10,000,000 pages protected by Sibuna at $b = 16$. If
  each worker core hashes at 3,000,000 hashes per second (a fast native solver) and consumes
  15 W, calculate the core-hours and kilowatt-hours needed. Repeat for $b = 18$.
], hint: [Total hashes $= 10^7 times 2^b$. Divide by the hash rate for seconds.])

#teach_back([
  Explain why a puzzle whose verification costs one hash deters a harvesting fleet but not a
  reader who opens five articles in an evening.
])
