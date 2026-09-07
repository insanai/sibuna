#import "theme.typ": *
#import "figures.typ": *

#part_page("I", [Foundations of Asymmetric Web Defense], [
  We explore the macroeconomic drivers of automated web scraping, expose why traditional
  defensive boundaries fail, and establish Proof-of-Work as a thermodynamic friction barrier.
])

= The AI Scraping Arms Race

#objectives([
  By the end of this chapter, you should be able to quantify the economic asymmetry between web
  scrapers and origin servers, articulate why IP reputation lists cannot prevent distributed
  harvesting, and explain why modern computer vision models have rendered CAPTCHAs obsolete.
])

== The Economics of Automated Data Extraction

The explosion of generative artificial intelligence and frontier foundation models has ignited
a global gold rush for high-quality human text, code, scientific papers, and creative media.
Training a modern foundation model demands trillions of tokens harvested from the public web.
Consequently, commercial AI entities, specialized data brokers, and private automated scrapers
subject web services to unceasing, high-throughput extraction pipelines.

Under traditional HTTP traffic patterns, the computational cost of an interaction was borne
disproportionately by the *server*:

#table(
  columns: (1fr, 1.2fr, 1.2fr),
  table.header([*Actor*], [*Action*], [*Computational Cost*]),
  [Scraper Client],
  [Emits HTTP GET over existing TCP connection],
  [$approx 0.0001$ ms CPU time (negligible energy)],

  [Origin Web Server],
  [Accepts socket, TLS termination, routing, database query, template rendering, response serialization],
  [$5$ to $50$ ms CPU time + database I/O + bandwidth],
)

This asymmetry favored the attacker by an order of at least $10,000 : 1$. A bot running on a
cheap \$5/month virtual private server could easily saturate an origin server backed by dozens
of high-end database replicas.

== The Collapse of Legacy Defenses

#warning([The Failure of Convention], [
  Relying on `robots.txt` in the modern AI era is equivalent to locking a vault door with a
  paper ribbon. Commercial scrapers routinely disguise their User-Agent headers, spoof human
  browsers, or ignore crawling directives altogether.
])

=== The Residential Proxy Revolution

Historically, firewalls blocked crawlers by maintaining IP reputation lists and imposing
per-IP rate limits. Attackers neutralized this defense by acquiring access to vast *residential
proxy pools* (such as Bright Data, Oxylabs, and Smartproxy). These networks route traffic
through millions of compromised consumer routers and IoT devices around the world. A botnet
can issue 100,000 requests per minute with each individual request originating from a unique,
previously unseen IPv4 address in a residential ISP range. Under these conditions, standard
token-bucket rate limiting based on client IP is completely blind.

=== The Death of the CAPTCHA

When IP filtering failed, the industry turned to CAPTCHAs (Completely Automated Public Turing test
to tell Computers and Humans Apart). Users were subjected to clicking distorted letters, audio
puzzles, and image classification challenges.

However, modern multi-modal neural networks solve standard image CAPTCHAs with accuracy exceeding
$98%$, often solving them in under 400 milliseconds. Legitimate human users, particularly those
with visual impairments or mobile devices, suffer failure rates between $15%$ and $30%$.
CAPTCHAs now punish real humans while offering zero defense against automated AI systems.

#v(4mm)

= Proof-of-Work as a Thermodynamic Barrier

#objectives([
  Derive the mathematical mechanics of Hashcash, calculate expected nonce trials as a function
  of difficulty, and demonstrate how computational friction destroys the profitability of mass
  scraping.
])

== The Hashcash Paradigm

In 1997, Adam Back proposed *Hashcash* as a mechanism to throttle email spam and denial-of-service
attacks. Instead of relying on identity, reputation, or human cognitive tests, Hashcash conditions
service admission upon the presentation of a cryptographic proof that a verifiable quantity of
computational work was expended by the caller.

Given a server-issued challenge string $C$ and a target difficulty parameter $D$, the client must
discover a nonce integer $N$ such that:

$ "SHA-256"(C || ":" || N) < 2^{256 - 4 D} $

In hexadecimal notation, this inequality dictates that the leading $D$ hexadecimal characters
(nibbles) of the 32-byte SHA-256 output digest must be identically zero.

=== Probability and Geometric Distribution

Because SHA-256 behaves as a cryptographically secure pseudo-random oracle, each candidate nonce
$N$ produces a digest whose leading nibbles are uniformly distributed across $\{0, 1, ..., 15\}$.
The probability $P$ that any single trial satisfies a difficulty of $D$ leading hex zeros is:

$ P = (frac(1, 16))^D = 16^(-D) $

The number of trials $X$ required to locate a valid nonce follows a *Geometric Distribution*:

$ E[X] = frac(1, P) = 16^D $

Let us tabulate the expected trial counts and representative single-core solving times across
typical difficulty settings:

#table(
  columns: (1fr, 1.2fr, 1.2fr, 1.4fr),
  table.header([*Difficulty ($D$)*], [*Prefix Constraint*], [*Expected Hashes ($16^D$)*], [*Average Solve Time (Core)*]),
  [3], [`000...`], [4,096], [$approx 3$ to $8$ ms],
  [4], [`0000...`], [65,536], [$approx 50$ to $180$ ms],
  [5], [`00000...`], [1,048,576], [$approx 0.8$ to $2.5$ seconds],
  [6], [`000000...`], [16,777,216], [$approx 15$ to $40$ seconds],
)

== Reversing the Asymmetry

Notice the extraordinary asymmetry inherent in this mathematical relation:
- *The Scraper's Burden:* To harvest a single page protected by difficulty $D=4$, the scraper's
  CPU must compute, on average, $65,536$ distinct SHA-256 iterations.
- *The Server's Verification:* To verify the validity of the submitted solution, the server
  executes exactly *one single SHA-256 hash operation* and inspects the leading bytes.

On modern server silicon (Apple M-series or Intel Xeon with SHA-NI instructions), a single SHA-256
hash of a 40-byte input takes less than *30 nanoseconds*.

$ "Asymmetry Ratio" = frac(E["Hashes"_"Client"], 1) = 65,536 : 1 $

The computational balance is completely inverted. The server spends 30 nanoseconds of CPU time
to force the automated crawler to burn 100 milliseconds of dedicated core compute.

#exercise([1.1], [
  A crawler botnet attempts to scrape a database of 10,000,000 product pages protected by
  Sibuna at difficulty $D=4$. If each worker CPU core hashes at $150,000$ hashes per second
  and consumes $15$ Watts of power, calculate the total compute time (in core-hours) and the
  total electrical energy (in kilowatt-hours) required to complete the crawl.
], hint: [Total hashes required = $10^7 times 65,536$. Divide by hashing rate to find seconds.])

#teach_back([
  Explain why Proof-of-Work friction deters a commercial AI data scraper while remaining
  completely acceptable to a human reader visiting five articles in an evening.
])
