:sid-number: 0010
:sid-title: The Rust Port: Workspace, Crates, Dependency Policy and Performance Parity
:sid-state: discussion
:sid-status: Open for Discussion
:sid-type: Architectural Specification
:sid-authors: ["Vikrant Rathore"]
:sid-created: 2026-10-15
:sid-updated: 2026-10-15
:sid-discussion: No external discussion URL assigned
:sid-summary: Ports Sibuna from Zig 0.16 to a Rust workspace that keeps every wire format bit for bit, builds the data plane from small in-house crates without external dependencies, and is accepted when it matches or exceeds the Zig daemon in the benchmarks of SID 0002.
:sid-labels: ["architecture","rust","performance"]

The Rust Port: Workspace, Crates, Dependency Policy and Performance Parity
==========================================================================

Abstract
--------

Sibuna was written in Zig 0.16. We port it to Rust. The Zig source is the specification of behaviour, and SID 0001 to SID 0009 remain the design records; this record says how their mechanisms map onto a Rust workspace. The port keeps every wire format bit for bit, so a Rust node and a Zig node that share a seed accept each other's challenges and session tokens. The data plane depends on no external crate: hashing, signatures, base64, JSON, DEFLATE, Aho-Corasick and the HTTP/1.1 parser are small workspace crates that other projects may use on their own. Storage is the one exception, and SID 0011 records it. The port is accepted when it passes the ported test suites and matches or exceeds the Zig daemon in the throughput and latency benchmarks of SID 0002.

Motivation and scope
--------------------

Zig 0.16 served the first version well. Its standard library carried SHA-256 with SHA-NI, BLAKE3, Ed25519, base64, JSON and a TLS client, so the daemon needed almost nothing else. Rust brings an ownership model that turns the Zig comments "this slice borrows the connection buffer until the next read" into lifetimes the compiler checks, a mature ecosystem for the one large problem we do not want to own (SQL storage), and a broader pool of maintainers.

The scope is the whole repository: the data plane (SID 0002 to SID 0004, SID 0006, SID 0009), the browser solver, storage (SID 0005, replaced by SID 0011), the console and its WebAssembly interface (SID 0007, SID 0008), the tools, the benchmarks and the documentation. Documentation moves from Typst to reStructuredText managed with guidedog: the design records with ``guidedog dsc`` and the book with ``guidedog build``.

Specification
-------------

Behavioural parity
~~~~~~~~~~~~~~~~~~

The following are identical to the Zig daemon, and each has tests whose expected values were produced with the Zig 0.16 standard library or taken from the Zig test suite:

- the challenge identifier (36-byte payload, 16-byte keyed BLAKE3 tag, 70 URL-safe base64 characters), the requirement ticket (59 characters), and both session token formats (75-character keyed BLAKE3 MAC token, 139-character Ed25519 token);
- the key schedule (keyed BLAKE3 subkeys ``sibuna/token/v1`` and the others of SID 0002) and node binding of challenge keys;
- Hashcash (``SHA-256(challenge ":" decimal(nonce))`` with bit-level difficulty) and the Cohen-Pietrzak proof layout of SID 0006;
- the rule hash (Zig's ``std.hash.Wyhash`` with its fixed seed), so rule identities stored in tokens agree across implementations;
- the HTTP/1.1 parser's acceptance and rejection set, including every smuggling and chunked-framing case of SID 0009;
- policy evaluation order, WEIGH scoring, WAF categories and the Elm-style diagnostics of SID 0001 and SID 0003;
- every route, status code, header and response body the end-to-end suite observes.

Workspace
~~~~~~~~~

.. list-table:: Crates and their responsibilities
   :header-rows: 1
   :widths: 25 15 60

   * - Crate
     - Reusable
     - Responsibility
   * - ``sibuna-crypto``
     - yes
     - SHA-1, SHA-256 with SHA-NI and ARMv8 dispatch, BLAKE3 (keyed, derive-key), HMAC, Ed25519, Wyhash, constant-time comparison; ``no_std``
   * - ``sibuna-encoding``
     - yes
     - base64 (standard and URL-safe, with and without padding) and hexadecimal; ``no_std``
   * - ``sibuna-json``
     - yes
     - bounded JSON parser with located errors and an escaping writer
   * - ``sibuna-pow``
     - yes
     - Hashcash and the Cohen-Pietrzak prover and verifier with a fixed workspace; ``no_std``
   * - ``sibuna-http``
     - yes
     - zero-copy HTTP/1.1 request parser, strict chunked decoder, response writer, RFC 6455 frames and handshake
   * - ``sibuna-patterns``
     - yes
     - tagged Aho-Corasick automata over bytes
   * - ``sibuna-cidr``
     - yes
     - IPv4 and IPv6 parsing and a radix trie of prefixes
   * - ``sibuna-store``
     - yes
     - Vyukov MPSC ring, Robin Hood spent set, GCRA limiter, ban table, striped counters
   * - ``sibuna-inflate``
     - yes
     - DEFLATE and gzip with explicit output bounds
   * - ``sibuna-geoip``
     - yes
     - IP to country lookup from open CSV datasets and canonical snapshots
   * - ``sibuna-html``
     - yes
     - escaped HTML snippet rendering; templates are compiled to Rust at build time
   * - ``sibuna-core``
     - no
     - configuration, command-line parsing, diagnostics, metrics, incident types
   * - ``sibuna-policy``
     - no
     - rules, loader, evaluation engine, semantic WAF, normaliser, page templates, embeddings
   * - ``sibuna-challenge``
     - no
     - keys, tokens, challenge coordinator, tickets, adaptive difficulty
   * - ``sibuna-net``
     - no
     - streaming reverse proxy, upstream pool, forwarded metadata, WebSocket relay
   * - ``sibuna-storage``
     - no
     - persistent layer over sqlx (SID 0011)
   * - ``sibuna-serve``
     - yes
     - bounded HTTP/1.1 listener with joinable workers, deadlines, admission classes and WebSocket upgrades
   * - ``sibuna-tls``
     - no
     - blocking outbound TLS through rustls for the console (SID 0012)
   * - ``sibuna-console*``
     - no
     - console protocol, server and WebAssembly interface (SID 0007)

Binaries live under ``cmd/``: the daemon ``sibuna`` and the browser solver ``sibuna-pow-wasm``. Repository tools are Rust programs under ``tools/``, run through ``cargo xtask``. Dependencies point one way: reusable crates, then ``sibuna-core``, then the application crates, then the binaries.

.. graphviz::
   :caption: Crate dependencies. Reusable crates depend on no application crate.
   :alt: A layered graph from reusable crates through sibuna-core to the application crates and the daemon.

   digraph crates {
     graph [rankdir=BT, bgcolor="transparent"];
     node [shape=box, fontname="Helvetica"];
     subgraph cluster_reusable {
       label="reusable"; style=dashed;
       crypto; encoding; json; pow; http; patterns; cidr; store; inflate; geoip; html;
     }
     pow -> crypto; http -> crypto; http -> encoding; geoip -> inflate; geoip -> crypto;
     policy -> patterns; policy -> cidr; policy -> json; policy -> core;
     challenge -> crypto; challenge -> pow; challenge -> store; challenge -> encoding;
     net -> http; net -> core;
     storage -> policy; storage -> core;
     sibuna -> policy; sibuna -> challenge; sibuna -> net; sibuna -> storage;
     "sibuna-pow-wasm" -> pow;
   }

Mapping of mechanisms
~~~~~~~~~~~~~~~~~~~~~

.. list-table:: Zig idioms and their Rust form
   :header-rows: 1
   :widths: 40 60

   * - Zig
     - Rust
   * - slices into the 64 KiB connection buffer
     - ``&'a [u8]`` borrowed from the buffer; a parsed ``Request<'a>`` cannot outlive the bytes it describes, and the compiler rejects a use after the buffer is refilled
   * - error unions and error sets
     - ``Result<T, E>`` with one ``enum`` per module implementing ``Display`` and ``std::error::Error``
   * - ``maxInt`` and empty-string sentinels
     - ``Option<T>``
   * - engine slot with an atomic reader count (read-copy-update)
     - ``Arc<Engine>`` published through a slot; the storage thread builds a new engine off the hot path and swaps it in; the old one is freed when its last request finishes
   * - lock-striped fixed tables with spin locks
     - the same striping with ``std::sync::Mutex`` per shard (a futex in the uncontended case), unless a benchmark shows a spin lock wins
   * - ``threadlocal`` sampling state and counter stripe
     - ``thread_local!`` with ``Cell``
   * - ``comptime`` tables and the HTML snippet compiler
     - ``const`` tables and ``const fn``; snippets are compiled by a build script into Rust functions, so template errors (HTML001 to HTML007) stop the build as before
   * - ``@embedFile``
     - ``include_bytes!`` and ``include_str!``
   * - ``defer`` and ``errdefer``
     - ``Drop`` and guard values
   * - thread-per-connection with a joinable task pool
     - the same model on ``std::thread``: accept workers hand each connection to a bounded pool of threads, and the slot is reclaimed by joining before reuse

Concurrency model
~~~~~~~~~~~~~~~~~

The Zig daemon serves each connection on its own thread, bounded by ``--max-connections``, with one 64 KiB buffer per connection. We keep this model. It is simple, it isolates a slow client to one thread, and it lets the request path stay synchronous and allocation-free. An asynchronous runtime would add a large dependency to the hot path and change the cost model of every mechanism the earlier records measured. The storage layer (SID 0011) is the only place that runs an asynchronous runtime, on its own thread, and the request path never waits on it.

Hardware acceleration
~~~~~~~~~~~~~~~~~~~~~

Zig's standard library selected SHA-NI and the ARMv8 SHA-2 instructions at build time. We detect them at run time with ``is_x86_feature_detected!`` and ``is_aarch64_feature_detected!`` and fall back to a portable implementation, so one binary is fast on every machine it runs on. Hashcash verification, PoSW verification and the challenge proof are SHA-256 bound, so this is where hardware acceleration pays. Other SIMD use (for example a vectorised byte-class pre-scan before WAF inspection) is added only with a benchmark that shows the gain, and lives in a module of its own with ``// SAFETY:`` comments on every ``unsafe`` block.

The browser solver
~~~~~~~~~~~~~~~~~~

``sibuna-pow-wasm`` is a ``no_std`` ``cdylib`` for ``wasm32-unknown-unknown``. It exports the same functions as the Zig module (``sibuna_get_buffer_ptr``, ``sibuna_get_buffer_len``, ``sibuna_solve_step``, ``sibuna_solve_sha256``, ``sibuna_posw_solve``, ``sibuna_posw_proof_ptr``), so the worker script and the JavaScript fallback are unchanged. It compiles the same ``sibuna-pow`` sources that the server uses to verify, so prover and verifier cannot drift apart. It uses no ``wasm-bindgen``; the module is built for size.

Dependency policy
~~~~~~~~~~~~~~~~~

Every external crate is a liability: it must be reviewed, updated and trusted. The data plane uses none. A dependency is admitted only when it is mature, self-contained and solves a genuinely large problem, and the reason is recorded next to it in ``Cargo.toml`` and in a design record. Storage is such a case: we use ``sqlx`` (SID 0011), confined to ``sibuna-storage`` behind cargo features, so ``cargo build --no-default-features`` produces a daemon with no external crate at all.

Engineering standards
~~~~~~~~~~~~~~~~~~~~~

The standards of SID 0001 carry over, written for Rust:

- A function body has at most 70 logical lines; a file at most 1,408 lines; a line at most 99 characters (``rustfmt.toml`` sets ``max_width = 99``). ``cargo xtask check`` enforces the limits, and ``clippy.toml`` sets ``too-many-lines-threshold = 70``.
- Every public item has a ``///`` comment saying what it borrows, what it returns and how it fails.
- No ``unsafe`` outside FFI and measured SIMD modules; every ``unsafe`` block has a ``// SAFETY:`` comment.
- No ``unwrap()`` or ``expect()`` on input-dependent values in library code. Libraries return structured errors and never print. The binaries render Elm-style diagnostics.
- Plain-data APIs: public-field structs with ``Default``, a small verb vocabulary (``load_*``, ``begin_*``/``end_*``, ``is_*``, ``*_count``), no ``get_`` prefix.
- Bounded work on untrusted input: explicit limits that return errors, never panics or unbounded allocation.
- ``cargo build``, ``cargo test``, ``cargo clippy --all-targets -- -D warnings``, ``cargo fmt --check`` and ``cargo xtask check`` pass before a change is merged. GitHub workflows may use shell or Python glue; repository tools are Rust.

Memory management that Rust makes unnecessary
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Much Zig code existed only to manage memory by hand or to avoid footguns: ``deinit`` and ``errdefer`` chains, arenas reset per rebuild, double-buffered engine slots reused to avoid reallocating several megabytes, ``undefined`` initialisation, alignment workarounds for heap fixtures, and comments of the form "this slice must not outlive the next read". The port does not carry this machinery over. Ownership, borrowing, ``Drop`` and values built once off the hot path give the same guarantees, checked by the compiler. Each crate's documentation names the Zig mechanisms it removed and what replaced them. The observable behaviour (bytes on the wire, decisions, bounds and error texts) does not change, and the request path still does not allocate.

Tools and documentation
~~~~~~~~~~~~~~~~~~~~~~~

Repository tools are Rust programs under ``tools/``, in the pattern guidedog uses: ``tools/xtask`` dispatches ``cargo xtask <task>`` (``check``, and later ``wasm`` and ``bench``), and standalone tool crates sit beside it. The Zig repository's Python and shell drivers are not ported as scripts. End-to-end tests become Rust integration tests, and browser checks drive headless Chromium from Rust over the DevTools protocol, reusing the workspace's WebSocket and JSON crates. Python is allowed only in GitHub workflow glue, or in a benchmark driver when no reasonable Rust alternative exists.

Documentation is not code. The design records are a guidedog discussion catalog (``docs/sid``, managed with ``guidedog dsc``) and the book and manual are guidedog projects; their PDFs use the Sibuna Typst design in each project's ``_templates/``. The repository contains no documentation build code: the Zig ``tools/sid.zig`` and the ``zig build sid*`` and ``book`` steps have no Rust counterpart.

The OWASP Core Rule Set
~~~~~~~~~~~~~~~~~~~~~~~

Sibuna's WAF is its own structural inspection (SID 0004), not the OWASP Core Rule Set, and the port keeps it that way. We evaluated the external SecLang engines available to Rust (pure-Rust engines a few months old with a single maintainer each, and bindings to libmodsecurity or Coraza) and admit none of them: an inspection engine on an edge server is security-critical code we must own, review and maintain, as the Zig daemon owned its own. If Sibuna adds compatibility with CRS rules, it does so in-house: a new design record specifies the subset of SecLang, the transformations, the operators and their algorithms (for example the existing Aho-Corasick automata for phrase matching and linear-time matching for expressions), and how CRS anomaly scores map onto WEIGH decisions; the implementation follows that record.

Rationale and alternatives
--------------------------

We considered porting zaxonlite as well. It is a 48,000-line Zig project of its own with a consensus library; porting it would double the work and keep an unusual storage engine in a firewall whose state is small. SID 0011 explains the replacement.

We considered ``tokio`` with ``hyper`` for the data plane. The Zig daemon's measured performance comes from a zero-copy parser, a fixed per-connection buffer and allocation-free decisions, none of which an asynchronous runtime improves; ``hyper`` would also take the request bytes away from the inspection code. We keep the thread model and measure it against the Zig daemon before considering an event loop. If the comparison shows a gap that the thread model cannot close, an ``epoll`` loop over the same parser is the next step, recorded in a new SID.

We considered ``wasm-bindgen`` for the browser modules. The solver and the console already use a small fixed bridge (shared buffers and integer exports); ``wasm-bindgen`` would add generated glue and a build tool without adding a capability.

Security and operational considerations
---------------------------------------

Bit-identical formats are a security property as well as a convenience: a mixed Zig and Rust cluster during migration must not accept a token one node minted under different rules. The test vectors pin each format. Constant-time comparison is used wherever the Zig code used ``timing_safe.eql``. Secrets are zeroed on drop where the Zig code used ``secureZero``.

Backwards compatibility
-----------------------

Command-line options, routes, the policy file format and wire formats are unchanged, except for the storage options that SID 0011 replaces. A data directory written by the Zig daemon (Zaxonlite files) is not read by the Rust daemon; operators export policies with ``sibuna console policies export`` before migrating and import them afterwards.

Acceptance criteria and implementation status
---------------------------------------------

The port is accepted when:

1. Every Zig unit test has a Rust counterpart that passes, and the end-to-end suite passes against the Rust daemon.
2. Cross-implementation tests show that a Zig node and a Rust node sharing a seed verify each other's session tokens and requirement tickets.
3. The browser solver passes in a headless browser with WebAssembly and with the JavaScript fallback.
4. The benchmarks of SID 0002 (primitives, and whole-product runs under ``wrk``) show the Rust daemon at or above the Zig daemon's throughput, with p99 latency no worse, on the same machine; the results are recorded under ``benchmarks/results/``.
5. The console passes its golden fixtures and its browser workflows in a headless browser, with screenshots reviewed.

Status: in progress. This section is updated with the evidence as each criterion is met.

Evidence recorded so far (2026-10-15):

- Criterion 2: Rust and Zig daemons sharing a seed verify each other's MAC and Ed25519 session tokens and requirement tickets (``crates/challenge`` cross-implementation tests against the Zig baseline binary).
- Criterion 3: ``cargo xtask browser`` drives Chromium 155 headless through the interstitial; the challenge passes with WebAssembly (solve 29 to 34 ms) and with the JavaScript fallback (84 to 91 ms, WebAssembly disabled). Detection relies on the default interstitial markup (``#status``, ``.progress-bar``).
- Differential behaviour: ``cargo xtask parity`` replays generated corpora against both daemons in 17 configurations. At commit ``dda1162`` four seeds (three of 20,000 requests and one of 60,000) gave no unexplained difference; every allowed difference is listed with its reason in ``tools/parity/allow-list.json``.
- Criterion 4 (preliminary): ``cargo xtask bench`` records primitives, whole-product and open-loop latency runs in ``benchmarks/results/``. The final figures are taken on a quiet machine after the console port.

Open questions
--------------

- Closed 2026-10-15: the spent set and the limiter use ``std::sync::Mutex`` (see the review history for the measurements); the ban table keeps its seqlock readers with a mutex for writers.
- Whether an ``epoll`` event loop is needed to reach parity: decided by benchmark.

Review history
--------------

- 2026-10-15: drafted with the start of the port.
- 2026-10-15 (Rust port): each crate lists its deliberate changes from Zig in its crate documentation, and the design records that those changes touch carry dated revision notes (SID 0002 to SID 0007, SID 0009, SID 0011, SID 0012). Evidence for the first open question: ``sibuna-store`` measured ``std::sync::Mutex`` against a spin lock on a Ryzen 9 5950X. The spin lock saves about a nanosecond per uncontended operation but loses under contention (the spent set at 64 threads: 11.2 against 6.9 million operations per second; GCRA on six hot addresses at 64 threads: 37.4 against 6.5 million), so the spent set and the limiter use the mutex; the question is closed in favour of the mutex. The HTML snippet compiler of ``sibuna-html`` adds the code ``HTML008`` (a snippet file name must yield Rust item names) to ``HTML001`` to ``HTML007``.
- 2026-10-15 (security review): limiter and ban-table placement is process-local, keyed per table, and not part of any wire format; only the rule hash keeps Zig's ``std.hash.Wyhash`` with its fixed seed. The Vyukov ring remains the store's only non-FFI ``unsafe``: ``std::sync::mpsc::sync_channel`` was measured to cost 20 to 45% more per push with 16 producers (``tests/timing.rs``, ``bounded_queue_producers``). An adversarial review (2026-10-15) found request-path weaknesses inherited from Zig (trusted forwarded address, origin pool reuse, request-target normalisation, WAF canonicalisation bound, keyed tables, honeypot cross-site requests, adaptive input, connection limits); each fix is recorded in the SID that specifies the mechanism.
- 2026-10-15 (console port): ``cmd/sibuna`` features are ``default = [sqlite, console]``; ``console`` enables storage and the crates ``sibuna-console``, ``sibuna-console-protocol``, ``sibuna-console-storage`` and ``sibuna-json``. ``--no-default-features`` stays free of external crates. The console server is the application crate ``sibuna-console``; TOTP joins ``sibuna-crypto`` and the range-to-prefix split joins ``sibuna-geoip``, both reusable.
- 2026-10-15 (console port): ``sibuna-crypto`` gains ``totp`` (RFC 4226 and 6238, HMAC-SHA1, six digits, 30 s steps, base32 seeds) for the console's second factor; ``sibuna-geoip::prefixes`` holds the range-to-prefix split used by country actions.
- 2026-10-15 (console port): ``sibuna-tls`` has a ``testing`` feature, ``testing::Ingress``, a TLS-terminating test proxy with the fixed test certificates; only dev-dependencies enable it.
- 2026-10-15 (console port): ``sibuna`` has an optional build-dependency on ``sibuna-geoip`` (console feature) to validate the embedded GeoIP snapshot. The console's end-to-end suite is ``cmd/sibuna/tests/console_*.rs``; its PostgreSQL cluster scenarios run when ``SIBUNA_TEST_DATABASE_URL`` is set. With the console compiled in, disabled, storage only, or enabled and idle, the 16 product workloads stay within about 1% of the daemon built without it, which is within noise.

References
----------

- SID 0001: the Sibuna Discussion process and engineering standards.
- SID 0002: foundation architecture and performance contract.
- SID 0006: mathematical foundations.
- SID 0009: chunked request bodies.
- SID 0011: storage through sqlx.
- The Rust Reference and the Rust standard library documentation, ``std::arch`` (runtime feature detection).


.. rubric:: Lifecycle event

::

   2026-10-15: prediscussion -> discussion. Specification of the port, drafted
   before the code
