:sid-number: 0004
:sid-title: Semantic Attack Inspection and GCRA Rate Limiting: The Shield Surface
:sid-state: published
:sid-status: Published
:sid-type: Architectural Specification
:sid-authors: ["Sibuna Contributors <team@sibuna.local>"]
:sid-created: 2026-09-07
:sid-updated: 2026-10-15
:sid-discussion: No external discussion URL assigned
:sid-summary: Design and measured implementation of Sibuna's Shield surface: a single-pass tagged signature automaton, single-pass structural tokenizers for SQL injection, cross-site scripting, path traversal, and command injection, the byte-class pre-scan and canonicalisation gate, the GCRA rate limiter, the ban table, and incident recording.
:sid-labels: ["waf", "security", "rate-limiting", "zero-alloc"]

Semantic Attack Inspection and GCRA Rate Limiting: The Shield Surface
=====================================================================

Revision note
-------------

2026-10-15: Ported from the Typst original in the Zig repository. The record describes the Zig implementation as it was decided; SID 0010 maps its packages to the Rust crates of the port.

2026-10-15 (Rust port): the tagged signature automaton is built by ``sibuna-patterns``, whose table holds one ``u32`` successor per state and byte class instead of 256 ``u16`` successors per state. Bytes that occur in no signature share one class, and with case folding both cases of a letter share a class, so a row is as wide as the number of distinct signature bytes plus one. A scan is still exactly one dependent load per input byte with failure links folded in, and the state capacity is still derived from the signature lengths; the signature sets need several times less memory. Case folding is an option of the builder, which Sibuna turns on, instead of a fixed comptime table. Category tags run from 0 to 63, so that the set of categories found in a field is one 64-bit word; Sibuna's categories are below 4. Findings are unchanged: a differential test replays generated requests and payloads against the Zig library.

2026-10-15 (Rust port): the GCRA limiter (``sibuna-store``) keeps its decisions, its bound, its table layout and its probe rule. Zig's limiter already used saturating arithmetic; the port also saturates the conversion of a window in seconds to milliseconds in its convenience entry point, where Zig would have overflowed. The ban table keeps its versioned snapshots and lock-free readers. WAF denials and honeypot hits still enter the bounded incident ring; the storage layer behind it is SID 0011 instead of SID 0005.

.. admonition:: Revision note (2026-09-07)

   Revised after the implementation review of 2026-09-07. The first implementation matched a flat list of substrings in every header; because ``/*`` was on that list, every browser's ``Accept: text/html,...,*/*;q=0.8`` header was classified as SQL injection and every real browser received ``403``. The review replaced the flat list with the tagged automaton and the structural tokenizers described here, added a test that passes a complete Chrome request untouched, and corrected the "sliding window" description of the rate limiter to what the code implements: the Generic Cell Rate Algorithm.

2026-10-15 (Rust port, WAF review): canonicalisation no longer stops at 8 KiB. Zig canonicalised into an 8 KiB stack buffer and inspected a longer field raw only, so a header, query string or cookie padded beyond 8 KiB hid a percent-encoded payload from the second pass. Every inspected field is now canonicalised whole: values from the request head up to the 16 KiB head bound, and body fields within the unchanged 8 KiB body prefix. Fields longer than 2 KiB use a 16 KiB buffer that each thread allocates once, so inspection still allocates nothing per request. Canonicalisation also decodes JSON string escapes (``\"``, ``\\``, ``\/``, ``\'``, ``\b``, ``\f``, ``\n``, ``\r``, ``\t`` and ``\uXXXX`` below U+0080) and HTML character references (decimal and hexadecimal references below U+0080, and named references of ASCII punctuation and white space such as ``&lt;`` and ``&colon;``), and it keeps the text of MySQL executable comments (``/*!50000select*/``), whose markers become spaces. A backslash, or an ``&`` together with a ``;`` or a ``#``, now triggers the second pass. The decoded form, before whitespace folding, is searched for a line feed followed by a shell command (``%0a``), which folding used to turn into a space, and for a ``javascript:`` or ``vbscript:`` scheme split by tabs or line breaks. The structural detectors also find an event handler with white space before its ``=`` (``onerror =``), an event handler inside a tag of any name, tautologies with ``<``, ``>``, ``<=``, ``>=``, ``<>`` and ``!=`` (``or 2>1``), and ``union`` joined to ``select`` by parentheses (``union(select``). Body coverage changes in three ways. A body of a declared binary type is inspected as text unless its prefix looks binary, that is, unless at least one byte in sixteen is a control byte other than tab, line feed, vertical tab, form feed and carriage return. Multipart delimiters accept the transport padding of RFC 2046. A part with an empty ``filename`` is an ordinary field. Work stays linear in the input. The differential test lists the requests whose findings change for these reasons.

Abstract
--------

Design and measured implementation of Sibuna's Shield surface: a single-pass tagged signature automaton, single-pass structural tokenizers for SQL injection, cross-site scripting, path traversal, and command injection, the byte-class pre-scan and canonicalisation gate, the GCRA rate limiter, the ban table, and incident recording.

Context and problem statement
-----------------------------

An edge proxy faces two threat classes at once: automated harvesting that looks like ordinary traffic, and application-layer exploitation (SQL injection, cross-site scripting, path traversal and local file inclusion, command injection, and request floods). Deployments typically chain a challenge proxy in front of a separate application firewall and pay for two processes, two parsers, and an inter-process hop on every request. Sibuna's **Shield** surface (``--shield``, the default) performs both roles inside the same zero-allocation pass; the **Gate** surface (``--gate``) switches the semantic inspection and the flood limiter off for deployments that only want proof-of-work admission.

Engine choice: automata and tokenizers, not regular expressions
---------------------------------------------------------------

Three families of engine were considered.

- **Regular-expression rule sets** (backtracking engines) execute hundreds of backtracking patterns per request, allocate match contexts, and are notoriously prone to false positives.
- **SIMD literal engines** (Hyperscan, Vectorscan) prefilter with shuffle-based literal matchers and verify with automata; they win on long inputs and very large literal sets, at the cost of a multi-megabyte C++ dependency, a compile-time pattern database, and no portability to the browser side.
- **Aho-Corasick automata with structural tokenizers** (the libinjection lineage) scan each field once in linear time with a fixed table and detect structure with small deterministic scanners.

Sibuna's inputs are dominated by short header fields; a User-Agent scans in 85 ns and an entire browser request is measured by the standalone policy benchmark. The third family was chosen. The measured cost on an 8 KB body is 23.7 :math:`\mu\mathrm{s}` (about 2.9 ns per byte); SIMD prefiltering remains an open item for body-heavy deployments (SID 0006 records the analysis).

Design
------

Byte-class pre-scan
~~~~~~~~~~~~~~~~~~~

One pass over each field records which byte classes occur: quote characters, ``=``, ``<``, shell separators (``;``, ``|``, ``&``, ``$``, the backtick, and ``\n``), ``%``, NUL, canonicalisation triggers (``%``, ``+``, ``\t``, ``\r``, ``\n``, ``/*``), and double spaces. Every subsequent detector consults the classes instead of rescanning, and the second (canonicalised) pass runs only when a trigger byte was seen.

Tagged signature automaton
~~~~~~~~~~~~~~~~~~~~~~~~~~

All strong signatures of every category (traversal targets such as ``../`` and ``/etc/passwd``, SQL constructs such as ``union select`` and ``xp_cmdshell``, script vectors such as ``<script`` and ``javascript:``, command vectors such as ``/bin/sh`` and ``${jndi:``) live in one dense Aho-Corasick automaton sized from the sum of signature lengths with an 8-bit category tag per pattern. A field is scanned exactly once regardless of the number of signatures; a hit yields a ``Decision`` of ``deny`` named ``waf:<category>``. The automaton is case-folded through a comptime table.

.. admonition:: Rust port note (2026-10-15)

   The Rust automaton indexes its rows by byte class rather than by byte, and its tags run from 0 to 63. A scan is still one load per byte. See the revision note.

Structural tokenizers
~~~~~~~~~~~~~~~~~~~~~

Strong signatures alone cannot catch ``id=5' or 1=1`` without also catching prose, so each category has a single-pass structural detector gated by the byte classes:

- **SQL injection**: a word scanner looks up every alphanumeric word (at most 7 bytes) in the keyword table and, for ``or``/``and``, checks for a ``literal = literal`` tautology. A tautology is terminal. Otherwise a quote is mandatory, and a score of quote (1) + up to two keywords + comment marker (1) + ``=`` (1) must reach 4; ``admin'--`` and ``admin'/*`` are terminal on their own. "it's a group order from the shop" scores 3 and passes.
- **Cross-site scripting**: requires ``<``; fires when a tag that can host script (``svg``, ``img``, ``body``, ``iframe``, ...) co-occurs with an ``on<event>=`` attribute in attribute position (preceded by whitespace, ``/``, or a quote). ``onboarding=1`` in a query string does not count.
- **Command injection**: requires a separator; fires when ``;``, ``|``, ``&&``, ``||``, ``$(``, a backtick, or a newline is followed by a known command name (``cat``, ``wget``, ``curl``, ``nc``, ``bash``, ...). A bare ``;`` is punctuation.
- **Path traversal**: signatures plus the NUL byte and ``%00``.

Field coverage and canonicalisation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The path, the query string, the User-Agent, every header except the structural content-negotiation set (``Accept*``, ``Content-Type``, ``Sec-*``, ``If-*``, ``Cache-Control``, ...), and the first 8 KB of the body are inspected. When the pre-scan saw percent escapes, plus signs, comment openers, or collapsible whitespace, the field is canonicalised (two rounds of percent decoding, ``/* */`` stripping, whitespace folding, lower-casing) into an 8 KB stack buffer and inspected again, so ``1%27/**/UnIoN/**/SeLeCt`` and ``%252e%252e/`` collapse onto the raw signatures.

GCRA rate limiter
~~~~~~~~~~~~~~~~~

The flood limiter is the Generic Cell Rate Algorithm in its virtual-scheduling form. A client's state is one 16-byte cell (keyed hash, theoretical arrival time). With emission interval :math:`T = \max(1, \lceil W / N \rceil)` and burst tolerance :math:`\tau = (N - 1) T`, an arrival at :math:`t` conforms iff :math:`\mathrm{TAT} \le t + \tau`, after which :math:`\mathrm{TAT} = \max(\mathrm{TAT}, t) + T`. The guarantee is the token-bucket bound: at most :math:`N + \lfloor L / T \rfloor` requests conform in any interval of length :math:`L`, with no fixed-window boundary artefact and no per-request log. Cells live in 16 lock-striped shards of 512 slots with a 16-slot probe window; a cell whose TAT is older than :math:`t - \tau` is drained and reclaimed in place. Defaults are 100 requests per 10 s (``--rate-limit``, ``--rate-window``); a rejection answers ``429`` with ``Retry-After``.

Ban table and incidents
~~~~~~~~~~~~~~~~~~~~~~~

Honeypot hits ban the client address for ``--ban-seconds`` (default 3600) in an open-addressed table with versioned atomic snapshots and retry on concurrent replacement. WAF denials and honeypot hits are handed to the storage layer's incident ring when a data directory is configured (SID 0005).

Product boundary
----------------

Gate provides admission, policy and local flood controls. Shield adds payload inspection. Distributed edge deployment adds replicated policy and reputation to either surface. No vendor feature-parity claim is made; coverage and limitations are defined by the code and tests.

Verification
------------

- Unit tests: each detector on attack and benign inputs; evasion inputs (percent-encoded, comment-obfuscated, double-encoded); the automaton and the sequential scan agree on every signature; a complete Chrome request with ``Accept``, ``Accept-Language``, ``Sec-Ch-Ua``, cookies containing ``--``, and a JSON body containing "I'd select the second option -- it's cheaper" passes untouched; custom headers, query strings, and bodies carrying attacks are caught.
- Rate limiter: exact burst admission and pacing, the :math:`N + L/T` bound across a window boundary, client independence, and reclamation of drained cells under a flood of keys.
- End-to-end: traversal in the path and SQL injection in the query string answer ``403``; the honeypot answers ``403`` and the address is banned for subsequent requests; a burst of 12 requests against a limit of 8 yields exactly 4 ``429`` responses with ``Retry-After``.

Review corrections (2026-09-07)
-------------------------------

A valid session never bypasses inspection or a terminal policy denial. Canonicalisation now uses its caller's buffer in place and covers the full 8 KB inspection prefix; an encoded attack after byte 2048 is a regression case. Inputs beyond the bound remain a documented coverage gap. The signature automaton's capacity is derived from pattern lengths, preserving dense lookups with a smaller footprint. GCRA uses a ceiling-rounded interval and tolerance ``(rate-1)*interval``, so non-divisible windows do not over-admit. Zero rate refuses requests. Hash zero alone is remapped: forcing every hash odd previously wasted half the shards. Saturated probe windows refuse new clients instead of evicting active quota state. Ban readers validate a versioned key/expiry snapshot, retrying concurrent replacements. These synchronization operations have real costs. Current measurements are in the benchmark result files; earlier numeric examples in this record are historical and must not be used as current performance gates.

References
----------

The Typst original has no bibliography. This list collects the records that the text cites.

- SID 0005, Distributed Storage Architecture: Zaxonlite Integration for Dynamic Policies, Replicated Reputation, and Incident Forensics (the incident ring that receives WAF denials and honeypot hits).
- SID 0006, Mathematical Foundations of Sibuna: Sequential Work, Symmetric Authentication, Bounded State, and Linear-Time Inspection (the analysis of SIMD prefiltering).
- SID 0010, the mapping from the Zig packages to the Rust crates of the port.

.. rubric:: Lifecycle event

::

   2026-10-15: prediscussion -> discussion. Ported from the Zig repository's
   Typst record

.. rubric:: Lifecycle event

::

   2026-10-15: discussion -> published. State carried over from the Zig
   repository's registry
