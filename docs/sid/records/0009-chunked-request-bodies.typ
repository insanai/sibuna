#let sid-number = "0009"
#let sid-title = "Chunked Request Bodies: Strict In-Place Decoding, Canonical Re-Framing, and Inspection Equivalence"
#let sid-state = "committed"
#let sid-created = "2026-10-02"
#let sid-discussion = "Specifies how the reverse proxy accepts chunked request bodies without a heap allocation or a second buffer: a strict RFC 9112 chunk grammar that rejects every known terminator and extension ambiguity, an in-place decoder whose output never overtakes its input, Content-Length forwarding for bodies that complete within the connection buffer and canonical re-chunking for the rest, and proofs that inspection sees exactly the bytes a Content-Length request would show and that the origin cannot observe the client's framing."
#let sid-labels = ("http", "proxy", "security", "request-smuggling", "performance",)
#let sid-authors = ("Sibuna Contributors <team@sibuna.local>",)
#let sid-category = "Architectural Specification"
#let sid-status = "Committed"
#let sid-last-updated = "2026-10-02"

#import "../../shared/sid.typ": sid-document

#let blue = rgb("0284c7")
#let blue-light = rgb("f0f9ff")
#let green = rgb("16a34a")
#let green-light = rgb("f0fdf4")
#let amber = rgb("d97706")
#let amber-light = rgb("fffbeb")
#let purple = rgb("7c3aed")
#let purple-light = rgb("f5f3ff")

#let stmt-counter = counter("sibuna-statement")
#let statement(kind, title, body, fill: blue-light, stroke: blue) = {
  stmt-counter.step()
  block(
    width: 100%,
    breakable: true,
    inset: 9pt,
    radius: 4pt,
    fill: fill,
    stroke: (left: 2.4pt + stroke),
  )[
    #text(weight: "bold", fill: stroke)[#kind #context stmt-counter.display()]
    #if title != none [ #text(weight: "bold")[(#title).] ]
    #h(4pt)
    #body
  ]
}
#let definition(title, body) = statement("Definition", title, body)
#let lemma(title, body) = statement("Lemma", title, body, fill: green-light, stroke: green)
#let theorem(title, body) = statement("Theorem", title, body, fill: purple-light, stroke: purple)
#let corollary(title, body) = statement("Corollary", title, body, fill: green-light, stroke: green)
#let rule-box(id, body) = block(
  width: 100%, inset: (left: 8pt, y: 3pt), stroke: (left: 2pt + amber),
)[#text(weight: "bold", fill: amber)[#id]#h(6pt)#body]
#let proof(body) = block(width: 100%, breakable: true, inset: (left: 12pt, right: 6pt, y: 5pt))[
  _Proof._ #body #h(1fr) $square$
]

#show: doc => sid-document(
  sid-number,
  sid-title,
  doc,
  authors: sid-authors,
  state: sid-state,
  created: sid-created,
  discussion: sid-discussion,
  labels: sid-labels,
  category: sid-category,
  status: sid-status,
  last-updated: sid-last-updated,
)

= Abstract

Sibuna's reverse proxy answers every request that carries `Transfer-Encoding` with 400. The
request parser returns `UnsupportedTransferEncoding` (`libs/net/src/http.zig`), so a valid
HTTP/1.1 upload of unknown length never reaches the origin. Clients that stream a body produce
exactly such requests: `curl -T -`, Go's `net/http` with an unsized reader, Java's chunked
streaming mode, `fetch` with a stream body, and git, Docker registry and S3-compatible
clients. For a proxy that claims transparency this is a compatibility gap, and forward-auth
mode is not a substitute because the ingress never shows Sibuna the body.

This record specifies the fix. A strict chunk grammar rejects every terminator and extension
ambiguity behind the request-smuggling disclosures of 2024–2025. An in-place decoder turns the
chunked coding back into the body inside the connection's existing 64 KiB buffer, without a
second buffer or a heap allocation. A body that completes within the buffer reaches the origin
with `Content-Length`. A longer body is re-chunked canonically, one chunk per read. The record
proves three properties. Decoding is safe in place. The policy engine and the WAF inspect
exactly the bytes they would inspect for the same body sent with `Content-Length`. The origin
cannot observe the client's chunk sizes, extensions or trailers, so no parser differential
between Sibuna and the origin can exist. Requests without a body, and requests with
`Content-Length`, keep their current code path.

= Introduction

HTTP/1.1 delimits a request body in one of two ways: a `Content-Length`, or the chunked
transfer coding when the sender does not know the length in advance (RFC 9112 §6.1, §7.1).
Every HTTP/1.1 recipient must be able to parse chunked coding (RFC 9112 §7.1). Sibuna does not
parse it today.

The rejection was deliberate. Chunked coding is where request smuggling lives. Watchfire's
original 2005 paper named the CL.TE and TE.CL desynchronisations. Kettle's desync research
(2019, 2021, 2022, 2025) turned them into a methodology. Weikop's "Funky chunks" (2025)
showed that a lone LF or CR in a chunk line, or a chunk extension parsed differently by two
hops, splits one request into two. Those reports led to fixes in Apache Traffic Server
(CVE-2024-53868), aiohttp (CVE-2024-52304), Go `net/http` (CVE-2025-22871), h11
(CVE-2025-43859), ASP.NET Core Kestrel (CVE-2025-55315), Netty and Jetty. Refusing the coding
was safe but incomplete. This record replaces the refusal with a decoder whose safety is
argued, not assumed.

= Terminology and Scope

#table(
  columns: (1fr, 3fr),
  table.header([*Term*], [*Meaning in this record*]),
  [Raw stream $x$], [The bytes the client sends after the request head.],
  [Body $B$], [$"dechunk"(x)$: the concatenated chunk data, as defined by the decoding algorithm of RFC 9112 §7.1.3.],
  [Chunk line], [A chunk-size line (size and optional extensions) or a trailer field line, each terminated by CRLF.],
  [$C$, $H$, $L$, $P$], [Connection buffer capacity (65,536 bytes), length of the request head ($<= 16,384$), maximum chunk line length (4,096), inspected body prefix (`body_fields.max_prefix`, 8,192).],
  [Admission], [Everything before the policy decision: head parse, body prefix, rules and WAF.],
  [Canonical chunked], [Lower-case hexadecimal size without leading zeros, CRLF, data, CRLF; no extensions; terminated by `0` CRLF CRLF with no trailer fields.],
)

*In scope:* request bodies in reverse-proxy mode, and the same admission decoding in
forward-auth mode and for Sibuna's internal endpoints. *Out of scope:* transfer codings other
than `chunked`, compressed content inspection (unchanged: compressed payloads stay opaque),
the response direction (origin chunked responses are already relayed by `relayChunked`), and
HTTP/2.

= Problem Statement

`parseRequest` records whether `Transfer-Encoding` is present and returns an error whenever
it is. The error becomes a 400 "Malformed HTTP request". The surrounding code also assumes
that a body is described by `Content-Length` alone:

- `serveOne` buffers `min(declared, C - H)` body bytes;
- `RequestContext.declared_body` drives keep-alive and the verify endpoint's size check;
- `proxy.writeHead` re-emits `Content-Length` from the request header;
- `proxy.exchange` relays `declared - buffered` further bytes;
- `streamProxy` decides retry safety from the same two numbers.

A correct fix must therefore give the body an explicit framing that every one of these sites
reads, rather than add a special case to one of them.

= Goals and Non-Goals

== Goals

+ Accept every chunked request that RFC 9112 permits, except the ones that rules R1 to R7
  below reject.
+ Reject every input on which two RFC-adjacent parsers are known to disagree: lone CR or LF,
  malformed extensions, whitespace around sizes, size overflow, and malformed trailers.
+ Ensure the policy engine and the WAF cannot be evaded by splitting a payload across chunks.
+ Keep the request path free of heap allocation and of a second per-connection buffer.
+ Leave requests without a body, and `Content-Length` requests, on their current code path.
+ Bound decoding work and memory per connection, and keep the existing slow-body defence.

== Non-Goals

- Spooling bodies to disk to give every upload a `Content-Length` (nginx's
  `proxy_request_buffering`). Sibuna has no disk on the request path.
- Forwarding request trailers. RFC 9110 §6.5.1 lets a recipient that removes the chunked
  coding discard them. Discarding also keeps uninspected fields away from the origin.
- Stricter validation of origin responses, which would risk breaking existing origins.

= State of the Art

#table(
  columns: (1fr, 2.6fr),
  table.header([*System*], [*Request-body behaviour*]),
  [nginx], [Decodes chunked input. With `proxy_request_buffering on` (the default) it spools the whole body to memory or disk and forwards `Content-Length`; with it off, it re-chunks to an HTTP/1.1 upstream.],
  [HAProxy], [Parses and normalises chunked coding. `option http-buffer-request` waits for the body up to one buffer before the request is processed, so ACLs see a decoded prefix.],
  [Envoy, Pingora], [Decode in the codec and re-encode for the upstream. The upstream framing is generated, never copied.],
  [ModSecurity, Coraza], [Inspect the de-chunked body up to `SecRequestBodyLimit`, either rejecting or processing partially beyond it. Rules that inspect raw chunked bytes are a well-known evasion path.],
  [Hardened parsers after the 2025 disclosures], [Accept CRLF only, reject lone CR/LF anywhere in a chunk line, parse extensions strictly (including quoted strings), bound line length and size digits.],
)

The common lesson is that a proxy must *re-frame*: it decodes with a strict parser and emits
framing it generated itself. A proxy that copies the client's framing verbatim lets the
origin's parser make a second, possibly different, decision. Sibuna combines HAProxy's bounded
buffering of the prefix that admission needs, nginx's `Content-Length` hand-off when the body
is complete, and Envoy's generated upstream framing. It does this inside the buffer that
already holds the request head.

= Protocol Rules

#rule-box("R1")[`Transfer-Encoding` is accepted only in an HTTP/1.1 request, in exactly one
field line whose value, trimmed of optional whitespace, is `chunked` (case-insensitive).]
#rule-box("R2")[A request with both `Transfer-Encoding` and `Content-Length` is answered 400 and
the connection closed. RFC 9112 §6.3 permits this, and the parser already does it.]
#rule-box("R3")[A coding list whose final coding is not `chunked` is answered 400 and closed
(RFC 9112 §6.3, a MUST). A list that ends in `chunked` after another coding, such as
`gzip, chunked`, is answered 501 and closed (RFC 9112 §6.1, a SHOULD). The latter would need
decompression before inspection. More than one `Transfer-Encoding` line is answered 400.]
#rule-box("R4")[An HTTP/1.0 request with `Transfer-Encoding` is answered 400 and closed: RFC 9112
§6.1 requires faulty-framing handling for it.]
#rule-box("R5")[A chunk line ends at its first LF. The byte before that LF must be CR. No other
byte of the line may be CR, LF, or any control byte except HTAB. The line, including CRLF,
may be at most $L = 4096$ bytes. A size is 1 to 16 hexadecimal digits with no sign, prefix
or surrounding whitespace. Extensions follow the RFC 9112 §7.1.1 grammar exactly: optional
whitespace, `;`, a token name, and optionally `=` with a token or a quoted string whose
quoted pairs escape only visible characters, space or HTAB.]
#rule-box("R6")[Chunk data must be followed by exactly CRLF.]
#rule-box("R7")[Trailer field lines must satisfy the header grammar (token name, no whitespace
before the colon, no control bytes in the value). The trailer section may total at most
16 KiB. Trailers are discarded.]
#rule-box("R8")[A body that completes within the connection buffer is forwarded with
`Content-Length: |B|`. Otherwise the decoded prefix and every later read are forwarded as
canonical chunks.]
#rule-box("R9")[A framing error found after forwarding began aborts the origin exchange without
the terminal chunk. The origin sees a truncated body, never a complete altered one. The client
receives 400 and the connection is closed.]
#rule-box("R10")[An upgrade request with a body coding is refused, as one with a non-zero
length already is. `Expect: 100-continue` is answered for chunked requests. The client
connection is reused after a local response only when the body was fully consumed.]

= Detailed Design

== The decoder

`libs/net/src/chunked.zig` defines a decoder state machine:

```zig
pub const Decoder = struct {
    state: enum { size, data, data_end, trailer, done } = .size,
    remaining: u64 = 0,     // data bytes left in the current chunk
    trailer_bytes: u32 = 0, // bytes of trailer section consumed so far
    pub fn decode(self: *Decoder, bytes: []u8) Error!Step   // Step{ output, consumed }
};
```

`decode` reads `bytes` from index $r$ and writes decoded data back into the same slice at index
$w$. It returns the output length $w$ and the consumed length $r$. It consumes only complete
syntactic units: a whole line, a run of data bytes, or the two bytes after data. It stops when
the next unit is incomplete. The caller keeps the unconsumed tail and calls again after the
next read.

#definition("Configuration")[A decoder configuration is a pair $(s, k)$: a state
$s in {"size", "data", "data_end", "trailer", "done"}$ and the count $k$ of data bytes
remaining when $s = "data"$. One call maps a configuration and a byte string $b$ to a new
configuration, an output length $w$, and a consumed length $r$, with $w <= r <= |b|$.]

#lemma("In-place safety")[Throughout a call, the write index never exceeds the read index:
$w <= r$. Each data byte moves from $b[r]$ to $b[w]$ with $w <= r$, so a forward copy never
overwrites a byte that has not yet been read.]
#proof[Both indices start at 0. A line or the CRLF after data advances $r$ alone. A run of
$n$ data bytes copies $b[r .. r+n]$ to $b[w .. w+n]$ and advances both indices by $n$. Each
step preserves $w <= r$, and the base case satisfies it. `std.mem.copyForwards` is correct
for overlapping ranges whenever the destination does not start after the source.]

#lemma("Progress")[If the unconsumed tail is at least $L$ bytes long and the state is not
`done`, a call consumes at least one byte or returns an error.]
#proof[In `data`, any available byte is consumed. In `data_end`, two available bytes are
either CRLF and consumed, or rejected. In `size` and `trailer`, the decoder looks for an LF
within the first $L$ bytes. If it finds one, it consumes the line or rejects it. If it does
not, the line exceeds $L$ and R5 rejects it.]

#theorem("Partition invariance")[Let $x = x_1 x_2 dots x_m$ be any split of the raw stream
into the bytes delivered by successive reads, with each call's unconsumed tail prefixed to
the next delivery. The concatenated outputs equal $"dechunk"(x)$ exactly when $x$ satisfies
R5 to R7. Otherwise some call returns an error, and no output past the faulty unit is
produced. The verdict and the output do not depend on the split.]
#proof[By induction on consumed units. The decoder consumes a unit only when all of its
bytes are present, and whether a unit is accepted depends only on those bytes and on the
configuration. The configuration after a unit depends only on the configuration before it
and on the unit. A split changes when a unit becomes complete, but not its bytes, so the
sequence of units, configurations and outputs is the same for every split. A data run may be
cut by a split, but it is consumed byte for byte, and $k$ records exactly the bytes still
owed. This matches the RFC 9112 §7.1.3 algorithm, which is defined on whole units.]

The theorem is what the property test checks. Random valid and invalid streams are decoded
with random split points, and every split must produce the same output and verdict as a
single call.

== Admission: decoding into the head buffer

The connection reader holds the head in its first $H$ bytes. Admission calls `decode` on
everything after the head and the body decoded so far. It then *excises* the consumed framing
by moving the unconsumed tail down to the end of the output, which shortens the reader's
buffered region. Finally it reads more, unless the body is complete or the buffer is full.
The head is never moved by excision. A reader rebase moves the head and body together, so
positions are kept relative to the reader's seek and the head is re-parsed after the loop, as
the `Content-Length` path already does.

#lemma("Prefix bound")[When admission stops, the decoded prefix is either the whole body $B$,
or longer than $C - H - L$ bytes.]
#proof[Admission stops on `done` or when the buffered region fills the buffer. When it is
full, the region holds $H$ head bytes, $d$ decoded bytes, and an unconsumed tail $t$. Every
call consumes all complete units, so the tail is an incomplete line, with $t < L$ by
Lemma 3, or at most one byte of a pending CRLF. Therefore $d = C - H - t > C - H - L$.]

#theorem("Inspection equivalence")[The policy engine and the WAF see the first
$min(|B|, P)$ bytes of $B$, the same bytes they see when $B$ is sent with `Content-Length`.
Splitting a payload across chunks therefore cannot change a verdict.]
#proof[The WAF inspects `body[0 .. min(len, P)]` (`body_fields.Fields.init`). By Lemma 5 the
decoded prefix is $B$, or longer than $C - H - L = 65,536 - 16,384 - 4,096 = 45,056 > P$.
Both cases contain $B[0 .. min(|B|, P)]$. Theorem 4 makes that prefix independent of chunk
sizes and arrival timing. Rules other than the WAF see the head, which is unchanged.]

Admission waits for the body to complete or the buffer to fill. A `Content-Length` request
waits for $min("declared", C - H)$ bytes, so this is the same bound, and it is HAProxy's
`http-buffer-request` behaviour. The existing head deadline applies unchanged.

== Forwarding

The proxy's request body becomes an explicit union read by `writeHead`, `exchange` and
`streamProxy`:

```zig
pub const Upload = union(enum) {
    none,                       // no body framing; nothing follows the head
    length: u64,                // Content-Length; `length - body.len` bytes still follow
    chunked: *chunked.Decoder,  // the rest is chunked: decode in place, re-chunk per read
};
```

A complete chunked body becomes `.length = |B|`. From there it takes exactly the
`Content-Length` path, including the retry rule for safe methods with a fully buffered
body. An incomplete one becomes `.chunked`. Its head carries `Transfer-Encoding: chunked`;
its decoded prefix is sent as the first chunk; then each read is decoded in place and sent
as one chunk. The terminal `0` CRLF CRLF is written only once the decoder reaches `done`.

#corollary("Origin framing independence")[The bytes the origin receives depend only on $B$ and
on how Sibuna's reads segment the stream. They do not depend on the client's chunk sizes,
extensions, trailers or letter case. Every message is either `Content-Length` framed or
canonical chunked.]

Canonical chunked is a subset of every grammar that strict and lenient parsers accept. A
parser differential between Sibuna and the origin would need two parsers that disagree on
some input. The origin only ever receives that subset, so the TE.TE, lone-terminator and
extension classes cannot occur behind Sibuna.

== Cost

#lemma("Linear work, constant memory")[Admission moves each body byte at most once (Lemma 2)
plus an unconsumed tail shorter than $L$ per read, and moves any pipelined bytes once when
the body completes. Streaming touches each byte once in place and adds at most 20 framing
bytes per origin chunk (16 hexadecimal digits and two CRLFs). The decoder state is 24 bytes
on the stack. Neither phase allocates.]

The `Content-Length` and body-less paths gain one branch each in `serveOne` and in
`exchange`. Chunked uploads pay one in-L1 `memmove` per byte, which is cheap next to the
socket read that delivered the byte, plus a chunk-size line per read. Streaming keeps the
relay discipline of `proxy.step`: forward what is buffered, flush the origin before waiting,
read once. The slow-body defence counts raw bytes received, so a chunked upload must sustain
the same 16 KiB per idle period as a `Content-Length` upload.

= Verification and Testing

#table(
  columns: (1.3fr, 2.7fr),
  table.header([*Test*], [*Acceptance*]),
  [`chunked.zig` rejection table], [Every R5–R7 violation is rejected, including the "Funky chunks" terminator and extension vectors, a lone CR inside a quoted string, 17-digit and signed sizes, whitespace before CRLF, and trailers with whitespace before the colon or above 16 KiB.],
  [`chunked.zig` partition property], [Random streams decoded with random split points produce the same output and verdict as a single call (Theorem 4), including streams with extensions and trailers.],
  [`http.zig` framing rules], [R1–R4: one exact `chunked` field accepted; duplicate fields, `chunked, gzip`, HTTP/1.0 with a coding and TE with CL rejected with the specified errors.],
  [Daemon end-to-end], [A small chunked POST pipelined with a GET reaches the origin with `Content-Length` and the GET is answered on the same connection; a 256 KiB body in irregular chunks reaches the origin as chunked with an identical digest; an SQL-injection payload split across chunks is denied; a malformed chunk is answered 400 and the origin never sees the request.],
)

= Security Considerations

- *Smuggling.* R1–R7 reject every chunked input that two HTTP/1.1 parsers are known to
  disagree on. Corollary 7 removes the second parser's decision altogether. Rule R9 ensures
  that an attacker who breaks framing mid-stream leaves the origin with a truncated body.
- *Evasion.* Theorem 6 means chunk boundaries are invisible to inspection.
- *Resource use.* Lines are bounded by $L$ and trailers by 16 KiB. Sizes are bounded by
  16 digits and counted in a `u64`. The minimum upload rate is unchanged. A client that sends
  one data byte per chunk pays six framing bytes per decoded byte. Sibuna's work per byte
  stays constant, and no state grows with the client's chunk count.
- *Trailers.* They are discarded, so fields the head inspection never saw cannot reach the
  origin.

= Rollout and Operational Plan

No configuration is added. Operators who sent `Content-Length` because chunked uploads were
refused need not change anything. The book's operations chapter, the README and SID 0002
drop the "chunked request bodies are rejected" limitation and state that trailers are
discarded and other transfer codings receive 501. Origins that cannot parse chunked requests
(HTTP/1.0-era servers) still receive `Content-Length` for any body under about 44 KiB.
Larger streamed bodies require an HTTP/1.1 origin, which RFC 9112 §7.1 already requires.

= Implementation Record (2026-10-02)

The design landed without changes to the rules. The decoder is `libs/net/src/chunked.zig`
(`Decoder.decode`, line limit 4,096, trailer limit 16 KiB, at most 16 size digits). The parser
rules R1–R4 are in `net.http.parseRequest`, which sets `Request.chunked` and distinguishes
`InvalidTransferEncoding` (400) from `UnsupportedTransferEncoding` (501). Admission decoding
is `bufferChunked` in `apps/sibuna/src/server.zig`. It cuts each call's framing out of the
reader's window by moving the tail down and shortening `end`. Forwarding uses
`net.proxy.Upload` (`none`, `length`, `chunked`), which `writeHead`, `exchange` and
`streamProxy` all read; `relayChunkedBody` re-chunks per read, flushes before it waits, and
writes the terminal chunk only at `done`. A body that continues past the buffer records no
declared length in incident evidence: the evidence carries the decoded bytes seen, flagged
incomplete.

*Verification.* Unit tests cover the grammar (six accepted forms, 24 rejected vectors and the
trailer bound), the partition property (3,000 random streams, half of them mutated, each
decoded whole and in random pieces), and R1–R4. Three daemon end-to-end tests check:

- a pipelined small upload that reaches the origin with `Content-Length`, followed by a GET
  on the same connection;
- a 256 KiB upload in irregular chunks with extensions that reaches the origin as canonical
  chunks with an identical digest;
- an injection payload split across chunks, which is denied;
- a lone LF, `gzip, chunked`, HTTP/1.0 with a coding, and a malformed chunk after 80 KiB had
  already streamed, each answered as R3–R9 require.

The origin stub in those tests parses only canonical framing, so any client framing leaking
through fails the test. `zig build test` passed on Linux (paxos-zig).

*Performance.* These measurements were taken on paxos-zig, 2026-10-02, on loopback, with the
product pinned to four CPUs. On the reverse-proxy GET path, the build with this change and the
build before it were indistinguishable under the tools-comparison load: medians of 59.0k and
59.2k requests per second over five interleaved rounds. Uploads of 256 MiB reached 2.0–2.4 GiB/s
chunked and 1.7–2.9 GiB/s with `Content-Length`. Both figures are bound by the Python origin
that drains them, so they show that chunked uploads stream at the same order as sized ones.
They do not measure the decoder.

= References

+ R. Fielding, M. Nottingham, J. Reschke. RFC 9112, _HTTP/1.1_, §6 (message body), §7.1 (chunked transfer coding), §11.2 (request smuggling). IETF, 2022.
+ R. Fielding, M. Nottingham, J. Reschke. RFC 9110, _HTTP Semantics_, §6.5 (trailer fields). IETF, 2022.
+ C. Linhart, A. Klein, R. Heled, S. Orrin. _HTTP Request Smuggling_. Watchfire, 2005.
+ J. Kettle. _HTTP Desync Attacks: Request Smuggling Reborn_. Black Hat USA, 2019.
+ J. Kettle. _HTTP/1.1 Must Die: The Desync Endgame_. Black Hat USA and DEF CON 33, 2025. https://portswigger.net/research/http1-must-die
+ J. B. Weikop. _Funky chunks: abusing ambiguous chunk line terminators for request smuggling_, 2025. https://w4ke.info/2025/06/18/funky-chunks.html; follow-up on chunk extensions, https://w4ke.info/2025/10/29/funky-chunks-2.html
+ GitHub advisories GHSA-vqfr-h8mv-ghfj (h11, CVE-2025-43859), GHSA-fghv-69vj-qj49 (Netty chunk extensions), GHSA-355h-qmc2-wpwf (Jetty quoted-string extensions); Microsoft CVE-2025-55315 (Kestrel chunk extensions).
+ HAProxy configuration manual, `option http-buffer-request`; nginx `proxy_request_buffering`; OWASP Coraza `SecRequestBodyLimit`.
