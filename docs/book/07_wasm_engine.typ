#import "theme.typ": *
#import "figures.typ": *

#part_page("VII", [The Browser Proof-of-Work Engine], [
  We look at the 8,831-byte WebAssembly module that shares its source with the server's
  verifiers, the Web Worker protocol, the JavaScript fallback provers, and the interstitial.
])

= One Source, Two Targets

#objectives([
  By the end of this chapter, you should be able to explain how the browser module is built
  from the server's own `pow.zig` and `posw.zig`, name the exported functions, and describe the
  memory the sequential-work prover needs in a tab.
])

== Build Wiring

The browser solver imports the exact files the server verifies with. `build.zig` creates
`wasm32-freestanding` modules from `libs/crypto/src/pow.zig` and `libs/crypto/src/posw.zig` and
hands them to the solver entry point:

```zig
const wasm_pow = b.addExecutable(.{
    .name = "sibuna-pow",
    .root_module = b.createModule(.{
        .root_source_file = b.path("apps/wasm-pow/src/entry.zig"),
        .target = wasm_target,
        .optimize = .ReleaseSmall,
        .imports = &.{
            .{ .name = "pow", .module = wasm_pow_mod },
            .{ .name = "posw", .module = wasm_posw_mod },
        },
    }),
});
```

There is no second implementation to drift. The module measures 8,831 bytes with both tiers
and is served from the daemon with a one-hour cache header.

== Exports

#table(
  columns: (1.6fr, 2.4fr),
  table.header([*Export*], [*Purpose*]),
  [`sibuna_get_buffer_ptr()` / `_len()`], [256-byte input buffer the worker writes the challenge string into],
  [`sibuna_solve_step(ptr, len, bits, start, max_steps)`], [Hashcash: search `max_steps` nonces from `start`; returns the nonce or the all-ones sentinel],
  [`sibuna_posw_solve(len, depth, challenges)`], [Sequential work: runs the prover over the buffer and returns the proof length],
  [`sibuna_posw_proof_ptr()`], [Start of the proof bytes in the prover workspace],
)

The prover's workspace, the retained top levels, the sibling stack, and the proof, is a static
90 KB region; no allocator is linked.

== Prefix Pre-Hashing

The Hashcash inner loop absorbs the challenge and the colon once and copies the SHA-256 state
per nonce, so each candidate costs one compression rather than two:

```zig
var base_hasher = Sha256.init(.{});
base_hasher.update(challenge);
base_hasher.update(":");
while (step < max_steps) : (step += 1) {
    var hasher = base_hasher;            // value copy of the absorbed prefix
    hasher.update(nonce_buf[0..nonce_len]);
    hasher.final(&digest);
    if (pow.checkDifficultyBits(digest, difficulty_bits)) return nonce;
    nonce += 1;
}
```

The sequential-work prover uses the same trick with the statement $chi$ absorbed once in
`baseHasher`.

= The Worker Protocol

#objectives([
  Read the message protocol, understand the fallback hierarchy, and see the sentinel bug that
  the signed-integer boundary between WebAssembly and JavaScript caused.
])

The page posts one message and receives progress, fallback, and result messages:

```javascript
// page -> worker
{ challenge: spec.id, algorithm: spec.algorithm, difficulty: spec.difficulty, challenges: spec.challenges }

// worker -> page
{ type: 'progress', iterations: 40000 }
{ type: 'fallback', message: 'Wasm unavailable; running JS prover' }
{ type: 'solved', challenge: spec.id, solution: { nonce: '90766' } }       // hashcash
{ type: 'solved', challenge: spec.id, solution: { proof: '<base64url>' } }  // posw
{ type: 'error', message: '...' }
```

The worker tries WebAssembly first and falls back to pure JavaScript when `WebAssembly` is
absent, blocked by policy, or fails to instantiate. The JavaScript provers are line-for-line
ports of the Zig code and produce *byte-identical* output: a Node.js harness compares the two
paths for both tiers. They are slower, about 60 times for the sequential prover, but they
guarantee that every browser can pass.

#warning([The signed sentinel], [
  WebAssembly returns a 64-bit integer to JavaScript as a *signed* `BigInt`. The Hashcash
  export signals "batch exhausted" with all ones, which JavaScript sees as `-1n`, not
  `18446744073709551615n`. The original worker compared against the unsigned value, so the loop
  exited after the first batch with a bogus nonce. The fix is one call:
  `BigInt.asUintN(64, result)`. The lesson generalises: every u64 crossing the boundary must be
  normalised.
])

= Calibration

#objectives([
  Relate difficulty settings to wall-clock time in a browser engine and on native silicon.
])

Measured under V8 (the engine of Chrome and Node.js) on an Apple M1, with the shipped module:

#table(
  columns: (1.2fr, 1fr, 1fr, 1fr),
  table.header([*Work bits*], [*Hashcash (WASM)*], [*PoSW depth*], [*PoSW (WASM)*]),
  [15], [$approx 10$ ms], [12], [17.8 ms],
  [16], [$approx 20$ ms], [13], [15.4 ms],
  [17], [$approx 40$ ms], [14], [32.0 ms],
  [18], [$approx 80$ ms], [15], [66.4 ms],
  [19], [$approx 160$ ms], [16], [137.9 ms],
  [20], [$approx 320$ ms], [17], [285.1 ms],
)

Hashcash costs about 0.3 µs per hash in WebAssembly; the sequential prover at depth $n$
costs about $2^(n+3)$ compressions, which is why depth is work bits minus three. The default of
16 work bits is a 15–20 ms interstitial on a laptop and a few hundred milliseconds on a
low-end phone; an operator under attack raises it, or lets the adaptive controller do so.

= The Interstitial

The page is a single embedded HTML file with a card, an indeterminate progress bar, and a
status line. It requests the challenge for its own location (`?path=`), spawns the worker,
posts the solution with `fetch`, and reloads on success; `fetch` calls retry with jittered
exponential backoff, and a `4xx` verification answer is shown with its diagnostic title. An
off-screen honeypot link (`/__sibuna/honeypot`) is invisible to people and to script-running
browsers; blind crawlers that follow every `href` ban themselves.

#exercise([7.1], [
  The JavaScript sequential prover is about 60 times slower than WebAssembly. Estimate the
  fallback solve time at the default difficulty and propose a policy for clients that report
  the fallback (hint: the worker posts a `fallback` message the page can forward).
])

#teach_back([
  Explain why compiling the browser module from the server's verifier sources is a stronger
  guarantee than testing two implementations against each other.
])
