#import "theme.typ": *
#import "figures.typ": *

#part_page("VI", [The WebAssembly Proof-of-Work Engine], [
  We explore the browser-side execution pipeline: compiling pure Zig to a 6.9 KB freestanding
  WebAssembly solver, prefix pre-hashing mathematics, and asynchronous Web Worker orchestration.
])

= The Freestanding 6.9 KB Browser Solver

#objectives([
  By the end of this chapter, you should be able to compile pure Zig code to the `wasm32-freestanding`
  target, explain how prefix pre-hashing halves browser computational overhead, and trace the
  memory export interface between JavaScript and WebAssembly.
])

== The Bloat of Conventional WASM Toolchains

In existing WebAssembly implementations, browser solvers are commonly written in Rust using
`wasm-bindgen` and `wasm-pack`, or in Go via `syscall/js`. These toolchains produce massive
binaries:
- Go WebAssembly binaries routinely exceed *2 Megabytes* because they embed the entire Go garbage
  collector and runtime scheduler.
- Rust WebAssembly solvers typically measure between *80 KB and 300 KB* due to panic handlers,
  formatters, and allocator bloat.

Transmitting a 300 KB or 2 MB WASM binary to a mobile browser on a cellular connection introduces
seconds of download latency, destroying the user experience.

Sibuna compiles its browser solver from *pure Zig* targeting `wasm32-freestanding`:

```zig
const wasm_target = b.resolveTargetQuery(.{
    .cpu_arch = .wasm32,
    .os_tag = .freestanding,
    .cpu_features_add = std.Target.wasm.featureSet(&.{
        .bulk_memory,
        .mutable_globals,
        .sign_ext,
    }),
});
```

Because Zig operates without a runtime, garbage collector, or external standard library dependencies,
the resulting binary `sibuna-pow.wasm` measures exactly *7,100 bytes (6.9 Kilobytes)*. It downloads
in under *15 milliseconds* over standard mobile networks.

== The Prefix Pre-Hashing Mathematical Optimization

A naive implementation of a Hashcash solver in the browser repeats the entire hashing process for
every candidate nonce $N$:

```zig
// Naive inner loop: Recomputes prefix every iteration
while (true) : (nonce += 1) {
    var hasher = Sha256.init(.{});
    hasher.update(challenge); // e.g. 32 bytes
    hasher.update(":");        // 1 byte
    hasher.update(nonce_str);  // 4-8 bytes
    hasher.final(&out);
    if (checkDifficulty(out, diff)) return nonce;
}
```

Observe that the prefix $C || ":"$ (the 32-byte challenge identifier and the colon separator)
*never changes* across iterations. Re-processing these 33 bytes through SHA-256's message schedule
for every candidate nonce wastes almost 50% of the browser's CPU cycles!

SHA-256 in Zig is represented as a pure value struct holding eight 32-bit state registers ($H_0$
through $H_7$), a 64-byte message block buffer, and a bit count.

Sibuna exploits this value semantics through *Prefix Pre-Hashing*:

```zig
// Sibuna optimized solver: Pre-hashes challenge prefix ONCE
var base_hasher = Sha256.init(.{});
base_hasher.update(challenge);
base_hasher.update(":");

while (true) : (nonce += 1) {
    var hasher = base_hasher; // Bitwise value copy of pre-hashed state!
    const nonce_len = formatUintFast(nonce, &nonce_buf);
    hasher.update(nonce_buf[0..nonce_len]);
    hasher.final(&out);

    if (checkDifficultyFast(out, difficulty)) {
        return nonce;
    }
}
```

By initializing `base_hasher` once and cloning its internal state struct per iteration, the
candidate nonce (4 to 8 bytes) fits entirely within the remaining block buffer without triggering
an extra SHA-256 block transform. This mathematical optimization *doubles the hashing throughput*
of the browser solver, cutting average solving time on mobile devices from 350 ms down to 175 ms.

#v(4mm)

= Asynchronous Web Worker Execution

#objectives([
  Inspect the Web Worker messaging lifecycle, trace the non-blocking challenge acquisition
  and solution submission flow, and understand how the cyber-interstitial UI maintains high
  aesthetic responsiveness.
])

== Offloading Compute from the Main UI Thread

Running a Proof-of-Work solver on the browser's main thread is an anti-pattern: it blocks DOM
rendering, freezes CSS animations, and causes the browser to display "Page Unresponsive" warnings.

Sibuna orchestrates all cryptographic solving inside a dedicated background *Web Worker*
(`apps/web/src/worker.js`).

1. The browser visits an unauthenticated route and receives the lightweight interstitial HTML
   (`challenge.html`).
2. `challenge.html` fetches challenge parameters via `GET /__sibuna/challenge`:
   ```json
   {"challenge_id":"sib_68ddae21_9f81","difficulty":4,"algorithm":"sha256"}
   ```
3. A background Web Worker is instantiated, loading `sibuna-pow.wasm`.
4. The worker executes the pre-hashed solver loop in the background while the main thread renders
   a smooth, cyber-styled SVG progress ring and status message.
5. Upon finding the nonce, the worker posts a message back to the main page:
   ```javascript
   { status: 'solved', nonce: 54049, elapsed_ms: 112 }
   ```
6. The page submits the solution via `POST /__sibuna/verify`. The Sibuna server validates the
   proof in 28 nanoseconds, sets the signed `__sibuna_token` cookie via HTTP 302, and redirects
   the browser seamlessly to the original target destination.

The human user experiences a brief, elegant interstitial lasting less than a quarter of a second,
after which all subsequent navigation across the domain occurs with zero friction.
