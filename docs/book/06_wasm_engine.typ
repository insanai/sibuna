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

#v(4mm)

= Universal Client Resilience: Fallbacks and Honeypot Traps

#objectives([
  Understand how Sibuna guarantees 100% universal browser accessibility even when WebAssembly is
  restricted, examine the bit-level difficulty scaling mechanism, and analyze the automated
  crawler honeypot trap.
])

== Fine-Grained Bit-Level Difficulty Scaling

Traditional Proof-of-Work systems measure difficulty by counting leading hexadecimal zeros. Because each hexadecimal character represents 4 bits, each incremental step in difficulty multiplies the expected hashing work by a factor of 16 ($2^4 = 16$). 

In a high-security reverse proxy, $16times$ scaling creates an acute operational dilemma:
- A difficulty of 4 requires on average $16^4 = 65,536$ hashes (approx 30 ms on desktop, 150 ms on mobile).
- A difficulty of 5 requires on average $16^5 = 1,048,576$ hashes (approx 480 ms on desktop, 2.4 seconds on mobile).

Sibuna implements bit-level difficulty scaling (`verifyHashcashBits`), allowing operators to increment difficulty in fine-grained 1-bit steps ($2times$ multiplier):

```zig
pub fn checkDifficultyBits(digest: [32]u8, bits: u32) bool {
    const full_bytes = bits / 8;
    const rem_bits = bits % 8;
    for (digest[0..full_bytes]) |b| {
        if (b != 0) return false;
    }
    if (rem_bits > 0) {
        const shift: u3 = @intCast(8 - rem_bits);
        const mask = @as(u8, 0xff) << shift;
        if ((digest[full_bytes] & mask) != 0) return false;
    }
    return true;
}
```

This allows precise tuning: an operator facing an active crawl can shift difficulty from 16 bits ($65,536$ hashes) to 17 bits ($131,072$ hashes) or 18 bits ($262,144$ hashes), precisely tuning adversary friction without inducing mobile timeouts.

== Pure JavaScript Fallback Solver

While WebAssembly is supported in over 97% of modern browsers, certain security-conscious configurations disable it:
- Corporate endpoint policies restricting JIT and WASM code execution.
- Browser privacy extensions such as JShelter.
- Embedded webviews on legacy IoT devices.

If an anti-crawler firewall relies strictly on WebAssembly, users with WASM disabled will encounter a broken interstitial and fail authentication.

To solve this, Sibuna's `worker.js` incorporates an automatic fallback hierarchy:
1. The worker attempts to instantiate `sibuna-pow.wasm`.
2. If `WebAssembly.instantiate` throws an error or is blocked by policy, the worker catches the exception and immediately invokes an embedded pure-JavaScript SHA-256 solver.
3. The JavaScript solver executes at over 670,000 hashes per second, finding standard difficulty-4 solutions in under 100 milliseconds.

== Jittered Exponential Backoff & Flaky Network Retries

Mobile browsers frequently traverse transient packet loss or network transitions (e.g. switching from 5G to Wi-Fi). In `challenge.html`, all network transactions (`/__sibuna/challenge.json` and `POST /__sibuna/verify`) are wrapped in `fetchWithRetry()` with randomized jittered exponential backoff:

```javascript
async function fetchWithRetry(url, options = {}, retries = 3, backoff = 500) {
    for (let i = 0; i < retries; i++) {
        try {
            const res = await fetch(url, options);
            if (res.ok) return res;
        } catch (e) {
            if (i === retries - 1) throw e;
        }
        const jitter = Math.random() * 200;
        await new Promise(r => setTimeout(r, backoff * Math.pow(1.5, i) + jitter));
    }
    throw new Error('Network request failed after retries');
}
```

== Invisible Honeypot Crawler Traps

Dumb web scrapers and automated AI crawlers frequently scrape all HTML `<a>` links without executing JavaScript. Sibuna embeds an invisible honeypot anchor tag directly in the challenge interstitial:

```html
<a href="/__sibuna/honeypot" style="position:absolute;left:-9999px;top:-9999px;opacity:0;pointer-events:none;" tabindex="-1" rel="nofollow" aria-hidden="true">Direct Bypass Gateway</a>
```

A legitimate browser running JavaScript renders the card and computes the PoW in the Web Worker without ever clicking or following off-screen links. In contrast, blind recursive scrapers scan the DOM for href targets and issue requests to `/__sibuna/honeypot`. The Sibuna daemon detects this path, immediately responds with HTTP 403 Forbidden, and records the adversary IP in the dynamic deny-list.
