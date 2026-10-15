Part VII: The Browser Proof-of-Work Engine
==========================================

We look at the WebAssembly module that compiles the server's own verifier crate, the Web Worker protocol, the JavaScript fallback provers, and the interstitial.

One Source, Two Targets
-----------------------

.. admonition:: Objectives

   By the end of this chapter, we should be able to explain how the browser module is built from the server's own ``sibuna-pow`` crate, name the exported functions, and describe the memory the sequential-work prover needs in a tab.

Build Wiring
~~~~~~~~~~~~

The browser solver compiles the exact sources the server verifies with. ``cmd/sibuna-pow-wasm`` is a ``no_std`` library crate of type ``cdylib``, built for ``wasm32-unknown-unknown``, whose only dependencies are the workspace crates ``sibuna-pow`` and ``sibuna-crypto``:

.. code-block:: toml

   # cmd/sibuna-pow-wasm/Cargo.toml
   [lib]
   crate-type = ["cdylib", "rlib"]

   [dependencies]
   sibuna-crypto = { workspace = true }
   sibuna-pow = { workspace = true }

   # Cargo.toml (workspace root): the module is built for size
   [profile.release.package.sibuna-pow-wasm]
   opt-level = "z"
   debug = false
   strip = true

The daemon embeds the module. Its build script (``cmd/sibuna/build.rs``) runs a nested ``cargo build -p sibuna-pow-wasm --target wasm32-unknown-unknown --release`` with a target directory of its own, so it never waits on the lock of the outer build, checks that the result starts with the WebAssembly magic bytes, and copies it to the build output directory. ``SIBUNA_POW_WASM=<path>`` embeds a prebuilt module instead, for builds without the WebAssembly target. The daemon then includes the bytes in its binary:

.. code-block:: rust

   /// The browser solver, built by `build.rs` from `cmd/sibuna-pow-wasm`.
   pub const WASM_SOLVER: &[u8] =
       include_bytes!(concat!(env!("OUT_DIR"), "/sibuna-pow.wasm"));
   /// The solver's Web Worker.
   pub const WORKER_JS: &str = include_str!("../../../web/worker.js");

There is no second implementation to drift. The module is served from the daemon at ``/__sibuna/wasm/sibuna-pow.wasm`` with a one-hour cache header (``Cache-Control: public, max-age=3600``). The Zig module measured 8,831 bytes with both tiers (measured on the Zig implementation, September 2026). The Rust module, built with the profile above, measures 15,181 bytes with both tiers (measured on the Rust implementation, October 2026).

Exports
~~~~~~~

The module exports the same functions, with the same signatures, as the Zig module, so the worker script needed no change:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Export
     - Purpose
   * - ``sibuna_get_buffer_ptr()`` / ``sibuna_get_buffer_len()``
     - 256-byte input buffer the worker writes the challenge string into
   * - ``sibuna_solve_step(ptr, len, bits, start, max_steps)``
     - Hashcash: search ``max_steps`` nonces from ``start``; returns the nonce or the all-ones sentinel
   * - ``sibuna_solve_sha256(ptr, len, bits)``
     - Hashcash in one batch from nonce 0 (``sibuna_solve_step`` with ``u32::MAX`` steps)
   * - ``sibuna_posw_solve(len, depth, challenges)``
     - Sequential work: runs the prover over the buffer and returns the proof length, or 0 for invalid arguments
   * - ``sibuna_posw_proof_ptr()``
     - Start of the proof bytes in the prover workspace

The prover's workspace, the retained top levels, the sibling stack, and the proof, is a static region of about 92 KiB; no allocator is linked, and the module has no imports. ``Workspace::new`` is a ``const fn``, so the static costs only zeroed memory, not initialised data in the module.

.. admonition:: Implementation: ``sibuna_solve_step``

   The Hashcash export: borrows the challenge from linear memory and runs one batch of the shared nonce search. In ``cmd/sibuna-pow-wasm/src/lib.rs`` (crate ``sibuna-pow-wasm``).

.. code-block:: rust

   #[unsafe(no_mangle)]
   pub unsafe extern "C" fn sibuna_solve_step(
       challenge_ptr: *const u8,
       challenge_len: usize,
       difficulty_bits: u32,
       start_nonce: u64,
       max_steps: u32,
   ) -> u64 {
       let challenge: &[u8] = if challenge_len == 0 {
           &[]
       } else {
           // SAFETY: the caller guarantees `challenge_len` readable bytes at
           // `challenge_ptr` that stay unchanged for the duration of the call.
           unsafe { core::slice::from_raw_parts(challenge_ptr, challenge_len) }
       };
       Search::new(challenge)
           .find(difficulty_bits, start_nonce, u64::from(max_steps))
           .unwrap_or(EXHAUSTED)
   }

The exports are the crate's foreign function boundary, and the only place its ``unsafe`` code lives. The input buffer and the prover workspace are statics in an ``ExportCell``, a wrapper around ``UnsafeCell`` that is declared ``Sync`` with a stated reason: a WebAssembly instance without shared memory runs one thread, and each export creates its references, uses them and drops them before it returns, so at most one reference into a cell is ever live. On the host, where the tests call the exports directly, a test-only mutex serialises them. A panic traps (the ``unreachable`` instruction) instead of formatting a message, which keeps the module free of formatting code and imports; panics are unreachable by construction, because the functions of ``sibuna-pow`` are total and never panic.

Prefix Pre-Hashing
~~~~~~~~~~~~~~~~~~

The Hashcash inner loop absorbs the challenge and the colon once and clones the SHA-256 state per nonce, so each candidate costs one compression rather than two. The search is ``sibuna_pow::hashcash::Search``, shared by the browser module and the native reference solver:

.. code-block:: rust

   pub fn new(challenge: &[u8]) -> Self {
       let mut prefix = Sha256::new();
       prefix.update(challenge);
       prefix.update(b":");
       Self { prefix }
   }

   pub fn digest(&self, nonce: u64) -> Digest {
       let mut buf = [0u8; NONCE_DIGITS_MAX];
       let mut hasher = self.prefix.clone(); // value copy of the absorbed prefix
       hasher.update(format_decimal(nonce, &mut buf));
       hasher.finalize()
   }

   pub fn find(&self, bits: u32, start: u64, steps: u64) -> Option<u64> {
       let mut nonce = start;
       for _ in 0..steps {
           if meets_bits(&self.digest(nonce), bits) {
               return Some(nonce);
           }
           nonce = nonce.wrapping_add(1);
       }
       None
   }

The hasher state is a plain value of about 110 bytes, so the clone is cheap. The sequential-work prover uses the same trick with the statement :math:`\chi` absorbed once in ``base_hasher`` and cloned for every node, and the verifier now does too: it derives each challenged leaf from a state that has absorbed the statement once, which makes verification :math:`t` compressions cheaper with the same digests.

On the server the compression function uses the x86-64 SHA extensions or the ARMv8 SHA-2 instructions, detected at run time. In the browser there are no such instructions, and the solver spends nearly all its time in the portable compression function (``crates/crypto/src/sha256/portable.rs``). That function is written for WebAssembly: the 64 rounds are unrolled, the message schedule lives in a 16-word window in which each round from 16 on overwrites the word it no longer needs, and the eight working variables are renamed from round to round instead of being shifted:

.. code-block:: rust

   fn compress_block(state: &mut State, block: &Block) {
       let mut w = [0u32; 16];
       for (word, bytes) in w.iter_mut().zip(block.as_chunks::<4>().0) {
           *word = u32::from_be_bytes(*bytes);
       }
       let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
       eight_rounds!(w, 0, a, b, c, d, e, f, g, h);
       eight_rounds!(w, 8, a, b, c, d, e, f, g, h);
       // ... rounds 16 to 55
       eight_rounds!(w, 56, a, b, c, d, e, f, g, h);
       for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
           *word = word.wrapping_add(value);
       }
   }

   /// Returns the schedule word W(i), computing it in place for rounds 16 and later.
   #[inline(always)]
   fn schedule(w: &mut [u32; 16], i: usize) -> u32 {
       if i >= 16 {
           let w15 = w[(i + 1) % 16];
           let w2 = w[(i + 14) % 16];
           let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
           let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
           w[i % 16] = w[i % 16]
               .wrapping_add(s0)
               .wrapping_add(w[(i + 9) % 16])
               .wrapping_add(s1);
       }
       w[i % 16]
   }

Each ``eight_rounds!`` is one full turn of the variable names: the macro passes them rotated by one position per round, so a round writes only two of them and never moves the other six. With a literal round index every schedule position is a constant, and the whole block becomes straight-line code whose values stay in WebAssembly locals. This layout runs about 20% faster in V8 than a 64-word schedule with a rolled loop, and about 14% faster natively (measured on the Rust implementation, October 2026).

The Worker Protocol
-------------------

.. admonition:: Objectives

   Read the message protocol, understand the fallback hierarchy, and see the sentinel bug that the signed-integer boundary between WebAssembly and JavaScript caused.

The page posts one message to ``web/worker.js`` and receives progress, fallback, and result messages:

.. code-block:: javascript

   // page -> worker
   { challenge: spec.id, algorithm: spec.algorithm, difficulty: spec.difficulty,
       challenges: spec.challenges }

   // worker -> page
   { type: 'progress', iterations: 40000 }
   { type: 'fallback', message: 'Wasm unavailable; running JS prover' }
   { type: 'solved', challenge: spec.id, solution: { nonce: '90766' } }  // hashcash
   { type: 'solved', challenge: spec.id, solution: { proof: '<base64url>' } } // posw
   { type: 'error', message: '...' }

The worker tries WebAssembly first and falls back to pure JavaScript when ``WebAssembly`` is absent, blocked by policy, or fails to instantiate. The JavaScript provers mirror the Rust prover of ``sibuna-pow`` label for label and produce *byte-identical* output; in the Zig repository a Node.js harness compared the two paths for both tiers, and the Rust tests pin nonces and proofs generated by the Zig implementation, so the agreement carries over to the port. SID 0010 makes the browser check part of the port's acceptance: the solver must pass in a headless browser with WebAssembly and with the JavaScript fallback. The JavaScript provers are slower, about 60 times for the sequential prover (measured on the Zig implementation, September 2026), but they guarantee that every browser can pass.

.. admonition:: The signed sentinel
   :class: warning

   WebAssembly returns a 64-bit integer to JavaScript as a *signed* ``BigInt``. The Hashcash export signals "batch exhausted" with all ones (``EXHAUSTED``, ``u64::MAX``), which JavaScript sees as ``-1n``, not ``18446744073709551615n``. The original worker compared against the unsigned value, so the loop exited after the first batch with a bogus nonce. The fix is one call, ``BigInt.asUintN(64, result)``, and the worker keeps it:

   .. code-block:: javascript

      // WebAssembly i64 results arrive as signed BigInts, so the u64
      // "exhausted" sentinel (all ones) reads back as -1n.
      const found = BigInt.asUintN(64,
          ex.sibuna_solve_step(ptr, encoded.length, bits, nonce, maxSteps));
      if (found !== 18446744073709551615n) return found.toString();

   The lesson generalises: every u64 crossing the boundary must be normalised. Rust cannot enforce this on the JavaScript side; the export's type says ``u64``, and the conversion happens in the engine.

Calibration
-----------

.. admonition:: Objectives

   Relate difficulty settings to wall-clock time in a browser engine and on native silicon.

Do not choose a difficulty from one laptop's average solve. Hashcash has a geometric tail; browser clocks include scheduling, thermal state, startup and compilation. A deployment calibration should record the browser version, device, algorithm, parameters, and a distribution of repeated solves. Keep module fetch and compilation separate from steady-state hashing.

.. admonition:: Worked calibration plan

   Hold :math:`b` fixed, warm the module, and solve at least 100 independently issued puzzles on each target device class. Record median and high-percentile durations, failures and proof sizes. Repeat at :math:`b+1`. Expected trial count doubles; an individual sample need not. Choose a setting against the slow-device budget, then test the complete fetch, solve and verify flow.

The repository's native primitive measurements are not evidence for a promised phone or browser solve time. A WASM module can run the same arithmetic while having different startup, execution, and memory costs: natively the server hashes with SHA-NI, while the browser runs the portable compression function above. The worker's messages form the boundary at which those costs can be measured without adding a timer to the server's request handler.

The Interstitial
----------------

The page (``web/challenge.html``, embedded in the daemon) is a single HTML file with a card, an indeterminate progress bar, and a status line. It requests the challenge for its own location (``?path=``), spawns the worker, posts the solution with ``fetch``, and reloads on success; ``fetch`` calls retry with jittered exponential backoff, and a ``4xx`` verification answer is shown with its diagnostic title. The page's ``Content-Security-Policy`` admits exactly one script, the solver block, by its SHA-256 hash, which the daemon computes once from the embedded page. An off-screen honeypot link (``/__sibuna/honeypot``) is invisible to people and to script-running browsers; blind crawlers that follow every ``href`` ban themselves.

.. admonition:: Exercise 7.1

   The JavaScript sequential prover is about 60 times slower than WebAssembly. Estimate the fallback solve time at the default difficulty and propose a policy for clients that report the fallback (hint: the worker posts a ``fallback`` message the page can forward).

.. admonition:: Explain the invariant

   Explain why compiling the browser module from the server's verifier sources is a stronger guarantee than testing two implementations against each other.
