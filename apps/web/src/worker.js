// Sibuna Proof-of-Work Web Worker
//
// Solves either tier: Hashcash (leading zero bits) or the Cohen-Pietrzak
// Proof of Sequential Work. The primary engine is the pure-Zig WebAssembly
// module; when WebAssembly is unavailable a JavaScript implementation of the
// same algorithms takes over so every browser can pass.

const K_CONSTS = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

function rotr(v, n) { return (v >>> n) | (v << (32 - n)); }

// SHA-256 over a Uint8Array; returns a 32-byte Uint8Array.
function sha256(bytes) {
    const bitLen = bytes.length * 8;
    const padded = new Uint8Array(((bytes.length + 9 + 63) >> 6) << 6);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 4, bitLen >>> 0);
    dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    const w = new Int32Array(64);
    for (let off = 0; off < padded.length; off += 64) {
        for (let i = 0; i < 16; i++) w[i] = dv.getInt32(off + i * 4);
        for (let i = 16; i < 64; i++) {
            const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
            const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
        }
        let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
        for (let i = 0; i < 64; i++) {
            const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const ch = (e & f) ^ (~e & g);
            const t1 = (h + S1 + ch + K_CONSTS[i] + w[i]) | 0;
            const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const t2 = (S0 + maj) | 0;
            h = g; g = f; f = e; e = (d + t1) | 0;
            d = c; c = b; b = a; a = (t1 + t2) | 0;
        }
        h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
        h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
    }
    const out = new Uint8Array(32);
    const ov = new DataView(out.buffer);
    [h0, h1, h2, h3, h4, h5, h6, h7].forEach((v, i) => ov.setInt32(i * 4, v));
    return out;
}

function leadingZeroBits(digest) {
    let bits = 0;
    for (let i = 0; i < digest.length; i++) {
        if (digest[i] === 0) { bits += 8; continue; }
        bits += Math.clz32(digest[i]) - 24;
        break;
    }
    return bits;
}

const encoder = new TextEncoder();

function concat(parts) {
    let len = 0;
    for (const p of parts) len += p.length;
    const out = new Uint8Array(len);
    let off = 0;
    for (const p of parts) { out.set(p, off); off += p.length; }
    return out;
}

function base64url(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ---------------------------------------------------------------- Hashcash

function solveHashcashJs(challenge, bits, report) {
    const prefix = encoder.encode(challenge + ':');
    let nonce = 0;
    for (;;) {
        const digest = sha256(concat([prefix, encoder.encode(String(nonce))]));
        if (leadingZeroBits(digest) >= bits) return String(nonce);
        nonce++;
        if (nonce % 5000 === 0) report(nonce);
    }
}

// ------------------------------------------------- Proof of Sequential Work
// Mirrors libs/crypto/src/posw.zig label for label.

function poswNodeInput(chi, depth, index, parents) {
    const enc = new Uint8Array(5);
    enc[0] = depth;
    new DataView(enc.buffer).setUint32(1, index, true);
    return concat([chi, enc].concat(parents));
}

function pathBit(gamma, n, d) { return (gamma >>> (n - d)) & 1; }

function solvePoswJs(challenge, depth, challenges, report) {
    const chi = encoder.encode(challenge);
    const n = depth;
    const m = Math.min(n, 10);
    const top = new Array((1 << (m + 1)));
    const stack = new Array(n + 1);
    let capture = null;
    let target = 0;
    let hashed = 0;

    function record(d, index, label) {
        if (d === 0) return;
        if (d === n && index === target) capture[0] = label;
        else if (index === ((target >>> (n - d)) ^ 1)) capture[1 + (n - d)] = label;
    }

    function labelOf(d, index) {
        let label;
        if (d === n) {
            const parents = [];
            for (let i = 1; i <= n; i++) if (pathBit(index, n, i) === 1) parents.push(stack[i]);
            label = sha256(poswNodeInput(chi, d, index, parents));
        } else {
            const left = labelOf(d + 1, index * 2);
            stack[d + 1] = left;
            const right = labelOf(d + 1, index * 2 + 1);
            label = sha256(poswNodeInput(chi, d, index, [left, right]));
        }
        if ((++hashed & 0x3fff) === 0) report(hashed);
        if (capture) record(d, index, label);
        else if (d <= m) top[(1 << d) - 1 + index] = label;
        return label;
    }

    const phi = labelOf(0, 0);
    const openings = [];
    for (let i = 0; i < challenges; i++) {
        const seedInput = concat([chi, phi, new Uint8Array([i])]);
        const gamma = new DataView(sha256(seedInput).buffer).getUint32(0, true) & ((1 << n) - 1);
        const out = new Array(n + 1);
        for (let d = 1; d <= m; d++) {
            const sib = (gamma >>> (n - d)) ^ 1;
            const sibLabel = top[(1 << d) - 1 + sib];
            out[1 + (n - d)] = sibLabel;
            if (pathBit(gamma, n, d) === 1) stack[d] = sibLabel;
        }
        if (m === n) {
            out[0] = top[(1 << n) - 1 + gamma];
        } else {
            target = gamma;
            capture = out;
            labelOf(m, gamma >>> (n - m));
            capture = null;
        }
        openings.push(concat(out));
    }
    return base64url(concat([phi].concat(openings)));
}

// ------------------------------------------------------------- WebAssembly

let wasmExports = null;

async function loadWasm() {
    if (wasmExports) return wasmExports;
    const response = await fetch('/__sibuna/wasm/sibuna-pow.wasm');
    if (!response.ok) throw new Error('Wasm fetch failed: ' + response.status);
    const { instance } = await WebAssembly.instantiate(await response.arrayBuffer(), {});
    wasmExports = instance.exports;
    return wasmExports;
}

async function solveHashcashWasm(challenge, bits, report) {
    const ex = await loadWasm();
    const ptr = ex.sibuna_get_buffer_ptr();
    const encoded = encoder.encode(challenge);
    new Uint8Array(ex.memory.buffer).set(encoded, ptr);
    const maxSteps = 20000;
    let nonce = 0n;
    for (;;) {
        // WebAssembly i64 results arrive as signed BigInts, so the u64
        // "exhausted" sentinel (all ones) reads back as -1n.
        const found = BigInt.asUintN(64, ex.sibuna_solve_step(ptr, encoded.length, bits, nonce, maxSteps));
        if (found !== 18446744073709551615n) return found.toString();
        nonce += BigInt(maxSteps);
        report(Number(nonce));
    }
}

async function solvePoswWasm(challenge, depth, challenges) {
    const ex = await loadWasm();
    const ptr = ex.sibuna_get_buffer_ptr();
    const encoded = encoder.encode(challenge);
    if (encoded.length > ex.sibuna_get_buffer_len()) throw new Error('challenge too long');
    new Uint8Array(ex.memory.buffer).set(encoded, ptr);
    const len = ex.sibuna_posw_solve(encoded.length, depth, challenges);
    if (len === 0) throw new Error('posw solver rejected parameters');
    const proof = new Uint8Array(ex.memory.buffer, ex.sibuna_posw_proof_ptr(), len);
    return base64url(new Uint8Array(proof));
}

// ------------------------------------------------------------------ Driver

self.onmessage = async function (event) {
    const { challenge, algorithm, difficulty, challenges } = event.data;
    const report = (iterations) => self.postMessage({ type: 'progress', iterations: iterations });
    const hasWasm = typeof WebAssembly === 'object' && typeof WebAssembly.instantiate === 'function';
    try {
        let solution;
        if (algorithm === 'posw') {
            try {
                if (!hasWasm) throw new Error('no wasm');
                solution = { proof: await solvePoswWasm(challenge, difficulty, challenges) };
            } catch (wasmErr) {
                self.postMessage({ type: 'fallback', message: 'Wasm unavailable; running JS prover' });
                solution = { proof: solvePoswJs(challenge, difficulty, challenges, report) };
            }
        } else {
            try {
                if (!hasWasm) throw new Error('no wasm');
                solution = { nonce: await solveHashcashWasm(challenge, difficulty, report) };
            } catch (wasmErr) {
                self.postMessage({ type: 'fallback', message: 'Wasm unavailable; running JS solver' });
                solution = { nonce: solveHashcashJs(challenge, difficulty, report) };
            }
        }
        self.postMessage({ type: 'solved', challenge: challenge, solution: solution });
    } catch (err) {
        self.postMessage({ type: 'error', message: err.message });
    }
};
