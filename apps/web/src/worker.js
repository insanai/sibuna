// Sibuna Proof-of-Work Web Worker
// Primary solver: Pure Zig WebAssembly (silicon-accelerated)
// Fallback solver: Pure JavaScript SHA-256 (for environments where Wasm is disabled/restricted)

function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
}

const K_CONSTS = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

function sha256Hex(ascii) {
    const words = [];
    const asciiBitLength = ascii.length * 8;
    words[asciiBitLength >> 5] |= 0x80 << (24 - (asciiBitLength % 32));
    words[(((asciiBitLength + 64) >> 9) << 4) + 15] = asciiBitLength;

    for (let i = 0; i < ascii.length; i++) {
        words[i >> 2] |= ascii.charCodeAt(i) << ((3 - (i % 4)) * 8);
    }

    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    const w = new Int32Array(64);

    for (let chunk = 0; chunk < words.length; chunk += 16) {
        let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
        for (let i = 0; i < 64; i++) {
            if (i < 16) {
                w[i] = words[chunk + i] | 0;
            } else {
                const s0 = rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ (w[i - 15] >>> 3);
                const s1 = rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >>> 10);
                w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
            }
            const s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            const ch = (e & f) ^ ((~e) & g);
            const t1 = (h + s1 + ch + K_CONSTS[i] + w[i]) | 0;
            const s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const t2 = (s0 + maj) | 0;

            h = g;
            g = f;
            f = e;
            e = (d + t1) | 0;
            d = c;
            c = b;
            b = a;
            a = (t1 + t2) | 0;
        }
        h0 = (h0 + a) | 0;
        h1 = (h1 + b) | 0;
        h2 = (h2 + c) | 0;
        h3 = (h3 + d) | 0;
        h4 = (h4 + e) | 0;
        h5 = (h5 + f) | 0;
        h6 = (h6 + g) | 0;
        h7 = (h7 + h) | 0;
    }

    let result = '';
    const hashes = [h0, h1, h2, h3, h4, h5, h6, h7];
    for (let i = 0; i < 8; i++) {
        for (let j = 3; j >= 0; j--) {
            const byte = (hashes[i] >> (8 * j)) & 255;
            result += (byte < 16 ? '0' : '') + byte.toString(16);
        }
    }
    return result;
}

function checkHexDifficulty(hex, difficulty) {
    for (let i = 0; i < difficulty; i++) {
        if (hex.charCodeAt(i) !== 48) return false;
    }
    return true;
}

function solveWithJavaScript(challenge, difficulty) {
    self.postMessage({ type: 'fallback', message: 'Wasm unavailable; running JS fallback' });
    let nonce = 0n;
    const batch = 5000;
    while (true) {
        for (let i = 0; i < batch; i++) {
            const input = challenge + ':' + (nonce + BigInt(i)).toString();
            const digest = sha256Hex(input);
            if (checkHexDifficulty(digest, difficulty)) {
                return (nonce + BigInt(i)).toString();
            }
        }
        nonce += BigInt(batch);
        self.postMessage({ type: 'progress', iterations: nonce.toString() });
    }
}

async function solveWithWasm(challenge, difficulty) {
    const response = await fetch('/__sibuna/wasm/sibuna-pow.wasm');
    if (!response.ok) throw new Error('Wasm fetch failed: ' + response.status);
    const buffer = await response.arrayBuffer();
    const { instance } = await WebAssembly.instantiate(buffer, {});

    const exports = instance.exports;
    const ptr = exports.sibuna_get_buffer_ptr();
    const mem = new Uint8Array(exports.memory.buffer);

    const encoder = new TextEncoder();
    const encoded = encoder.encode(challenge);
    mem.set(encoded, ptr);

    const maxSteps = 20000;
    let currentNonce = 0n;
    const maxUint64 = 18446744073709551615n;

    while (true) {
        const found = exports.sibuna_solve_step(
            ptr,
            encoded.length,
            difficulty,
            currentNonce,
            maxSteps
        );
        if (found !== maxUint64) {
            return found.toString();
        }
        currentNonce += BigInt(maxSteps);
        self.postMessage({
            type: 'progress',
            iterations: currentNonce.toString()
        });
    }
}

self.onmessage = async function(event) {
    const { challenge, difficulty } = event.data;
    try {
        let nonce;
        if (typeof WebAssembly === 'object' && typeof WebAssembly.instantiate === 'function') {
            try {
                nonce = await solveWithWasm(challenge, difficulty);
            } catch (wasmErr) {
                // Fall back to pure JS if Wasm instantiation or fetch fails
                nonce = solveWithJavaScript(challenge, difficulty);
            }
        } else {
            nonce = solveWithJavaScript(challenge, difficulty);
        }

        self.postMessage({
            type: 'solved',
            nonce: nonce,
            challenge: challenge
        });
    } catch (err) {
        self.postMessage({ type: 'error', message: err.message });
    }
};
