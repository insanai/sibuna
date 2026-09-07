// Sibuna Proof-of-Work Web Worker
// Loads pure Zig WebAssembly solver and computes solution nonces.

self.onmessage = async function(event) {
    const { challenge, difficulty } = event.data;
    try {
        const response = await fetch('/__sibuna/wasm/sibuna-pow.wasm');
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
                self.postMessage({
                    type: 'solved',
                    nonce: found.toString(),
                    challenge: challenge
                });
                return;
            }
            currentNonce += BigInt(maxSteps);
            self.postMessage({
                type: 'progress',
                iterations: currentNonce.toString()
            });
        }
    } catch (err) {
        self.postMessage({ type: 'error', message: err.message });
    }
};
