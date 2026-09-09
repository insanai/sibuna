// Execute the shipped Wasm ABI. This is a browser-capability fixture, not a DOM test.
import {readFile} from "node:fs/promises";
import {createInterface} from "node:readline";
const {instance} = await WebAssembly.instantiate(await readFile(process.argv[2]), {});
const wasm = instance.exports;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
function read(pointer, length) {
    return decoder.decode(new Uint8Array(wasm.memory.buffer, pointer, length));
}
for await (const line of createInterface({input: process.stdin})) {
    const message = JSON.parse(line);
    if (message.init) wasm.sb_init();
    else if (message.geometry) {
        const bytes = Buffer.from(message.geometry, "base64");
        if (bytes.length > wasm.sb_geometry_capacity()) throw Error("geometry capacity");
        new Uint8Array(wasm.memory.buffer, wasm.sb_geometry_input(), bytes.length).set(bytes);
        wasm.sb_geometry_loaded(bytes.length);
    } else {
        const bytes = encoder.encode(JSON.stringify(message.value));
        if (bytes.length > wasm.sb_input_capacity()) throw Error("event capacity");
        new Uint8Array(wasm.memory.buffer, wasm.sb_input(), bytes.length).set(bytes);
        wasm.sb_event(message.kind, bytes.length);
    }
    process.stdout.write(JSON.stringify({
        commands: JSON.parse(read(wasm.sb_commands(), wasm.sb_commands_length())),
        html: read(wasm.sb_html(), wasm.sb_html_length()),
    }) + "\n");
}
