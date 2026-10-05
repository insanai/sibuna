// Execute the shipped socket bridge with queued callbacks retained across replacement.
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = fs.readFileSync("apps/console-ui/web/glue.js", "utf8");
const start = source.indexOf("function disconnectStream()");
const end = source.indexOf("async function run(command)", start);
assert(start >= 0 && end > start, "shipped socket bridge not found");
const sockets = [];
const events = [];
class Socket {
  constructor(url) { this.url = url; sockets.push(this); }
  close() { this.closed = true; }
}
const context = vm.createContext({
  URL, WebSocket: Socket,
  location: {href: "https://console.example/console/", protocol: "https:"},
  event: (kind, value) => events.push({kind, value}),
});
vm.runInContext(`let socket;\n${source.slice(start, end)}`, context);
const run = code => vm.runInContext(code, context);
run('connectStream("/console/ws")');
const old = sockets[0];
assert.equal(old.url.href, "wss://console.example/console/ws");
const queued = {open: old.onopen, message: old.onmessage, close: old.onclose};
run('connectStream("/console/ws")');
const current = sockets[1];
assert(old.closed);
assert.equal(old.onopen, null);
assert.equal(old.onmessage, null);
assert.equal(old.onclose, null);
queued.open();
queued.message({data: '{"error":"unauthorized"}'});
queued.message({data: "malformed"});
queued.close({code: 1008});
assert.equal(events.length, 0, "replaced callbacks reached the new session");
current.onopen();
current.onmessage({data: '{"op":"snapshot_begin"}'});
assert.equal(events.length, 2);
assert.equal(events[1].value.body.op, "snapshot_begin");
current.onmessage({data: "malformed"});
assert.equal(events.at(-1).value.state, "invalid");
const afterSignOut = current.onmessage;
run("disconnectStream()");
afterSignOut({data: '{"error":"unauthorized"}'});
assert.equal(events.length, 3, "sign-out retained a socket callback");
assert.equal(run("socket"), undefined);
run('connectStream("/console/ws")');
sockets[2].onclose({code: 1008});
assert.equal(events.at(-1).value.code, 1008);
assert.equal(run("socket"), undefined);
console.log("console bridge: replaced and signed-out socket callbacks are fenced");
