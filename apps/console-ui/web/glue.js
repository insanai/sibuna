// Fixed browser capability bridge. Routing, forms, application state and markup live in Zig.
const root = document.getElementById("app");
const decoder = new TextDecoder();
const encoder = new TextEncoder();
const module = await WebAssembly.instantiateStreaming(fetch("/console/assets/console.wasm"), {});
const wasm = module.instance.exports;
let socket;
const timers = new Map();
function read(pointer, length) {
  return decoder.decode(new Uint8Array(wasm.memory.buffer, pointer, length));
}
function event(kind, value) {
  const bytes = encoder.encode(JSON.stringify(value));
  if (bytes.length > wasm.sb_input_capacity()) return;
  new Uint8Array(wasm.memory.buffer, wasm.sb_input(), bytes.length).set(bytes);
  wasm.sb_event(kind, bytes.length);
  flush();
}
function flush() {
  const html = read(wasm.sb_html(), wasm.sb_html_length());
  const focus = document.activeElement;
  const activeId = focus?.id;
  const selection = typeof focus?.selectionStart === "number" ? focus.selectionStart : null;
  if (html !== root.innerHTML) {
    root.innerHTML = html;
    root.setAttribute("aria-busy", "false");
    const next = activeId && document.getElementById(activeId);
    if (next) {
      next.focus({preventScroll: true});
      if (selection !== null && next.setSelectionRange) next.setSelectionRange(selection, selection);
    }
  }
  const commands = JSON.parse(read(wasm.sb_commands(), wasm.sb_commands_length()) || "[]");
  for (const command of commands) run(command);
}
async function run(command) {
  if (command.op === "request") {
    const headers = {};
    if (command.body) headers["Content-Type"] = "application/json";
    if (command.csrf) headers["X-Console-CSRF"] = command.csrf;
    try {
      const response = await fetch(command.path, {
        method: command.method, credentials: "same-origin", headers,
        body: command.body ? JSON.stringify(command.body) : undefined,
      });
      const body = await response.json();
      event(2, {id: command.id, status: response.status, body});
    } catch {
      event(2, {id: command.id, status: 0, body: {}});
    }
  } else if (command.op === "timer") {
    clearTimeout(timers.get(command.id));
    timers.set(command.id, setTimeout(() => event(3, {id: command.id}), command.delay_ms));
  } else if (command.op === "connect") {
    if (socket) { socket.onclose = null; socket.close(); }
    const url = new URL(command.path, location.href);
    url.protocol = location.protocol === "https:" ? "wss:" : "ws:";
    socket = new WebSocket(url);
    socket.onopen = () => event(4, {state: "open"});
    socket.onmessage = ({data}) => {
      try { event(4, {state: "message", body: JSON.parse(data)}); }
      catch { event(4, {state: "invalid"}); }
    };
    socket.onclose = ({code}) => event(4, {state: "closed", code});
  } else if (command.op === "send") {
    if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify(command.body));
  } else if (command.op === "disconnect") {
    if (socket) { socket.onclose = null; socket.close(); socket = undefined; }
    for (const timer of timers.values()) clearTimeout(timer);
    timers.clear();
  } else if (command.op === "theme") {
    document.documentElement.dataset.theme = command.value;
  }
}
root.addEventListener("submit", e => {
  e.preventDefault();
  event(1, {action: e.target.id, fields: Object.fromEntries(new FormData(e.target))});
});
root.addEventListener("click", e => {
  const button = e.target.closest("[data-action]");
  if (button) event(1, {action: button.dataset.action, fields: {}});
});
wasm.sb_init();
flush();
