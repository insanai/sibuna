// Fixed browser capability bridge. Routing, forms, application state and markup live in Zig.
const root = document.getElementById("app");
const decoder = new TextDecoder();
const encoder = new TextEncoder();
const module = await WebAssembly.instantiateStreaming(fetch("/console/assets/console.wasm"), {});
const wasm = module.instance.exports;
let socket;
let geometryController;
let pendingFocus;
let renderedHtml;
const timers = new Map();
function read(pointer, length) {
  return decoder.decode(new Uint8Array(wasm.memory.buffer, pointer, length));
}
function event(kind, value) {
  value.browser_time = Math.floor(Date.now() / 1000);
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
  const activeAction = focus?.dataset?.action;
  const submitForm = focus?.type === "submit" ? focus.closest("form")?.id : null;
  const selection = typeof focus?.selectionStart === "number" ? focus.selectionStart : null;
  // Compare renderer output with its previous output. Browser serialization normalizes
  // markup, so comparing innerHTML would replace forms even for unchanged state.
  if (html !== renderedHtml) {
    renderedHtml = html;
    root.innerHTML = html;
    root.setAttribute("aria-busy", "false");
    const target = (activeId && `#${CSS.escape(activeId)}`) ||
      (activeAction && `[data-action="${CSS.escape(activeAction)}"]`) ||
      (submitForm && `#${CSS.escape(submitForm)} [type=submit]`) || pendingFocus;
    const next = target && root.querySelector(target);
    pendingFocus = next?.disabled ? target : undefined;
    if (next && !next.disabled) {
      next.focus({preventScroll: true});
      if (selection !== null && next.setSelectionRange) next.setSelectionRange(selection, selection);
    }
  }
  const commands = JSON.parse(read(wasm.sb_commands(), wasm.sb_commands_length()) || "[]");
  for (const command of commands) run(command);
}
async function run(command) {
  if (command.op === "download") {
    await download(command);
  } else if (command.op === "request") {
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
  } else if (command.op === "geometry") {
    geometryController?.abort();
    const controller = new AbortController();
    geometryController = controller;
    try {
      const response = await fetch(command.path, {
        credentials: "same-origin", signal: controller.signal,
      });
      if (!response.ok) throw new Error("Geometry unavailable");
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (bytes.length > wasm.sb_geometry_capacity()) throw new Error("Geometry too large");
      if (geometryController !== controller) return;
      new Uint8Array(wasm.memory.buffer, wasm.sb_geometry_input(), bytes.length).set(bytes);
      wasm.sb_geometry_loaded(bytes.length);
    } catch {
      if (geometryController !== controller) return;
      wasm.sb_geometry_loaded(0);
    }
    flush();
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
    geometryController?.abort();
    if (socket) { socket.onclose = null; socket.close(); socket = undefined; }
    for (const timer of timers.values()) clearTimeout(timer);
    timers.clear();
  } else if (command.op === "focus") {
    const element = root.querySelector(command.selector);
    if (element) {
      pendingFocus = undefined;
      element.tabIndex = -1;
      element.focus({preventScroll: true});
      if (command.top) window.scrollTo({top: 0});
      else element.scrollIntoView({block: "start"});
    }
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
document.addEventListener("visibilitychange", () => event(5, {hidden: document.hidden}));
wasm.sb_init();
flush();


async function download(command) {
  try {
    const response = await fetch(command.path, {
      method: command.method, credentials: "same-origin",
      headers: {"Content-Type": "application/json", "X-Console-CSRF": command.csrf},
      body: JSON.stringify(command.body),
    });
    if (!response.ok) {
      await response.body?.cancel();
      event(2, {id: command.id, status: response.status, body: {}});
      return;
    }
    const reader = response.body.getReader();
    const chunks = [];
    let length = 0;
    try {
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        length += part.value.length;
        if (length > 4096) {
          await reader.cancel();
          throw new Error("Export capacity exceeded");
        }
        chunks.push(part.value);
      }
    } finally { reader.releaseLock(); }
    const type = response.headers.get("Content-Type") || "application/octet-stream";
    const url = URL.createObjectURL(new Blob(chunks, {type}));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = command.filename;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    event(2, {id: command.id, status: 200, body: {}});
  } catch { event(2, {id: command.id, status: 0, body: {}}); }
}
