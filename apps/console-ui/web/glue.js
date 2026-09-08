// Fixed browser capability bridge. Routing, forms, application state and markup live in Zig.
const root = document.getElementById("app");
const decoder = new TextDecoder();
const encoder = new TextEncoder();
const module = await loadConsole();
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
    // Keep browser-owned scrolling across replacement; visibility remains Wasm state.
    const scrolling = [...root.querySelectorAll("[data-preserve-scroll][id]")].slice(0, 16)
      .map(node => ({id: node.id, left: node.scrollLeft, top: node.scrollTop}));
    renderedHtml = html;
    root.innerHTML = html;
    for (const position of scrolling) {
      const region = root.querySelector(`#${CSS.escape(position.id)}[data-preserve-scroll]`);
      if (region) { region.scrollLeft = position.left; region.scrollTop = position.top; }
    }
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
  if (command.op === "save-text") {
    const url = URL.createObjectURL(new Blob([command.text], {type: "application/json"}));
    const link = document.createElement("a");
    link.href = url;
    link.download = command.filename;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } else if (command.op === "download") {
    await download(command);
  } else if (command.op === "request") {
    const headers = {};
    if (command.body) headers["Content-Type"] = "application/json";
    if (command.csrf) headers["X-Console-CSRF"] = command.csrf;
    const deadline = fetchDeadline();
    try {
      const response = await fetch(command.path, {
        method: command.method, credentials: "same-origin", headers,
        body: command.body ? JSON.stringify(command.body) : undefined,
        signal: deadline.signal,
      });
      // Reserve room for the event envelope before copying into the bounded Wasm input.
      const bytes = await readBounded(response, wasm.sb_input_capacity() - 256);
      const body = JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(bytes));
      event(2, {id: command.id, status: response.status, body});
    } catch {
      event(2, {id: command.id, status: 0, body: {}});
    } finally { deadline.clear(); }
  } else if (command.op === "geometry") {
    geometryController?.abort();
    const controller = new AbortController();
    geometryController = controller;
    const deadline = fetchDeadline(controller);
    try {
      const response = await fetch(command.path, {
        credentials: "same-origin", signal: controller.signal,
      });
      if (!response.ok) throw new Error("Geometry unavailable");
      const bytes = await readBounded(response, wasm.sb_geometry_capacity());
      if (geometryController !== controller) return;
      new Uint8Array(wasm.memory.buffer, wasm.sb_geometry_input(), bytes.length).set(bytes);
      wasm.sb_geometry_loaded(bytes.length);
    } catch {
      if (geometryController !== controller) return;
      wasm.sb_geometry_loaded(0);
    } finally { deadline.clear(); }
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
root.addEventListener("change", e => {
  const form = e.target.closest("form[data-change]");
  if (form) event(1, {action: form.dataset.change,
    fields: Object.fromEntries(new FormData(form))});
});
root.addEventListener("click", e => {
  const button = e.target.closest("[data-action]");
  if (button?.dataset.validate === "true" && button.form && !button.form.reportValidity()) return;
  if (button) event(1, {action: button.dataset.action,
    fields: button.form ? Object.fromEntries(new FormData(button.form)) : {}});
});
document.addEventListener("visibilitychange", () => event(5, {hidden: document.hidden}));
wasm.sb_init();
flush();
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
const motionPreference = () => event(7, {reduced_motion: reducedMotion.matches});
reducedMotion.addEventListener("change", motionPreference);
motionPreference();
let lastFrame = 0;
function animate(now) {
  // Zig owns projection, timing and scene state. Only the globe region changes per frame.
  if (!document.hidden && now - lastFrame >= 1000 / 24) {
    lastFrame = now;
    const length = wasm.sb_frame(now);
    const scene = document.getElementById("globe-scene");
    if (length && scene) scene.innerHTML = read(wasm.sb_frame_html(), length);
  }
  requestAnimationFrame(animate);
}
requestAnimationFrame(animate);


async function download(command) {
  const deadline = fetchDeadline();
  try {
    const response = await fetch(command.path, {
      method: command.method, credentials: "same-origin",
      headers: {"Content-Type": "application/json", "X-Console-CSRF": command.csrf},
      body: JSON.stringify(command.body),
      signal: deadline.signal,
    });
    if (!response.ok) {
      await response.body?.cancel();
      event(2, {id: command.id, status: response.status, body: {}});
      return;
    }
    const bytes = await readBounded(response, 4096);
    const type = response.headers.get("Content-Type") || "application/octet-stream";
    const url = URL.createObjectURL(new Blob([bytes], {type}));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = command.filename;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    event(2, {id: command.id, status: 200, body: {}});
  } catch { event(2, {id: command.id, status: 0, body: {}}); }
  finally { deadline.clear(); }
}

// This deadline bounds browser work only. A timed-out mutation may still commit on the server.
function fetchDeadline(controller = new AbortController()) {
  const timer = setTimeout(() => controller.abort(), 15000);
  return {signal: controller.signal, clear: () => clearTimeout(timer)};
}

async function readBounded(response, limit) {
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      if (part.value.length === 0) continue;
      length += part.value.length;
      if (length > limit) {
        await reader.cancel();
        throw new Error("Response capacity exceeded");
      }
      chunks.push(part.value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return bytes;
}

async function loadConsole() {
  const deadline = fetchDeadline();
  try {
    const response = await fetch("/console/assets/console.wasm", {signal: deadline.signal});
    if (!response.ok) throw new Error("Console asset unavailable");
    return await WebAssembly.instantiate(await readBounded(response, 300 * 1024), {});
  } catch (error) {
    root.textContent = "Console could not load. Reload this page to retry.";
    root.setAttribute("aria-busy", "false");
    throw error;
  } finally { deadline.clear(); }
}
