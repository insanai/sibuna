// Guidedog theme enhancements: the theme switch, live search in the header and on the
// search page, copy buttons for code, the navigation drawer's keyboard handling, and the
// current section in "On this page". Every page works without this script.
(() => {
  "use strict";
  const root = document.documentElement;
  const labels = document.body.dataset; // the page's words, in its language
  const base = labels.base || "";

  // -- Theme: auto (the system's), light, or dark, remembered across pages. ----------
  const toggle = document.querySelector(".theme-toggle");
  const modes = ["auto", "light", "dark"];
  const names = (labels.labelModes || "auto|light|dark").split("|");
  const themeWord = labels.labelTheme || "Theme";
  let mode = root.dataset.theme;
  if (!modes.includes(mode)) mode = "auto";
  function setTheme(value, save) {
    mode = value;
    root.dataset.theme = value;
    if (toggle) {
      const label = themeWord + ": " + (names[modes.indexOf(value)] || value);
      toggle.setAttribute("aria-label", label);
      toggle.title = label;
    }
    if (save) try { localStorage.setItem("guidedog-theme", value); } catch (_) {}
  }
  setTheme(mode, false);
  if (toggle) {
    toggle.hidden = false;
    toggle.addEventListener("click", () => {
      setTheme(modes[(modes.indexOf(mode) + 1) % modes.length], true);
    });
  }

  // Paper is light: print with the light colours, code included, whatever the screen's.
  window.addEventListener("beforeprint", () => { root.dataset.theme = "light"; });
  window.addEventListener("afterprint", () => { root.dataset.theme = mode; });

  // -- Navigation drawer on small screens: Escape closes it, and following a link in it
  // closes it too, so a link to a section of this page shows the section.
  const drawer = document.getElementById("gd-nav-toggle");
  if (drawer) {
    document.addEventListener("keydown", e => {
      if (e.key === "Escape" && drawer.checked) { drawer.checked = false; drawer.focus(); }
    });
    document.querySelectorAll(".gd-sidebar a").forEach(a =>
      a.addEventListener("click", () => { drawer.checked = false; }));
  }

  // Show the current page in the sidebar without scrolling the window.
  const sidebar = document.querySelector(".gd-sidebar-inner");
  const here = sidebar && sidebar.querySelector("a[aria-current='page']");
  if (here) {
    const box = sidebar.getBoundingClientRect(), at = here.getBoundingClientRect();
    if (at.bottom > box.bottom) sidebar.scrollTop += at.top - box.top - box.height / 3;
  }

  // -- "On this page": mark the section being read. ---------------------------------
  const railLinks = [...document.querySelectorAll(".gd-rail a[href^='#']")];
  const targets = railLinks.map(a => document.getElementById(decodeURIComponent(a.hash.slice(1))));
  let ticking = false;
  function spy() {
    ticking = false;
    let current = -1;
    const line = 120; // a little below the sticky header
    targets.forEach((t, i) => { if (t && t.getBoundingClientRect().top <= line) current = i; });
    // At the very end of the page, the last section counts even when it is short.
    if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2) {
      for (let i = targets.length - 1; i >= 0; i--) {
        if (targets[i] && targets[i].getBoundingClientRect().top < window.innerHeight) {
          current = Math.max(current, i);
          break;
        }
      }
    }
    railLinks.forEach((a, i) => {
      if (i === current) a.setAttribute("aria-current", "location");
      else a.removeAttribute("aria-current");
    });
  }
  if (railLinks.length) {
    window.addEventListener("scroll", () => {
      if (!ticking) { ticking = true; requestAnimationFrame(spy); }
    }, { passive: true });
    spy();
  }

  // -- Copy buttons on code blocks. -------------------------------------------------
  const copyWord = labels.labelCopy || "Copy";
  const copiedWord = labels.labelCopied || "Copied";
  function codeText(pre) {
    const clone = pre.cloneNode(true);
    clone.querySelectorAll(".linenos, .gd-copy").forEach(n => n.remove());
    return clone.textContent.replace(/\n$/, "");
  }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); return true; } catch (_) {}
    const area = document.createElement("textarea"); // file:// pages and older browsers
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.cssText = "position:fixed;top:0;left:0;opacity:0";
    document.body.append(area);
    area.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch (_) {}
    area.remove();
    return ok;
  }
  document.querySelectorAll(".gd-article pre").forEach(pre => {
    if (pre.classList.contains("productionlist")) return;
    let holder = pre.closest("div.highlight");
    if (!holder) { // a literal block without highlighting: give it a box to sit in
      holder = document.createElement("div");
      holder.className = "gd-code";
      pre.replaceWith(holder);
      holder.append(pre);
    }
    const button = document.createElement("button");
    button.type = "button";
    button.className = "gd-copy";
    button.textContent = copyWord;
    button.setAttribute("aria-label", copyWord);
    button.addEventListener("click", async () => {
      const ok = await copy(codeText(pre));
      if (!ok) return;
      button.textContent = copiedWord;
      button.classList.add("gd-copied");
      setTimeout(() => {
        button.textContent = copyWord;
        button.classList.remove("gd-copied");
      }, 1600);
    });
    holder.classList.add("gd-has-copy");
    holder.append(button);
  });

  // -- Search: _static/searchindex.js is an inverted index of every section's words and
  // every object's name (written by Guidedog's HTML builder); results link to the section.
  const index = window.GUIDEDOG_INDEX || null;
  let vocabulary = null; // every indexed word, sorted, for prefix lookups.
  function ideographic(c) {
    const n = c.codePointAt(0);
    return (n >= 0x3040 && n <= 0x30ff) || (n >= 0x3400 && n <= 0x4dbf) ||
      (n >= 0x4e00 && n <= 0x9fff) || (n >= 0xf900 && n <= 0xfaff) ||
      (n >= 0x20000 && n <= 0x2fa1f);
  }
  // words splits a query as the index was split: runs of letters, digits, and
  // underscores, lowercased, and each Chinese or Japanese character alone.
  function words(query) {
    const out = [];
    const stop = new Set(index ? index.stopwords : []);
    for (const run of query.toLowerCase().match(/[\p{L}\p{Nd}_]+/gu) || []) {
      let word = "";
      for (const c of run) {
        if (!ideographic(c)) { word += c; continue; }
        if (word) out.push(word);
        word = "";
        out.push(c);
      }
      if (word) out.push(word);
    }
    return out.filter(w => !stop.has(w) && ([...w].length > 1 || ideographic(w)));
  }
  // matching lists the indexed words that begin with w, w itself first.
  function matching(w) {
    if (!vocabulary) {
      vocabulary = [...new Set(Object.keys(index.terms).concat(Object.keys(index.titles)))];
      vocabulary.sort();
    }
    let lo = 0, hi = vocabulary.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (vocabulary[mid] < w) lo = mid + 1; else hi = mid;
    }
    const out = [];
    for (let i = lo; i < vocabulary.length && out.length < 100; i++) {
      if (!vocabulary[i].startsWith(w)) break;
      out.push(vocabulary[i]);
    }
    return out;
  }
  // scores gives each section the query word w occurs in a score: more for a title than
  // for text, and more for the word itself than for a longer word it begins.
  function scores(w) {
    const found = new Map();
    const add = (s, n) => found.set(s, (found.get(s) || 0) + n);
    for (const t of matching(w)) {
      const weight = t === w ? 2 : 1;
      const posting = index.terms[t] || [];
      for (let i = 0; i < posting.length; i += 2) {
        add(posting[i], weight * Math.min(posting[i + 1], 10));
      }
      for (const s of index.titles[t] || []) add(s, 15 * weight);
    }
    return found;
  }
  // find returns the sections that have every word of the query, best first.
  function find(query, limit) {
    const ws = words(query);
    if (!index || !ws.length) return [];
    let found = null;
    for (const w of ws) {
      const here = scores(w);
      if (found === null) { found = here; continue; }
      const both = new Map();
      for (const [s, n] of found) if (here.has(s)) both.set(s, n + here.get(s));
      found = both;
      if (!found.size) break;
    }
    return [...found].sort((a, b) => b[1] - a[1] || a[0] - b[0]).slice(0, limit)
      .map(([s]) => {
        const [page, title, anchor, text] = index.sections[s];
        const [pageTitle, url] = index.pages[page];
        return { title, page: pageTitle, url: url + (anchor ? "#" + anchor : ""), text };
      });
  }
  // mark writes text into el, with the query's words in <mark>.
  function mark(el, text, ws) {
    const lower = text.toLowerCase();
    let i = 0;
    while (i < text.length) {
      let next = -1, len = 0;
      for (const w of ws) {
        const at = lower.indexOf(w, i);
        if (at >= 0 && (next < 0 || at < next)) { next = at; len = w.length; }
      }
      if (next < 0) { el.append(text.slice(i)); break; }
      el.append(text.slice(i, next));
      const m = document.createElement("mark");
      m.textContent = text.slice(next, next + len);
      el.append(m);
      i = next + len;
    }
  }
  function resultItem(d, ws, size) {
    const li = document.createElement("li");
    const a = document.createElement("a");
    a.href = base + d.url;
    const title = document.createElement("span");
    title.className = "gd-result-title";
    mark(title, d.title || d.page, ws);
    a.append(title);
    if (d.page && d.page !== d.title) {
      const page = document.createElement("span");
      page.className = "gd-result-page";
      page.textContent = d.page;
      a.append(page);
    }
    const text = document.createElement("span");
    text.className = "gd-result-text";
    mark(text, d.text.length > size ? d.text.slice(0, size).trimEnd() + "..." : d.text, ws);
    a.append(text);
    li.append(a);
    return li;
  }
  function emptyItem() {
    const li = document.createElement("li");
    li.className = "gd-result-empty";
    li.textContent = labels.labelEmpty || "No pages match.";
    return li;
  }

  // The search page: search.html?q=words.
  const pageInput = document.getElementById("search-page-input");
  const pageResults = document.getElementById("search-page-results");
  if (pageInput && pageResults) {
    const run = () => {
      const q = pageInput.value;
      const ws = words(q);
      pageResults.replaceChildren();
      if (!ws.length) return;
      const found = find(q, 200);
      found.forEach(d => pageResults.append(resultItem(d, ws, 240)));
      if (!found.length) pageResults.append(emptyItem());
    };
    const q = new URLSearchParams(location.search).get("q") || "";
    pageInput.value = q;
    pageInput.addEventListener("input", () => {
      run();
      const url = new URL(location.href);
      if (pageInput.value) url.searchParams.set("q", pageInput.value);
      else url.searchParams.delete("q");
      history.replaceState(null, "", url);
    });
    run();
    if (!q) pageInput.focus();
  }

  // The header's search box: results appear under it as you type.
  const input = document.getElementById("search");
  const results = document.getElementById("gd-search-results");
  if (!input || !results) return;
  let active = -1;
  function items() { return [...results.querySelectorAll("a")]; }
  function highlight(i) {
    const all = items();
    active = all.length ? (i + all.length) % all.length : -1;
    all.forEach((a, j) => a.classList.toggle("gd-active", j === active));
    if (active >= 0) all[active].scrollIntoView({ block: "nearest" });
  }
  function close() {
    results.hidden = true;
    active = -1;
    input.setAttribute("aria-expanded", "false");
  }
  function search() {
    const ws = words(input.value);
    results.replaceChildren();
    active = -1;
    if (!ws.length) { close(); return; }
    const found = find(input.value, 12);
    found.forEach(d => results.append(resultItem(d, ws, 110)));
    if (!found.length) results.append(emptyItem());
    results.hidden = false;
    input.setAttribute("aria-expanded", "true");
  }
  input.addEventListener("input", search);
  input.addEventListener("focus", () => { if (input.value) search(); });
  input.addEventListener("keydown", e => {
    if (e.key === "ArrowDown") { e.preventDefault(); highlight(active + 1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); highlight(active - 1); }
    else if (e.key === "Enter" && active >= 0) { e.preventDefault(); items()[active].click(); }
    else if (e.key === "Escape") {
      if (input.value) { input.value = ""; close(); } else input.blur();
    }
  });
  document.addEventListener("click", e => {
    if (!e.target.closest(".gd-search")) close();
  });
  document.addEventListener("keydown", e => {
    const typing = e.target.closest("input, textarea, select, [contenteditable]");
    if (e.key === "/" && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
      e.preventDefault();
      input.focus();
      input.select();
    }
  });
})();
