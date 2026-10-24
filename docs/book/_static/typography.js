/* Paragraph-wide Knuth–Plass layout for English reading prose.
   The original DOM is retained for resize and print. Emphasis survives.
   Link-bearing paragraphs keep native layout.
   Equations, code, interactive content and unsuitable measures use native CSS layout. */
(() => {
  "use strict";
  const article = document.querySelector(".gd-article");
  const language = document.documentElement.lang.toLowerCase();
  if (!article || !/^en(?:-|$)/.test(language) || typeof Typeset === "undefined" ||
      typeof Typeset.linebreak !== "function" || !Typeset.LinkedList ||
      typeof Hypher === "undefined" || !Hypher.en) return;
  const hypher = new Hypher(Hypher.en);
  const breaker = Typeset.linebreak;
  const canvas = document.createElement("canvas").getContext("2d");
  if (!canvas) return;
  const originals = new Map();
  const paragraphs = [...article.querySelectorAll("section > p, .desc-content > p")].filter(p => {
    const length = p.textContent.length;
    return length >= 180 && length <= 5000 &&
      !p.closest("table, .admonition, .toctree-wrapper, figure, li, dd") &&
      !p.querySelector("code, .math, img, br, sup, sub, [id], [role], [tabindex], button") &&
      !p.querySelector("a") &&
      [...p.querySelectorAll("*")].every(e => /^(A|EM|STRONG|SPAN)$/.test(e.tagName));
  });

  function restore(p) {
    const original = originals.get(p);
    if (original) p.replaceChildren(...original);
    delete p.dataset.layout;
  }

  function textMap(p) {
    const walker = document.createTreeWalker(p, NodeFilter.SHOW_TEXT);
    const map = [];
    let text = "", node;
    while ((node = walker.nextNode())) {
      map.push({node, start: text.length, end: text.length + node.length});
      text += node.textContent;
    }
    return {map, text};
  }

  function point(map, offset) {
    const item = map.find(a => offset >= a.start && offset < a.end) || map.at(-1);
    return {node: item.node, offset: Math.min(offset - item.start, item.node.length)};
  }

  function fontAt(map, offset) {
    const style = getComputedStyle(point(map, offset).node.parentElement);
    return `${style.fontStyle} ${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
  }

  function width(text, font) {
    canvas.font = font;
    return canvas.measureText(text).width;
  }

  function nodesFor(text, map, space) {
    const nodes = [];
    const words = [...text.matchAll(/\S+/g)];
    for (let i = 0; i < words.length; i++) {
      const word = words[i][0], start = words[i].index;
      const font = fontAt(map, start);
      const letters = word.match(/^([“‘(]*)([a-zA-Z]{6,})([.,;:!?"”’)\]]*)$/);
      const fragments = letters ? hypher.hyphenate(letters[2]) : [word];
      if (letters) {
        fragments[0] = letters[1] + fragments[0];
        fragments[fragments.length - 1] += letters[3];
      }
      let offset = start;
      for (let j = 0; j < fragments.length; j++) {
        const fragment = fragments[j];
        const box = breaker.box(width(fragment, font), fragment);
        nodes.push(box);
        offset += fragment.length;
        if (j < fragments.length - 1) {
          const penalty = breaker.penalty(width("‐", font), 80, 1);
          penalty.offset = offset;
          nodes.push(penalty);
        }
      }
      const end = start + word.length;
      const last = i === words.length - 1;
      const glue = breaker.glue(last ? 0 : space, last ? breaker.infinity : space / 2,
        last ? 0 : space / 3);
      glue.offset = last ? text.length : words[i + 1].index;
      nodes.push(glue);
    }
    const final = breaker.penalty(0, -breaker.infinity, 0);
    final.offset = text.length;
    nodes.push(final);
    return nodes;
  }

  function lineFragment(map, start, end) {
    const range = document.createRange();
    const from = point(map, start), to = point(map, end);
    range.setStart(from.node, from.offset);
    range.setEnd(to.node, to.offset);
    return range.cloneContents();
  }

  function render(p, map, text, nodes, breaks, space) {
    const fragment = document.createDocumentFragment();
    let start = 0;
    for (let i = 1; i < breaks.length; i++) {
      const choice = breaks[i], node = nodes[choice.position];
      const line = document.createElement("span");
      line.className = "gd-typeset-line";
      line.append(lineFragment(map, start, node.offset));
      if (node.type === "penalty" && node.penalty > 0) line.dataset.hyphen = "";
      if (i < breaks.length - 1) {
        const flexibility = choice.ratio < 0 ? space / 3 : space / 2;
        line.style.wordSpacing = `${choice.ratio * flexibility}px`;
      }
      fragment.append(line);
      start = node.offset;
    }
    // Layout is optional: never replace the source with an incomplete result.
    if (start !== text.length || fragment.textContent !== text) return;
    p.replaceChildren(fragment);
    p.dataset.layout = "knuth-plass";
    if ([...p.children].some(line => line.scrollWidth > p.clientWidth + 1)) restore(p);
  }

  function typeset(p) {
    restore(p);
    const measure = p.clientWidth;
    if (measure < 400) return;
    const {map, text} = textMap(p);
    if (!map.length || !text.trim()) return;
    const space = width(" ", fontAt(map, 0));
    const nodes = nodesFor(text, map, space);
    if (nodes.length > 1800) return;
    const breaks = breaker(nodes, [measure - 1], {tolerance: 1.5, maxTolerance: 3,
      demerits: {line: 10, flagged: 400, fitness: 3000}});
    if (breaks.length < 3 || breaks.at(-1).position !== nodes.length - 1) return;
    if (breaks.slice(1, -1).some(b => b.ratio > 1.8 || b.ratio < -0.8)) return;
    if (!originals.has(p)) originals.set(p, [...p.childNodes]);
    render(p, map, text, nodes, breaks, space);
  }

  let scheduled = false, printing = false;
  function schedule() {
    if (scheduled || printing) return;
    scheduled = true;
    requestAnimationFrame(() => {
      scheduled = false;
      for (const p of paragraphs) typeset(p);
    });
  }
  document.fonts.ready.then(schedule);
  let previousWidth = 0;
  const resized = entries => {
    const measure = entries[0].contentRect.width;
    if (Math.abs(measure - previousWidth) > 0.5) {
      previousWidth = measure;
      schedule();
    }
  };
  if (typeof ResizeObserver !== "undefined") new ResizeObserver(resized).observe(article);
  else addEventListener("resize", schedule);
  addEventListener("beforeprint", () => {
    printing = true;
    for (const p of paragraphs) restore(p);
  });
  addEventListener("afterprint", () => { printing = false; schedule(); });
  // Copy the selected source text, without visual line divisions or inserted hyphens.
  addEventListener("copy", event => {
    const selection = getSelection();
    if (!selection || selection.isCollapsed || !selection.rangeCount) return;
    const paragraph = node => (node.nodeType === Node.TEXT_NODE ? node.parentElement : node)
      ?.closest('p[data-layout="knuth-plass"]');
    const from = paragraph(selection.anchorNode), to = paragraph(selection.focusNode);
    if (!from || from !== to || !event.clipboardData) return;
    event.clipboardData.setData("text/plain", selection.getRangeAt(0).cloneContents().textContent);
    event.preventDefault();
  });
})();
