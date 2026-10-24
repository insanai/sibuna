/* Paragraph-wide Knuth-Plass layout for English reading prose across the website.
   The original DOM is retained for resize and print. Emphasis, links, and inline code survive.
   Inline math, footnote references, superscripts and subscripts are kept whole, as boxes of
   their rendered width. Display equations, code blocks, interactive content, and unsuitable
   measures use native CSS layout.
   Adapted from the CCM documentation (github.com/insanai/ccm, docs/shared/_static), which
   covers paragraphs with links and code; Sibuna adds plain list items and inline boxes. */
(() => {
  "use strict";
  const article = document.querySelector(".gd-article, .landing");
  const language = (document.documentElement.lang || "en").toLowerCase();
  if (!article || !/^en(?:-|$)/.test(language) || typeof Typeset === "undefined" ||
      typeof Typeset.linebreak !== "function" || !Typeset.LinkedList ||
      typeof Hypher === "undefined" || !Hypher.en) return;
  const hypher = new Hypher(Hypher.en);
  const breaker = Typeset.linebreak;
  const canvas = document.createElement("canvas").getContext("2d");
  if (!canvas) return;
  const originals = new Map();
  // Elements set as one unbreakable box. Each stands for one character of the text,
  // OBJECT REPLACEMENT CHARACTER, and is moved, not copied, into the line that holds it.
  const atoms = ".math, mjx-container, a.footnote-reference, sup, sub";
  const ATOM = "￼";
  const selector = [
    "section > p",
    ".desc-content > p",
    "li > p",
    "dd > p",
    "li",
    "dd",
    ".admonition > p:not(.admonition-title)",
    "p.lead",
    ".lead > p",
    ".pillar > p",
    ".split-copy > p",
    ".book-copy > p"
  ].join(", ");
  const excluded = [
    "table",
    ".toctree-wrapper",
    "figure",
    "nav",
    ".actions",
    ".text-links",
    ".eyebrow",
    ".rubric",
    ".hero-note",
    ".art-caption"
  ].join(", ");
  // Only inline elements whose layout the canvas can measure, outside the atoms. A list
  // item that holds a paragraph or a nested list fails this test, and its paragraphs are
  // set on their own.
  const outsideAtoms = p => [...p.querySelectorAll("*")].filter(e => !e.parentElement.closest(atoms));
  const paragraphs = [...article.querySelectorAll(selector)].filter(p => {
    const length = p.textContent.length;
    return length >= 65 && length <= 5000 &&
      !p.matches(excluded) &&
      !p.closest(excluded) &&
      outsideAtoms(p).every(e => e.matches(atoms) ||
        (/^(A|EM|STRONG|SPAN|CODE)$/.test(e.tagName) &&
         !e.matches("[id], [role], [tabindex]")));
  });

  // Atoms moved into the lines of each paragraph, with the copies left in their place.
  const swaps = new Map();

  function restore(p) {
    for (const [atom, copy] of swaps.get(p) || []) copy.replaceWith(atom);
    swaps.delete(p);
    const original = originals.get(p);
    if (original) p.replaceChildren(...original);
    delete p.dataset.layout;
  }

  // The paragraph's text, with each atom as one character, and a map from text offsets
  // to the text nodes and atoms that hold them.
  function textMap(p) {
    const walker = document.createTreeWalker(p, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, {
      acceptNode: node => node.parentElement.closest(atoms)
        ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT
    });
    const map = [];
    let text = "", node;
    while ((node = walker.nextNode())) {
      if (node.nodeType === Node.TEXT_NODE) {
        map.push({node, element: node.parentElement, start: text.length,
          end: text.length + node.length});
        text += node.textContent;
      } else if (node.matches(atoms)) {
        map.push({atom: node, element: node.parentElement, start: text.length,
          end: text.length + 1,
          width: node.getBoundingClientRect().width});
        text += ATOM;
      }
    }
    return {map, text};
  }

  function itemAt(map, offset) {
    return map.find(a => offset >= a.start && offset < a.end) || map.at(-1);
  }

  // A DOM boundary point for a text offset; an atom's offsets fall just before or after it.
  function point(map, offset) {
    const item = itemAt(map, offset);
    if (item.atom) {
      const parent = item.atom.parentNode;
      const index = [...parent.childNodes].indexOf(item.atom);
      return {node: parent, offset: index + (offset > item.start ? 1 : 0)};
    }
    return {node: item.node, offset: Math.min(offset - item.start, item.node.length)};
  }

  function fontOf(item) {
    if (!item.font) {
      const style = getComputedStyle(item.element);
      item.font = `${style.fontStyle} ${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
    }
    return item.font;
  }

  function fontAt(map, offset) {
    return fontOf(itemAt(map, offset));
  }

  function width(text, font) {
    canvas.font = font;
    return canvas.measureText(text).width;
  }

  // The width of the text from offset to offset + length, measured a piece at a time in
  // each piece's own font; an atom counts its rendered width.
  function spanWidth(map, offset, length) {
    let total = 0;
    for (let at = offset, end = offset + length; at < end;) {
      const item = itemAt(map, at), stop = Math.min(end, item.end);
      total += item.atom ? item.width
        : width(item.node.data.slice(at - item.start, stop - item.start), fontOf(item));
      at = stop;
    }
    return total;
  }

  // The inline code elements that the text from start to end touches.
  function codesIn(map, start, end) {
    return new Set(map.filter(item => item.end > start && item.start < end)
      .map(item => item.element.closest("code")).filter(Boolean));
  }

  // The padding and border of the code boxes that open (left) or close (right) within a
  // word. Where a line breaks inside a code box, render() removes them at the cut.
  function codeEdges(map, start, end) {
    let left = 0, right = 0;
    for (const code of codesIn(map, start, end)) {
      const items = map.filter(item => item.element.closest("code") === code);
      const style = getComputedStyle(code);
      if (items[0].start >= start) {
        left += (parseFloat(style.paddingLeft) || 0) + (parseFloat(style.borderLeftWidth) || 0);
      }
      if (items.at(-1).end <= end) {
        right += (parseFloat(style.paddingRight) || 0) + (parseFloat(style.borderRightWidth) || 0);
      }
    }
    return [left, right];
  }

  function pushSyllables(map, part, partStart, inCode, font, extra, nodes) {
    const letters = inCode
      ? null
      : part.match(/^([“‘(]*)([a-zA-Z]{6,})((?:['’][a-zA-Z]+)?[.,;:!?"”’)\]]*-?)$/);
    const fragments = letters ? hypher.hyphenate(letters[2]) : [part];
    if (letters) {
      fragments[0] = letters[1] + fragments[0];
      fragments[fragments.length - 1] += letters[3];
    }
    let offset = partStart;
    for (let j = 0; j < fragments.length; j++) {
      const fragment = fragments[j];
      const boxWidth = spanWidth(map, offset, fragment.length) + (j === 0 ? extra : 0);
      const box = breaker.box(boxWidth, fragment);
      nodes.push(box);
      offset += fragment.length;
      if (j < fragments.length - 1) {
        const penalty = breaker.penalty(width("‐", font), 80, 1);
        penalty.offset = offset;
        penalty.trimEnd = offset;
        nodes.push(penalty);
      }
    }
  }

  function nodesFor(text, map, space) {
    const nodes = [];
    const words = [...text.matchAll(/\S+/g)];
    for (let i = 0; i < words.length; i++) {
      const word = words[i][0], start = words[i].index, end = start + word.length;
      const inCode = codesIn(map, start, end).size > 0;
      const font = fontAt(map, start);
      const [left, right] = inCode ? codeEdges(map, start, end) : [0, 0];
      // Code may break after a path's slash or a Rust path's double colon, as in the PDF;
      // other words after a hyphen between letters. Splitting keeps every character, so
      // arrows such as -> stay whole.
      const parts = word.split(inCode ? /(?<=\/|::)(?=.)/ : /(?<=\p{L}-)(?=\p{L})/u);
      let partOffset = start;
      for (let p = 0; p < parts.length; p++) {
        const part = parts[p];
        const extra = (p === 0 ? left : 0) + (p === parts.length - 1 ? right : 0);
        pushSyllables(map, part, partOffset, inCode, font, extra, nodes);
        partOffset += part.length;
        if (p < parts.length - 1 && inCode) {
          const penalty = breaker.penalty(0, 100, 0);
          penalty.offset = partOffset;
          penalty.trimEnd = partOffset;
          nodes.push(penalty);
        } else if (p < parts.length - 1 && part.endsWith("-")) {
          const penalty = breaker.penalty(0, 50, 1);
          penalty.offset = partOffset;
          penalty.trimEnd = partOffset;
          nodes.push(penalty);
        }
      }
      const last = i === words.length - 1;
      // A space inside inline code is as wide as that font's space. CSS stretches and
      // shrinks every space of a line alike, so all glue gets the body space's flexibility.
      const gap = !last && codesIn(map, end, end + 1).size ? width(" ", fontAt(map, end)) : space;
      const glue = breaker.glue(last ? 0 : gap, last ? breaker.infinity : space / 2,
        last ? 0 : space / 3);
      glue.offset = last ? text.length : words[i + 1].index;
      glue.trimEnd = end;
      nodes.push(glue);
    }
    const final = breaker.penalty(0, -breaker.infinity, 0);
    final.offset = text.length;
    final.trimEnd = text.length;
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

  // Put each atom itself into the new lines and leave its copy in the retained original,
  // so that MathJax's menus and the footnote anchors keep working on the page.
  function moveAtoms(map, fragment) {
    const placed = [];
    const copies = [...fragment.querySelectorAll(atoms)].filter(e => !e.parentElement.closest(atoms));
    const items = map.filter(item => item.atom);
    if (copies.length !== items.length) return placed;
    copies.forEach((copy, i) => {
      const atom = items[i].atom, marker = document.createComment("");
      copy.replaceWith(marker);
      atom.replaceWith(copy);
      marker.replaceWith(atom);
      placed.push([atom, copy]);
    });
    return placed;
  }

  function render(p, map, text, nodes, breaks, space) {
    const fragment = document.createDocumentFragment();
    const codeOf = offset => offset >= 0 && offset < text.length
      ? itemAt(map, offset).element.closest("code") : null;
    let start = 0, cut = false;
    for (let i = 1; i < breaks.length; i++) {
      const choice = breaks[i], node = nodes[choice.position];
      const trimEnd = node.trimEnd ?? node.offset;
      const line = document.createElement("span");
      line.className = "gd-typeset-line";
      line.append(lineFragment(map, start, trimEnd));
      if (node.type === "penalty" && node.penalty > 0 && node.width > 0) {
        line.dataset.hyphen = "";
      }
      // A code box cut by the line break loses its padding and border at the cut.
      if (cut) line.querySelector("code")?.classList.add("gd-code-cut-start");
      cut = codeOf(trimEnd - 1) !== null && codeOf(trimEnd - 1) === codeOf(node.offset);
      if (cut) [...line.querySelectorAll("code")].at(-1)?.classList.add("gd-code-cut-end");
      // CSS justification stretches the spaces of a line, but it never shrinks them.
      if (i < breaks.length - 1 && choice.ratio < 0) {
        line.style.wordSpacing = `${choice.ratio * space / 3}px`;
      }
      if (trimEnd < node.offset) {
        const sep = document.createElement("span");
        sep.className = "gd-line-space";
        sep.textContent = text.slice(trimEnd, node.offset);
        line.append(sep);
      }
      fragment.append(line);
      start = node.offset;
    }
    // Layout is optional: never replace the source with an incomplete result.
    if (start !== text.length || fragment.textContent !== p.textContent) return;
    if (!originals.has(p)) originals.set(p, [...p.childNodes]);
    const placed = moveAtoms(map, fragment);
    if (placed.length !== map.filter(item => item.atom).length) return;
    p.replaceChildren(fragment);
    swaps.set(p, placed);
    p.dataset.layout = "knuth-plass";
  }

  function typeset(p) {
    restore(p);
    const measure = p.clientWidth;
    if (measure < 220) return;
    const {map, text} = textMap(p);
    if (!map.length || !text.trim()) return;
    // Spaces take the paragraph's own font, even where it opens in italics or bold.
    const space = width(" ", fontOf({element: p}));
    const nodes = nodesFor(text, map, space);
    if (nodes.length > 1800) return;
    const breaks = breaker(nodes, [measure - 1], {tolerance: 2, maxTolerance: 4,
      demerits: {line: 10, flagged: 400, fitness: 3000}});
    if (breaks.length < 3 || breaks.at(-1).position !== nodes.length - 1) return;
    if (breaks.slice(1, -1).some(b => b.ratio > 2.5 || b.ratio < -0.95)) return;
    render(p, map, text, nodes, breaks, space);
  }

  let scheduled = false, printing = false;
  function run() {
    scheduled = false;
    if (printing) return;
    for (const p of paragraphs) typeset(p);
  }
  function schedule() {
    if (scheduled || printing) return;
    scheduled = true;
    requestAnimationFrame(run);
  }
  // Inline math is measured as MathJax draws it, so we wait for its first typesetting.
  // Deferred scripts have all run by DOMContentLoaded, so MathJax exists by then if the
  // page loads it.
  const loaded = document.readyState === "loading"
    ? new Promise(resolve => addEventListener("DOMContentLoaded", resolve, {once: true}))
    : Promise.resolve();
  loaded
    .then(() => window.MathJax?.startup?.promise)
    .catch(() => {})
    .then(() => document.fonts.ready)
    .then(() => {
      run();
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
    });
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
      ?.closest('[data-layout="knuth-plass"]');
    const from = paragraph(selection.anchorNode), to = paragraph(selection.focusNode);
    if (!from || from !== to || !event.clipboardData) return;
    event.clipboardData.setData("text/plain", selection.getRangeAt(0).cloneContents().textContent);
    event.preventDefault();
  });
})();
