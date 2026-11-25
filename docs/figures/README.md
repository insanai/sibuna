# Figures

## Diagrams in the published documents

We keep each drawing beside its publication in `docs/book/diagrams`, `docs/whitepaper/diagrams`, or `docs/sid/diagrams`. We include its source in the RST with a Guidedog directive. For example, the operations chapter uses `.. typst-diagram:: diagrams/dns-01.typ` for the DNS exchange and `.. graphviz:: diagrams/edge-paths.dot` for the routing graph. A caption names the figure. Its alt text explains the result for readers who cannot see it.

Guidedog renders both formats during its HTML and PDF builds. The sequence diagrams use CeTZ, and the timetable and OCSP diagrams use Fletcher. A shared style file controls type size and spacing. The book's gettext catalogs translate the captions, alt text and labels in the figure source. When we change that source, we update its message in each catalog.

## Pre-rendered charts and figures

This directory holds the sources, translations and input digests of the book and whitepaper figures rendered by `cargo xtask figures`. They include charts drawn from recorded benchmark data.

```
docs/figures/
  style.typ          colours, fonts, legends and the words of each language
  posw-tree.typ      the proof-of-work tree, shared by two figures
  words/<lang>.toml  the words of every figure, one file per language
  book/*.typ         figures of the book       -> docs/book/assets/figures/
  whitepaper/*.typ   figures of the whitepaper -> docs/whitepaper/assets/figures/
  rendered.txt       what each SVG file was rendered from
```

## Rendering

We render the figures with

```sh
cargo xtask figures
```

The command compiles each figure once per language. English gives `name.svg`, and German gives `name.de.svg`, which guidedog shows in the German build in place of `name.svg`. It needs Typst 0.15 (on the `PATH`, or named by the `TYPST` variable) and the Noto fonts (Debian packages `fonts-noto-core` and `fonts-noto-cjk`). Typst fetches the CeTZ package on first use.

The SVG files are committed, and the documentation builds use them as they are. The command renders a figure only when one of its inputs changed: the figure's source, `style.typ`, a word table, or a data file the figure reads, such as `benchmarks/results/primitives-latest.json`. It records these inputs and a SHA-256 over them in `rendered.txt`. A figure whose inputs are unchanged is not rendered again, so its SVG file does not change in Git, even on a machine with other fonts or another version of Typst. `cargo xtask figures --force` renders every figure.

CI runs `cargo xtask figures --check`. It fails when a source changed but its figure was not rendered again. It needs neither Typst nor the fonts.

## Words and languages

A figure holds no prose of its own. It takes its words from `words/<lang>.toml` by its name, for instance `words("gcra")`. A word that a language leaves out falls back to English. A `{name}` in a word is a value the figure fills in, often a number, which `num` writes with the language's decimal mark and digit groups. Adding a language means adding its word table; the next `cargo xtask figures` renders every figure in it.

## Adding a figure

1. Write `book/<name>.typ` or `whitepaper/<name>.typ`. Start it with `#show: figure-page`, and take its words with `#let w = words("<name>")`.
2. Add a `[<name>]` table to `words/en.toml`, and to the other word tables.
3. Run `cargo xtask figures`.
4. Show it with a figure directive, an `:alt:` text and a caption:

   ```rst
   .. figure:: /assets/figures/<name>.svg
      :alt: What the figure shows, for a reader who cannot see it.

      The caption.
   ```

5. Commit the source, the SVG files and `rendered.txt` together.
