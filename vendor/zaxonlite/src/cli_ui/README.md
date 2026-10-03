# zaxon-cli-ui

The terminal parts of a database shell, with the database removed.

## The idea

Every good interactive shell is really two programs. One program knows the
domain: SQL, sessions, dot commands, authentication. The other program
knows terminals: how to edit a line when the cursor sits inside a grapheme
cluster, how to search history backward, how to align a table when a cell
contains something hostile, how to page output without losing the screen.

People keep writing the second program badly, over and over, inside the
first one. So we pulled it out. `zaxon_cli_ui` is only the second program.
It knows nothing about SQL execution, table names, prompts, dot commands,
or authorization. It cannot connect to anything. That is not a limitation.
That is the design. Two different shells, the
[zaxon](https://github.com/insanai/zaxonlite) SQL shell and Kynetica's
database shell, are built by composing these pieces, and neither leaks into
this module.

## What is in the box

Each piece is a small module with a single job:

- `term`: the [libvaxis](https://github.com/rockorager/libvaxis) seam and
  terminal capability detection.
- `editor`: a grapheme-aware line-editor state machine.
- `history`: bounded history with reverse search (`ctrl+r`).
- `highlight`: a SQL tokenizer and the multi-line continuation answer.
- `view`: a neutral result view with plain and JSON writers.
- `table`: aligned rich renderers, including sanitization of hostile cells.
- `reader`: the interactive `LineReader` that ties the pieces together.
- `pager`: an alternate-screen pager.

One rule matters to callers: when output is piped or scripted, the plain
writers produce byte-for-byte stable output. Interactive polish never
changes what a script sees.

Almost everything here is a pure state machine. Key sequences drive the
editor, text drives the tokenizer and history, and the renderers are
compared against golden strings. The whole test suite runs without a TTY:

```sh
zig build test
```

## Getting it

```sh
zig fetch --save https://github.com/insanai/zaxon-cli-ui/archive/refs/tags/v0.7.0.tar.gz
```

Then in your `build.zig`:

```zig
const cli_ui = b.dependency("zaxon_cli_ui", .{
    .target = target,
    .optimize = optimize,
}).module("zaxon_cli_ui");

// add to your executable's imports:
.imports = &.{
    .{ .name = "zaxon_cli_ui", .module = cli_ui },
},
```

And in your code:

```zig
const ui = @import("zaxon_cli_ui");

// ui.LineReader, ui.View, ui.editor, ui.history, ui.highlight,
// ui.table, ui.reader, ui.pager, ui.term
```

The only dependency is libvaxis, pinned in `build.zig.zon`. Zig 0.16.

## Where it came from

This module was extracted from the `zaxon` interactive shell in
[zaxonlite](https://github.com/insanai/zaxonlite). The design is recorded
in ZDS 0005 (and Kynetica's KDS 0016) in the
[insanai/zxdocs](https://github.com/insanai/zxdocs) repository. What
stayed behind in zaxonlite is exactly the domain half: statement routing,
the dot-command registry, and remote result conversion.

## License

MIT. Copyright 2026 Vikrant Rathore and Ronak Rathore. See
[LICENSE](LICENSE).
