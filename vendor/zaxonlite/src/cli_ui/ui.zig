//! `zaxon_cli_ui` — the shared, domain-neutral terminal UI module
//! (ZDS 0005; Kynetica KDS 0016).
//!
//! Reusable terminal mechanics only: the libvaxis seam with capability
//! detection (`term`), the grapheme-aware line-editor state machine
//! (`editor`), bounded history with reverse search (`history`), the SQL
//! tokenizer and multi-line continuation answer (`highlight`), the neutral
//! result view with plain/JSON writers (`view`), the aligned rich
//! renderers (`table`), the interactive line reader (`reader`), and the
//! alternate-screen pager (`pager`).
//!
//! This module never imports `zaxonlite` or any product code. It knows
//! nothing about SQL execution, table names, prompts, dot commands,
//! authentication, or authorization: Zaxon's shell and Kynetica's database
//! shell are separate callers composing these pieces.

pub const term = @import("term.zig");
pub const editor = @import("editor.zig");
pub const history = @import("history.zig");
pub const highlight = @import("highlight.zig");
pub const view = @import("view.zig");
pub const table = @import("table.zig");
pub const reader = @import("reader.zig");
pub const pager = @import("pager.zig");

pub const View = view.View;
pub const LineReader = reader.LineReader;

test {
    // Collect tests from every file in this module.
    _ = term;
    _ = editor;
    _ = history;
    _ = highlight;
    _ = view;
    _ = table;
    _ = reader;
    _ = pager;
    _ = @import("tests.zig");
}
