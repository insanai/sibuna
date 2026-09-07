//! Shibuna Discussion (SID) management tool.
//!
//! Drives the numbering workflow defined in SID 0001: placeholder drafts are
//! created from the template as `XXXXX-<slug>.typ`, and promotion assigns the
//! next permanent four-digit number, rewrites the draft's metadata, and adds
//! the registry and bundle entries. `build.zig` discovers numbered records by
//! scanning `docs/sid/records`, so no build file edit is needed.

const std = @import("std");
const Io = std.Io;

const usage_text =
    \\usage: sid-tool --root <repo-root> <command> [arguments]
    \\
    \\Commands:
    \\  list             Show registry entries and placeholder drafts.
    \\  new <slug>       Create docs/sid/records/XXXXX-<slug>.typ from the
    \\                   template with today's date.
    \\  promote <slug>   Assign the next four-digit number to the placeholder
    \\                   draft XXXXX-<slug>.typ, rewrite its metadata for
    \\                   discussion, and append registry.typ and bundle.typ
    \\                   entries.
    \\
    \\Slugs are lowercase words separated by hyphens, as in `sha256-simd`.
    \\
;

const records_dir = "docs/sid/records";
const registry_path = "docs/sid/registry.typ";
const bundle_path = "docs/sid/bundle.typ";
const template_path = "docs/sid/template/rfc-template.typ";
const placeholder = "XXXXX";
const maximum_file_bytes = 4 * 1024 * 1024;

const exit_ok: u8 = 0;
const exit_error: u8 = 1;
const exit_usage: u8 = 2;

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;

    var stdout_buffer: [16 * 1024]u8 = undefined;
    var stdout_writer = Io.File.stdout().writerStreaming(io, &stdout_buffer);
    const out = &stdout_writer.interface;
    var stderr_buffer: [4096]u8 = undefined;
    var stderr_writer = Io.File.stderr().writerStreaming(io, &stderr_buffer);
    const err_out = &stderr_writer.interface;

    const code = run(gpa, io, init.minimal.args, out, err_out) catch |err| blk: {
        err_out.print("error: {t}\n", .{err}) catch {};
        break :blk exit_error;
    };
    out.flush() catch {};
    err_out.flush() catch {};
    return code;
}

fn run(
    gpa: std.mem.Allocator,
    io: Io,
    args: std.process.Args,
    out: *Io.Writer,
    err_out: *Io.Writer,
) !u8 {
    var iterator = std.process.Args.Iterator.init(args);
    defer iterator.deinit();
    _ = iterator.next();

    var root_path: ?[]const u8 = null;
    var command: ?[]const u8 = null;
    var operand: ?[]const u8 = null;
    while (iterator.next()) |arg| {
        if (std.mem.eql(u8, arg, "--root")) {
            root_path = iterator.next() orelse return usageError(err_out, "--root needs value");
        } else if (command == null) {
            command = arg;
        } else if (operand == null) {
            operand = arg;
        } else {
            return usageError(err_out, "too many arguments");
        }
    }

    const root = root_path orelse return usageError(err_out, "--root is required");
    const name = command orelse {
        try out.writeAll(usage_text);
        return exit_usage;
    };

    var root_dir = Io.Dir.cwd().openDir(io, root, .{}) catch |err| {
        try err_out.print("error: cannot open repository root {s}: {t}\n", .{ root, err });
        return exit_error;
    };
    defer root_dir.close(io);

    if (std.mem.eql(u8, name, "list")) {
        if (operand != null) return usageError(err_out, "list takes no argument");
        return list(gpa, io, root_dir, out);
    }
    if (std.mem.eql(u8, name, "new")) {
        const slug = operand orelse return usageError(err_out, "new needs a slug");
        return create(gpa, io, root_dir, slug, out, err_out);
    }
    if (std.mem.eql(u8, name, "promote")) {
        const slug = operand orelse return usageError(err_out, "promote needs a slug");
        return promote(gpa, io, root_dir, slug, out, err_out);
    }
    return usageError(err_out, "unknown command; expected list, new, or promote");
}

fn usageError(err_out: *Io.Writer, message: []const u8) !u8 {
    try err_out.print("error: {s}\n\n", .{message});
    try err_out.writeAll(usage_text);
    return exit_usage;
}

// ---------------------------------------------------------------- list

fn list(gpa: std.mem.Allocator, io: Io, root: Io.Dir, out: *Io.Writer) !u8 {
    const registry = try root.readFileAlloc(io, registry_path, gpa, .limited(maximum_file_bytes));
    defer gpa.free(registry);

    try out.writeAll("Registered discussions:\n");
    var registered: std.ArrayList([]const u8) = .empty;
    defer {
        for (registered.items) |entry| gpa.free(entry);
        registered.deinit(gpa);
    }
    var cursor: usize = 0;
    while (fieldAfter(registry, &cursor, "number: \"")) |number| {
        var entry_cursor = cursor;
        const slug = fieldAfter(registry, &entry_cursor, "slug: \"") orelse break;
        const title = fieldAfter(registry, &entry_cursor, "title: \"") orelse break;
        const state = fieldAfter(registry, &entry_cursor, "state: \"") orelse break;
        cursor = entry_cursor;
        try registered.append(gpa, try std.fmt.allocPrint(gpa, "{s}-{s}", .{ number, slug }));
        try out.print("  SID {s}  {s:<13}  {s}  ({s})\n", .{ number, state, title, slug });
    }

    var names = try recordFileNames(gpa, io, root);
    defer {
        for (names.items) |file_name| gpa.free(file_name);
        names.deinit(gpa);
    }

    var drafts_seen = false;
    for (names.items) |file_name| {
        const stem = file_name[0 .. file_name.len - ".typ".len];
        if (std.mem.startsWith(u8, stem, placeholder ++ "-")) {
            if (!drafts_seen) {
                try out.writeAll("Placeholder drafts:\n");
                drafts_seen = true;
            }
            try out.print("  {s}  (promote with: zig build sid-promote -- {s})\n", .{
                file_name,
                stem[placeholder.len + 1 ..],
            });
        }
    }

    try checkMismatches(names.items, registered.items, out);
    return exit_ok;
}

fn checkMismatches(
    names: []const []const u8,
    registered: []const []const u8,
    out: *Io.Writer,
) !void {
    for (names) |file_name| {
        const stem = file_name[0 .. file_name.len - ".typ".len];
        if (std.mem.startsWith(u8, stem, placeholder ++ "-")) continue;
        var known = false;
        for (registered) |entry| known = known or std.mem.eql(u8, entry, stem);
        if (!known) {
            try out.print("warning: {s}/{s} has no registry.typ entry\n", .{
                records_dir,
                file_name,
            });
        }
    }
    for (registered) |entry| {
        var present = false;
        for (names) |file_name| {
            const stem = file_name[0 .. file_name.len - ".typ".len];
            present = present or std.mem.eql(u8, entry, stem);
        }
        if (!present) try out.print("warning: registry entry {s} has no record file\n", .{entry});
    }
}

// ----------------------------------------------------------------- new

fn create(
    gpa: std.mem.Allocator,
    io: Io,
    root: Io.Dir,
    slug: []const u8,
    out: *Io.Writer,
    err_out: *Io.Writer,
) !u8 {
    if (!validSlug(slug)) {
        return usageError(err_out, "slug must be lowercase words joined by hyphens");
    }

    const draft_path = try std.fmt.allocPrint(
        gpa,
        records_dir ++ "/" ++ placeholder ++ "-{s}.typ",
        .{slug},
    );
    defer gpa.free(draft_path);
    if (fileExists(io, root, draft_path)) {
        try err_out.print("error: {s} already exists\n", .{draft_path});
        return exit_error;
    }

    const template = try root.readFileAlloc(io, template_path, gpa, .limited(maximum_file_bytes));
    defer gpa.free(template);
    const date = try today(io);
    const quoted_date = try std.fmt.allocPrint(gpa, "\"{s}\"", .{&date});
    defer gpa.free(quoted_date);
    const dated = try replaceOnce(gpa, template, "\"YYYY-MM-DD\"", quoted_date);
    defer gpa.free(dated);

    try root.writeFile(io, .{ .sub_path = draft_path, .data = dated });
    try out.print("created {s}\n", .{draft_path});
    try out.print("promote when ready: zig build sid-promote -- {s}\n", .{slug});
    return exit_ok;
}

// ------------------------------------------------------------- promote

fn findHighestRecordNumber(names: []const []const u8) u16 {
    var highest: u16 = 0;
    for (names) |file_name| {
        const parsed = std.fmt.parseInt(u16, file_name[0..4], 10) catch continue;
        highest = @max(highest, parsed);
    }
    return highest;
}

fn buildRegistryEntry(
    gpa: std.mem.Allocator,
    num: []const u8,
    slug: []const u8,
    title: []const u8,
    area: []const u8,
    category: []const u8,
    created: []const u8,
    date: []const u8,
    summary: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(gpa,
        \\  (
        \\    number: "{s}",
        \\    slug: "{s}",
        \\    title: "{s}",
        \\    state: "discussion",
        \\    area: "{s}",
        \\    category: "{s}",
        \\    status: "Open for Discussion",
        \\    created: "{s}",
        \\    updated: "{s}",
        \\    summary: "{s}",
        \\    source: "docs/sid/records/{s}-{s}.typ",
        \\    html: "sid/{s}-{s}.html",
        \\    pdf: "pdf/sid-{s}-{s}.pdf",
        \\  ),
        \\
    , .{
        num,     slug, title, area, category, created, date,
        summary, num,  slug,  num,  slug,     num,     slug,
    });
}

fn buildBundleEntry(
    gpa: std.mem.Allocator,
    num: []const u8,
    slug: []const u8,
    title: []const u8,
    summary: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(gpa,
        \\
        \\#document(
        \\  "sid/{s}-{s}.html",
        \\  title: [SID {s}: {s}],
        \\  author: ("Sibuna Contributors",),
        \\  description: [{s}],
        \\)[
        \\  #include "records/{s}-{s}.typ"
        \\]
        \\
        \\#document("pdf/sid-{s}-{s}.pdf")[
        \\  #include "records/{s}-{s}.typ"
        \\]
        \\
    , .{
        num,  slug, num, title, summary,
        num,  slug, num, slug,  num,
        slug,
    });
}

fn rewriteDraftContent(
    gpa: std.mem.Allocator,
    draft: []const u8,
    number: []const u8,
    date: []const u8,
) ![]u8 {
    var content = try replaceMeta(gpa, draft, "number", number);
    content = try replaceMetaOwned(gpa, content, "state", "discussion");
    content = try replaceMetaOwned(gpa, content, "status", "Open for Discussion");
    content = try replaceMetaOwned(gpa, content, "last-updated", date);
    if (std.mem.eql(u8, metaValue(content, "created") orelse "", "YYYY-MM-DD")) {
        content = try replaceMetaOwned(gpa, content, "created", date);
    }
    return content;
}

fn appendToRegistry(
    gpa: std.mem.Allocator,
    io: Io,
    root: Io.Dir,
    entry: []const u8,
) !void {
    const registry = try root.readFileAlloc(io, registry_path, gpa, .limited(maximum_file_bytes));
    defer gpa.free(registry);
    const close_at = std.mem.lastIndexOf(u8, registry, "\n)") orelse {
        return error.MissingClosingParenthesis;
    };
    const updated = try std.mem.concat(gpa, u8, &.{
        registry[0 .. close_at + 1],
        entry,
        registry[close_at + 1 ..],
    });
    defer gpa.free(updated);
    try root.writeFile(io, .{ .sub_path = registry_path, .data = updated });
}

fn appendToBundle(
    gpa: std.mem.Allocator,
    io: Io,
    root: Io.Dir,
    entry: []const u8,
) !void {
    const bundle = try root.readFileAlloc(io, bundle_path, gpa, .limited(maximum_file_bytes));
    defer gpa.free(bundle);
    const updated = try std.mem.concat(gpa, u8, &.{ bundle, entry });
    defer gpa.free(updated);
    try root.writeFile(io, .{ .sub_path = bundle_path, .data = updated });
}

fn promote(
    gpa: std.mem.Allocator,
    io: Io,
    root: Io.Dir,
    slug: []const u8,
    out: *Io.Writer,
    err_out: *Io.Writer,
) !u8 {
    if (!validSlug(slug)) {
        return usageError(err_out, "slug must be lowercase words joined by hyphens");
    }

    const draft_path = try std.fmt.allocPrint(
        gpa,
        records_dir ++ "/" ++ placeholder ++ "-{s}.typ",
        .{slug},
    );
    defer gpa.free(draft_path);
    const draft = root.readFileAlloc(
        io,
        draft_path,
        gpa,
        .limited(maximum_file_bytes),
    ) catch |err| {
        try err_out.print("error: cannot read {s}: {t}\n", .{ draft_path, err });
        return exit_error;
    };
    defer gpa.free(draft);

    var names = try recordFileNames(gpa, io, root);
    defer {
        for (names.items) |file_name| gpa.free(file_name);
        names.deinit(gpa);
    }

    var number: [4]u8 = undefined;
    _ = try std.fmt.bufPrint(&number, "{d:0>4}", .{findHighestRecordNumber(names.items) + 1});

    const date = try today(io);
    const content = try rewriteDraftContent(gpa, draft, &number, &date);
    defer gpa.free(content);

    const title = metaValue(content, "title") orelse "Untitled";
    const summary = metaValue(content, "discussion") orelse "";
    const created = metaValue(content, "created") orelse &date;
    const area = firstLabel(content) orelse "engineering";
    const category = metaValue(content, "category") orelse "Engineering Discussion";

    const record_path = try std.fmt.allocPrint(
        gpa,
        records_dir ++ "/{s}-{s}.typ",
        .{ number, slug },
    );
    defer gpa.free(record_path);
    if (fileExists(io, root, record_path)) {
        try err_out.print("error: {s} already exists\n", .{record_path});
        return exit_error;
    }

    const reg_entry = try buildRegistryEntry(
        gpa,
        &number,
        slug,
        title,
        area,
        category,
        created,
        &date,
        summary,
    );
    defer gpa.free(reg_entry);
    const bun_entry = try buildBundleEntry(gpa, &number, slug, title, summary);
    defer gpa.free(bun_entry);

    try appendToRegistry(gpa, io, root, reg_entry);
    try appendToBundle(gpa, io, root, bun_entry);
    try root.writeFile(io, .{ .sub_path = record_path, .data = content });
    try root.deleteFile(io, draft_path);

    try out.print("promoted {s} -> {s}\n", .{ draft_path, record_path });
    try out.print("updated {s} and {s}\n", .{ registry_path, bundle_path });
    try out.print("build it with: zig build sid -Dsid={s}\n", .{number});
    try out.writeAll("review the registry summary and area fields before committing.\n");
    return exit_ok;
}

// ------------------------------------------------------------- helpers

fn recordFileNames(
    gpa: std.mem.Allocator,
    io: Io,
    root: Io.Dir,
) !std.ArrayList([]const u8) {
    var names: std.ArrayList([]const u8) = .empty;
    errdefer names.deinit(gpa);
    var dir = try root.openDir(io, records_dir, .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".typ")) continue;
        if (entry.name.len < "0000-a.typ".len) continue;
        try names.append(gpa, try gpa.dupe(u8, entry.name));
    }
    std.mem.sort([]const u8, names.items, {}, stringLessThan);
    return names;
}

fn stringLessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn fileExists(io: Io, root: Io.Dir, sub_path: []const u8) bool {
    root.access(io, sub_path, .{}) catch return false;
    return true;
}

fn validSlug(slug: []const u8) bool {
    if (slug.len == 0 or slug[0] == '-' or slug[slug.len - 1] == '-') return false;
    for (slug) |byte| {
        const ok = std.ascii.isLower(byte) or std.ascii.isDigit(byte) or byte == '-';
        if (!ok) return false;
    }
    return std.mem.indexOf(u8, slug, "--") == null;
}

/// Returns the value of `#let sid-<key> = "<value>"`, or null.
fn metaValue(source: []const u8, comptime key: []const u8) ?[]const u8 {
    const prefix = "#let sid-" ++ key ++ " = \"";
    const start = (std.mem.indexOf(u8, source, prefix) orelse return null) + prefix.len;
    const end = std.mem.indexOfScalarPos(u8, source, start, '"') orelse return null;
    return source[start..end];
}

/// Returns the first entry of `#let sid-labels = ("a", ...)`, or null.
fn firstLabel(source: []const u8) ?[]const u8 {
    const prefix = "#let sid-labels = (\"";
    const start = (std.mem.indexOf(u8, source, prefix) orelse return null) + prefix.len;
    const end = std.mem.indexOfScalarPos(u8, source, start, '"') orelse return null;
    return source[start..end];
}

fn replaceMeta(
    gpa: std.mem.Allocator,
    source: []const u8,
    comptime key: []const u8,
    value: []const u8,
) ![]u8 {
    const old = metaValue(source, key) orelse return error.MissingMetadata;
    const value_start = @intFromPtr(old.ptr) - @intFromPtr(source.ptr);
    return std.mem.concat(gpa, u8, &.{
        source[0..value_start],
        value,
        source[value_start + old.len ..],
    });
}

fn replaceMetaOwned(
    gpa: std.mem.Allocator,
    source: []u8,
    comptime key: []const u8,
    value: []const u8,
) ![]u8 {
    defer gpa.free(source);
    return replaceMeta(gpa, source, key, value);
}

fn replaceOnce(
    gpa: std.mem.Allocator,
    source: []const u8,
    needle: []const u8,
    replacement: []const u8,
) ![]u8 {
    const at = std.mem.indexOf(u8, source, needle) orelse return error.MissingMetadata;
    return std.mem.concat(gpa, u8, &.{
        source[0..at],
        replacement,
        source[at + needle.len ..],
    });
}

fn fieldAfter(
    source: []const u8,
    cursor: *usize,
    comptime prefix: []const u8,
) ?[]const u8 {
    const start = (std.mem.indexOfPos(u8, source, cursor.*, prefix) orelse return null) +
        prefix.len;
    const end = std.mem.indexOfScalarPos(u8, source, start, '"') orelse return null;
    cursor.* = end + 1;
    return source[start..end];
}

/// Today's UTC date as `YYYY-MM-DD`.
fn today(io: Io) ![10]u8 {
    const timestamp = Io.Clock.real.now(io);
    const seconds: u64 = @intCast(@divTrunc(timestamp.nanoseconds, std.time.ns_per_s));
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = seconds };
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    var date: [10]u8 = undefined;
    _ = try std.fmt.bufPrint(&date, "{d:0>4}-{d:0>2}-{d:0>2}", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
    });
    return date;
}
