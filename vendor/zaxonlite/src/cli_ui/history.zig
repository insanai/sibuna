//! Bounded statement history with readline navigation semantics and
//! reverse incremental search (ZDS 0005, M2/M3).
//!
//! Pure state plus explicit load/save: navigation never mutates stored
//! entries (a recalled entry is edited as a copy in the editor), entries
//! beginning with a space are never stored, and consecutive duplicates
//! collapse. The persistence format is one entry per line with newlines
//! and backslashes escaped, written with owner-only permissions because
//! operators paste secrets into SQL.

const std = @import("std");
const builtin = @import("builtin");

pub const max_entries = 1000;
const max_file_bytes = 4 * 1024 * 1024;
const max_entry_bytes = 64 * 1024;

pub const History = struct {
    gpa: std.mem.Allocator,
    entries: std.ArrayList([]u8) = .empty,
    encoded_bytes: usize = 0,
    nav: ?usize = null,
    saved: ?[]u8 = null,

    pub fn init(gpa: std.mem.Allocator) History {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *History) void {
        for (self.entries.items) |item| self.gpa.free(item);
        self.entries.deinit(self.gpa);
        if (self.saved) |saved| self.gpa.free(saved);
        self.* = undefined;
    }

    pub fn count(self: *const History) usize {
        return self.entries.items.len;
    }

    pub fn entry(self: *const History, index: usize) []const u8 {
        return self.entries.items[index];
    }

    /// Records a submitted statement. A leading space is the standard
    /// escape hatch for sensitive statements; consecutive duplicates are
    /// stored once; the oldest entry is evicted beyond the bound.
    pub fn append(self: *History, text: []const u8) !void {
        if (text.len == 0 or text.len > max_entry_bytes or text[0] == ' ') return;
        if (self.entries.items.len > 0) {
            const last = self.entries.items[self.entries.items.len - 1];
            if (std.mem.eql(u8, last, text)) return;
        }
        const copy = try self.gpa.dupe(u8, text);
        errdefer self.gpa.free(copy);
        std.debug.assert(self.entries.items.len <= max_entries);
        try self.entries.append(self.gpa, copy);
        self.encoded_bytes += encodedSize(text) + 1;
        while (self.entries.items.len > max_entries or
            self.encoded_bytes > max_file_bytes)
        {
            const evicted = self.entries.orderedRemove(0);
            self.encoded_bytes -= encodedSize(evicted) + 1;
            self.gpa.free(evicted);
        }
        std.debug.assert(self.entries.items.len <= max_entries);
    }

    /// Walks backward from the in-progress line. The first call saves the
    /// current line so `next` past the newest entry restores it.
    pub fn prev(self: *History, current: []const u8) !?[]const u8 {
        if (self.entries.items.len == 0) return null;
        if (self.nav) |index| {
            if (index == 0) return self.entries.items[0];
            self.nav = index - 1;
            return self.entries.items[index - 1];
        }
        const copy = try self.gpa.dupe(u8, current);
        if (self.saved) |old| self.gpa.free(old);
        self.saved = copy;
        self.nav = self.entries.items.len - 1;
        return self.entries.items[self.entries.items.len - 1];
    }

    /// Walks forward; past the newest entry it returns the saved
    /// in-progress line and leaves navigation.
    pub fn next(self: *History) ?[]const u8 {
        const index = self.nav orelse return null;
        if (index + 1 < self.entries.items.len) {
            self.nav = index + 1;
            return self.entries.items[index + 1];
        }
        self.nav = null;
        if (self.saved) |saved| {
            // The caller copies before the next mutation; free lazily.
            return saved;
        }
        return "";
    }

    /// Leaves navigation mode, dropping the saved line.
    pub fn resetNav(self: *History) void {
        self.nav = null;
        if (self.saved) |saved| {
            self.gpa.free(saved);
            self.saved = null;
        }
    }

    /// Backward substring scan for `ctrl+r`: the newest match strictly
    /// before `before`, or from the end when `before` is null.
    pub fn searchBefore(
        self: *const History,
        query: []const u8,
        before: ?usize,
    ) ?usize {
        if (query.len == 0) return null;
        var index = before orelse self.entries.items.len;
        while (index > 0) {
            index -= 1;
            if (std.mem.indexOf(u8, self.entries.items[index], query) != null) {
                return index;
            }
        }
        return null;
    }

    /// Loads persisted history; a missing file is an empty history, and a
    /// malformed line is skipped rather than fatal.
    pub fn load(self: *History, io: std.Io, path: []const u8) !void {
        const bytes = std.Io.Dir.cwd().readFileAlloc(
            io,
            path,
            self.gpa,
            .limited(max_file_bytes),
        ) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer self.gpa.free(bytes);
        var lines = std.mem.splitScalar(u8, bytes, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            const decoded = decodeAlloc(self.gpa, line) catch |err| switch (err) {
                error.InvalidEscape => continue,
                else => return err,
            };
            defer self.gpa.free(decoded);
            try self.append(decoded);
        }
    }

    /// Writes the history file with owner-only permissions. Statements may
    /// contain secrets; the mode is not optional.
    pub fn save(self: *const History, io: std.Io, path: []const u8) !void {
        var data: std.Io.Writer.Allocating = .init(self.gpa);
        defer data.deinit();
        for (self.entries.items) |item| {
            try encode(&data.writer, item);
            try data.writer.writeAll("\n");
        }
        var file = try std.Io.Dir.cwd().createFile(io, path, .{
            .truncate = false,
            .permissions = @fromBackingInt(@intCast(0o600)),
        });
        defer file.close(io);
        // Creation permissions do not tighten an existing file, so enforce
        // the security invariant on the opened handle before writing data.
        // Windows uses the file's inherited ACL and Zig 0.16 does not
        // implement its POSIX-shaped file permission setter.
        if (builtin.os.tag != .windows) {
            try file.setPermissions(io, @fromBackingInt(@intCast(0o600)));
        }
        try file.setLength(io, 0);
        try file.writeStreamingAll(io, data.written());
    }
};

fn encodedSize(text: []const u8) usize {
    var size: usize = 0;
    for (text) |byte| {
        size += if (byte == '\\' or byte == '\n') 2 else 1;
    }
    return size;
}

fn encode(out: *std.Io.Writer, text: []const u8) !void {
    for (text) |byte| {
        switch (byte) {
            '\\' => try out.writeAll("\\\\"),
            '\n' => try out.writeAll("\\n"),
            else => try out.writeAll(&.{byte}),
        }
    }
}

fn decodeAlloc(gpa: std.mem.Allocator, line: []const u8) ![]u8 {
    var decoded = try gpa.alloc(u8, line.len);
    errdefer gpa.free(decoded);
    var length: usize = 0;
    var index: usize = 0;
    while (index < line.len) : (index += 1) {
        const byte = line[index];
        if (byte == '\\' and index + 1 == line.len) return error.InvalidEscape;
        if (byte == '\\') {
            index += 1;
            decoded[length] = switch (line[index]) {
                'n' => '\n',
                '\\' => '\\',
                else => return error.InvalidEscape,
            };
        } else {
            decoded[length] = byte;
        }
        length += 1;
    }
    if (gpa.resize(decoded, length)) {
        return decoded[0..length];
    }
    const exact = try gpa.dupe(u8, decoded[0..length]);
    gpa.free(decoded);
    return exact;
}
