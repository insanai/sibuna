//! Canonical USTAR/GNU tar subset used by the signed minimal release. Never writes
//! to a filesystem. Unsupported extensions reject the entire candidate; a signed
//! archive still cannot supply links, devices, ambiguous names or wrapped sizes.
const std = @import("std");
const paths = @import("rule_data.zig");
const work = @import("work.zig");
const buffers = @import("buffers.zig");
pub const Error = work.Error || error{
    InvalidArchive,
    InvalidArchivePath,
    UnsupportedArchiveEntry,
    DuplicateArchiveEntry,
    ArchiveEntryLimit,
    ArchiveNameLimit,
    ArchiveByteLimit,
};
pub const Kind = enum { file, directory };
pub const Entry = struct { path: []const u8, bytes: []const u8, kind: Kind };
pub const maximum_entries = 256;
pub const maximum_source = 32 * 1024 * 1024;
pub const maximum_expanded = maximum_source + maximum_entries * 1024 + 1024;
pub const maximum_names = maximum_entries * 256;
pub const Reader = struct {
    entries: []Entry,
    names: []u8,
    used: usize = 0,
    name_used: usize = 0,

    /// Names are copied into caller-owned monotonic storage; file data borrows the
    /// complete expanded archive until compilation ends. Initialize only once.
    pub fn parse(
        self: *Reader,
        input: []const u8,
        prefix: []const u8,
        budget: *work.Budget,
    ) Error![]const Entry {
        if (self.used != 0 or self.name_used != 0 or self.entries.len > maximum_entries or
            input.len > maximum_expanded or input.len < 1024 or input.len % 512 != 0)
            return error.InvalidArchive;
        paths.validatePath(prefix) catch return error.InvalidArchivePath;
        buffers.assertExclusive(&.{ input, self.names, std.mem.sliceAsBytes(self.entries) });
        try budget.debitLinear(input.len, 8, 1);
        var at: usize = 0;
        var total: usize = 0;
        var terminated = false;
        while (input.len - at >= 512) {
            const head = input[at..][0..512];
            if (zero(head)) {
                if (input.len - at < 1024 or !zero(input[at..])) return error.InvalidArchive;
                terminated = true;
                break;
            }
            const kind = try header(head);
            const size = try octal(head[124..136]);
            if (size > maximum_source - total) return error.ArchiveByteLimit;
            if (kind == .directory and size != 0) return error.InvalidArchive;
            total += size;
            const padded = std.mem.alignForward(usize, size, 512);
            at += 512;
            if (padded > input.len - at) return error.InvalidArchive;
            var full: [256]u8 = undefined;
            const name = try fullName(head, &full);
            const normalized = if (kind == .directory and name[name.len - 1] == '/')
                name[0 .. name.len - 1]
            else
                name;
            paths.validatePath(normalized) catch return error.InvalidArchivePath;
            const relative = try stripPrefix(normalized, prefix, kind);
            if (!zero(input[at + size ..][0 .. padded - size])) return error.InvalidArchive;
            try self.append(relative, input[at..][0..size], kind, budget);
            at += padded;
        }
        if (!terminated or self.used == 0) return error.InvalidArchive;
        return self.entries[0..self.used];
    }

    fn append(
        self: *Reader,
        name: []const u8,
        bytes: []const u8,
        kind: Kind,
        budget: *work.Budget,
    ) Error!void {
        if (self.used == self.entries.len) return error.ArchiveEntryLimit;
        if (name.len > self.names.len - self.name_used) return error.ArchiveNameLimit;
        for (self.entries[0..self.used]) |previous| {
            try budget.debit(name.len + 1);
            if (std.mem.eql(u8, previous.path, name)) return error.DuplicateArchiveEntry;
        }
        try budget.debit(name.len + 1);
        const owned = self.names[self.name_used..][0..name.len];
        @memcpy(owned, name);
        self.name_used += name.len;
        self.entries[self.used] = .{ .path = owned, .bytes = bytes, .kind = kind };
        self.used += 1;
    }
};

fn header(bytes: []const u8) Error!Kind {
    if (!std.mem.eql(u8, bytes[257..265], "ustar\x0000") and
        !std.mem.eql(u8, bytes[257..265], "ustar  \x00")) return error.InvalidArchive;
    const expected = try octal(bytes[148..156]);
    var checksum: usize = 0;
    for (bytes, 0..) |byte, index| {
        checksum += if (index >= 148 and index < 156) 32 else byte;
    }
    if (checksum != expected) return error.InvalidArchive;
    if (!zero(bytes[157..257])) return error.UnsupportedArchiveEntry;
    return switch (bytes[156]) {
        0, '0' => .file,
        '5' => .directory,
        else => error.UnsupportedArchiveEntry,
    };
}

fn octal(bytes: []const u8) Error!usize {
    const text = std.mem.trim(u8, bytes, "\x00 ");
    if (text.len == 0) return error.InvalidArchive;
    var value: usize = 0;
    for (text) |byte| {
        if (byte < '0' or byte > '7') return error.InvalidArchive;
        value = std.math.mul(usize, value, 8) catch return error.ArchiveByteLimit;
        value = std.math.add(usize, value, byte - '0') catch return error.ArchiveByteLimit;
    }
    return value;
}

fn fullName(head: []const u8, output: *[256]u8) Error![]const u8 {
    const name = try string(head[0..100]);
    // GNU uses this region for other metadata, not a USTAR path prefix. The
    // minimal release leaves it zero; reject richer GNU variants explicitly.
    if (std.mem.eql(u8, head[257..265], "ustar  \x00") and !zero(head[345..500]))
        return error.UnsupportedArchiveEntry;
    const prefix = try string(head[345..500]);
    if (name.len == 0) return error.InvalidArchivePath;
    const separator: usize = @intFromBool(prefix.len != 0);
    const length = prefix.len + separator + name.len;
    @memcpy(output[0..prefix.len], prefix);
    if (separator != 0) output[prefix.len] = '/';
    @memcpy(output[prefix.len + separator ..][0..name.len], name);
    return output[0..length];
}

fn string(bytes: []const u8) Error![]const u8 {
    const end = std.mem.indexOfScalar(u8, bytes, 0) orelse bytes.len;
    if (!zero(bytes[end..])) return error.InvalidArchive;
    for (bytes[0..end]) |byte| if (byte < 32 or byte == 127) return error.InvalidArchivePath;
    return bytes[0..end];
}

fn stripPrefix(name: []const u8, prefix: []const u8, kind: Kind) Error![]const u8 {
    if (std.mem.eql(u8, name, prefix)) {
        if (kind != .directory) return error.InvalidArchivePath;
        return "";
    }
    if (name.len <= prefix.len or !std.mem.startsWith(u8, name, prefix) or
        name[prefix.len] != '/') return error.InvalidArchivePath;
    return name[prefix.len + 1 ..];
}

fn zero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}

test {
    _ = @import("release_tar_test.zig");
}
