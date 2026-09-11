//! Embedded browser assets are served under a content digest so a new build names its
//! files; the shell resolves those names at start and is the only revalidated document.
const std = @import("std");
const Context = @import("http.zig").Context;
const wasm = @embedFile("console_wasm");
// The contract test checks the same bound in the build verifier and browser loader.
const max_wasm_bytes = 768 * 1024;
comptime {
    if (wasm.len > max_wasm_bytes) @compileError("console Wasm exceeds the 768 KiB budget");
}
const names = [_][]const u8{ "console.wasm", "glue.js", "console.css" };
const types = [_][]const u8{ "application/wasm", "text/javascript", "text/css" };
const bytes = [_][]const u8{ wasm, @embedFile("console_glue"), @embedFile("console_css") };
const placeholders = [_][]const u8{ "{{ wasm }}", "{{ glue }}", "{{ css }}" };
const shell_template = @embedFile("console_shell");
pub const prefix_len = 16;
pub const immutable = "public, max-age=31536000, immutable";

pub const Assets = struct {
    prefixes: [names.len][prefix_len]u8,
    shell_bytes: [shell_template.len + names.len * prefix_len]u8,
    shell_len: usize,

    pub fn init() Assets {
        var self: Assets = undefined;
        for (bytes, &self.prefixes) |content, *prefix| {
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(content, &digest, .{});
            prefix.* = std.fmt.bytesToHex(digest[0 .. prefix_len / 2], .lower);
        }
        var writer: std.Io.Writer = .fixed(&self.shell_bytes);
        var rest: []const u8 = shell_template;
        while (rest.len != 0) {
            const index, const placeholder = nextPlaceholder(rest) orelse {
                writer.writeAll(rest) catch unreachable;
                break;
            };
            writer.writeAll(rest[0..index]) catch unreachable;
            writer.writeAll(&self.prefixes[placeholder]) catch unreachable;
            rest = rest[index + placeholders[placeholder].len ..];
        }
        self.shell_len = writer.buffered().len;
        return self;
    }

    fn nextPlaceholder(text: []const u8) ?struct { usize, usize } {
        var best: ?struct { usize, usize } = null;
        for (placeholders, 0..) |placeholder, i| {
            const index = std.mem.indexOf(u8, text, placeholder) orelse continue;
            if (best == null or index < best.?[0]) best = .{ index, i };
        }
        return best;
    }

    pub fn shell(self: *const Assets) []const u8 {
        return self.shell_bytes[0..self.shell_len];
    }

    /// `/console/assets/<digest prefix>/<name>`; any other prefix is an unknown path.
    pub fn lookup(self: *const Assets, path: []const u8) ?usize {
        const root = "/console/assets/";
        if (!std.mem.startsWith(u8, path, root)) return null;
        const rest = path[root.len..];
        if (rest.len < prefix_len + 1 or rest[prefix_len] != '/') return null;
        for (names, &self.prefixes, 0..) |name, *prefix, i| {
            if (std.mem.eql(u8, rest[0..prefix_len], prefix) and
                std.mem.eql(u8, rest[prefix_len + 1 ..], name)) return i;
        }
        return null;
    }

    pub fn serve(self: *const Assets, context: *Context, path: []const u8) Context.Error!bool {
        const method = context.request.head.method;
        if (method != .GET and method != .HEAD) return false;
        const index = self.lookup(path) orelse return false;
        try context.respondCached(.ok, types[index], bytes[index], immutable, &.{});
        return true;
    }
};

test "assets resolve only under their own digest and the shell names every one" {
    const t = std.testing;
    const assets = Assets.init();
    var path: [64]u8 = undefined;
    for (names, &assets.prefixes, 0..) |name, *prefix, i| {
        const found = try std.fmt.bufPrint(&path, "/console/assets/{s}/{s}", .{ prefix, name });
        try t.expectEqual(@as(?usize, i), assets.lookup(found));
        try t.expect(std.mem.indexOf(u8, assets.shell(), found) != null);
        const wrong = try std.fmt.bufPrint(&path, "/console/assets/{s}/{s}", .{
            "0000000000000000", name,
        });
        try t.expect(assets.lookup(wrong) == null);
    }
    try t.expect(assets.lookup("/console/assets/console.wasm") == null);
    try t.expect(assets.lookup("/console/assets/") == null);
    try t.expect(std.mem.indexOf(u8, assets.shell(), "{{") == null);
    try t.expect(std.mem.indexOf(u8, assets.shell(), "world-110m") == null);
}
