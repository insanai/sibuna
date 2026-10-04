//! Test adapter for differential PCRE2 checks. The production backend is native Zig.
const std = @import("std");
const crs = @import("crs");
const Io = std.Io;

pub fn main(init: std.process.Init) !u8 {
    var args = std.process.Args.Iterator.init(init.minimal.args);
    defer args.deinit();
    _ = args.next();
    var pattern_hex = args.next() orelse return error.MissingPattern;
    const seclang = std.mem.eql(u8, pattern_hex, "--seclang");
    if (seclang) pattern_hex = args.next() orelse return error.MissingPattern;
    if (std.mem.eql(u8, pattern_hex, "--stock")) {
        if (args.next() != null) return error.TooManyArguments;
        return stock(init);
    }
    const input_hex = args.next() orelse return error.MissingInput;
    if (args.next() != null) return error.TooManyArguments;
    const pattern = try decode(init.gpa, pattern_hex, 64 * 1024);
    defer init.gpa.free(pattern);
    const input = try decode(init.gpa, input_hex, 64 * 1024);
    defer init.gpa.free(input);
    var program = if (seclang)
        try crs.regex.secLang(init.gpa, pattern, false)
    else
        try crs.regex.compile(init.gpa, pattern, .{});
    defer program.deinit();
    var workspace = try crs.regex.Workspace.init(init.gpa, &program);
    defer workspace.deinit();
    var budget: crs.work.Budget = .{ .remaining = 100_000_000 };
    const result = try crs.regex.match.search(&program, input, &workspace.scratch, &budget);
    var buffer: [4096]u8 = undefined;
    var file = Io.File.stdout().writerStreaming(init.io, &buffer);
    const out = &file.interface;
    if (result) |found| {
        try out.writeByte('[');
        for (0..@as(usize, program.groups) + 1) |group| {
            if (group > 0) try out.writeByte(',');
            if (found.span(group)) |span| {
                try out.print("[{d},{d}]", .{ span.start, span.end });
            } else try out.writeAll("[null,null]");
        }
        try out.writeAll("]\n");
    } else try out.writeAll("null\n");
    try out.flush();
    return 0;
}

fn decode(allocator: std.mem.Allocator, bytes: []const u8, limit: usize) ![]u8 {
    if (bytes.len % 2 != 0 or bytes.len / 2 > limit) return error.InputLimit;
    const result = try allocator.alloc(u8, bytes.len / 2);
    errdefer allocator.free(result);
    _ = try std.fmt.hexToBytes(result, bytes);
    return result;
}

fn stock(init: std.process.Init) !u8 {
    const fixture = @import("crs-fixture");
    var builder = crs.compiler.Compiler.init(init.gpa, .{});
    defer builder.deinit();
    for (fixture.sources) |source| try builder.addSource(source.path, source.bytes);
    var plan = try builder.finish();
    defer plan.deinit();
    var buffer: [4096]u8 = undefined;
    var file = Io.File.stdout().writerStreaming(init.io, &buffer);
    const out = &file.interface;
    for (plan.conditions) |condition| {
        const expression = condition.expression orelse continue;
        if (expression.kind != .rx) continue;
        try std.json.Stringify.value(.{
            .id = condition.id,
            .pattern = expression.argument,
        }, .{}, out);
        try out.writeByte('\n');
    }
    try out.flush();
    return 0;
}
