//! Test adapter for pinned upstream primitive vectors. Never linked into the daemon.
const std = @import("std");
const crs = @import("crs");

pub fn main(init: std.process.Init) !u8 {
    var args = std.process.Args.Iterator.init(init.minimal.args);
    defer args.deinit();
    _ = args.next();
    const kind = args.next() orelse return error.MissingKind;
    const name = args.next() orelse return error.MissingName;
    const input = try decode(init.gpa, args.next() orelse return error.MissingInput);
    defer init.gpa.free(input);
    const argument = try decode(init.gpa, args.next() orelse return error.MissingArgument);
    defer init.gpa.free(argument);
    if (args.next() != null) return error.TooManyArguments;
    var buffer: [4096]u8 = undefined;
    var file = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    const out = &file.interface;
    const failed_init = std.mem.eql(u8, kind, "op-uninitialized");
    if (std.mem.eql(u8, kind, "op") or failed_init) {
        if (failed_init and !std.mem.eql(u8, name, "validateByteRange")) {
            return error.InvalidInitializationFixture;
        }
        const prefixes = try init.gpa.alloc(usize, 64 * 1024);
        defer init.gpa.free(prefixes);
        const predicate: crs.primitives.Predicate = .{
            .kind = crs.model.operators.get(name) orelse return error.UnknownOperator,
            .argument = argument,
        };
        var budget: crs.work.Budget = .{ .remaining = 16_000_000 };
        const result = if (predicate.kind == .validate_byte_range) result: {
            var range: crs.byte_range.Range = .{};
            if (!failed_init) range = try crs.byte_range.compile(argument);
            const findings = try range.inspect(input, &budget);
            break :result crs.primitives.Result{ .matched = findings.count != 0 };
        } else try predicate.evaluate(input, .{ .prefixes = prefixes, .budget = &budget });
        try out.writeAll(if (result.matched) "true\n" else "false\n");
    } else if (std.mem.eql(u8, kind, "tfn")) {
        if (argument.len != 0) return error.UnexpectedArgument;
        const storage = try init.gpa.alloc(u8, 128 * 1024);
        defer init.gpa.free(storage);
        const transform = crs.model.transforms.get(name) orelse return error.UnknownTransform;
        var budget: crs.work.Budget = .{ .remaining = 16_000_000 };
        const result = try crs.transforms.apply(transform, .{
            .input = input,
            .output = storage,
            .budget = &budget,
        });
        for (result) |byte| try out.print("{x:0>2}", .{byte});
        try out.writeByte('\n');
    } else return error.UnknownKind;
    try out.flush();
    return 0;
}

fn decode(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    if (bytes.len % 2 != 0 or bytes.len / 2 > 64 * 1024) return error.InputLimit;
    const result = try allocator.alloc(u8, bytes.len / 2);
    errdefer allocator.free(result);
    _ = try std.fmt.hexToBytes(result, bytes);
    return result;
}
