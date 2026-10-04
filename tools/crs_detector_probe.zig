//! Development oracle adapter. No process I/O or allocation reaches the detector.
const std = @import("std");
const crs = @import("crs");

pub fn main(init: std.process.Init) !u8 {
    var args = std.process.Args.Iterator.init(init.minimal.args);
    defer args.deinit();
    _ = args.next();
    const mode = args.next() orelse return error.MissingMode;
    const folding = std.mem.eql(u8, mode, "fingerprint");
    const detecting = std.mem.eql(u8, mode, "sqli");
    if (!folding and !detecting and !std.mem.eql(u8, mode, "tokens")) return error.InvalidMode;
    const flags = try std.fmt.parseInt(u8, args.next() orelse return error.MissingFlags, 10);
    const options: crs.sql_tokens.Options = switch (flags) {
        0, 9 => .{},
        17 => .{ .dialect = .mysql },
        10 => .{ .quote = .single },
        18 => .{ .dialect = .mysql, .quote = .single },
        12 => .{ .quote = .double },
        20 => .{ .dialect = .mysql, .quote = .double },
        else => return error.InvalidFlags,
    };
    const hex = args.next() orelse return error.MissingInput;
    if (hex.len % 2 != 0 or hex.len / 2 > 64 * 1024) return error.InputLimit;
    const input = try init.gpa.alloc(u8, hex.len / 2);
    defer init.gpa.free(input);
    _ = try std.fmt.hexToBytes(input, hex);
    if (args.next() != null) return error.TooManyArguments;
    const prefixes = try init.gpa.alloc(usize, input.len);
    defer init.gpa.free(prefixes);
    var budget: crs.work.Budget = .{ .remaining = 64_000_000 };
    var state: crs.sql_tokens.Context = .{
        .input = input,
        .prefixes = prefixes,
        .budget = &budget,
        .options = options,
    };
    var buffer: [4096]u8 = undefined;
    var file = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    const out = &file.interface;
    try runMode(out, &state, folding, detecting);
    try out.flush();
    return 0;
}

fn tokenStream(out: *std.Io.Writer, state: *crs.sql_tokens.Context) !void {
    var token: crs.sql_tokens.Token = .{};
    while (try crs.sql_tokens.next(state, &token)) try writeToken(out, &token);
    try out.print("s {d} {d} {d}\n", .{
        state.stats.tokens, state.stats.dash_comment, state.stats.hash,
    });
}

fn writeToken(out: *std.Io.Writer, token: *const crs.sql_tokens.Token) !void {
    try out.print("{d} {d} {d} {d} {d} {d} ", .{
        @backingInt(token.kind), token.position, token.length,
        token.count,             token.open,     token.close,
    });
    for (token.bytes()) |byte| try out.print("{x:0>2}", .{byte});
    try out.writeByte('\n');
}

fn runMode(
    out: *std.Io.Writer,
    state: *crs.sql_tokens.Context,
    folding: bool,
    detecting: bool,
) !void {
    if (detecting) {
        var scratch: crs.sql_folding.Result = .{};
        const result = try crs.sql_detector.detect(state, &scratch);
        try out.print("d {d} ", .{@intFromBool(result.matched)});
        for (result.capture()) |byte| try out.print("{x:0>2}", .{byte});
        try out.writeByte('\n');
    } else if (folding) {
        var fingerprint: crs.sql_folding.Result = .{};
        try crs.sql_folding.fingerprint(state, &fingerprint);
        try out.writeAll("f ");
        for (fingerprint.bytes()) |byte| try out.print("{x:0>2}", .{byte});
        try out.writeByte('\n');
        for (fingerprint.tokens[0..fingerprint.length]) |*token| try writeToken(out, token);
        try out.print("s {d} {d} {d} {d}\n", .{
            state.stats.tokens, state.stats.dash_comment, state.stats.hash, fingerprint.folds,
        });
    } else try tokenStream(out, state);
}
