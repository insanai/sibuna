//! Test adapter for pinned upstream primitive vectors. Never linked into the daemon.
const std = @import("std");
const crs = @import("crs");

pub fn main(init: std.process.Init) !u8 {
    var args = try init.minimal.args.iterateAllocator(init.gpa);
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
        if (failed_init and !std.mem.eql(u8, name, "validateByteRange") and
            !std.mem.eql(u8, name, "ipMatch"))
        {
            return error.InvalidInitializationFixture;
        }
        const probe: OperatorProbe = .{
            .allocator = init.gpa,
            .kind = crs.model.operators.get(name) orelse return error.UnknownOperator,
            .input = input,
            .argument = argument,
            .failed_init = failed_init,
        };
        try out.writeAll(if (try probe.evaluate()) "true\n" else "false\n");
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

const OperatorProbe = struct {
    allocator: std.mem.Allocator,
    kind: crs.model.Operator,
    input: []const u8,
    argument: []const u8,
    failed_init: bool,

    fn evaluate(self: OperatorProbe) !bool {
        var budget: crs.work.Budget = .{ .remaining = 16_000_000 };
        if (self.kind == .detect_xss) {
            var context: crs.xss_detector.Context = .{ .input = self.input, .budget = &budget };
            return crs.xss_detector.detect(&context);
        }
        if (self.kind == .validate_byte_range) {
            var range: crs.byte_range.Range = .{};
            if (!self.failed_init) range = try crs.byte_range.compile(self.argument);
            return (try range.inspect(self.input, &budget)).count != 0;
        }
        if (self.kind == .ip_match) {
            const source = if (self.failed_init) "" else self.argument;
            var program = try crs.address_set.compile(self.allocator, source, .{});
            defer program.deinit();
            return program.contains(self.input, &budget);
        }
        if (self.kind == .pm or self.kind == .pm_from_file) {
            const options: crs.phrases.Options = .{ .profile = .modsecurity_3_0_14 };
            var program = if (self.kind == .pm)
                try crs.phrases_source.inlineWords(self.allocator, self.argument, options)
            else
                try crs.phrases_source.fileWords(self.allocator, self.argument, options);
            defer program.deinit();
            return try program.search(self.input, &budget) != null;
        }
        const prefixes = try self.allocator.alloc(usize, 64 * 1024);
        defer self.allocator.free(prefixes);
        if (self.kind == .detect_sqli) {
            var context: crs.sql_tokens.Context = .{
                .input = self.input,
                .prefixes = prefixes,
                .budget = &budget,
            };
            var scratch: crs.sql_folding.Result = .{};
            return (try crs.sql_detector.detect(&context, &scratch)).matched;
        }
        const predicate: crs.primitives.Predicate = .{
            .kind = self.kind,
            .argument = self.argument,
        };
        const result = try predicate.evaluate(self.input, .{
            .prefixes = prefixes,
            .budget = &budget,
        });
        return result.matched;
    }
};

fn decode(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    if (bytes.len % 2 != 0 or bytes.len / 2 > 64 * 1024) return error.InputLimit;
    const result = try allocator.alloc(u8, bytes.len / 2);
    errdefer allocator.free(result);
    _ = try std.fmt.hexToBytes(result, bytes);
    return result;
}
