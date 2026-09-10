//! Owned subscription commands and bounded transport contracts, shared by native and Wasm.
const std = @import("std");
const p = @import("root.zig");
pub const topic_count = @typeInfo(p.Topic).@"enum".fields.len;
pub const ring_capacity = 1024;
pub const record_bytes = 2048;
pub const queue_capacity = 64;
pub const messages_per_second = 64;
pub const snapshot_bytes = 65536;
pub const fragment_bytes = 512;
pub const Op = enum { sub, unsub, filter, ping };
pub const Args = struct {
    node: ?u32 = null,
    module: ?p.security.Module = null,
    category: p.Bytes(32) = .{},
    country: p.events.country.Filter = .{},
    ip: p.Bytes(48) = .{},
    path_prefix: p.Bytes(128) = .{},
    actor: ?u64 = null,
    action: p.Bytes(48) = .{},

    pub fn jsonStringify(self: Args, writer: *std.json.Stringify) !void {
        try writer.beginObject();
        inline for (@typeInfo(Args).@"struct".fields) |field| {
            const value = @field(self, field.name);
            if (field.type == ?p.security.Module) {
                if (value) |module| {
                    try writer.objectField(field.name);
                    try writer.write(module);
                }
            } else if (field.type == ?u32 or field.type == ?u64) {
                if (value) |number| {
                    try writer.objectField(field.name);
                    try p.writeCounter(writer, number);
                }
            } else if (value.len != 0) {
                try writer.objectField(field.name);
                try writer.write(value.slice());
            }
        }
        try writer.endObject();
    }
};
pub const Command = struct { op: Op, topic: ?p.Topic = null, args: Args = .{} };
const WireArgs = struct {
    node: ?u32 = null,
    module: ?p.security.Module = null,
    category: []const u8 = "",
    country: []const u8 = "",
    ip: []const u8 = "",
    path_prefix: []const u8 = "",
    actor: ?u64 = null,
    action: []const u8 = "",
};

pub fn parse(bytes: []const u8) error{InvalidCommand}!Command {
    if (bytes.len > p.max_message or !std.unicode.utf8ValidateSlice(bytes))
        return error.InvalidCommand;
    var memory: [8192]u8 = undefined;
    var allocator = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = std.json.parseFromSlice(struct {
        op: Op,
        topic: ?p.Topic = null,
        args: WireArgs = .{},
    }, allocator.allocator(), bytes, .{}) catch return error.InvalidCommand;
    defer parsed.deinit();
    const wire = parsed.value;
    var command: Command = .{ .op = wire.op, .topic = wire.topic };
    command.args = .{
        .node = wire.args.node,
        .module = wire.args.module,
        .actor = wire.args.actor,
        .category = p.Bytes(32).init(wire.args.category) catch return error.InvalidCommand,
        .country = p.events.country.Filter.init(wire.args.country) catch
            return error.InvalidCommand,
        .ip = p.Bytes(48).init(wire.args.ip) catch return error.InvalidCommand,
        .path_prefix = p.Bytes(128).init(wire.args.path_prefix) catch return error.InvalidCommand,
        .action = p.Bytes(48).init(wire.args.action) catch return error.InvalidCommand,
    };
    try validate(command);
    return command;
}

pub fn validate(command: Command) error{InvalidCommand}!void {
    const args = command.args;
    if (!p.events.country.validFilter(args.country.slice())) return error.InvalidCommand;
    const event = args.category.len != 0 or args.ip.len != 0 or args.path_prefix.len != 0 or
        args.country.len != 0 or args.module != null;
    const audit = args.actor != null or args.action.len != 0;
    if (args.node == 0 or args.actor == 0) return error.InvalidCommand;
    if (args.actor) |actor| if (actor > std.math.maxInt(i64)) return error.InvalidCommand;
    if (command.op == .ping) {
        if (command.topic != null or event or audit or args.node != null)
            return error.InvalidCommand;
        return;
    }
    const topic = command.topic orelse return error.InvalidCommand;
    if (command.op == .unsub and (event or audit or args.node != null))
        return error.InvalidCommand;
    if (event and topic != .events) return error.InvalidCommand;
    if (audit and topic != .audit) return error.InvalidCommand;
    if (args.node != null and topic != .events and topic != .nodes and topic != .stats)
        return error.InvalidCommand;
}

pub fn allowed(topic: p.Topic, principal: p.Principal) bool {
    return principal.token_id == null and !principal.must_change and
        (!principal.kiosk or topic == .stats);
}

/// A fragment is independently valid UTF-8. JSON escaping is applied by the wire writer,
/// and the receiver reconstructs the original JSON bytes before interpreting any fields.
pub fn fragmentLength(bytes: []const u8) usize {
    var length = @min(bytes.len, fragment_bytes);
    if (length == bytes.len) return length;
    while (length > 0 and bytes[length] & 0xc0 == 0x80) length -= 1;
    std.debug.assert(length != 0);
    return length;
}

test "subscription filters reject unrelated fields and retain owned UTF-8" {
    const t = std.testing;
    const command = try parse(
        "{\"op\":\"filter\",\"topic\":\"events\",\"args\":{\"node\":2,\"category\":\"sqli\"}}",
    );
    try t.expectEqual(@as(?u32, 2), command.args.node);
    try t.expectEqualStrings("sqli", command.args.category.slice());
    try t.expectError(error.InvalidCommand, parse("{\"op\":\"sub\"}"));
    try t.expectError(error.InvalidCommand, parse(
        "{\"op\":\"sub\",\"topic\":\"stats\",\"args\":{\"actor\":2}}",
    ));
    try t.expectError(error.InvalidCommand, parse(
        "{\"op\":\"sub\",\"topic\":\"events\",\"args\":{\"node\":0}}",
    ));
    const unicode = "a" ** (fragment_bytes - 1) ++ "界";
    try t.expectEqual(fragment_bytes - 1, fragmentLength(unicode));
}

test "owned command serialization preserves an actor above the browser integer range" {
    const t = std.testing;
    const command: Command = .{
        .op = .filter,
        .topic = .audit,
        .args = .{ .actor = 9007199254740993, .action = try p.Bytes(48).init("policy.edit") },
    };
    var bytes: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try std.json.Stringify.value(command, .{}, &writer);
    const result = try parse(writer.buffered());
    try t.expectEqual(command.args.actor, result.args.actor);
    try t.expectEqualStrings(command.args.action.slice(), result.args.action.slice());
}
