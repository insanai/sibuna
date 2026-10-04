//! Stock generation fixtures for whole-graph tests; never part of runtime imports.
const std = @import("std");
const fixture = @import("crs-fixture");
const compiler = @import("compiler.zig");
const rules = @import("rule_program.zig");
const data = @import("rule_data.zig");

pub fn prepare() !rules.Program {
    var builder = compiler.Compiler.init(std.testing.allocator, .{});
    defer builder.deinit();
    for (fixture.sources) |file| try builder.addSource(file.path, file.bytes);
    var plan = try builder.finish();
    defer plan.deinit();
    var files: [fixture.data.len]data.File = undefined;
    for (fixture.data, &files) |file, *prepared| prepared.* = .{
        .path = file.path,
        .bytes = file.bytes,
    };
    return rules.compile(std.testing.allocator, &plan, &files, .{});
}
