const std = @import("std");
const compiler = @import("compiler.zig");
const rules = @import("rule_program.zig");
const Diagnostic = @import("text").source_diagnostic.Diagnostic;

test "source diagnostic remains valid after failed compiler teardown" {
    var diagnostic: ?Diagnostic = null;
    {
        var builder = compiler.Compiler.init(std.testing.allocator, .{});
        defer builder.deinit();
        builder.diagnostic = &diagnostic;
        try std.testing.expectError(error.UnknownOperator, builder.addSource(
            "sibuna-operator.conf",
            "# A source comment is not copied into the error.\n" ++
                "SecRule ARGS \"@unsupported secret-value\" \"id:120\"\n",
        ));
    }
    try diagnostic.?.validate();
    try std.testing.expectEqualStrings("sibuna-operator.conf", diagnostic.?.path.slice());
    try std.testing.expectEqual(@as(?u32, 2), diagnostic.?.line);
    // No identifier was resolved before the unsupported operator was refused.
    try std.testing.expect(diagnostic.?.rule == null);
    try std.testing.expectEqualStrings("UnknownOperator", diagnostic.?.cause.slice());
}

test "executable diagnostic binds the actual failing condition and owns its site" {
    var diagnostic: ?Diagnostic = null;
    {
        var builder = compiler.Compiler.init(std.testing.allocator, .{});
        defer builder.deinit();
        try builder.addSource(
            "rules/local.conf",
            "# local\nSecRule ARGS \"@pmFromFile missing.data\" \"id:120\"\n",
        );
        var plan = try builder.finish();
        defer plan.deinit();
        try std.testing.expectError(error.MissingData, rules.compile(
            std.testing.allocator,
            &plan,
            &.{},
            .{ .diagnostic = &diagnostic },
        ));
    }
    try diagnostic.?.validate();
    try std.testing.expectEqualStrings("rules/local.conf", diagnostic.?.path.slice());
    try std.testing.expectEqual(@as(?u32, 2), diagnostic.?.line);
    try std.testing.expectEqual(@as(?u32, 120), diagnostic.?.rule);
    try std.testing.expectEqualStrings("MissingData", diagnostic.?.cause.slice());
}

test "reference diagnostics identify the target update rather than the last rule" {
    var diagnostic: ?Diagnostic = null;
    {
        var builder = compiler.Compiler.init(std.testing.allocator, .{});
        defer builder.deinit();
        builder.diagnostic = &diagnostic;
        try builder.addSource(
            "sibuna-operator.conf",
            "SecRuleUpdateTargetById 120 \"!ARGS:token\"\n",
        );
        try std.testing.expectError(error.UnknownRuleId, builder.finish());
    }
    try diagnostic.?.validate();
    try std.testing.expectEqual(@as(?u32, 1), diagnostic.?.line);
    try std.testing.expectEqual(@as(?u32, 120), diagnostic.?.rule);
}
