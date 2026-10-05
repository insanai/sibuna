//! Reviews share the joined compiler and session ownership with private samples.
//! Compile sources sequentially; only fixed-width root inventories overlap.
const std = @import("std");
const crs = @import("crs");
const p = @import("console_protocol");
const App = @import("app.zig").App;
const worker = @import("crs_test_worker.zig");
const access = @import("crs_task_access.zig");
const sources = @import("crs_sources.zig");

pub fn run(
    app: *App,
    input: worker.Input,
    result: *p.crs_tasks.Status,
    inventory: *worker.Inventory,
) !void {
    var memory: [4096]u8 = undefined;
    defer std.crypto.secureZero(u8, &memory);
    var fixed: std.heap.FixedBufferAllocator = .init(&memory);
    const parsed = try std.json.parseFromSlice(
        p.crs_tasks.Source,
        fixed.allocator(),
        input.body[0..input.length],
        .{ .allocate = .alloc_always, .max_value_len = 32 },
    );
    defer parsed.deinit();
    try parsed.value.validate();
    result.source = try p.crs_management.Id.init(parsed.value.source);
    result.expected_revision = try std.fmt.parseInt(u64, parsed.value.expected_revision, 10);
    const job = try access.begin(app, input.auth, result);
    const selected = try app.request(.{ .crs_management = .{ .status = input.auth } });
    if (selected != .crs_selection or selected.crs_selection.revision != result.expected_revision)
        return error.CrsSelectionConflict;
    const before = if (selected.crs_selection.current) |current| blk: {
        result.baseline = (try @import("crs_views.zig").candidate(current)).artifact;
        var prepared = try sources.loadDiagnosed(app, current, &result.diagnostic);
        defer prepared.deinit();
        inventory.before = try app.gpa.dupe(
            p.crs_tasks.review.exclusions.Row,
            prepared.package.?.program.exclusions,
        );
        const roots = prepared.package.?.program.review;
        break :blk try app.gpa.dupe(crs.rule_review.Fingerprint, roots);
    } else try app.gpa.alloc(crs.rule_review.Fingerprint, 0);
    defer app.gpa.free(before);
    var prepared = try sources.loadDiagnosed(app, job, &result.diagnostic);
    defer prepared.deinit();
    var comparison: p.crs_tasks.review.Report = undefined;
    try crs.rule_review.compare(app.gpa, before, prepared.package.?.program.review, &comparison);
    try access.recheck(app, input.auth, result);
    inventory.after = try app.gpa.dupe(
        p.crs_tasks.review.exclusions.Row,
        prepared.package.?.program.exclusions,
    );
    result.comparison = comparison;
    result.artifact = (try @import("crs_views.zig").candidate(job)).artifact;
    result.state = .complete;
}
