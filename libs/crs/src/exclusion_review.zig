//! Compile a complete bounded inventory off-path. Every row owns its previews.
const std = @import("std");
const model = @import("model.zig");
const selectors = @import("selectors.zig");
const controls = @import("controls.zig");
const post = @import("action_compile.zig");
pub const api = @import("crs-protocol").review.exclusions;
pub const Error = std.mem.Allocator.Error || error{ExclusionReviewLimit};
pub const Builder = struct {
    allocator: std.mem.Allocator,
    rows: std.ArrayList(api.Row) = .empty,

    pub fn deinit(self: *Builder) void {
        self.rows.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn append(
        self: *Builder,
        item: *const model.Condition,
        index: usize,
        actions: *const post.Program,
    ) Error!void {
        for (item.targets) |target| {
            if (target.mode != .exclude) continue;
            var row = base(item, index, .static_target);
            row.first = item.id;
            row.last = item.id;
            row.collection = name(target.collection);
            switch (target.selection) {
                .all => row.selection = .all,
                .name => |key| {
                    row.selection = .exact;
                    row.key = api.Text.init(key);
                },
                .pattern => |key| {
                    row.selection = .pattern;
                    row.key = api.Text.init(key);
                },
                .xml => |kind| row.selection = if (kind == .elements)
                    .xml_elements
                else
                    .xml_attributes,
            }
            try self.push(row);
        }
        for (actions.steps) |step| {
            if (step != .control or step.control.operation != .exclude) continue;
            for (step.control.operation.exclude) |excluded| {
                var row = base(item, index, if (excluded.target == null)
                    .conditional_rule
                else
                    .conditional_target);
                switch (excluded.selector) {
                    .ids => |ids| {
                        row.selector = if (ids.first == ids.last) .rule_id else .rule_range;
                        row.first = ids.first;
                        row.last = ids.last;
                    },
                    .tag => |tag| {
                        row.selector = .tag;
                        row.tag = api.Text.init(tag);
                    },
                }
                if (excluded.target) |target| {
                    row.collection = name(target.collection);
                    row.selection = if (target.key == null) .all else .exact;
                    if (target.key) |key| row.key = api.Text.init(key);
                }
                try self.push(row);
            }
        }
    }

    fn push(self: *Builder, row: api.Row) Error!void {
        if (self.rows.items.len == api.capacity) return error.ExclusionReviewLimit;
        try self.rows.append(self.allocator, row);
    }

    pub fn take(self: *Builder) Error![]api.Row {
        return self.rows.toOwnedSlice(self.allocator);
    }
};

fn base(item: *const model.Condition, index: usize, scope: api.Scope) api.Row {
    return .{
        .rule_id = item.id,
        .phase = @backingInt(item.phase),
        .chain_link = @intCast(index - item.root),
        .scope = scope,
        .selector = .rule_id,
    };
}

fn name(collection: @import("collections.zig").Collection) @import("text").buffers.Bytes(32) {
    return @import("text").buffers.Bytes(32).init(@tagName(collection)) catch unreachable;
}

pub fn page(rows: []const api.Row, side: api.Side, offset: u32, out: *api.Page) !void {
    if (rows.len > api.capacity or offset > rows.len) return error.InvalidRequest;
    const end = @min(rows.len, @as(usize, offset) + api.page_capacity);
    out.* = .{
        .side = side,
        .offset = offset,
        .total = @intCast(rows.len),
        .count = end - offset,
        .next = if (end < rows.len) @intCast(end) else null,
    };
    for (rows[offset..end], out.rows[0..out.count]) |row, *output| output.* = row;
}

test {
    _ = @import("exclusion_review_test.zig");
}
