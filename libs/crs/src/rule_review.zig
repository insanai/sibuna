//! Immutable review metadata is prepared off-path; it never retains source or
//! enters evaluation. Explicit lengths and tags avoid host padding and ambiguity.
const std = @import("std");
const model = @import("model.zig");
const selectors = @import("selectors.zig");
const post = @import("action_compile.zig");
const api = @import("crs-protocol").review;
const Hash = std.crypto.hash.sha2.Sha256;
pub const Fingerprint = struct {
    id: u32,
    phase: u8,
    position: u16,
    digest: [32]u8,
    target_exclusions: u32 = 0,
    runtime_exclusions: u32 = 0,
};
pub const Builder = struct {
    allocator: std.mem.Allocator,
    rows: []Fingerprint,
    used: usize = 0,
    hash: Hash = undefined,
    active: bool = false,

    pub fn init(allocator: std.mem.Allocator, conditions: []const model.Condition) !Builder {
        var roots: usize = 0;
        for (conditions, 0..) |item, index| if (item.root == index) {
            roots += 1;
        };
        return .{ .allocator = allocator, .rows = try allocator.alloc(Fingerprint, roots) };
    }

    pub fn deinit(self: *Builder) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn append(
        self: *Builder,
        item: *const model.Condition,
        all: []const model.Condition,
        index: usize,
        files: []const []const u8,
        actions: *const post.Program,
    ) void {
        if (item.root == index) {
            std.debug.assert(!self.active and self.used < self.rows.len);
            self.hash = Hash.init(.{});
            self.hash.update("sibuna/crs/rule-review/v1");
            self.rows[self.used] = .{
                .id = item.id,
                .phase = @backingInt(item.phase),
                .position = @intCast(self.used),
                .digest = undefined,
            };
            self.active = true;
        }
        std.debug.assert(self.active and item.id == self.rows[self.used].id);
        definition(&self.hash, item, all, files);
        const row = &self.rows[self.used];
        for (item.targets) |target| if (target.mode == .exclude) {
            row.target_exclusions += 1;
        };
        for (actions.steps) |step| if (step == .control and step.control.operation == .exclude) {
            row.runtime_exclusions += @intCast(step.control.operation.exclude.len);
        };
        if (item.chain_next == null) {
            self.hash.final(&row.digest);
            self.used += 1;
            self.active = false;
        }
    }

    pub fn take(self: *Builder) []Fingerprint {
        std.debug.assert(!self.active and self.used == self.rows.len);
        const result = self.rows;
        self.rows = &.{};
        return result;
    }
};

fn definition(
    hash: *Hash,
    item: *const model.Condition,
    all: []const model.Condition,
    files: []const []const u8,
) void {
    number(hash, item.id);
    number(hash, @backingInt(item.phase));
    number(hash, @intFromBool(item.chain_next != null));
    number(hash, @intFromBool(item.skip_to != null));
    if (item.skip_to) |position| {
        // EOF is distinct from every rule ID. Inserting an unrelated earlier
        // rule must not change a skip destination's authenticated identity.
        number(hash, if (position < all.len) all[position].id else 0);
    }
    number(hash, item.targets.len);
    for (item.targets) |target| selector(hash, target);
    number(hash, @intFromBool(item.expression != null));
    if (item.expression) |expression| {
        bytes(hash, @tagName(expression.kind));
        bytes(hash, expression.argument);
        number(hash, @intFromBool(expression.negated));
    }
    actionList(hash, item.inherited_actions);
    actionList(hash, item.actions);
    number(hash, files.len);
    for (files) |file| bytes(hash, file);
}

fn selector(hash: *Hash, target: selectors.Selector) void {
    bytes(hash, @tagName(target.collection));
    bytes(hash, @tagName(target.mode));
    bytes(hash, @tagName(target.selection));
    switch (target.selection) {
        .all => {},
        .name, .pattern => |value| bytes(hash, value),
        .xml => |value| bytes(hash, @tagName(value)),
    }
}

fn actionList(hash: *Hash, actions: []const model.Action) void {
    number(hash, actions.len);
    for (actions) |action| {
        bytes(hash, @tagName(action.kind));
        number(hash, @intFromBool(action.value != null));
        if (action.value) |value| bytes(hash, value);
        number(hash, @intFromBool(action.transform != null));
        if (action.transform) |value| bytes(hash, @tagName(value));
    }
}

fn bytes(hash: *Hash, value: []const u8) void {
    number(hash, value.len);
    hash.update(value);
}

fn number(hash: *Hash, value: u64) void {
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, value, .big);
    hash.update(&encoded);
}

pub fn compare(
    allocator: std.mem.Allocator,
    before: []const Fingerprint,
    after: []const Fingerprint,
    result: *api.Report,
) !void {
    if (before.len > 4096 or after.len > 4096) return error.ReviewLimit;
    const left = try sorted(allocator, before);
    defer allocator.free(left);
    const right = try sorted(allocator, after);
    defer allocator.free(right);
    rankRetained(left, right);
    rankRetained(right, left);
    result.* = .{ .before = try summary(left), .after = try summary(right) };
    var old: usize = 0;
    var next: usize = 0;
    while (old < left.len or next < right.len) {
        if (next == right.len or (old < left.len and left[old].id < right[next].id)) {
            result.removed += 1;
            append(result, .{
                .id = left[old].id,
                .kind = .removed,
                .before_phase = left[old].phase,
            });
            old += 1;
        } else if (old == left.len or right[next].id < left[old].id) {
            result.added += 1;
            append(result, .{
                .id = right[next].id,
                .kind = .added,
                .after_phase = right[next].phase,
            });
            next += 1;
        } else {
            retained(result, left[old], right[next]);
            old += 1;
            next += 1;
        }
    }
    try result.validate();
}

fn sorted(allocator: std.mem.Allocator, source: []const Fingerprint) ![]Fingerprint {
    const rows = try allocator.dupe(Fingerprint, source);
    errdefer allocator.free(rows);
    std.mem.sort(Fingerprint, rows, {}, struct {
        fn less(_: void, left: Fingerprint, right: Fingerprint) bool {
            return left.id < right.id;
        }
    }.less);
    var positions: [4096]bool = @splat(false);
    for (rows, 0..) |row, index| {
        if (row.id == 0 or row.phase < 1 or row.phase > 5 or row.position >= source.len or
            (index != 0 and rows[index - 1].id == row.id)) return error.InvalidReview;
        if (positions[row.position]) return error.InvalidReview;
        positions[row.position] = true;
    }
    return rows;
}

fn summary(rows: []const Fingerprint) !api.Summary {
    var result: api.Summary = .{ .rules = @intCast(rows.len) };
    for (rows) |row| {
        result.target_exclusions = std.math.add(
            u32,
            result.target_exclusions,
            row.target_exclusions,
        ) catch return error.InvalidReview;
        result.runtime_exclusions = std.math.add(
            u32,
            result.runtime_exclusions,
            row.runtime_exclusions,
        ) catch return error.InvalidReview;
    }
    return result;
}

fn rankRetained(rows: []Fingerprint, other: []const Fingerprint) void {
    var positions: [4096]u16 = undefined;
    for (rows, 0..) |row, index| positions[row.position] = @intCast(index);
    var ranks: [5]u16 = @splat(0);
    for (positions[0..rows.len]) |index| {
        const phase = rows[index].phase;
        rows[index].position = 0;
        // Execution orders roots within a phase. Insertions, removals and phase
        // changes must not falsely reorder the roots retained in that phase.
        if (retainedPhase(other, rows[index].id, phase)) {
            rows[index].position = ranks[phase - 1];
            ranks[phase - 1] += 1;
        }
    }
}

fn retainedPhase(rows: []const Fingerprint, id: u32, phase: u8) bool {
    var low: usize = 0;
    var high: usize = rows.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (rows[middle].id == id) return rows[middle].phase == phase;
        if (rows[middle].id < id) low = middle + 1 else high = middle;
    }
    return false;
}

fn retained(result: *api.Report, old: Fingerprint, next: Fingerprint) void {
    const phase_changed = old.phase != next.phase;
    const moved = phase_changed or old.position != next.position;
    const modified = phase_changed or !std.mem.eql(u8, &old.digest, &next.digest);
    if (!moved and !modified) {
        result.unchanged += 1;
        return;
    }
    if (modified) result.modified += 1 else result.reordered += 1;
    append(result, .{
        .id = next.id,
        .kind = if (modified) .modified else .reordered,
        .before_phase = old.phase,
        .after_phase = next.phase,
        .moved = moved,
    });
}

fn append(result: *api.Report, change: api.Change) void {
    if (result.count == result.changes.len) {
        result.omitted += 1;
        return;
    }
    result.changes[result.count] = change;
    result.count += 1;
}

test {
    _ = @import("rule_review_test.zig");
}
