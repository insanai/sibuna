//! Bounded scalar review. A modified fingerprint is not an equivalence claim.
pub const change_capacity = 64;
pub const Kind = enum { added, removed, modified, reordered };
pub const Change = struct {
    id: u32,
    kind: Kind,
    before_phase: ?u8 = null,
    after_phase: ?u8 = null,
    moved: bool = false,
};
pub const Summary = struct {
    rules: u32 = 0,
    target_exclusions: u32 = 0,
    runtime_exclusions: u32 = 0,
};
pub const Report = struct {
    before: Summary = .{},
    after: Summary = .{},
    added: u32 = 0,
    removed: u32 = 0,
    modified: u32 = 0,
    reordered: u32 = 0,
    unchanged: u32 = 0,
    changes: [change_capacity]?Change = @splat(null),
    count: usize = 0,
    omitted: u32 = 0,

    pub fn validate(self: *const Report) error{InvalidReview}!void {
        if (self.before.rules > 4096 or self.after.rules > 4096 or
            self.count > change_capacity) return error.InvalidReview;
        const retained = @as(u64, self.modified) + self.reordered + self.unchanged;
        const changed = @as(u64, self.added) + self.removed + self.modified + self.reordered;
        if (retained + self.removed != self.before.rules or
            retained + self.added != self.after.rules or
            self.count + @as(u64, self.omitted) != changed) return error.InvalidReview;
        var previous: ?u32 = null;
        for (self.changes[0..self.count]) |item| {
            const change = item orelse return error.InvalidReview;
            if (change.id == 0 or (previous != null and change.id <= previous.?))
                return error.InvalidReview;
            if (change.before_phase) |phase| if (phase < 1 or phase > 5)
                return error.InvalidReview;
            if (change.after_phase) |phase| if (phase < 1 or phase > 5)
                return error.InvalidReview;
            if ((change.kind != .added) != (change.before_phase != null) or
                (change.kind != .removed) != (change.after_phase != null))
                return error.InvalidReview;
            previous = change.id;
        }
        for (self.changes[self.count..]) |item| if (item != null) return error.InvalidReview;
    }
};
