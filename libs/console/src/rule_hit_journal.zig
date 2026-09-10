//! The storage owner samples generation-pinned counters. Pending frames own every identity;
//! recycling an engine arena cannot invalidate a retry. Publication never waits for this queue.
const std = @import("std");
const p = @import("console_protocol").rule_hits;
const Counters = @import("store").rule_hits.Counters(p.max_rules);

pub const Journal = struct {
    generation: ?p.Generation = null,
    before: Counters.Snapshot = undefined,
    clock: p.Clock = .{ .utc = 0, .ms = 0 },
    current: p.Frame = .{},
    candidate: bool = false,
    sequence: u64 = 0,
    frames: [4]p.Frame = undefined,
    head: usize = 0,
    count: usize = 0,
    offset: usize = 0,
    status: p.Status = .{},

    /// Called before requests can use the initial generation, or immediately after swapping
    /// to a freshly zeroed generation. Reading a post-publication baseline would lose hits.
    pub fn begin(self: *Journal, generation: *const p.Generation) void {
        std.debug.assert(self.generation == null and generation.number != 0);
        std.debug.assert(generation.len <= p.max_rules);
        self.generation = generation.*;
        self.before = .{
            .generation = generation.number,
            .values = @splat(0),
            .overflow = false,
        };
        self.clock = generation.born;
        self.current.len = 0;
        self.current.span = .{};
        self.candidate = false;
    }

    pub fn observe(self: *Journal, snapshot: *const Counters.Snapshot, now: p.Clock) void {
        if (self.generation == null) return;
        const generation = &self.generation.?;
        std.debug.assert(snapshot.generation == generation.number);
        if (now.ms == self.clock.ms and now.utc == self.clock.utc) return;
        if (now.ms <= self.clock.ms or now.utc < self.clock.utc) {
            self.seal(false);
            self.status.clock_resets +|= 1;
            self.status.unconfirmed +|= 1;
            self.before = snapshot.*;
            self.clock = now;
            return;
        }
        var delta: [p.max_rules]u64 = undefined;
        const valid = validDelta(snapshot, &self.before, &delta);
        const elapsed = now.ms - self.clock.ms;
        const utc_elapsed = (now.utc - self.clock.utc) *| 1000;
        const gap = elapsed > 2500 or utc_elapsed > elapsed +| 1500 or
            elapsed > utc_elapsed +| 1500;
        if (self.current.span.observations != 0 and now.utc / 60 != self.current.span.minute) {
            const contiguous = now.utc / 60 == self.current.span.minute +| 1 and !gap;
            self.seal(contiguous);
            self.candidate = contiguous;
        }
        if (self.current.span.observations == 0) self.open(now);
        const span = &self.current.span;
        span.utc_end = now.utc;
        span.end_ms = now.ms;
        span.observed_ms += elapsed;
        span.observations +|= 1;
        span.gap = span.gap or gap;
        for (self.current.entries[0..self.current.len], 0..) |*entry, index| {
            if (valid and entry.hits != null) {
                entry.hits = std.math.add(u64, entry.hits.?, delta[index]) catch null;
            } else entry.hits = null;
            if (entry.hits == null) self.status.overflow = true;
        }
        self.before = snapshot.*;
        self.clock = now;
    }

    fn validDelta(
        after: *const Counters.Snapshot,
        before: *const Counters.Snapshot,
        delta: *[p.max_rules]u64,
    ) bool {
        after.delta(before, delta) catch return false;
        return true;
    }

    fn open(self: *Journal, now: p.Clock) void {
        const generation = &self.generation.?;
        self.current.span = .{
            .node = generation.node,
            .boot = generation.boot,
            .generation = generation.number,
            .revision = generation.revision,
            .minute = now.utc / 60,
            .utc_start = self.clock.utc,
            .start_ms = self.clock.ms,
        };
        self.current.len = generation.len;
        const entries = self.current.entries[0..generation.len];
        for (entries, generation.rules[0..generation.len]) |*entry, identity| {
            entry.* = .{ .identity = identity };
        }
    }

    /// A drained old slot is stable. Cutover minutes remain partial even when their duration
    /// happens to resemble a complete minute; a different generation owns the other side.
    pub fn finish(self: *Journal, snapshot: *const Counters.Snapshot, now: p.Clock) void {
        self.observe(snapshot, now);
        // Two publications within one clock tick still have distinct pinned request sets.
        // Such a zero-duration tail cannot be represented as an observed interval.
        if (!std.mem.eql(u64, &snapshot.values, &self.before.values))
            self.status.unconfirmed +|= 1;
        self.seal(false);
        self.generation = null;
    }

    fn seal(self: *Journal, contiguous: bool) void {
        const span = &self.current.span;
        if (span.observations == 0) return;
        span.complete = self.candidate and contiguous and !span.gap and
            span.observed_ms >= 59000 and span.observed_ms <= 61000;
        self.sequence +|= 1;
        span.sequence = self.sequence;
        span.unconfirmed = self.status.unconfirmed;
        if (self.current.len != 0) {
            if (self.count == self.frames.len or self.sequence > std.math.maxInt(i64)) {
                self.status.unconfirmed +|= 1;
            } else {
                self.frames[(self.head + self.count) % self.frames.len] = self.current;
                self.count += 1;
                self.status.pending = @intCast(self.count);
            }
        }
        self.current.len = 0;
        self.current.span = .{};
        self.candidate = false;
    }

    pub const Batch = struct { span: *const p.Span, entries: []const p.Entry };

    /// Borrow lasts until acknowledge/discard; observe and publication never overwrite it.
    pub fn pending(self: *const Journal) ?Batch {
        if (self.count == 0) return null;
        const frame = &self.frames[self.head];
        return .{
            .span = &frame.span,
            .entries = frame.entries[self.offset..@min(frame.len, self.offset + p.batch_rows)],
        };
    }

    pub fn acknowledge(self: *Journal) void {
        const batch = self.pending() orelse unreachable;
        self.offset += batch.entries.len;
        if (self.offset != self.frames[self.head].len) return;
        self.status.confirmed +|= 1;
        self.status.last_stored_utc = batch.span.utc_end;
        self.remove();
    }

    /// After bounded retries, make the loss visible and let newer generations make progress.
    pub fn discard(self: *Journal) void {
        std.debug.assert(self.count != 0);
        self.status.unconfirmed +|= 1;
        self.remove();
    }

    fn remove(self: *Journal) void {
        self.head = (self.head + 1) % self.frames.len;
        self.count -= 1;
        self.offset = 0;
        self.status.pending = @intCast(self.count);
    }
};
