//! Sole-owner bridge: request workers only touch pinned atomic counters. SQL, identities,
//! retry scheduling and reclamation stay on Persistent's thread.
const std = @import("std");
const console = @import("console");
const p = console.protocol;
const Persistent = @import("persistent.zig").Persistent;
const Counters = @import("store").rule_hits.Counters(p.rule_hits.max_rules);

pub const State = struct {
    journal: ?*console.RuleHitJournal = null,
    generation: u64 = 0,
    next_sample: u64 = 0,
    retry_at: u64 = 0,
    retries: u8 = 0,
};

pub fn clock(owner: *Persistent) p.rule_hits.Clock {
    const ns = std.Io.Clock.awake.now(owner.io).nanoseconds;
    return .{ .utc = owner.nowSeconds(), .ms = @intCast(@max(0, @divTrunc(ns, 1000000))) };
}

pub fn prepare(owner: *Persistent, revision: u64) !void {
    if (owner.console_hits.generation == std.math.maxInt(i64))
        return error.RuleGenerationExhausted;
    const number = owner.console_hits.generation + 1;
    const slot = &owner.spare.hits;
    slot.counters.reset(number);
    slot.generation.node = owner.node_id;
    slot.generation.boot = owner.console_node.boot;
    slot.generation.number = number;
    slot.generation.revision = revision;
    slot.generation.born = clock(owner);
}

/// Called after publishEngine has drained the old readers. Its identities remain owned.
pub fn published(owner: *Persistent) void {
    const live = owner.state.slot.load(.acquire);
    owner.console_hits.generation = live.hits.generation.number;
    const journal = owner.console_hits.journal orelse return;
    var snapshot: Counters.Snapshot = undefined;
    owner.spare.hits.counters.read(&snapshot);
    journal.finish(&snapshot, clock(owner));
    journal.begin(&live.hits.generation);
}

/// Internal startup command, before any data-plane worker starts. A second call never
/// resets live counters. The mailbox provides the publication barrier to the composition layer.
pub fn start(owner: *Persistent) !p.StorageResult {
    if (owner.console_hits.journal != null) return .command_recorded;
    const journal = try owner.gpa.create(console.RuleHitJournal);
    journal.* = .{};
    const slot = owner.state.slot.load(.acquire);
    slot.hits.counters.reset(slot.hits.generation.number);
    slot.hits.generation.born = clock(owner);
    journal.begin(&slot.hits.generation);
    owner.console_hits.journal = journal;
    return .command_recorded;
}

/// Maintenance follows incidents and policy publication. At most one eight-row commit per
/// tick prevents history backlogs from monopolizing the storage owner.
pub fn tick(owner: *Persistent) void {
    const state = &owner.console_hits;
    const journal = state.journal orelse return;
    const now = clock(owner);
    if (now.ms >= state.next_sample) {
        const slot = owner.state.acquireEngine();
        defer @import("server.zig").AppState.releaseEngine(slot);
        var snapshot: Counters.Snapshot = undefined;
        slot.hits.counters.read(&snapshot);
        journal.observe(&snapshot, now);
        state.next_sample = now.ms +| 1000;
    }
    if (now.ms < state.retry_at or journal.pending() == null) return;
    @import("console_store_rule_hits.zig").write(owner, journal.pending().?) catch |err| {
        state.retries += 1;
        std.log.warn("rule history commit unconfirmed: {t}", .{err});
        if (state.retries == 8) {
            journal.discard();
            state.retries = 0;
        }
        state.retry_at = now.ms +| (@as(u64, 1000) << @intCast(state.retries));
        return;
    };
    state.retries = 0;
    state.retry_at = 0;
    journal.acknowledge();
}

/// Shutdown has joined workers and storage. Flush within a bounded number of owner operations;
/// errors stop the drain, and unconfirmed records are reported rather than acknowledged.
pub fn stop(owner: *Persistent) void {
    const journal = owner.console_hits.journal orelse return;
    defer owner.gpa.destroy(journal);
    defer owner.console_hits.journal = null;
    const live = owner.state.slot.load(.acquire);
    var snapshot: Counters.Snapshot = undefined;
    live.hits.counters.read(&snapshot);
    journal.finish(&snapshot, clock(owner));
    const deadline = clock(owner).ms +| 2000;
    while (journal.pending()) |batch| {
        if (clock(owner).ms >= deadline) break;
        @import("console_store_rule_hits.zig").write(owner, batch) catch break;
        journal.acknowledge();
    }
    if (journal.count != 0 or journal.status.unconfirmed != 0)
        std.log.warn("rule history shutdown: {d} pending, {d} unconfirmed frames", .{
            journal.count, journal.status.unconfirmed,
        });
}
