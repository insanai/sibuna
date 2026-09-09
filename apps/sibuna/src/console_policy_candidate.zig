//! Owner-only draft composition. Each query is bounded; revision checks reject mixed snapshots.
const std = @import("std");
const policy = @import("policy");
const p = @import("console").protocol;
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const candidates = policy.candidate;
const source_budget = 2 * 1024 * 1024;

pub fn revision(owner: *Persistent) !u64 {
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT value FROM sibuna_meta WHERE key='policy_version' LIMIT 1",
        &.{},
    );
    defer rows.deinit();
    if (rows.rows.len != 1) return error.MissingPolicyVersion;
    return util.number(rows.rows[0][0]);
}

pub fn build(
    owner: *Persistent,
    expected: u64,
    source: []const u8,
    now: u64,
) !candidates.Candidate {
    return compose(owner, expected, source, now, "");
}

pub fn current(owner: *Persistent, expected: u64, now: u64) !candidates.Candidate {
    return compose(owner, expected, null, now, "");
}

/// Replacement preflights omit the old owned rows before inserting the new complete set.
pub fn withoutSource(
    owner: *Persistent,
    expected: u64,
    now: u64,
    source: []const u8,
) !candidates.Candidate {
    std.debug.assert(source.len != 0);
    return compose(owner, expected, null, now, source);
}

fn compose(
    owner: *Persistent,
    expected: u64,
    source: ?[]const u8,
    now: u64,
    omit_source: []const u8,
) !candidates.Candidate {
    if (try revision(owner) != expected) return error.Conflict;
    const memory = try owner.gpa.alloc(u8, source_budget);
    defer owner.gpa.free(memory);
    var arena = std.heap.FixedBufferAllocator.init(memory);
    const allocator = arena.allocator();
    const replacement = if (source) |text| try policy.management.parse(allocator, text) else null;
    var sources: [policy.engine.MAX_RULES][]const u8 = undefined;
    const count = try documents(
        owner,
        allocator,
        &sources,
        if (replacement) |document| document.id else "",
        source,
    );
    const reputation = try reputations(owner, allocator, now, omit_source);
    var candidate = try candidates.Candidate.init(owner.gpa, .{
        .default_difficulty = owner.cfg.default_difficulty,
        .waf = owner.cfg.waf,
        .file = owner.policy_text,
    }, sources[0..count], reputation);
    errdefer candidate.deinit();
    try @import("policy_inspection.zig").apply(owner, candidate.engine);
    // Includes reputation mutations. A caller must check again before any conditional commit.
    if (try revision(owner) != expected) return error.Conflict;
    return candidate;
}

fn documents(
    owner: *Persistent,
    allocator: std.mem.Allocator,
    output: *[policy.engine.MAX_RULES][]const u8,
    replace_id: []const u8,
    replacement: ?[]const u8,
) !usize {
    var cursor: []const u8 = "";
    var count: usize = 0;
    var replaced = false;
    while (true) {
        var rows = try db.query(
            owner.db,
            owner.gpa,
            "SELECT id,name,priority,enabled,path_pattern,ua_pattern,action,difficulty," ++
                "algorithm,weight,header_matchers,cidr_matchers,limit_config FROM policies " ++
                "WHERE id>=? AND (?='' OR id>?) ORDER BY id LIMIT 8",
            &.{ util.text(cursor), util.text(cursor), util.text(cursor) },
        );
        defer rows.deinit();
        for (rows.rows) |row| {
            if (count == output.len) return error.TooManyDocuments;
            const id = row[0] orelse return error.InvalidStoredPolicy;
            if (std.mem.eql(u8, id, replace_id)) {
                output[count] = replacement.?;
                replaced = true;
            } else {
                const document = try encode(row);
                output[count] = try allocator.dupe(u8, document.slice());
            }
            cursor = try allocator.dupe(u8, id);
            count += 1;
        }
        if (rows.rows.len < 8) break;
    }
    if (!replaced and replacement != null) {
        if (count == output.len) return error.TooManyDocuments;
        output[count] = replacement.?;
        count += 1;
    }
    return count;
}

/// A candidate built from the given documents only (plus the file, reputation and
/// inspection settings), for a set import that replaces every managed rule.
pub fn fromSources(
    owner: *Persistent,
    expected: u64,
    sources: []const []const u8,
    now: u64,
) !candidates.Candidate {
    if (try revision(owner) != expected) return error.Conflict;
    const memory = try owner.gpa.alloc(u8, 256 * 1024);
    defer owner.gpa.free(memory);
    var arena = std.heap.FixedBufferAllocator.init(memory);
    const reputation = try reputations(owner, arena.allocator(), now, "");
    var candidate = try candidates.Candidate.init(owner.gpa, .{
        .default_difficulty = owner.cfg.default_difficulty,
        .waf = owner.cfg.waf,
        .file = owner.policy_text,
    }, sources, reputation);
    errdefer candidate.deinit();
    try @import("policy_inspection.zig").apply(owner, candidate.engine);
    if (try revision(owner) != expected) return error.Conflict;
    return candidate;
}

/// The stored document with its priority replaced; used by ordering to write history.
pub fn documentWithPriority(owner: *Persistent, id: []const u8, priority: i32) !?p.Bytes(4096) {
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT id,name,priority,enabled,path_pattern,ua_pattern,action,difficulty," ++
            "algorithm,weight,header_matchers,cidr_matchers,limit_config " ++
            "FROM policies WHERE id=? LIMIT 1",
        &.{util.text(id)},
    );
    defer rows.deinit();
    if (rows.rows.len == 0) return null;
    var buffer: [12]u8 = undefined;
    var cells = rows.rows[0];
    var patched: [13]?[]const u8 = undefined;
    @memcpy(&patched, cells[0..13]);
    patched[2] = try std.fmt.bufPrint(&buffer, "{d}", .{priority});
    cells = &patched;
    return try encode(cells);
}

pub fn readDocument(owner: *Persistent, id: []const u8) !?p.Bytes(4096) {
    var rows = try db.query(
        owner.db,
        owner.gpa,
        "SELECT id,name,priority,enabled,path_pattern,ua_pattern,action,difficulty," ++
            "algorithm,weight,header_matchers,cidr_matchers,limit_config " ++
            "FROM policies WHERE id=? LIMIT 1",
        &.{util.text(id)},
    );
    defer rows.deinit();
    if (rows.rows.len == 0) return null;
    return try encode(rows.rows[0]);
}

fn encode(row: []const ?[]const u8) !p.Bytes(4096) {
    std.debug.assert(row.len == 13);
    var output: p.Bytes(4096) = .{};
    var writer: std.Io.Writer = .fixed(&output.data);
    const action = policy.Action.parse(row[6] orelse return error.InvalidStoredPolicy) orelse
        return error.InvalidStoredPolicy;
    const enabled = try util.number(row[3]);
    if (enabled > 1) return error.InvalidStoredPolicy;
    try std.json.Stringify.value(.{
        .id = row[0] orelse return error.InvalidStoredPolicy,
        .name = row[1] orelse return error.InvalidStoredPolicy,
        .priority = try std.fmt.parseInt(i32, row[2] orelse return error.InvalidStoredPolicy, 10),
        .enabled = enabled == 1,
        .path = row[4],
        .user_agent = row[5],
        .action = action,
        .difficulty = if (row[7]) |value| try std.fmt.parseInt(u32, value, 10) else null,
        .algorithm = row[8],
        .weight = try std.fmt.parseInt(i32, row[9] orelse return error.InvalidStoredPolicy, 10),
    }, .{}, &writer);
    writer.end -= 1;
    try matcher(&writer, "headers", row[10]);
    try matcher(&writer, "cidrs", row[11]);
    try matcher(&writer, "limits", row[12]);
    try writer.writeByte('}');
    output.len = writer.buffered().len;
    return output;
}

fn matcher(writer: *std.Io.Writer, name: []const u8, optional: ?[]const u8) !void {
    const source = optional orelse return;
    if (source.len > policy.management.max_document) return error.InvalidStoredPolicy;
    var memory: [16384]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const value = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), source, .{});
    try writer.print(",\"{s}\":", .{name});
    try std.json.Stringify.value(value, .{}, writer);
}

fn reputations(
    owner: *Persistent,
    allocator: std.mem.Allocator,
    now: u64,
    omit_source: []const u8,
) ![]const candidates.Reputation {
    const entries = try allocator.alloc(candidates.Reputation, policy.radix_trie.MAX_NODES);
    var count: usize = 0;
    var cursor: []const u8 = "";
    while (true) {
        var rows = try db.query(
            owner.db,
            owner.gpa,
            "SELECT ip_or_cidr,reputation_score FROM ip_reputation WHERE ip_or_cidr>? " ++
                "AND (banned_until IS NULL OR banned_until>?) " ++
                "AND (reputation_score<=-50 OR reputation_score>=50) " ++
                "AND (?='' OR source<>?) " ++
                "ORDER BY ip_or_cidr LIMIT 64",
            &.{
                util.text(cursor),      util.integer(now),
                util.text(omit_source), util.text(omit_source),
            },
        );
        defer rows.deinit();
        for (rows.rows) |row| {
            if (count == entries.len) return error.TooManyReputations;
            const cidr = row[0] orelse return error.InvalidStoredPolicy;
            if (cidr.len == 0 or cidr.len > 48) return error.InvalidCidr;
            cursor = try allocator.dupe(u8, cidr);
            const score = try std.fmt.parseInt(i32, row[1].?, 10);
            entries[count] = .{ .cidr = cursor, .action = if (score < 0) .deny else .allow };
            count += 1;
        }
        if (rows.rows.len < 64) return entries[0..count];
    }
}
