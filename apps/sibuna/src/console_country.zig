//! Country blocks: the console stages the prefixes of a country from the active GeoIP
//! generation in bounded chunks; the owner verifies the staged set, preflights every prefix
//! in a private candidate, and applies all of them in one revision pinned to the generation.
const std = @import("std");
const policy = @import("policy");
const p = @import("console").protocol;
const w = p.workflows;
const zx = @import("zaxonlite");
const Persistent = @import("persistent.zig").Persistent;
const db = @import("console_database.zig");
const util = @import("console_store.zig");
const candidates = @import("console_policy_candidate.zig");
const auth = @import("console_policy_authorization.zig");

pub fn chunk(owner: *Persistent, input: w.CountryChunk, now: u64) !p.StorageResult {
    try p.validate(.{ .country_chunk = input });
    const digest = std.fmt.bytesToHex(input.digest, .lower);
    for (input.prefixes[0..input.count], 0..) |prefix, index| {
        if (policy.radix_trie.parseCidr(prefix.slice()) == null)
            return .{ .failed = .invalid_input };
        const ordinal = @as(u32, input.ordinal) * w.chunk_prefixes + @as(u32, @intCast(index));
        if (ordinal >= w.max_country_prefixes) return .{ .failed = .invalid_input };
        _ = try db.exec(
            owner.db,
            owner.gpa,
            "INSERT OR REPLACE INTO console_country_stage(digest,ordinal,prefix,recorded_at) " ++
                "VALUES(?,?,?,?)",
            &.{
                util.text(&digest),
                util.integer(ordinal),
                util.text(prefix.slice()),
                util.integer(now),
            },
        );
    }
    return .command_recorded;
}

pub fn preflight(owner: *Persistent, input: w.CountryPreflight, now: u64) !p.StorageResult {
    try p.validate(.{ .country_preflight = input });
    if (try auth.checkAuth(owner, input.auth)) |reason| return .{ .failed = reason };
    const summary = check(owner, input, now) catch |err|
        return .{ .failed = mapped(err) };
    return .{ .country_summary = summary };
}

pub fn apply(owner: *Persistent, input: w.CountryApply, now: u64) !p.StorageResult {
    try p.validate(.{ .country_apply = input });
    if (try auth.checkAuth(owner, input.auth)) |reason| return .{ .failed = reason };
    const valid_country = @import("console").geoip.country.valid(&input.country);
    if (!valid_country or input.geo_generation.len != 64) return .{ .failed = .invalid_input };
    if (input.until) |until| if (until <= now) return .{ .failed = .invalid_input };
    _ = check(owner, .{
        .auth = input.auth,
        .digest = input.digest,
        .count = input.count,
        .expected_revision = input.expected_revision,
        .country = input.country,
        .action = input.action,
    }, now) catch |err|
        return .{ .failed = mapped(err) };
    const credentials = auth.Credentials.fromAuth(input.auth, now);
    const digest = std.fmt.bytesToHex(input.digest, .lower);
    const changes = try db.exec(
        owner.db,
        owner.gpa,
        "INSERT INTO console_country_commit SELECT 1,u.id," ++ auth.role ++
            ",?,?,?,?,?,?,?,?,? " ++
            "FROM console_users u JOIN console_sessions s ON s.user_id=u.id " ++
            "WHERE " ++ auth.predicate ++ "AND " ++
            "(SELECT CAST(value AS INTEGER) FROM sibuna_meta WHERE key='policy_version')=?",
        &([_]zx.Value{
            util.integer(now),
            util.integer(input.expected_revision),
            util.text(&digest),
            util.integer(input.count),
            util.text(&input.country),
            .{ .integer = if (input.action == .deny) -100 else 100 },
            if (input.until) |until| util.integer(until) else .null_value,
            util.text(input.geo_generation.slice()),
            credentials.address(),
        } ++ credentials.values() ++ [_]zx.Value{util.integer(input.expected_revision)}),
    );
    if (changes == 0) {
        if (try auth.checkAuth(owner, input.auth)) |reason| return .{ .failed = reason };
        return .{ .failed = .conflict };
    }
    return .{ .revision = .{
        .committed = input.expected_revision + 1,
        .applied = owner.version,
    } };
}

fn mapped(err: anyerror) p.Failure {
    return switch (err) {
        error.IncompleteStage, error.InvalidCidr => .invalid_input,
        error.TrieFull => .capacity,
        else => @import("console_store_policies.zig").draftFailure(err),
    };
}

/// Verifies the staged set is complete and inserts every prefix into a private candidate.
/// Errors map to the caller's failure: an incomplete set is invalid input, a full trie is a
/// capacity refusal, and a moved revision is a conflict.
fn check(
    owner: *Persistent,
    input: w.CountryPreflight,
    now: u64,
) !w.CountrySummary {
    if (!@import("console").geoip.country.valid(&input.country)) return error.InvalidCidr;
    const digest = std.fmt.bytesToHex(input.digest, .lower);
    var source = "console:country:XX".*;
    @memcpy(source[16..], &input.country);
    var summary = try @import("console_country_diff.zig").describe(owner, input, &source);
    {
        var before = try candidates.current(owner, input.expected_revision, now);
        defer before.deinit();
        summary.nodes_before = before.engine.ip_trie.node_count;
    }
    var candidate = try candidates.withoutSource(owner, input.expected_revision, now, &source);
    defer candidate.deinit();
    const action: policy.Action = if (input.action == .deny) .deny else .allow;
    var ordinal: u64 = 0;
    while (true) {
        var rows = try db.query(
            owner.db,
            owner.gpa,
            "SELECT ordinal,prefix FROM console_country_stage WHERE digest=? AND ordinal>=? " ++
                "ORDER BY ordinal LIMIT 64",
            &.{ util.text(&digest), util.integer(ordinal) },
        );
        defer rows.deinit();
        for (rows.rows) |cells| {
            const prefix = cells[1] orelse return error.InvalidStoredPolicy;
            candidate.engine.ip_trie.insertCidr(prefix, action) catch |err| return err;
            if (summary.sample_count < summary.sample.len) {
                summary.sample[summary.sample_count] = try p.Bytes(w.max_prefix).init(prefix);
                summary.sample_count += 1;
            }
            ordinal = try util.number(cells[0]) + 1;
        }
        if (rows.rows.len < 64) break;
    }
    summary.nodes_after = candidate.engine.ip_trie.node_count;
    if (try candidates.revision(owner) != input.expected_revision) return error.Conflict;
    return summary;
}
