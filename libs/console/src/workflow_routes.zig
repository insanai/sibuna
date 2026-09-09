//! Policy workflow routes: ordering, replay, reputation prefixes, country blocks and the
//! chunked set import. Mutations carry the caller's expected revision; the storage owner
//! decides, and this layer only shapes bounded requests and replies.
const std = @import("std");
const App = @import("app.zig").App;
const http = @import("http.zig");
const p = @import("console_protocol");
const w = p.workflows;
const Handler = @import("routes.zig").Handler;

pub fn handle(app: *App, context: *http.Context, principal: p.Principal, handler: Handler) !void {
    const digest = try http.session(context);
    const auth: p.users.Auth = .{
        .session_digest = digest,
        .csrf_digest = principal.csrf_digest,
        .require_totp = app.config.behind_proxy,
    };
    return switch (handler) {
        .policy_order => order(app, context, auth),
        .policy_replay => replay(app, context, auth),
        .reputation_query => reputationQuery(app, context, auth),
        .reputation_edit => reputationEdit(app, context, auth),
        .reputation_remove => reputationRemove(app, context, auth),
        .country_preview => country(app, context, auth, false),
        .country_apply => country(app, context, auth, true),
        .import_chunk => importChunk(app, context),
        .import_commit => importCommit(app, context, auth),
        else => unreachable,
    };
}

fn revision(text: []const u8) error{InvalidRequest}!u64 {
    return std.fmt.parseInt(u64, text, 10) catch error.InvalidRequest;
}

fn reply(context: *http.Context, result: p.StorageResult) !void {
    switch (result) {
        .revision => |value| {
            var committed: [20]u8 = undefined;
            var applied: [20]u8 = undefined;
            return http.json(context, .{
                .committed = try std.fmt.bufPrint(&committed, "{d}", .{value.committed}),
                .applied = try std.fmt.bufPrint(&applied, "{d}", .{value.applied}),
            }, &.{});
        },
        .command_recorded => return http.json(context, .{ .ok = true }, &.{}),
        .failed => |reason| return fail(context, reason),
        else => return error.StorageUnavailable,
    }
}

fn fail(context: *http.Context, reason: p.Failure) !void {
    if (reason == .unavailable) return http.fail(context, .service_unavailable, "CONSOLEQUORUM");
    return http.fail(context, switch (reason) {
        .unauthorized => .unauthorized,
        .forbidden => .forbidden,
        .conflict => .conflict,
        .invalid_input => .bad_request,
        .capacity => .unprocessable_entity,
        else => .service_unavailable,
    }, if (reason == .capacity) "CONSOLECAPACITY" else "CONSOLEPOLICY");
}

fn order(app: *App, context: *http.Context, auth: p.users.Auth) !void {
    var body: [512]u8 = undefined;
    var memory: [1024]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(struct {
        id: []const u8,
        expected_revision: []const u8,
        direction: w.Direction,
    }, context, &body, arena.allocator());
    defer parsed.deinit();
    return reply(context, try app.request(.{ .policy_order = .{
        .auth = auth,
        .expected_revision = try revision(parsed.value.expected_revision),
        .id = try p.Bytes(128).init(parsed.value.id),
        .direction = parsed.value.direction,
    } }));
}

fn replay(app: *App, context: *http.Context, auth: p.users.Auth) !void {
    if (!app.query_budget.allow(app.io, auth.session_digest, app.now(), .query))
        return http.fail(context, .too_many_requests, "CONSOLEQUERY");
    var body: [8192]u8 = undefined;
    var memory: [16384]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(struct {
        rule: []const u8 = "",
        hours: u16 = 24,
        draft: ?[]const u8 = null,
        committed: ?[]const u8 = null,
    }, context, &body, arena.allocator());
    defer parsed.deinit();
    const input = parsed.value;
    const result = try app.request(.{ .policy_replay = .{
        .auth = auth,
        .committed = if (input.committed) |text| try revision(text) else null,
        .draft = if (input.draft) |draft| try p.Bytes(4096).init(draft) else null,
        .rule = try p.Bytes(128).init(input.rule),
        .hours = input.hours,
    } });
    if (result != .replay_summary) return reply(context, result);
    const summary = result.replay_summary;
    var rows: [w.replay_rows]struct {
        id: p.Counter,
        ip: []const u8,
        path: []const u8,
        action: []const u8,
        rule: []const u8,
        conclusive: bool,
        matched: bool,
    } = undefined;
    for (summary.rows[0..summary.count], 0..) |*row, index| rows[index] = .{
        .id = .{ .value = row.id },
        .ip = row.ip.slice(),
        .path = row.path.slice(),
        .action = row.action.slice(),
        .rule = row.rule.slice(),
        .conclusive = row.conclusive,
        .matched = row.matched,
    };
    var applied: [20]u8 = undefined;
    var committed: [20]u8 = undefined;
    return http.json(context, .{
        .total = summary.total,
        .matched = summary.matched,
        .inconclusive = summary.inconclusive,
        .applied = try std.fmt.bufPrint(&applied, "{d}", .{summary.applied}),
        .committed = try std.fmt.bufPrint(&committed, "{d}", .{summary.committed}),
        .preview = summary.preview,
        .rows = rows[0..summary.count],
    }, &.{});
}

fn reputationQuery(app: *App, context: *http.Context, auth: p.users.Auth) !void {
    if (!app.query_budget.allow(app.io, auth.session_digest, app.now(), .query))
        return http.fail(context, .too_many_requests, "CONSOLEQUERY");
    var body: [512]u8 = undefined;
    var memory: [1024]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(
        struct { after: []const u8 = "" },
        context,
        &body,
        arena.allocator(),
    );
    defer parsed.deinit();
    const result = try app.request(.{ .reputation_query = .{
        .auth = auth,
        .after = try p.Bytes(w.max_prefix).init(parsed.value.after),
    } });
    if (result != .reputation_page) return reply(context, result);
    const page = result.reputation_page;
    var rows: [w.page_rows]struct {
        prefix: []const u8,
        score: i32,
        banned_until: ?p.Counter,
        trigger: []const u8,
        source: []const u8,
        note: []const u8,
        hits: p.Counter,
        last_seen: p.Counter,
    } = undefined;
    for (page.rows[0..page.count], 0..) |*row, index| rows[index] = .{
        .prefix = row.prefix.slice(),
        .score = row.score,
        .banned_until = if (row.banned_until) |until| .{ .value = until } else null,
        .trigger = row.trigger.slice(),
        .source = row.source.slice(),
        .note = row.note.slice(),
        .hits = .{ .value = row.hits },
        .last_seen = .{ .value = row.last_seen },
    };
    var committed: [20]u8 = undefined;
    return http.json(context, .{
        .committed = try std.fmt.bufPrint(&committed, "{d}", .{page.committed}),
        .nodes = page.nodes,
        .rows = rows[0..page.count],
        .next = if (page.next) |next| next.slice() else null,
    }, &.{});
}

const ReputationForm = struct {
    prefix: []const u8,
    expected_revision: []const u8,
    action: w.ReputationAction = .deny,
    until: ?[]const u8 = null,
    note: []const u8 = "",
};

fn reputationEdit(app: *App, context: *http.Context, auth: p.users.Auth) !void {
    var body: [1024]u8 = undefined;
    var memory: [2048]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(ReputationForm, context, &body, arena.allocator());
    defer parsed.deinit();
    const form = parsed.value;
    return reply(context, try app.request(.{ .reputation_edit = .{
        .auth = auth,
        .expected_revision = try revision(form.expected_revision),
        .prefix = try p.Bytes(w.max_prefix).init(form.prefix),
        .action = form.action,
        .until = if (form.until) |text| try revision(text) else null,
        .note = try p.Bytes(w.max_note).init(form.note),
    } }));
}

fn reputationRemove(app: *App, context: *http.Context, auth: p.users.Auth) !void {
    var body: [512]u8 = undefined;
    var memory: [1024]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(struct {
        prefix: []const u8,
        expected_revision: []const u8,
    }, context, &body, arena.allocator());
    defer parsed.deinit();
    return reply(context, try app.request(.{ .reputation_remove = .{
        .auth = auth,
        .expected_revision = try revision(parsed.value.expected_revision),
        .prefix = try p.Bytes(w.max_prefix).init(parsed.value.prefix),
    } }));
}

const CountryForm = struct {
    country: []const u8,
    expected_revision: []const u8,
    action: w.ReputationAction = .deny,
    until: ?[]const u8 = null,
};

/// Stages every prefix of the country from the active generation, then asks the owner to
/// preflight them; `apply` commits the same staged set pinned to the generation digest.
fn country(app: *App, context: *http.Context, auth: p.users.Auth, applying: bool) !void {
    var body: [512]u8 = undefined;
    var memory: [1024]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(CountryForm, context, &body, arena.allocator());
    defer parsed.deinit();
    const form = parsed.value;
    if (form.country.len != 2 or !@import("geoip").country.valid(form.country))
        return http.fail(context, .bad_request, "CONSOLEPOLICY");
    const code: [2]u8 = form.country[0..2].*;
    const prefixes = try app.gpa.alloc(@import("geoip_cidr.zig").Prefix, w.max_country_prefixes);
    defer app.gpa.free(prefixes);
    var generation: [32]u8 = undefined;
    const count = app.geo.country(app.io, code, prefixes, &generation) catch |err| switch (err) {
        error.NoGeneration => return http.fail(context, .conflict, "CONSOLEGEOIP"),
        error.TooManyPrefixes => return http.fail(
            context,
            .unprocessable_entity,
            "CONSOLECAPACITY",
        ),
    };
    if (count == 0) return http.fail(context, .bad_request, "CONSOLEPOLICY");
    const digest = try stageCountry(app, context, prefixes[0..count]) orelse return;
    const expected = try revision(form.expected_revision);
    const result = if (applying) try app.request(.{ .country_apply = .{
        .auth = auth,
        .expected_revision = expected,
        .digest = digest,
        .count = @intCast(count),
        .country = code,
        .action = form.action,
        .until = if (form.until) |text| try revision(text) else null,
        .geo_generation = try p.Bytes(64).init(&std.fmt.bytesToHex(generation, .lower)),
    } }) else try app.request(.{ .country_preflight = .{
        .auth = auth,
        .expected_revision = expected,
        .digest = digest,
        .count = @intCast(count),
    } });
    if (result != .country_summary) return reply(context, result);
    const summary = result.country_summary;
    var sample: [8][]const u8 = undefined;
    for (summary.sample[0..summary.sample_count], 0..) |*prefix, index|
        sample[index] = prefix.slice();
    return http.json(context, .{
        .prefixes = summary.prefixes,
        .nodes_before = summary.nodes_before,
        .nodes_after = summary.nodes_after,
        .overlaps = summary.overlaps,
        .sample = sample[0..summary.sample_count],
        .generation = @as([]const u8, &std.fmt.bytesToHex(generation, .lower)),
    }, &.{});
}

/// Hashes the prefix list and stages it in bounded chunks; null means a chunk was refused
/// and the reply has been written.
fn stageCountry(
    app: *App,
    context: *http.Context,
    prefixes: []const @import("geoip_cidr.zig").Prefix,
) !?[32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    for (prefixes) |prefix| {
        hash.update(prefix.text[0..prefix.len]);
        hash.update("\n");
    }
    const digest = hash.finalResult();
    var ordinal: u16 = 0;
    var sent: usize = 0;
    while (sent < prefixes.len) : (ordinal += 1) {
        var chunk: w.CountryChunk = .{ .digest = digest, .ordinal = ordinal };
        while (chunk.count < w.chunk_prefixes and sent < prefixes.len) : (sent += 1) {
            const prefix = prefixes[sent];
            const text = prefix.text[0..prefix.len];
            chunk.prefixes[chunk.count] = try p.Bytes(w.max_prefix).init(text);
            chunk.count += 1;
        }
        const staged = try app.request(.{ .country_chunk = chunk });
        if (staged != .command_recorded) {
            try reply(context, staged);
            return null;
        }
    }
    return digest;
}

fn importChunk(app: *App, context: *http.Context) !void {
    var body: [8192]u8 = undefined;
    var memory: [16384]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(struct {
        digest: []const u8,
        ordinal: u16,
        document: []const u8,
    }, context, &body, arena.allocator());
    defer parsed.deinit();
    var digest: [32]u8 = undefined;
    if (parsed.value.digest.len != 64) return error.InvalidRequest;
    _ = std.fmt.hexToBytes(&digest, parsed.value.digest) catch return error.InvalidRequest;
    return reply(context, try app.request(.{ .import_chunk = .{
        .digest = digest,
        .ordinal = parsed.value.ordinal,
        .document = try p.Bytes(4096).init(parsed.value.document),
    } }));
}

fn importCommit(app: *App, context: *http.Context, auth: p.users.Auth) !void {
    var body: [512]u8 = undefined;
    var memory: [1024]u8 = undefined;
    var arena = std.heap.FixedBufferAllocator.init(&memory);
    const parsed = try http.parse(struct {
        digest: []const u8,
        count: u16,
        expected_revision: []const u8,
    }, context, &body, arena.allocator());
    defer parsed.deinit();
    var digest: [32]u8 = undefined;
    if (parsed.value.digest.len != 64) return error.InvalidRequest;
    _ = std.fmt.hexToBytes(&digest, parsed.value.digest) catch return error.InvalidRequest;
    return reply(context, try app.request(.{ .import_commit = .{
        .auth = auth,
        .expected_revision = try revision(parsed.value.expected_revision),
        .digest = digest,
        .count = parsed.value.count,
    } }));
}
