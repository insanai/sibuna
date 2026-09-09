//! Country refresh previews pin the exact replacement and every operator-selected parameter.
const std = @import("std");
const App = @import("app.zig").App;
const http = @import("http.zig");
const p = @import("console_protocol");
const w = p.workflows;
const revision = @import("workflow_routes.zig").revision;
const reply = @import("workflow_routes.zig").reply;

const CountryForm = struct {
    country: []const u8,
    expected_revision: []const u8,
    action: w.ReputationAction = .deny,
    until: ?[]const u8 = null,
    review: []const u8 = "",
    offset: u16 = 0,
};

/// Stages every prefix of the country from the active generation, then asks the owner to
/// preflight them; `apply` commits the same staged set pinned to the generation digest.
pub fn handle(app: *App, context: *http.Context, auth: p.users.Auth, applying: bool) !void {
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
    const digest = try stageCountry(app, context, prefixes[0..count]) orelse return;
    const expected = try revision(form.expected_revision);
    const expires = if (form.until) |text| try revision(text) else null;
    const reviewed = try reviewDigest(form, generation, digest, expected, expires);
    if ((applying or form.offset != 0) and !std.mem.eql(u8, form.review, &reviewed))
        return http.fail(context, .conflict, "CONSOLEPOLICY");
    const result = if (applying) try app.request(.{ .country_apply = .{
        .auth = auth,
        .expected_revision = expected,
        .digest = digest,
        .count = @intCast(count),
        .country = code,
        .action = form.action,
        .until = expires,
        .geo_generation = try p.Bytes(64).init(&std.fmt.bytesToHex(generation, .lower)),
    } }) else try app.request(.{ .country_preflight = .{
        .auth = auth,
        .expected_revision = expected,
        .digest = digest,
        .count = @intCast(count),
        .country = code,
        .action = form.action,
        .diff_offset = form.offset,
    } });
    if (result != .country_summary) return reply(context, result);
    return previewReply(context, result.country_summary, generation, reviewed);
}

fn previewReply(
    context: *http.Context,
    summary: w.CountrySummary,
    generation: [32]u8,
    reviewed: [64]u8,
) !void {
    var sample: [8][]const u8 = undefined;
    for (summary.sample[0..summary.sample_count], 0..) |*prefix, index|
        sample[index] = prefix.slice();
    var removed: [8][]const u8 = undefined;
    for (summary.removed_sample[0..summary.removed_count], 0..) |*prefix, index|
        removed[index] = prefix.slice();
    var changes: [8]struct { prefix: []const u8, kind: []const u8 } = undefined;
    for (summary.changes[0..summary.change_count], 0..) |*change, index|
        changes[index] = .{ .prefix = change.prefix.slice(), .kind = @tagName(change.kind) };
    return http.json(context, .{
        .prefixes = summary.prefixes,
        .nodes_before = summary.nodes_before,
        .nodes_after = summary.nodes_after,
        .overlaps = summary.overlaps,
        .previous = summary.previous,
        .added = summary.added,
        .removed = summary.removed,
        .retained = summary.retained,
        .previous_generation = summary.previous_generation.slice(),
        .removed_sample = removed[0..summary.removed_count],
        .sample = sample[0..summary.sample_count],
        .generation = @as([]const u8, &std.fmt.bytesToHex(generation, .lower)),
        .review = @as([]const u8, &reviewed),
        .changes = changes[0..summary.change_count],
        .next_offset = summary.next_offset,
    }, &.{});
}

// This is a consistency digest, not an authorization credential. Normal session/CSRF
// authorization is independently rechecked. A changed form, generation or revision needs
// a fresh preview, including when the country no longer has any ranges.
fn reviewDigest(
    form: CountryForm,
    generation: [32]u8,
    prefixes: [32]u8,
    expected: u64,
    expires: ?u64,
) ![64]u8 {
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try std.json.Stringify.value(.{
        .country = form.country,
        .action = form.action,
        .expected = expected,
        .expires = expires,
    }, .{}, &writer);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("sibuna-country-review-v1");
    hash.update(&generation);
    hash.update(&prefixes);
    hash.update(writer.buffered());
    return std.fmt.bytesToHex(hash.finalResult(), .lower);
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
