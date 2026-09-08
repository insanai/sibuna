//! A private, bounded engine used before management commits. No publication or storage here.
const std = @import("std");
const engine = @import("engine.zig");
const management = @import("management.zig");
const rule = @import("rule.zig");

pub const arena_bytes = 2 * 1024 * 1024;
pub const max_file_bytes = 256 * 1024;
pub const Options = struct {
    default_difficulty: u32,
    waf: bool,
    file: ?[]const u8 = null,
};
pub const Reputation = struct { cidr: []const u8, action: rule.Action };
pub const Error = management.ParseError || error{
    TooManyRules,
    InvalidRuleName,
    TooManyDocuments,
    TooManyReputations,
    DuplicateId,
    FileTooLarge,
    TrieFull,
    InvalidCidr,
    InvalidReputationAction,
};

pub const Candidate = struct {
    allocator: std.mem.Allocator,
    engine: *engine.Engine,
    memory: []u8,

    /// Engine and strings have one owner. Errors release both; a draft never borrows its input.
    /// Reputation rows must represent the caller's revision-bound active snapshot.
    pub fn init(
        allocator: std.mem.Allocator,
        options: Options,
        sources: []const []const u8,
        reputation: []const Reputation,
    ) Error!Candidate {
        if (sources.len > engine.MAX_RULES) return error.TooManyDocuments;
        if (reputation.len > @import("radix_trie.zig").MAX_NODES)
            return error.TooManyReputations;
        if (options.file) |file| if (file.len > max_file_bytes) return error.FileTooLarge;
        const output = try allocator.create(engine.Engine);
        errdefer allocator.destroy(output);
        const memory = try allocator.alloc(u8, arena_bytes);
        errdefer allocator.free(memory);
        var arena = std.heap.FixedBufferAllocator.init(memory);
        output.initInPlace(options.default_difficulty);
        output.waf_enabled = options.waf;
        if (options.file) |file| try output.loadFromJsonInto(arena.allocator(), file);
        try compileRules(output, arena.allocator(), sources);
        for (reputation) |entry| {
            if (entry.action != .allow and entry.action != .deny)
                return error.InvalidReputationAction;
            try output.ip_trie.insertCidr(entry.cidr, entry.action);
        }
        return .{ .allocator = allocator, .engine = output, .memory = memory };
    }

    pub fn deinit(self: *Candidate) void {
        self.allocator.destroy(self.engine);
        self.allocator.free(self.memory);
        self.* = undefined;
    }
};

fn compileRules(
    output: *engine.Engine,
    allocator: std.mem.Allocator,
    sources: []const []const u8,
) Error!void {
    var documents: [engine.MAX_RULES]management.Document = undefined;
    for (sources, 0..) |source, i| {
        documents[i] = try management.parse(allocator, source);
        for (documents[0..i]) |previous| {
            if (std.mem.eql(u8, previous.id, documents[i].id)) return error.DuplicateId;
        }
    }
    std.mem.sort(management.Document, documents[0..sources.len], {}, before);
    var enabled: usize = 0;
    for (documents[0..sources.len]) |document| enabled += @intFromBool(document.enabled);
    if (enabled + output.rule_count > engine.MAX_RULES) return error.TooManyRules;
    // Preserve fallback order while inserting dynamic rules ahead of file/default admission.
    const fallback_count = output.rule_count;
    std.mem.copyBackwards(
        rule.PolicyRule,
        output.rules[enabled .. enabled + fallback_count],
        output.rules[0..fallback_count],
    );
    output.rule_count = 0;
    for (documents[0..sources.len]) |document| {
        if (document.enabled) try output.addRule(document.value);
    }
    output.rule_count += fallback_count;
}

fn before(_: void, left: management.Document, right: management.Document) bool {
    if (left.priority != right.priority) return left.priority < right.priority;
    const names = std.mem.order(u8, left.value.name, right.value.name);
    if (names != .eq) return names == .lt;
    return std.mem.order(u8, left.id, right.id) == .lt;
}

test "private candidates retain file inspection modes and reject invalid settings" {
    const t = std.testing;
    var candidate = try Candidate.init(t.allocator, .{
        .default_difficulty = 16,
        .waf = true,
        .file = "{\"inspection\":{\"sqli\":\"audit\",\"xss\":\"disabled\"}}",
    }, &.{}, &.{});
    defer candidate.deinit();
    const decision = candidate.engine.evaluateRequest(.{
        .path = "/robots.txt",
        .query = "union select <script>",
        .client_ip = "8.8.8.8",
    });
    try t.expectEqual(rule.Action.allow, decision.action);
    try t.expectEqual(@import("inspection.zig").bit(.sqli), decision.audited);
    candidate.engine.waf_enabled = false;
    try t.expectEqual(@as(u8, 0), candidate.engine.evaluateRequest(.{
        .path = "/robots.txt",
        .query = "union select",
        .client_ip = "8.8.8.8",
    }).audited);
    try t.expectError(error.UnknownField, Candidate.init(t.allocator, .{
        .default_difficulty = 16,
        .waf = true,
        .file = "{\"inspection\":{\"sql\":\"audit\"}}",
    }, &.{}, &.{}));
    try t.expectError(error.InvalidEnumTag, Candidate.init(t.allocator, .{
        .default_difficulty = 16,
        .waf = true,
        .file = "{\"inspection\":{\"sqli\":\"ignore\"}}",
    }, &.{}, &.{}));
}

test "candidate owns inputs and composes ordered rules, file settings and reputation" {
    var document = ("{\"id\":\"deny\",\"name\":\"Deny\",\"action\":\"deny\"," ++
        "\"path\":\"/private\"}").*;
    var file = ("{\"default_action\":\"ALLOW\",\"rules\":[{\"name\":\"File\"," ++
        "\"action\":\"ALLOW\",\"path\":\"/from-file\"}]}").*;
    var draft = try Candidate.init(std.testing.allocator, .{
        .default_difficulty = 17,
        .waf = false,
        .file = &file,
    }, &.{&document}, &.{.{ .cidr = "8.8.4.0/24", .action = .deny }});
    defer draft.deinit();
    @memset(&document, 'x');
    @memset(&file, 'x');
    try std.testing.expectEqual(@as(usize, 2), draft.engine.rule_count);
    try std.testing.expectEqualStrings("Deny", draft.engine.rules[0].name);
    try std.testing.expectEqualStrings("File", draft.engine.rules[1].name);
    try std.testing.expectEqual(rule.Action.allow, draft.engine.default_action);
    try std.testing.expectEqual(@as(u32, 17), draft.engine.default_difficulty);
    try std.testing.expect(!draft.engine.waf_enabled);
    const result = draft.engine.evaluateRequest(.{
        .path = "/other",
        .client_ip = "8.8.4.4",
        .user_agent = "human",
    });
    try std.testing.expectEqual(rule.Action.deny, result.action);
}

test "candidate refuses duplicates and capacity overflow and releases failed drafts" {
    const source = "{\"id\":\"same\",\"name\":\"Same\",\"action\":\"deny\"}";
    const options: Options = .{ .default_difficulty = 16, .waf = true };
    try std.testing.expectError(error.DuplicateId, Candidate.init(
        std.testing.allocator,
        options,
        &.{ source, source },
        &.{},
    ));
    const sources = [_][]const u8{source} ** (engine.MAX_RULES + 1);
    try std.testing.expectError(error.TooManyDocuments, Candidate.init(
        std.testing.allocator,
        options,
        &sources,
        &.{},
    ));
    try std.testing.expectError(error.InvalidCidr, Candidate.init(
        std.testing.allocator,
        options,
        &.{},
        &.{.{ .cidr = "bad", .action = .deny }},
    ));
}

test "candidate counts fallbacks against capacity and validates disabled documents" {
    var storage: [engine.MAX_RULES][128]u8 = undefined;
    var sources: [engine.MAX_RULES][]const u8 = undefined;
    for (&sources, 0..) |*source, i| {
        source.* = try std.fmt.bufPrint(
            &storage[i],
            "{{\"id\":\"r{d}\",\"name\":\"Rule\",\"action\":\"deny\"}}",
            .{i},
        );
    }
    const options: Options = .{ .default_difficulty = 16, .waf = true };
    try std.testing.expectError(error.TooManyRules, Candidate.init(
        std.testing.allocator,
        options,
        &sources,
        &.{},
    ));
    const disabled = "{\"id\":\"off\",\"name\":\"Off\",\"action\":\"allow\"," ++
        "\"enabled\":false,\"cidrs\":[\"invalid\"]}";
    try std.testing.expectError(error.InvalidCidr, Candidate.init(
        std.testing.allocator,
        options,
        &.{disabled},
        &.{},
    ));
}

test "candidate ordering uses priority then name then identity and excludes disabled rules" {
    const a = "{\"id\":\"a\",\"name\":\"Same\",\"priority\":10,\"action\":\"deny\"}";
    const b = "{\"id\":\"b\",\"name\":\"Same\",\"priority\":10,\"action\":\"allow\"}";
    const c = "{\"id\":\"c\",\"name\":\"First\",\"priority\":10,\"action\":\"weigh\"}";
    const d = "{\"id\":\"d\",\"name\":\"Priority\",\"priority\":0,\"action\":\"weigh\"}";
    const off = "{\"id\":\"off\",\"name\":\"Off\",\"action\":\"deny\",\"enabled\":false}";
    var draft = try Candidate.init(std.testing.allocator, .{
        .default_difficulty = 16,
        .waf = true,
        .file = "{\"rules\":[]}",
    }, &.{ b, off, a, c, d }, &.{});
    defer draft.deinit();
    try std.testing.expectEqual(@as(usize, 4), draft.engine.rule_count);
    try std.testing.expectEqualStrings("Priority", draft.engine.rules[0].name);
    try std.testing.expectEqualStrings("First", draft.engine.rules[1].name);
    try std.testing.expectEqual(rule.Action.deny, draft.engine.rules[2].action);
    try std.testing.expectEqual(rule.Action.allow, draft.engine.rules[3].action);
}

test "candidate refuses a reputation set that exhausts the shared trie" {
    var storage: [128][48]u8 = undefined;
    var entries: [128]Reputation = undefined;
    for (&entries, 0..) |*entry, i| {
        entry.* = .{
            .cidr = try std.fmt.bufPrint(&storage[i], "{x}::1/128", .{i + 1}),
            .action = .deny,
        };
    }
    try std.testing.expectError(error.TrieFull, Candidate.init(
        std.testing.allocator,
        .{ .default_difficulty = 16, .waf = true },
        &.{},
        &entries,
    ));
}
