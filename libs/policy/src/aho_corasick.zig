//! Aho-Corasick Multi-Pattern Automaton
//!
//! Single-pass, linear-time matching of hundreds of literal patterns (Aho and
//! Corasick, CACM 1975). The automaton is a dense table: one `u16` successor
//! per (state, byte), so scanning is one load per input byte with no
//! branches on the pattern set. Case folding goes through a comptime table
//! so `GPTBot`, `gptbot`, and `GptBot` share one path. Memory is
//! `max_states * 512` bytes; callers size the automaton for their pattern
//! set (bots fit in 1024 states, WAF signatures in 2048).

const std = @import("std");

pub const Match = struct {
    name: []const u8,
    tag: u8,
};

pub fn Automaton(comptime max_states: u16) type {
    return struct {
        const Self = @This();
        pub const MAX_STATES = max_states;

        transitions: [max_states][256]u16 = [_][256]u16{[_]u16{0} ** 256} ** max_states,
        fail: [max_states]u16 = [_]u16{0} ** max_states,
        match_id: [max_states]u16 = [_]u16{no_match} ** max_states,
        pattern_names: [max_states][]const u8 = [_][]const u8{""} ** max_states,
        pattern_tags: [max_states]u8 = [_]u8{0} ** max_states,
        num_states: u16 = 1,
        num_patterns: u16 = 0,
        built: bool = false,

        pub fn init() Self {
            return .{};
        }

        pub fn addPattern(self: *Self, pattern: []const u8) !u16 {
            return addPatternImpl(self, pattern, 0);
        }

        pub fn addPatternTagged(self: *Self, pattern: []const u8, tag: u8) !u16 {
            return addPatternImpl(self, pattern, tag);
        }

        /// Computes failure links breadth-first and folds them into the
        /// transition table, so scanning never follows a failure chain.
        pub fn build(self: *Self) void {
            buildImpl(self);
        }

        pub fn findFirstTagged(self: *const Self, haystack: []const u8) ?Match {
            return findFirstImpl(self, haystack);
        }

        /// Selected-category inspection must also consider suffix outputs when a
        /// different category owns the state's first match. Failure links strictly
        /// shorten the prefix; fixed automaton capacity bounds this additional walk.
        pub fn findFirstTaggedAs(self: *const Self, haystack: []const u8, tag: u8) ?Match {
            var state: u16 = 0;
            for (haystack) |byte| {
                state = self.transitions[state][toLower(byte)];
                var candidate = state;
                while (candidate != 0) : (candidate = self.fail[candidate]) {
                    const pid = self.match_id[candidate];
                    if (pid == no_match) break;
                    if (self.pattern_tags[pid] == tag)
                        return .{ .name = self.pattern_names[pid], .tag = tag };
                }
            }
            return null;
        }

        pub fn findFirst(self: *const Self, haystack: []const u8) ?[]const u8 {
            const m = findFirstImpl(self, haystack) orelse return null;
            return m.name;
        }
    };
}

const no_match: u16 = std.math.maxInt(u16);

test "tag selection retains overlapping suffix matches and skips unselected outputs" {
    var matcher: Automaton(16) = .{};
    _ = try matcher.addPatternTagged("aab", 1);
    _ = try matcher.addPatternTagged("ab", 2);
    _ = try matcher.addPatternTagged("cd", 3);
    matcher.build();
    try std.testing.expectEqualStrings("ab", matcher.findFirstTaggedAs("AABcd", 2).?.name);
    try std.testing.expectEqualStrings("cd", matcher.findFirstTaggedAs("aabcd", 3).?.name);
    try std.testing.expect(matcher.findFirstTaggedAs("aabcd", 4) == null);
}

const to_lower_table: [256]u8 = blk: {
    var table: [256]u8 = undefined;
    for (0..256) |i| {
        const c: u8 = @intCast(i);
        table[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
    }
    break :blk table;
};

inline fn toLower(c: u8) u8 {
    return to_lower_table[c];
}

fn addPatternImpl(self: anytype, pattern: []const u8, tag: u8) !u16 {
    const max_states = @TypeOf(self.*).MAX_STATES;
    std.debug.assert(!self.built);
    if (pattern.len == 0) return error.EmptyPattern;
    if (self.num_patterns >= max_states) return error.TooManyPatterns;
    var state: u16 = 0;
    for (pattern) |byte| {
        const c = toLower(byte);
        if (self.transitions[state][c] == 0) {
            if (self.num_states >= max_states) return error.TooManyStates;
            self.transitions[state][c] = self.num_states;
            self.num_states += 1;
        }
        state = self.transitions[state][c];
    }
    const pid = self.num_patterns;
    self.match_id[state] = pid;
    self.pattern_names[pid] = pattern;
    self.pattern_tags[pid] = tag;
    self.num_patterns += 1;
    return pid;
}

fn buildImpl(self: anytype) void {
    const max_states = @TypeOf(self.*).MAX_STATES;
    var queue: [max_states]u16 = undefined;
    var head: usize = 0;
    var tail: usize = 0;

    for (0..256) |c| {
        const next = self.transitions[0][c];
        if (next != 0) {
            queue[tail] = next;
            tail += 1;
        }
    }

    while (head < tail) {
        const state = queue[head];
        head += 1;
        const fail_state = self.fail[state];
        if (self.match_id[state] == no_match) {
            self.match_id[state] = self.match_id[fail_state];
        }
        for (0..256) |c| {
            const next = self.transitions[state][c];
            if (next != 0) {
                self.fail[next] = self.transitions[fail_state][c];
                queue[tail] = next;
                tail += 1;
            } else {
                self.transitions[state][c] = self.transitions[fail_state][c];
            }
        }
    }
    self.built = true;
}

fn findFirstImpl(self: anytype, haystack: []const u8) ?Match {
    var state: u16 = 0;
    for (haystack) |byte| {
        state = self.transitions[state][toLower(byte)];
        const pid = self.match_id[state];
        if (pid != no_match) {
            return .{ .name = self.pattern_names[pid], .tag = self.pattern_tags[pid] };
        }
    }
    return null;
}

pub const MAX_STATES = 2048;
pub const Matcher = Automaton(MAX_STATES);
const bots = @import("bot_signatures.zig");

pub fn patternCapacity(comptime patterns: []const []const u8) u16 {
    comptime {
        var count: u16 = 0;
        for (patterns) |pattern| count += @intCast(pattern.len);
        return count;
    }
}

pub const BotMatcher = Automaton(1 + patternCapacity(&bots.AI_SCRAPERS) +
    patternCapacity(&bots.SCRAPER_LIBRARIES) + patternCapacity(&bots.SEARCH_CRAWLERS));

test "aho corasick matches substrings case-insensitively with tags" {
    var matcher = Matcher.init();
    _ = try matcher.addPatternTagged("GPTBot", 1);
    _ = try matcher.addPatternTagged("ClaudeBot", 1);
    _ = try matcher.addPatternTagged("python-requests", 2);
    matcher.build();

    const ua1 = "Mozilla/5.0 (compatible; gptbot/1.2; +https://openai.com/gptbot)";
    const m1 = matcher.findFirstTagged(ua1).?;
    try std.testing.expectEqualStrings("GPTBot", m1.name);
    try std.testing.expectEqual(@as(u8, 1), m1.tag);

    const ua2 = "Python-Requests/2.28.1";
    try std.testing.expectEqualStrings("python-requests", matcher.findFirst(ua2).?);
    try std.testing.expectEqual(@as(u8, 2), matcher.findFirstTagged(ua2).?.tag);

    const ua3 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36";
    try std.testing.expect(matcher.findFirst(ua3) == null);
}

test "aho corasick agrees with naive search on random inputs" {
    var matcher = BotMatcher.init();
    const patterns = [_][]const u8{ "he", "she", "his", "hers", "bot", "curl/", "xyz" };
    for (patterns) |p| _ = try matcher.addPattern(p);
    matcher.build();
    var prng = std.Random.DefaultPrng.init(42);
    const rand = prng.random();
    var buf: [48]u8 = undefined;
    var round: usize = 0;
    while (round < 2000) : (round += 1) {
        const len = rand.intRangeAtMost(usize, 0, buf.len);
        for (buf[0..len]) |*b| b.* = "hersibotcurl/XYZ "[rand.intRangeAtMost(usize, 0, 16)];
        const text = buf[0..len];
        var naive = false;
        for (patterns) |p| {
            if (std.ascii.indexOfIgnoreCase(text, p) != null) naive = true;
        }
        try std.testing.expectEqual(naive, matcher.findFirst(text) != null);
    }
}
