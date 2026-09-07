//! Aho-Corasick Multi-Pattern Automaton
//!
//! Provides single-pass linear-time multi-string pattern matching for
//! scanning User-Agent headers against hundreds of crawler signatures in <= 300ns.

const std = @import("std");

pub const MAX_STATES = 2048;

pub const Matcher = struct {
    transitions: [MAX_STATES][256]u16 = [_][256]u16{[_]u16{0} ** 256} ** MAX_STATES,
    fail: [MAX_STATES]u16 = [_]u16{0} ** MAX_STATES,
    match_id: [MAX_STATES]?u16 = [_]?u16{null} ** MAX_STATES,
    pattern_names: [MAX_STATES][]const u8 = [_][]const u8{""} ** MAX_STATES,
    num_states: u16 = 1,
    num_patterns: u16 = 0,

    pub fn init() Matcher {
        return .{};
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

    pub fn addPattern(self: *Matcher, pattern: []const u8) !u16 {
        if (self.num_patterns >= MAX_STATES) return error.TooManyPatterns;
        var state: u16 = 0;
        for (pattern) |byte| {
            const c = toLower(byte);
            if (self.transitions[state][c] == 0) {
                if (self.num_states >= MAX_STATES) return error.TooManyStates;
                self.transitions[state][c] = self.num_states;
                self.num_states += 1;
            }
            state = self.transitions[state][c];
        }
        const pid = self.num_patterns;
        self.match_id[state] = pid;
        self.pattern_names[pid] = pattern;
        self.num_patterns += 1;
        return pid;
    }

    pub fn build(self: *Matcher) void {
        var queue: [MAX_STATES]u16 = undefined;
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
            if (self.match_id[state] == null) {
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
    }

    pub fn findFirst(self: *const Matcher, haystack: []const u8) ?[]const u8 {
        var state: u16 = 0;
        for (haystack) |byte| {
            const c = toLower(byte);
            state = self.transitions[state][c];
            if (self.match_id[state]) |pid| {
                return self.pattern_names[pid];
            }
        }
        return null;
    }
};

test "aho corasick matches substrings case-insensitively" {
    var matcher = Matcher.init();
    _ = try matcher.addPattern("GPTBot");
    _ = try matcher.addPattern("ClaudeBot");
    _ = try matcher.addPattern("python-requests");
    matcher.build();

    const ua1 = "Mozilla/5.0 (compatible; gptbot/1.2; +https://openai.com/gptbot)";
    try std.testing.expectEqualStrings("GPTBot", matcher.findFirst(ua1).?);

    const ua2 = "Python-Requests/2.28.1";
    try std.testing.expectEqualStrings("python-requests", matcher.findFirst(ua2).?);

    const ua3 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36";
    try std.testing.expect(matcher.findFirst(ua3) == null);
}
