//! Reference program for the differential test of `sibuna-policy` (input data, not a tool):
//! it evaluates the generated requests, payloads, policy files and management documents
//! with the Zig 0.16 policy library and prints one line each. `expected.txt` is its output.
//! The Rust test `tests/differential.rs` generates the same inputs and must print the same
//! lines. Regenerate with (from this directory):
//!
//!     zig run -OReleaseSafe --dep policy -Mroot=reference.zig --dep core \
//!         -Mpolicy=<sibuna>/libs/policy/src/root.zig -Mcore=<sibuna>/libs/core/src/root.zig \
//!         2> expected.txt
const std = @import("std");
const policy = @import("policy");
const waf = policy.waf;
const inspection = policy.inspection;

const fragments_text = @embedFile("fragments.txt");
const sample_policy = @embedFile("policy.json");
const policies_text = @embedFile("policies.txt");
const documents_text = @embedFile("documents.txt");

const request_count = 2000;
const policy_count = 1200;
const document_count = 500;
const filler = "the quick brown fox jumps over the lazy dog, and the form holds a note. ";
const alphabet = "{}[]\",:0123456789 truefalsnul-.eE\\aAzZ/_x\xc3\xa9\xff\x01";
const tokens = [_][]const u8{
    "\"name\":\"x\",",        "\"bogus\":1,",            "null",               "\"DENY\"",
    "\"WEIGH\"",              "1e3",                     "\"10.0.0.0/33\"",    "-1",
    "\"1_0\"",                "[1,2]",                   "{}",                 "\"rules\":[],",
    "\"weight\":5,",          "\"action\":\"ALLOW\",",   "\"path\":\"/x\",",   "\"cidrs\":[\"1.2.3.4\"],",
    "\"limits\":{\"rate\":1,\"window_seconds\":1},",   "\"challenge\":{\"difficulty\":8},",
    "\"headers\":{\"A\":\"b\"},", "\"inspection\":{\"sqli\":1},", "\\u0041", "\"\\ud800\"",
    "0.5",                    "\"audit\"",               "true",               "\"posw\"",
};

const List = std.ArrayList([]const u8);

const Fragments = struct {
    ips: List = .empty,
    paths: List = .empty,
    queries: List = .empty,
    user_agents: List = .empty,
    header_names: List = .empty,
    header_values: List = .empty,
    content_types: List = .empty,
    bodies: List = .empty,
    payloads: List = .empty,
};

fn unescape(gpa: std.mem.Allocator, line: []const u8) ![]const u8 {
    if (std.mem.eql(u8, line, "(empty)")) return "";
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < line.len) : (i += 1) {
        if (line[i] != '\\' or i + 1 >= line.len) {
            try out.append(gpa, line[i]);
            continue;
        }
        i += 1;
        switch (line[i]) {
            'r' => try out.append(gpa, '\r'),
            'n' => try out.append(gpa, '\n'),
            't' => try out.append(gpa, '\t'),
            '\\' => try out.append(gpa, '\\'),
            'x' => {
                try out.append(gpa, try std.fmt.parseInt(u8, line[i + 1 .. i + 3], 16));
                i += 2;
            },
            else => {
                try out.append(gpa, '\\');
                try out.append(gpa, line[i]);
            },
        }
    }
    return out.items;
}

fn loadFragments(gpa: std.mem.Allocator) !Fragments {
    var result: Fragments = .{};
    var current: ?*List = null;
    var lines = std.mem.splitScalar(u8, fragments_text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (line[0] == '[' and line[line.len - 1] == ']') {
            const name = line[1 .. line.len - 1];
            inline for (@typeInfo(Fragments).@"struct".fields) |member| {
                if (std.mem.eql(u8, member.name, name)) current = &@field(result, member.name);
            }
            continue;
        }
        try current.?.append(gpa, try unescape(gpa, line));
    }
    return result;
}

fn splitmix(x0: u64) u64 {
    var z = x0 +% 0x9e3779b97f4a7c15;
    z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
    return z ^ (z >> 31);
}

const Rng = struct {
    state: u64,

    fn init(index: u64, salt: u64) Rng {
        return .{ .state = splitmix(index *% 0x9e3779b97f4a7c15 ^ salt) | 1 };
    }

    fn next(self: *Rng) u64 {
        var x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        return x *% 0x2545F4914F6CDD1D;
    }

    fn below(self: *Rng, n: usize) usize {
        return @intCast(self.next() % n);
    }
};

fn transform(gpa: std.mem.Allocator, text: []const u8, kind: usize) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (text, 0..) |c, index| switch (kind) {
        1 => try out.append(gpa, std.ascii.toUpper(c)),
        2, 3 => if (std.ascii.isAlphanumeric(c)) try out.append(gpa, c) else {
            if (kind == 3) try out.appendSlice(gpa, "%25") else try out.append(gpa, '%');
            const hex = "0123456789ABCDEF";
            try out.append(gpa, hex[c >> 4]);
            try out.append(gpa, hex[c & 15]);
        },
        4 => if (c == ' ') try out.appendSlice(gpa, "/**/") else try out.append(gpa, c),
        5 => try out.append(gpa, if (c == ' ') '+' else c),
        6 => try out.append(gpa, if (index % 2 == 0) std.ascii.toUpper(c) else std.ascii.toLower(c)),
        7 => if (c == ' ') try out.appendSlice(gpa, "  \t") else try out.append(gpa, c),
        else => try out.append(gpa, c),
    };
    return out.items;
}

fn field(gpa: std.mem.Allocator, rng: *Rng, list: List, f: *const Fragments, inject: usize) ![]const u8 {
    var text = list.items[rng.below(list.items.len)];
    if (rng.below(inject) == 0) {
        const payload = f.payloads.items[rng.below(f.payloads.items.len)];
        text = try std.mem.concat(gpa, u8, &.{ text, payload });
    }
    return transform(gpa, text, rng.below(24));
}

const Request = struct {
    view: policy.engine.RequestView,
    headers: [8]policy.Header = undefined,
    digest: u64 = 0,
};

fn generate(gpa: std.mem.Allocator, index: u64, f: *const Fragments, out: *Request) !void {
    var rng = Rng.init(index, 1);
    const path = try field(gpa, &rng, f.paths, f, 12);
    const query = try field(gpa, &rng, f.queries, f, 6);
    const ip = f.ips.items[rng.below(f.ips.items.len)];
    const ua = try field(gpa, &rng, f.user_agents, f, 16);
    const count = rng.below(4);
    var n: usize = 0;
    while (n < count) : (n += 1) {
        const name = f.header_names.items[rng.below(f.header_names.items.len)];
        out.headers[n] = .{ .name = name, .value = try field(gpa, &rng, f.header_values, f, 8) };
    }
    const content_type = f.content_types.items[rng.below(f.content_types.items.len)];
    if (!std.mem.eql(u8, content_type, "(none)")) {
        out.headers[n] = .{ .name = "Content-Type", .value = content_type };
        n += 1;
    }
    var body = try field(gpa, &rng, f.bodies, f, 5);
    if (rng.below(8) == 0) {
        var long: std.ArrayList(u8) = .empty;
        while (long.items.len < 8200) try long.appendSlice(gpa, filler);
        try long.appendSlice(gpa, body);
        body = long.items;
    }
    out.view = .{
        .path = path,
        .query = query,
        .client_ip = ip,
        .user_agent = ua,
        .headers = out.headers[0..n],
        .body = body,
    };
    var hasher = std.hash.Wyhash.init(0);
    for ([_][]const u8{ path, query, ip, ua }) |part| {
        hasher.update(part);
        hasher.update("\x00");
    }
    for (out.headers[0..n]) |h| {
        hasher.update(h.name);
        hasher.update("\x01");
        hasher.update(h.value);
        hasher.update("\x00");
    }
    hasher.update("\x02");
    hasher.update(body);
    out.digest = hasher.final();
}

fn actionLetter(action: policy.Action) u8 {
    return switch (action) {
        .allow => 'a',
        .deny => 'd',
        .challenge => 'c',
        .weigh => 'w',
    };
}

fn writeDecision(w: *std.Io.Writer, d: policy.Decision) !void {
    const alg: u8 = if (d.algorithm) |a| (if (a == .hashcash) 'h' else 'p') else '-';
    try w.print("{c}:{s}:{d}:{c}:{d}:{d}:", .{ actionLetter(d.action), d.rule_name, d.difficulty, alg, d.score, d.audited });
    if (d.limits) |l| try w.print("{d}/{d}/{d}", .{ l.rate, l.window_seconds, l.ban_seconds }) else try w.writeAll("-");
    try w.print(":{x}", .{d.limit_scope});
}

fn writeViolation(w: *std.Io.Writer, v: ?waf.Violation) !void {
    if (v) |hit| try w.print("{s}:{s}", .{ hit.category.toSlice(), hit.pattern }) else try w.writeAll("-");
}

const mixed: inspection.Modes = .{ .path_traversal = .audit, .sqli = .enforce, .xss = .audit, .rce = .disabled };

fn requests(gpa: std.mem.Allocator, w: *std.Io.Writer, f: *const Fragments) !void {
    const default_engine = try gpa.create(policy.Engine);
    default_engine.initInPlace(16);
    const gate = try gpa.create(policy.Engine);
    gate.initInPlace(16);
    gate.waf_enabled = false;
    const sample = try gpa.create(policy.Engine);
    sample.initInPlace(16);
    var arena = std.heap.ArenaAllocator.init(gpa);
    try sample.loadFromJsonInto(arena.allocator(), sample_policy);
    var index: u64 = 0;
    while (index < request_count) : (index += 1) {
        var scratch = std.heap.ArenaAllocator.init(gpa);
        defer scratch.deinit();
        var request: Request = .{ .view = undefined };
        try generate(scratch.allocator(), index, f, &request);
        try w.print("R{d} {x:0>16} ", .{ index, request.digest });
        try writeDecision(w, default_engine.evaluateRequest(request.view));
        try w.writeAll(" | ");
        try writeDecision(w, gate.evaluateRequest(request.view));
        try w.writeAll(" | ");
        var matches: policy.engine.RuleMatches = undefined;
        try writeDecision(w, sample.evaluateRequestWithMatches(request.view, &matches));
        var bits: u128 = 0;
        for (0..128) |bit| if (matches.isSet(bit)) {
            bits |= @as(u128, 1) << @intCast(bit);
        };
        try w.print(" {x} | ", .{bits});
        try writeViolation(w, waf.inspectRequest(&default_engine.waf_signatures, request.view));
        try w.writeAll(" | ");
        const findings = inspection.inspect(&default_engine.waf_signatures, mixed, request.view);
        try writeViolation(w, findings.denied);
        try w.print("/{d}\n", .{findings.audited});
    }
}

fn payloads(gpa: std.mem.Allocator, w: *std.Io.Writer, f: *const Fragments) !void {
    const sigs = try gpa.create(waf.Signatures);
    waf.buildSignatures(sigs);
    for (f.payloads.items, 0..) |payload, index| {
        for ([_]usize{ 0, 2, 3, 4 }) |kind| {
            const text = try transform(gpa, payload, kind);
            try w.print("P{d}.{d} ", .{ index, kind });
            try writeViolation(w, waf.inspectTextWith(sigs, text));
            try w.writeAll(" | ");
            try writeViolation(w, waf.inspectText(text));
            try w.writeAll(" |");
            inline for (comptime std.meta.tags(waf.AttackCategory)) |category| {
                try w.writeAll(" ");
                try writeViolation(w, waf.inspectCategory(sigs, category, text));
            }
            const vector = policy.embedding.embed(text);
            try w.print(" | {x:0>16}\n", .{std.hash.Wyhash.hash(0, &policy.embedding.toBytes(&vector))});
        }
    }
}

fn mutate(gpa: std.mem.Allocator, rng: *Rng, base: []const u8) ![]const u8 {
    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(gpa, base);
    const rounds = 1 + rng.below(3);
    for (0..rounds) |_| {
        const op = rng.below(6);
        const pos = rng.below(text.items.len + 1);
        switch (op) {
            0 => {
                const byte = alphabet[rng.below(alphabet.len)];
                if (text.items.len > 0) text.items[@min(pos, text.items.len - 1)] = byte;
            },
            1 => if (pos < text.items.len) {
                _ = text.orderedRemove(pos);
            },
            2 => try text.insert(gpa, pos, alphabet[rng.below(alphabet.len)]),
            3 => if (rng.below(2) == 0) text.shrinkRetainingCapacity(pos),
            4 => {
                const start = rng.below(text.items.len + 1);
                const len = rng.below(16);
                const end = @min(start + len, text.items.len);
                const copy = try gpa.dupe(u8, text.items[start..end]);
                try text.insertSlice(gpa, pos, copy);
            },
            else => try text.insertSlice(gpa, pos, tokens[rng.below(tokens.len)]),
        }
    }
    return text.items;
}

fn splitLines(gpa: std.mem.Allocator, text: []const u8) !List {
    var list: List = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| if (line.len != 0) try list.append(gpa, line);
    return list;
}

fn modeLetter(mode: inspection.Mode) u8 {
    return switch (mode) {
        .disabled => 'd',
        .audit => 'a',
        .enforce => 'e',
    };
}

fn loader(gpa: std.mem.Allocator, w: *std.Io.Writer) !void {
    const bases = try splitLines(gpa, policies_text);
    const engine = try gpa.create(policy.Engine);
    const probe_headers = [_]policy.Header{ .{ .name = "X-A", .value = "v1" }, .{ .name = "X-B", .value = "xx" } };
    const probe: policy.engine.RequestView = .{
        .path = "/api/checkout/pay",
        .client_ip = "10.1.2.3",
        .user_agent = "curl/8.0",
        .headers = &probe_headers,
    };
    var index: u64 = 0;
    while (index < policy_count) : (index += 1) {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        var rng = Rng.init(index, 2);
        const text = try mutate(arena.allocator(), &rng, bases.items[rng.below(bases.items.len)]);
        try w.print("L{d} {x:0>16} ", .{ index, std.hash.Wyhash.hash(0, text) });
        engine.initInPlace(16);
        var diagnostic: policy.loader.Diagnostic = .{};
        policy.loader.parseDiagnosed(arena.allocator(), text, engine, &diagnostic) catch |err| {
            try w.print("err {s} {s} {s}|{s}|{s}\n", .{
                @errorName(err),
                policy.loader.explain(err).title,
                diagnostic.rule,
                diagnostic.field,
                diagnostic.value,
            });
            continue;
        };
        const m = engine.inspection_modes;
        const t = engine.thresholds;
        try w.print("ok {d} {c} {} {c}{c}{c}{c} {d}/{d}/{d} ", .{
            engine.rule_count,
            actionLetter(engine.default_action),
            engine.waf_enabled,
            modeLetter(m.path_traversal),
            modeLetter(m.sqli),
            modeLetter(m.xss),
            modeLetter(m.rce),
            t.challenge_at,
            t.deny_at,
            t.bits_step,
        });
        try writeDecision(w, engine.evaluateRequest(probe));
        try w.writeAll("\n");
    }
}

fn documents(gpa: std.mem.Allocator, w: *std.Io.Writer) !void {
    const bases = try splitLines(gpa, documents_text);
    var index: u64 = 0;
    while (index < document_count) : (index += 1) {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        var rng = Rng.init(index, 3);
        const text = try mutate(arena.allocator(), &rng, bases.items[rng.below(bases.items.len)]);
        try w.print("M{d} {x:0>16} ", .{ index, std.hash.Wyhash.hash(0, text) });
        const document = policy.management.parse(arena.allocator(), text) catch |err| {
            try w.print("err {s}\n", .{@errorName(err)});
            continue;
        };
        const r = document.value;
        const alg: u8 = if (r.algorithm) |a| (if (a == .hashcash) 'h' else 'p') else '-';
        try w.print("ok {s}|{s}|{c}|{d}|{}|{s}|{s}|{d}|{c}|{d}|", .{
            document.id,
            r.name,
            actionLetter(r.action),
            document.priority,
            document.enabled,
            r.path_pattern orelse "-",
            r.ua_pattern orelse "-",
            r.difficulty orelse 0,
            alg,
            r.weight,
        });
        if (r.limits) |l| try w.print("{d}/{d}/{d}", .{ l.rate, l.window_seconds, l.ban_seconds }) else try w.writeAll("-");
        try w.print("|{d}|{d}|{x}\n", .{ r.header_count, r.cidr_count, r.limit_identity });
    }
}

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    const f = try loadFragments(gpa);
    var output: std.Io.Writer.Allocating = .init(gpa);
    const w = &output.writer;
    try requests(gpa, w, &f);
    try payloads(gpa, w, &f);
    try loader(gpa, w);
    try documents(gpa, w);
    std.debug.print("{s}", .{output.written()});
}
