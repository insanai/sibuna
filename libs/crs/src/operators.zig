//! Owned prepared predicates. Rule ordering, negation and effects belong to the executor.
//! The frame centralizes all request-path scratch; evaluation never allocates.
const std = @import("std");
const model = @import("model.zig");
const regex = @import("regex.zig");
const phrases = @import("phrases.zig");
const phrase_source = @import("phrases_source.zig");
const addresses = @import("address_set.zig");
const byte_range = @import("byte_range.zig");
const literal = @import("operator_literal.zig");
const lexical = @import("sql_tokens.zig");
const folding = @import("sql_folding.zig");
const sql = @import("sql_detector.zig");
const xss = @import("xss_detector.zig");
const variables = @import("variables.zig");
const work = @import("work.zig");

pub const Error = regex.types.Error || regex.match.Error || phrases.Error || addresses.Error ||
    byte_range.Error || literal.Error || sql.Error || error{
    MissingPhraseFile,
    UnexpectedPhraseFile,
    DiagnosticProfile,
    UnsupportedDynamicRegex,
};
pub const Source = struct {
    kind: model.Operator,
    argument: []const u8,
    phrase_files: []const []const u8 = &.{},
};
pub const Limits = struct {
    source: usize = 64 * 1024,
    regex: regex.types.Limits = .{},
    phrases: phrases.Options = .{},
    addresses: addresses.Options = .{},
};
pub const Frame = struct {
    input: []const u8,
    budget: *work.Budget,
    prefixes: []usize = &.{},
    regex: ?*regex.match.Scratch = null,
    variables: ?*const variables.View = null,
    pieces: [][]const u8 = &.{},
    argument_output: []u8 = &.{},
};
pub const Capture = union(enum) {
    none,
    borrowed: []const u8,
    regex: regex.match.Match,
    fingerprint: sql.Result,
};
pub const Result = struct {
    matched: bool = false,
    capture: Capture = .none,

    /// The caller retains this result, input and generation through capture copying.
    pub fn captured(self: *const Result, input: []const u8, group: usize) ?[]const u8 {
        if (!self.matched) return null;
        return switch (self.capture) {
            .none => null,
            .borrowed => |borrowed| if (group == 0) borrowed else null,
            .fingerprint => |*fingerprint| if (group == 0) fingerprint.capture() else null,
            .regex => |*captures| blk: {
                const span = captures.span(group) orelse return null;
                std.debug.assert(span.end <= input.len);
                break :blk input[span.start..span.end];
            },
        };
    }
};

pub const Program = union(enum) {
    literal: literal.Program,
    regex: regex.types.Program,
    phrases: phrases.Program,
    addresses: addresses.Program,
    range: byte_range.Range,
    sql,
    xss,

    pub fn deinit(self: *Program) void {
        switch (self.*) {
            .literal => |*program| program.deinit(),
            .regex => |*program| program.deinit(),
            .phrases => |*program| program.deinit(),
            .addresses => |*program| program.deinit(),
            .range, .sql, .xss => {},
        }
        self.* = undefined;
    }

    pub fn regexStates(self: *const Program) usize {
        return if (self.* == .regex) self.regex.instructions.len else 0;
    }

    pub fn evaluate(self: *const Program, frame: Frame) Error!Result {
        try frame.budget.debit(1);
        return switch (self.*) {
            .literal => |*program| .{ .matched = try program.evaluate(frame.input, .{
                .prefixes = frame.prefixes,
                .budget = frame.budget,
            }, if (frame.variables) |view| .{
                .view = view,
                .pieces = frame.pieces,
                .output = frame.argument_output,
                .budget = frame.budget,
            } else null) },
            .regex => |*program| if (try regex.match.search(
                program,
                frame.input,
                frame.regex orelse return error.ScratchTooSmall,
                frame.budget,
            )) |captures|
                .{ .matched = true, .capture = .{ .regex = captures } }
            else
                .{},
            .phrases => |*program| if (try program.search(frame.input, frame.budget)) |match|
                .{ .matched = true, .capture = .{ .borrowed = match.capture } }
            else
                .{},
            .addresses => |*program| .{
                .matched = try program.contains(frame.input, frame.budget),
            },
            .range => |range| .{
                .matched = (try range.inspect(frame.input, frame.budget)).count > 0,
            },
            .sql => detectSQL(frame),
            .xss => blk: {
                var context: xss.Context = .{ .input = frame.input, .budget = frame.budget };
                const matched = try xss.detect(&context);
                break :blk .{ .matched = matched, .capture = if (matched)
                    .{ .borrowed = frame.input }
                else
                    .none };
            },
        };
    }
};

fn detectSQL(frame: Frame) Error!Result {
    var context: lexical.Context = .{
        .input = frame.input,
        .prefixes = frame.prefixes,
        .budget = frame.budget,
    };
    var scratch: folding.Result = .{};
    const detected = try sql.detect(&context, &scratch);
    return .{ .matched = detected.matched, .capture = if (detected.matched)
        .{ .fingerprint = detected }
    else
        .none };
}

pub fn compile(allocator: std.mem.Allocator, source: Source, limits: Limits) Error!Program {
    if (source.argument.len > limits.source) return error.SourceLimit;
    if (limits.phrases.profile != .longest_suffix) return error.DiagnosticProfile;
    if (source.kind != .pm_from_file and source.phrase_files.len != 0) {
        return error.UnexpectedPhraseFile;
    }
    return switch (source.kind) {
        .rx => if (std.mem.indexOf(u8, source.argument, "%{") != null)
            error.UnsupportedDynamicRegex
        else if (source.argument.len == 0)
            .{ .literal = try literal.compile(allocator, .unconditional_match, "") }
        else
            .{ .regex = try regex.configured(
                allocator,
                source.argument,
                .{ .limits = limits.regex, .flags = .{ .dotall = true, .multiline = true } },
            ) },
        .pm => .{ .phrases = try phrase_source.inlineWords(
            allocator,
            source.argument,
            limits.phrases,
        ) },
        .pm_from_file => if (source.phrase_files.len == 0)
            error.MissingPhraseFile
        else
            .{ .phrases = try phrase_source.filesWords(
                allocator,
                source.phrase_files,
                limits.phrases,
            ) },
        .ip_match => .{ .addresses = try addresses.compile(
            allocator,
            source.argument,
            limits.addresses,
        ) },
        .validate_byte_range => .{ .range = try byte_range.compile(source.argument) },
        .detect_sqli => .sql,
        .detect_xss => .xss,
        else => .{ .literal = try literal.compile(allocator, source.kind, source.argument) },
    };
}

test {
    _ = @import("operators_test.zig");
}
