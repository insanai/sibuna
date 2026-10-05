//! Owned source locations cross compiler, storage and UI boundaries. No source
//! text or runtime data is retained; classifications and hints are stable.
const std = @import("std");
const Bytes = @import("buffers.zig").Bytes;
pub const Code = enum { syntax, unsupported, reference, capacity, compilation };
pub const Diagnostic = struct {
    code: Code,
    path: Bytes(256) = .{},
    path_truncated: bool = false,
    line: ?u32 = null,
    rule: ?u32 = null,
    cause: Bytes(64),

    /// Copy before the compiler arena is destroyed. Control bytes and invalid
    /// UTF-8 are replaced; valid UTF-8 truncation stops at a character boundary.
    pub fn capture(err: anyerror, path: ?[]const u8, line: ?usize, rule: ?u32) Diagnostic {
        const name = @errorName(err);
        var result: Diagnostic = .{
            .code = classify(name),
            .cause = Bytes(64).init(name[0..@min(name.len, 64)]) catch unreachable,
            .rule = rule,
            .line = if (line) |value| std.math.cast(u32, value) else null,
        };
        if (path) |source| {
            var length = @min(source.len, result.path.data.len);
            const valid = std.unicode.utf8ValidateSlice(source);
            if (valid) while (length < source.len and length != 0 and
                source[length] & 0xc0 == 0x80) : (length -= 1)
            {};
            result.path.len = length;
            result.path_truncated = length != source.len;
            for (source[0..length], 0..) |byte, index| {
                result.path.data[index] = if (byte < 32 or byte == 127 or
                    (!valid and byte >= 128)) '?' else byte;
            }
        }
        return result;
    }

    pub fn validate(self: *const Diagnostic) error{InvalidDiagnostic}!void {
        if (self.path.len > self.path.data.len or self.cause.len == 0 or
            self.cause.len > self.cause.data.len) return error.InvalidDiagnostic;
        for (self.cause.slice()) |byte| if (!std.ascii.isAlphanumeric(byte))
            return error.InvalidDiagnostic;
        if (!std.unicode.utf8ValidateSlice(self.path.slice())) return error.InvalidDiagnostic;
        for (self.path.slice()) |byte| if (byte < 32 or byte == 127)
            return error.InvalidDiagnostic;
        if (self.line) |line| if (line == 0) return error.InvalidDiagnostic;
        if (self.rule) |rule| if (rule == 0) return error.InvalidDiagnostic;
    }

    pub fn explanation(self: Diagnostic) []const u8 {
        return switch (self.code) {
            .syntax => "The candidate contains invalid rule syntax.",
            .unsupported => "The candidate uses a construct this engine does not support.",
            .reference => "A rule identifier or marker cannot be resolved unambiguously.",
            .capacity => "The candidate exceeds a preparation resource bound.",
            .compilation => "The candidate could not be compiled.",
        };
    }

    pub fn hint(self: Diagnostic) []const u8 {
        return switch (self.code) {
            .syntax => "Correct the indicated source line and prepare it again.",
            .unsupported => "Use a supported construct; unsupported rules are never skipped.",
            .reference => "Check identifiers, chain ordering and referenced markers.",
            .capacity => "Review source size and resource bounds before preparing again.",
            .compilation => "Review the indicated source and error before preparing again.",
        };
    }

    pub fn jsonStringify(self: Diagnostic, w: *std.json.Stringify) std.json.Stringify.Error!void {
        try w.beginObject();
        inline for (@typeInfo(Diagnostic).@"struct".field_names) |name| {
            try w.objectField(name);
            const value = @field(self, name);
            if (comptime std.mem.eql(u8, name, "path") or std.mem.eql(u8, name, "cause")) {
                try w.write(value.slice());
            } else try w.write(value);
        }
        try w.endObject();
    }
};

fn classify(name: []const u8) Code {
    if (std.mem.indexOf(u8, name, "Limit") != null or
        std.mem.eql(u8, name, "OutOfMemory")) return .capacity;
    if (std.mem.startsWith(u8, name, "Unsupported") or
        std.mem.startsWith(u8, name, "UnknownOperator") or
        std.mem.startsWith(u8, name, "UnknownAction") or
        std.mem.startsWith(u8, name, "UnknownDirective") or
        std.mem.startsWith(u8, name, "UnknownTransform")) return .unsupported;
    if (std.mem.indexOf(u8, name, "Marker") != null or
        std.mem.indexOf(u8, name, "Id") != null or
        std.mem.indexOf(u8, name, "Chain") != null) return .reference;
    if (std.mem.startsWith(u8, name, "Invalid") or
        std.mem.startsWith(u8, name, "Unterminated") or
        std.mem.startsWith(u8, name, "Missing")) return .syntax;
    return .compilation;
}

test "diagnostics own their location and never retain source text" {
    var path = "sibuna-operator.conf".*;
    const diagnostic = Diagnostic.capture(error.UnknownOperator, &path, 7, 120);
    @memset(&path, 'x');
    try diagnostic.validate();
    try std.testing.expectEqualStrings("sibuna-operator.conf", diagnostic.path.slice());
    try std.testing.expectEqual(Code.unsupported, diagnostic.code);
    try std.testing.expectEqual(@as(?u32, 7), diagnostic.line);
    try std.testing.expectEqual(@as(?u32, 120), diagnostic.rule);
    var bytes: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&bytes);
    try std.json.Stringify.value(diagnostic, .{}, &w);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "\"path\":\"sibuna") != null);
}

test "diagnostic truncation preserves UTF-8 and rejects control metadata" {
    var path: [258]u8 = @splat('a');
    @memcpy(path[255..], "€");
    const diagnostic = Diagnostic.capture(error.CompiledLimit, &path, null, null);
    try diagnostic.validate();
    try std.testing.expectEqual(@as(usize, 255), diagnostic.path.len);
    try std.testing.expect(diagnostic.path_truncated);
    var invalid = diagnostic;
    invalid.line = 0;
    try std.testing.expectError(error.InvalidDiagnostic, invalid.validate());
    const escaped = Diagnostic.capture(error.InvalidSyntax, "x\n\xff.conf", 1, null);
    try escaped.validate();
    try std.testing.expectEqualStrings("x??.conf", escaped.path.slice());
}
