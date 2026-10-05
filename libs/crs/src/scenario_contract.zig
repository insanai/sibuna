//! Pure native/Wasm test contracts. Borrowed samples need an owner through
//! evaluation; reports own their metadata and contain no request or response data.
const std = @import("std");
const fields = @import("text").http_fields;
const Bytes = @import("text").buffers.Bytes;
pub const entity_bytes = 64 * 1024;
pub const header_bytes = 16 * 1024;
pub const event_capacity = 64;
pub const Mode = enum { off, audit, enforce };
pub const Profile = enum { headers, full };
pub const Coverage = enum {
    disabled,
    incomplete,
    inspected,
    headers_profile,
    local_response,
    response_not_supplied,
    handshake_only,
    streaming_excluded,
};
pub const Entity = struct {
    body: ?[]const u8 = null,
    body_hex: ?[]const u8 = null,

    pub fn validate(self: Entity) error{InvalidSample}!void {
        if (self.body != null and self.body_hex != null) return error.InvalidSample;
        if (self.body) |body| if (body.len > entity_bytes) return error.InvalidSample;
        if (self.body_hex) |hex| {
            if (hex.len > entity_bytes * 2 or hex.len % 2 != 0) return error.InvalidSample;
            for (hex) |byte| if (!std.ascii.isHex(byte)) return error.InvalidSample;
        }
    }

    pub fn bytes(self: Entity, output: []u8) error{InvalidSample}![]const u8 {
        try self.validate();
        if (self.body_hex) |hex| {
            if (output.len < hex.len / 2) return error.InvalidSample;
            return std.fmt.hexToBytes(output, hex) catch return error.InvalidSample;
        }
        return self.body orelse "";
    }
};
pub const Request = struct {
    method: []const u8 = "GET",
    target: []const u8,
    protocol: []const u8 = "HTTP/1.1",
    client: []const u8 = "192.0.2.1",
    headers: []const fields.Header = &.{},
    entity: Entity = .{},
};
pub const Response = struct {
    status: u16 = 200,
    headers: []const fields.Header = &.{},
    entity: Entity = .{},
    ending: enum { complete, handshake, streaming } = .complete,
};
pub const Sample = struct {
    request: Request,
    response: ?Response = null,

    pub fn validate(self: Sample) error{InvalidSample}!void {
        const r = self.request;
        if (!fields.validToken(r.method) or r.method.len > 32 or r.target.len == 0 or
            r.target.len > 8192 or r.client.len == 0 or r.client.len > 64 or
            (!std.mem.eql(u8, r.protocol, "HTTP/1.1") and
                !std.mem.eql(u8, r.protocol, "HTTP/1.0"))) return error.InvalidSample;
        for (r.target) |byte| if (byte <= 32 or byte == 127) return error.InvalidSample;
        for (r.client) |byte| if (byte <= 32 or byte == 127) return error.InvalidSample;
        try headers(r.headers);
        try r.entity.validate();
        if (self.response) |response| {
            if (response.status < 100 or response.status > 599 or
                (response.status < 200 and response.status != 101) or
                (response.status == 101) != (response.ending == .handshake))
                return error.InvalidSample;
            try headers(response.headers);
            try response.entity.validate();
        }
    }
};
pub const Event = struct {
    rule_id: u32,
    phase: u8,
    severity: u8,
    would_deny: bool,
    saved: bool,
    audit_suppressed: bool,
};
pub const Report = struct {
    mode: Mode,
    profile: Profile,
    coverage: Coverage = .incomplete,
    attempted_phase: u8 = 0,
    denied: bool = false,
    would_deny: bool = false,
    selected_status: ?u16 = null,
    work_used: u32 = 0,
    failure: ?Bytes(64) = null,
    inbound_score: ?i32 = null,
    outbound_score: ?i32 = null,
    detection_inbound_score: ?i32 = null,
    detection_outbound_score: ?i32 = null,
    events: [event_capacity]?Event = @splat(null),
    event_count: usize = 0,
    omitted_events: usize = 0,
    unlogged_matches: usize = 0,

    pub fn validate(self: *const Report) error{InvalidReport}!void {
        if (self.event_count > event_capacity or self.attempted_phase > 5 or
            self.work_used > 1_000_000_000 or (self.denied and
            (!self.would_deny or self.mode != .enforce)) or
            (self.failure != null and self.coverage != .incomplete)) return error.InvalidReport;
        if (self.selected_status) |status| if (status < 100 or status > 599)
            return error.InvalidReport;
        for (self.events[0..self.event_count]) |item| {
            const event = item orelse return error.InvalidReport;
            if (event.phase < 1 or event.phase > 5 or event.severity > 7)
                return error.InvalidReport;
        }
        for (self.events[self.event_count..]) |event|
            if (event != null) return error.InvalidReport;
    }

    pub fn jsonStringify(self: Report, w: *std.json.Stringify) std.json.Stringify.Error!void {
        try w.beginObject();
        inline for (@typeInfo(Report).@"struct".field_names) |name| {
            try w.objectField(name);
            if (comptime std.mem.eql(u8, name, "failure")) {
                if (self.failure) |cause| try w.write(cause.slice()) else try w.write(null);
            } else try w.write(@field(self, name));
        }
        try w.endObject();
    }
};

fn headers(input: []const fields.Header) error{InvalidSample}!void {
    if (input.len > 128) return error.InvalidSample;
    var used: usize = 0;
    for (input) |header| {
        if (!fields.validToken(header.name) or header.name.len > 128 or
            header.value.len > 4096 or header.name.len > header_bytes - used)
            return error.InvalidSample;
        used += header.name.len;
        if (header.value.len > header_bytes - used) return error.InvalidSample;
        used += header.value.len;
        for (header.value) |byte| if ((byte < 32 and byte != '\t') or byte == 127)
            return error.InvalidSample;
    }
}

test "private test samples refuse ambiguous entities and invalid transport metadata" {
    const t = std.testing;
    var sample: Sample = .{ .request = .{ .target = "/upload" } };
    try sample.validate();
    sample.request.entity = .{ .body = "", .body_hex = "00" };
    try t.expectError(error.InvalidSample, sample.validate());
    sample.request.entity = .{ .body_hex = "00ff" };
    var output: [2]u8 = undefined;
    try t.expectEqualSlices(u8, &.{ 0, 255 }, try sample.request.entity.bytes(&output));
    sample.request.headers = &.{.{ .name = "Host", .value = "example.test\r\nX: bad" }};
    try t.expectError(error.InvalidSample, sample.validate());
}

pub const sample_json_bytes = 1024 * 1024;
pub const parser_bytes = 8 * 1024 * 1024;
pub const DecodeError = std.json.ParseError(std.json.Scanner) || error{InvalidSample};

/// The caller bounds the allocator and owns both input and parsed values through
/// evaluation. Unknown fields and duplicate keys are refused, never ignored.
pub fn decode(
    allocator: std.mem.Allocator,
    source: []const u8,
) DecodeError!std.json.Parsed(Sample) {
    if (source.len == 0 or source.len > sample_json_bytes) return error.InvalidSample;
    var parsed = try std.json.parseFromSlice(Sample, allocator, source, .{
        .allocate = .alloc_always,
        .max_value_len = entity_bytes * 2,
    });
    errdefer parsed.deinit();
    try parsed.value.validate();
    return parsed;
}

test "private sample JSON rejects misspellings duplicates and ambiguous binary inputs" {
    const t = std.testing;
    const cases = [_][]const u8{
        "{\"request\":{\"target\":\"/\",\"entitiy\":{}}}",
        "{\"request\":{\"target\":\"/\",\"target\":\"/other\"}}",
        "{\"request\":{\"target\":\"/\",\"entity\":{\"body\":\"\",\"body_hex\":\"00\"}}}",
    };
    for (cases) |source| {
        if (decode(t.allocator, source)) |parsed| {
            parsed.deinit();
            return error.InvalidSampleAccepted;
        } else |_| {}
    }
    var parsed = try decode(t.allocator,
        \\{"request":{"target":"/upload","entity":{"body_hex":"00ff"}}}
    );
    defer parsed.deinit();
    var bytes: [2]u8 = undefined;
    try t.expectEqualSlices(u8, &.{ 0, 255 }, try parsed.value.request.entity.bytes(&bytes));
}
