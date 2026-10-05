//! Forms construct the shared sample without retaining body data in application
//! state. Borrowed fields live through synchronous serialization into the outbox.
const std = @import("std");
const p = @import("console_protocol");
const sample = p.crs_tests.sample;
const fields = @import("events_state.zig");
const ctx = @import("controller_context.zig");
const controller = @import("crs_controller.zig");
const Header = @import("text").http_fields.Header;
pub const form_body_bytes = 16 * 1024;

pub fn submit(c: ctx.Context, values: std.json.Value) !void {
    const model = &c.state.crs;
    const snapshot = model.snapshot orelse return;
    const source = model.reviewed orelse snapshot.current orelse return;
    if (model.stale or source.artifact == null) return;
    var request_headers: [32]Header = undefined;
    var response_headers: [32]Header = undefined;
    const input = read(values, &request_headers, &response_headers) catch {
        try c.state.message.set("Check the sample fields, one header per line, and text/hex " ++
            "entities. Each form entity is at most 16 KiB. Leave response status empty " ++
            "when no response is available.");
        return;
    };
    const mode = std.meta.stringToEnum(sample.Mode, fields.string(values, "mode")) orelse return;
    try controller.ticket(c, .test_submit);
    errdefer model.busy = .idle;
    model.test_id = null;
    model.test_result = null;
    var revision: [20]u8 = undefined;
    try c.out.post(model.ticket.slice(), "/console/api/crs/test", .{
        .source = source.id.slice(),
        .expected_revision = try std.fmt.bufPrint(&revision, "{d}", .{snapshot.revision}),
        .mode = mode,
        .sample = input,
    });
}

fn read(
    values: std.json.Value,
    request_headers: []Header,
    response_headers: []Header,
) !sample.Sample {
    var input: sample.Sample = .{ .request = .{
        .method = fields.string(values, "request_method"),
        .target = fields.string(values, "request_target"),
        .client = fields.string(values, "client"),
        .headers = try headers(fields.string(values, "request_headers"), request_headers),
        .entity = try entity(values, "request_body", "request_encoding"),
    } };
    const status = fields.string(values, "response_status");
    if (status.len != 0) {
        for (status) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidSample;
        const ending = fields.string(values, "response_ending");
        input.response = .{
            .status = try std.fmt.parseInt(u16, status, 10),
            .headers = try headers(fields.string(values, "response_headers"), response_headers),
            .entity = try entity(values, "response_body", "response_encoding"),
            .ending = std.meta.stringToEnum(
                @FieldType(sample.Response, "ending"),
                ending,
            ) orelse return error.InvalidSample,
        };
    } else if (fields.string(values, "response_body").len != 0 or
        fields.string(values, "response_headers").len != 0)
    {
        return error.InvalidSample;
    }
    try input.validate();
    return input;
}

fn entity(value: std.json.Value, name: []const u8, encoding: []const u8) !sample.Entity {
    const body = fields.string(value, name);
    if (body.len > form_body_bytes) return error.InvalidSample;
    const kind = fields.string(value, encoding);
    if (std.mem.eql(u8, kind, "text")) return .{ .body = body };
    if (std.mem.eql(u8, kind, "hex")) return .{ .body_hex = body };
    return error.InvalidSample;
}

fn headers(text: []const u8, output: []Header) ![]const Header {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var count: usize = 0;
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        if (count == output.len) return error.InvalidSample;
        const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse return error.InvalidSample;
        output[count] = .{
            .name = trimmed[0..colon],
            .value = std.mem.trim(u8, trimmed[colon + 1 ..], " \t"),
        };
        count += 1;
    }
    return output[0..count];
}

pub fn poll(c: ctx.Context) !void {
    const id = c.state.crs.test_id orelse return;
    try controller.ticket(c, .test_read);
    errdefer c.state.crs.busy = .idle;
    try c.out.post(c.state.crs.ticket.slice(), "/console/api/crs/test/result", .{
        .id = id.slice(),
    });
}

pub fn response(
    c: ctx.Context,
    kind: @import("crs_state.zig").Kind,
    value: std.json.Value,
    allocator: std.mem.Allocator,
) !void {
    const model = &c.state.crs;
    if (kind == .test_submit) {
        const id = try p.crs_management.Id.init(fields.string(value, "id"));
        if (!p.crs_management.validId(id)) return error.InvalidResponse;
        model.test_id = id;
        try c.state.message.set("Private test queued. Active protection is unchanged.");
        return poll(c);
    }
    var result: p.crs_tests.Status = undefined;
    try @import("json_value.zig").into(&result, value, allocator);
    try result.validate();
    const id = model.test_id orelse return error.InvalidResponse;
    if (!std.mem.eql(u8, result.id.slice(), id.slice())) return error.InvalidResponse;
    model.test_result = result;
}

test "private test forms reject malformed and absent response samples without retaining data" {
    const t = std.testing;
    const parsed = try std.json.parseFromSlice(std.json.Value, t.allocator,
        \\{"request_method":"POST","request_target":"/upload","client":"192.0.2.1",
        \\ "request_headers":"Host: example.test\nContent-Type: application/octet-stream",
        \\ "request_body":"00ff","request_encoding":"hex","response_status":"",
        \\ "response_headers":"","response_body":"","response_encoding":"text"}
    , .{});
    defer parsed.deinit();
    var request_headers: [32]Header = undefined;
    var response_headers: [32]Header = undefined;
    const input = try read(parsed.value, &request_headers, &response_headers);
    try t.expect(input.response == null);
    var entity_bytes: [2]u8 = undefined;
    try t.expectEqualSlices(u8, &.{ 0, 255 }, try input.request.entity.bytes(&entity_bytes));
    try t.expectEqual(@as(usize, 2), input.request.headers.len);
    try t.expectError(error.InvalidSample, headers("Invalid header", &request_headers));
    try t.expectError(error.InvalidSample, read(.null, &request_headers, &response_headers));
}
