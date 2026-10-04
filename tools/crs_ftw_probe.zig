//! Whole-request rule evidence qualification. Transport/origin fixtures are
//! qualified separately; this tool does not claim a live HTTP connector gate.
const std = @import("std");
const crs = @import("crs");
const Io = std.Io;
// The pinned corpus's README prescribes these TX settings for rule assertions.
const ftw_configuration =
    \\SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" \
    \\ "id:200000,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
    \\SecRule REQUEST_HEADERS:Content-Type "^application/json" \
    \\ "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
    \\SecAction "id:900005,phase:1,nolog,pass,ctl:ruleRemoveById=910000,\
    \\setvar:tx.crs_validate_utf8_encoding=1,setvar:tx.arg_name_length=100,\
    \\setvar:tx.arg_length=400,setvar:tx.total_arg_length=64000,\
    \\setvar:tx.max_num_args=255,setvar:tx.max_file_size=64100,\
    \\setvar:tx.combined_file_sizes=65535,setvar:tx.reporting_level=4"
;
const Case = struct {
    id: u32,
    method: []const u8,
    target: []const u8,
    protocol: []const u8,
    line: []const u8,
    headers: @FieldType(crs.http_acquisition.Request, "headers"),
    body: []const u8,
    response: ?Response = null,
};
const Response = struct {
    status: u16,
    headers: @FieldType(crs.http_acquisition.Response, "headers"),
    body_hex: []const u8,
};

pub fn main(init: std.process.Init) !u8 {
    var buffer: [4096]u8 = undefined;
    var output = Io.File.stdout().writerStreaming(init.io, &buffer);
    defer output.interface.flush() catch {};
    return run(init, &output.interface) catch |err| {
        try output.interface.print("rejected {t}\n", .{err});
        return 1;
    };
}

fn run(init: std.process.Init, out: *Io.Writer) !u8 {
    var args = std.process.Args.Iterator.init(init.minimal.args);
    defer args.deinit();
    _ = args.next();
    const archive_path = args.next() orelse return error.MissingArchive;
    const signature_path = args.next() orelse return error.MissingSignature;
    const case_path = args.next() orelse return error.MissingCases;
    const now = try std.fmt.parseInt(u64, args.next() orelse return error.MissingClock, 10);
    if (args.next() != null) return error.TooManyArguments;
    const archive = try read(init, archive_path, crs.release_urls.archive_capacity);
    defer init.gpa.free(archive);
    const signature = try read(init, signature_path, crs.release_urls.signature_capacity);
    defer init.gpa.free(signature);
    const package = crs.release_package.prepare(init.gpa, .{
        .archive = archive,
        .signature = signature,
        .version = .{ .major = 4, .minor = 30, .patch = 0 },
        .now = now,
        .configuration = ftw_configuration,
    }) catch |err| {
        std.debug.print("FTW candidate preparation: {t}\n", .{err});
        return err;
    };
    defer package.deinit();
    const bytes = try read(init, case_path, 64 * 1024 * 1024);
    defer init.gpa.free(bytes);
    const cases = std.json.parseFromSlice([]const Case, init.gpa, bytes, .{}) catch |err| {
        std.debug.print("FTW fixture decoding: {t}\n", .{err});
        return err;
    };
    defer cases.deinit();
    if (cases.value.len == 0 or cases.value.len > 8192) return error.CaseLimit;
    var slot: crs.transaction_slot.Slot = undefined;
    // A diagnostic ceiling separates semantic failures from the production
    // budget. Per-case usage is reported; this is not a runtime default change.
    try slot.init(init.gpa, &package.program, .{ .work = 128_000_000 });
    defer slot.deinit();
    for (cases.value) |case| {
        const failure: ?anyerror = blk: {
            evaluate(&slot, case) catch |err| break :blk err;
            break :blk null;
        };
        defer if (slot.active) slot.finish();
        try emit(out, &slot, case.id, failure);
    }
    return 0;
}

fn read(init: std.process.Init, path: []const u8, maximum: usize) ![]u8 {
    return Io.Dir.cwd().readFileAlloc(init.io, path, init.gpa, .limited(maximum));
}

fn evaluate(slot: *crs.transaction_slot.Slot, case: Case) !void {
    if (case.headers.len > 128 or case.line.len > 16 * 1024 or
        case.body.len > slot.request.len) return error.InputLimit;
    var transaction = try crs.http_transaction.Transaction.beginConfigured(slot, .{
        .activation = .{ .mode = .audit, .blocking_paranoia = 4, .detection_paranoia = 4 },
    }, .{
        .method = case.method,
        .target = case.target,
        .protocol = case.protocol,
        .line = case.line,
        .client = "127.0.0.1",
        .id = "ftw-request",
        .headers = case.headers,
    });
    _ = try transaction.requestBody(case.body);
    if (case.response) |reply| {
        if (reply.headers.len > 128 or reply.body_hex.len > 2 * slot.response.len)
            return error.InputLimit;
        _ = try transaction.responseHeaders(.{ .status = reply.status, .headers = reply.headers });
        _ = try transaction.responseBody(try std.fmt.hexToBytes(slot.response, reply.body_hex));
        try transaction.finish(.inspected);
    } else try transaction.finish(.local_response);
}

fn emit(out: *Io.Writer, slot: *const crs.transaction_slot.Slot, id: u32, err: ?anyerror) !void {
    try out.print("{{\"id\":{d},\"error\":", .{id});
    if (err) |failure| {
        try out.print("\"{t}\"", .{failure});
    } else try out.writeAll("null");
    try out.print(",\"work\":{d},\"ids\":[", .{slot.limits.work - slot.budget.remaining});
    var count: usize = 0;
    if (slot.active) for (slot.state.events[0..slot.state.event_used]) |event| {
        if (!event.save) continue;
        if (count != 0) try out.writeByte(',');
        try out.print("{d}", .{event.id});
        count += 1;
    };
    try out.writeAll("]}\n");
}
