//! Development qualification for authenticated unpacking and private compilation.
//! This does not publish a running generation or assert whole-engine compatibility.
const std = @import("std");
const crs = @import("crs");
const Io = std.Io;

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
    const version = try crs.release_version.Version.parse(args.next() orelse
        return error.MissingVersion);
    const now = try std.fmt.parseInt(u64, args.next() orelse return error.MissingClock, 10);
    const configuration_path = args.next();
    if (args.next() != null) return error.TooManyArguments;
    const archive = try Io.Dir.cwd().readFileAlloc(
        init.io,
        archive_path,
        init.gpa,
        .limited(8 * 1024 * 1024),
    );
    defer init.gpa.free(archive);
    const signature = try Io.Dir.cwd().readFileAlloc(
        init.io,
        signature_path,
        init.gpa,
        .limited(16 * 1024),
    );
    defer init.gpa.free(signature);
    const configuration = if (configuration_path) |path|
        try Io.Dir.cwd().readFileAlloc(init.io, path, init.gpa, .limited(64 * 1024 + 2))
    else
        try init.gpa.alloc(u8, 0);
    defer init.gpa.free(configuration);
    const package = try crs.release_package.prepare(init.gpa, .{
        .archive = archive,
        .signature = signature,
        .version = version,
        .now = now,
        .configuration = configuration,
    });
    defer package.deinit();
    var operator_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(configuration, &operator_digest, .{});
    if (!std.mem.eql(u8, &operator_digest, &package.operator_digest))
        return error.OperatorDigestMismatch;
    // Compilation must own every source/table byte. Poisoning both inputs checks
    // that evaluation does not retain the archive or its detached signature.
    @memset(archive, '!');
    @memset(signature, '!');
    @memset(configuration, '!');
    try evaluate(init.gpa, &package.program, configuration.len != 0);
    try out.print("prepared {d} {d} {x} {d}\n", .{
        package.program.conditions.len,
        package.program.regex_states,
        &package.receipt.digest,
        package.bounded.peak,
    });
    return 0;
}

fn evaluate(
    allocator: std.mem.Allocator,
    program: *const crs.rule_program.Program,
    configured: bool,
) !void {
    var slot: crs.transaction_slot.Slot = undefined;
    try slot.init(allocator, program, .{});
    defer slot.deinit();
    for ([_][]const u8{ "/?q=ordinary", "/?q=1%27%20OR%20%271%27=%271" }, 0..) |target, index| {
        var line: [256]u8 = undefined;
        var transaction = try crs.http_transaction.Transaction.begin(&slot, .full, true, .{
            .method = "GET",
            .target = target,
            .protocol = "HTTP/1.1",
            .line = try std.fmt.bufPrint(&line, "GET {s} HTTP/1.1", .{target}),
            .client = "192.0.2.1",
            .id = "package-probe",
            .headers = &.{
                .{ .name = "Host", .value = "example.test" },
                .{ .name = "User-Agent", .value = "Mozilla/5.0" },
                .{ .name = "Accept", .value = "text/html" },
            },
        });
        defer slot.finish();
        if (configured) {
            const marker = (try slot.store.get("operator_marker", &slot.budget)) orelse
                return error.OperatorMarkerMissing;
            if (!std.mem.eql(u8, marker, "present")) return error.OperatorMarkerMismatch;
        }
        const result = try transaction.requestBody("");
        if ((result == .denied) != (index == 1)) return error.PackageDecisionMismatch;
        if (index == 1) {
            const score = (try slot.store.get("sql_injection_score", &slot.budget)).?;
            if (try std.fmt.parseInt(i32, score, 10) < 5) return error.PackageDecisionMismatch;
            try transaction.finish(.local_response);
        } else {
            _ = try transaction.responseHeaders(.{ .status = 200, .headers = &.{} });
            _ = try transaction.responseBody("ordinary page");
            try transaction.finish(.inspected);
        }
    }
}
