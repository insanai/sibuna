//! A signed candidate and an owned sample are evaluated privately. This command
//! imports no daemon, storage, telemetry or network management implementation.
const std = @import("std");
const crs = @import("crs");
const updater = @import("crs-update");
const contract = crs.scenario_contract;
const Io = std.Io;
const Args = struct {
    directory: []const u8,
    sample: []const u8,
    mode: ?crs.config.Mode,
};
const ParseError = crs.config.Error || error{
    InvalidTestCommand,
    MissingTestValue,
    DuplicateTestOption,
    UnknownTestOption,
    InvalidTestPath,
};

fn parse(argv: []const []const u8) ParseError!Args {
    if (argv.len == 0 or !std.mem.eql(u8, argv[0], "test")) return error.InvalidTestCommand;
    var directory: ?[]const u8 = null;
    var sample: ?[]const u8 = null;
    var mode: ?crs.config.Mode = null;
    var index: usize = 1;
    while (index < argv.len) : (index += 2) {
        if (index + 1 == argv.len) return error.MissingTestValue;
        const flag = argv[index];
        const value = argv[index + 1];
        if (std.mem.eql(u8, flag, "--directory")) {
            try path(&directory, value);
        } else if (std.mem.eql(u8, flag, "--case")) {
            try path(&sample, value);
        } else if (std.mem.eql(u8, flag, "--mode")) {
            if (mode != null) return error.DuplicateTestOption;
            mode = try crs.config.Mode.parse(value);
        } else return error.UnknownTestOption;
    }
    return .{
        .directory = directory orelse return error.InvalidTestCommand,
        .sample = sample orelse return error.InvalidTestCommand,
        .mode = mode,
    };
}

fn path(destination: *?[]const u8, value: []const u8) ParseError!void {
    if (destination.* != null) return error.DuplicateTestOption;
    if (value.len == 0 or value.len > 1024 or std.mem.indexOfScalar(u8, value, 0) != null)
        return error.InvalidTestPath;
    destination.* = value;
}

pub fn execute(allocator: std.mem.Allocator, io: Io, argv: []const []const u8) u8 {
    const args = parse(argv) catch |err| {
        std.debug.print("CRSTESTARGS: invalid private test command ({t}). Hint: use " ++
            "crs test --directory <signed-candidate> --case <json-file> " ++
            "[--mode off|audit|enforce].\n", .{err});
        return 1;
    };
    var bytes: [4096]u8 = undefined;
    var output = Io.File.stdout().writer(io, &bytes);
    var diagnostic: ?crs.release_package.Diagnostic = null;
    run(allocator, io, args, &output.interface, &diagnostic) catch |err| {
        @import("crs_diagnostic.zig").report(diagnostic);
        std.debug.print("CRSTESTREFUSED: private test could not run ({t}). Hint: authenticate " ++
            "a complete candidate and supply a bounded request/response JSON sample. " ++
            "Active protection is unchanged.\n", .{err});
        return 1;
    };
    output.interface.flush() catch {
        std.debug.print("CRSTESTWRITE: private report could not be delivered. " ++
            "Hint: check the output destination and repeat the test.\n", .{});
        return 1;
    };
    return 0;
}

fn run(
    allocator: std.mem.Allocator,
    io: Io,
    args: Args,
    writer: *Io.Writer,
    diagnostic: *?crs.release_package.Diagnostic,
) !void {
    const directory = try Io.Dir.cwd().openDir(io, args.directory, .{ .follow_symlinks = false });
    defer directory.close(io);
    const now = @divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s);
    if (now < 0 or now > std.math.maxInt(u64)) return error.InvalidClock;
    var candidate = try updater.artifact.load(.{
        .allocator = allocator,
        .io = io,
        .directory = directory,
        .now = @intCast(now),
        .observation = .request_response,
        .diagnostic = diagnostic,
    });
    defer candidate.deinit();
    const source = try @import("crs_candidate.zig").readFile(
        allocator,
        io,
        args.sample,
        contract.sample_json_bytes,
    );
    defer allocator.free(source.buffer);
    defer std.crypto.secureZero(u8, source.buffer);
    const memory = try allocator.alloc(u8, contract.parser_bytes);
    defer allocator.free(memory);
    defer std.crypto.secureZero(u8, memory);
    var fixed: std.heap.FixedBufferAllocator = .init(memory);
    const parsed = try contract.decode(fixed.allocator(), source.value);
    defer parsed.deinit();
    var execution: crs.config.Execution = .{
        .activation = candidate.manifest.activation,
        .thresholds = candidate.manifest.thresholds,
    };
    if (args.mode) |mode| execution.activation.mode = mode;
    var report: contract.Report = undefined;
    try crs.scenario.evaluate(.{
        .allocator = allocator,
        .program = &candidate.prepared.package.?.program,
        .execution = execution,
        .limits = candidate.manifest.limits,
        .sample = parsed.value,
    }, &report);
    try writeReport(writer, candidate.manifest, report);
}

fn writeReport(
    writer: *Io.Writer,
    manifest: crs.artifact_manifest.Manifest,
    report: contract.Report,
) Io.Writer.Error!void {
    var version: [17]u8 = undefined;
    try std.json.Stringify.value(.{
        .private_test = true,
        .active_protection = "unchanged",
        .origin_contacted = false,
        .release = manifest.version.write(&version) catch unreachable,
        .archive_digest = std.fmt.bytesToHex(&manifest.archive_digest, .lower),
        .operator_digest = std.fmt.bytesToHex(&manifest.operator_digest, .lower),
        .saved_candidate_revision = manifest.revision,
        .blocking_paranoia = manifest.activation.blocking_paranoia,
        .detection_paranoia = manifest.activation.detection_paranoia,
        .thresholds = manifest.thresholds,
        .report = report,
    }, .{}, writer);
    try writer.writeByte('\n');
}

test "private CRS test commands require explicit bounded inputs and reject management options" {
    const t = std.testing;
    const args = try parse(&.{ "test", "--directory", "candidate", "--case", "sample.json" });
    try t.expect(args.mode == null);
    try t.expectEqualStrings("sample.json", args.sample);
    try t.expectError(error.DuplicateTestOption, parse(&.{
        "test", "--directory", "first", "--directory", "second", "--case", "sample.json",
    }));
    try t.expectError(error.InvalidTestCommand, parse(&.{ "test", "--directory", "candidate" }));
    try t.expectError(error.UnknownTestOption, parse(&.{ "test", "--origin", "https://a.test" }));
    try t.expectError(error.InvalidMode, parse(&.{
        "test", "--directory", "candidate", "--case", "sample.json", "--mode", "live",
    }));
}
