//! Native candidate checks reuse the updater's authenticated preparation service.
//! These checks are independent of storage, the console and data-plane startup.
const std = @import("std");
const crs = @import("crs");
const updater = @import("crs-update");
const Writer = std.Io.Writer;
const Args = struct {
    version: ?crs.release_version.Version = null,
    timeout: u32 = 120,
    output: ?[]const u8 = null,
    configuration: ?[]const u8 = null,
};
const Error = crs.release_version.Error || error{
    InvalidCrsCommand,
    MissingCrsValue,
    DuplicateCrsOption,
    UnknownCrsOption,
    InvalidCrsTimeout,
    InvalidCrsPath,
};

test {
    _ = @import("command_line.zig");
    _ = @import("crs_candidate.zig");
}

fn parse(argv: []const []const u8) Error!Args {
    if (argv.len == 0 or !std.mem.eql(u8, argv[0], "check")) return error.InvalidCrsCommand;
    var args: Args = .{};
    var timeout_seen = false;
    var i: usize = 1;
    while (i < argv.len) : (i += 2) {
        const flag = argv[i];
        if (i + 1 == argv.len) return error.MissingCrsValue;
        const value = argv[i + 1];
        if (std.mem.eql(u8, flag, "--version")) {
            if (args.version != null) return error.DuplicateCrsOption;
            args.version = try crs.release_version.Version.parse(value);
        } else if (std.mem.eql(u8, flag, "--timeout")) {
            if (timeout_seen) return error.DuplicateCrsOption;
            timeout_seen = true;
            if (value.len == 0) return error.InvalidCrsTimeout;
            for (value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidCrsTimeout;
            args.timeout = std.fmt.parseInt(u32, value, 10) catch return error.InvalidCrsTimeout;
            if (args.timeout == 0 or args.timeout > 300) return error.InvalidCrsTimeout;
        } else if (std.mem.eql(u8, flag, "--output")) {
            try path(&args.output, value);
        } else if (std.mem.eql(u8, flag, "--configuration")) {
            try path(&args.configuration, value);
        } else return error.UnknownCrsOption;
    }
    return args;
}

fn path(destination: *?[]const u8, value: []const u8) Error!void {
    if (destination.* != null) return error.DuplicateCrsOption;
    if (value.len == 0 or value.len > 1024 or std.mem.indexOfScalar(u8, value, 0) != null)
        return error.InvalidCrsPath;
    destination.* = value;
}

pub fn execute(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8) u8 {
    const args = parse(argv) catch |err| {
        std.debug.print("CRSCLI001: invalid CRS candidate check ({t}). " ++
            "Hint: use sibuna crs check [--version <x.y.z>] [--timeout <1-300>] " ++
            "[--configuration <file>] [--output <new-directory>].\n", .{err});
        return 1;
    };
    const configuration = @import("crs_candidate.zig").readConfiguration(
        allocator,
        io,
        args.configuration,
    ) catch |err| {
        std.debug.print("CRSCLI002: operator configuration could not be read ({t}). " ++
            "Hint: use a regular file of at most 64 KiB.\n", .{err});
        return 1;
    };
    defer allocator.free(configuration.buffer);
    var stopping: std.atomic.Value(bool) = .init(false);
    var candidate = updater.prepare(.{
        .allocator = allocator,
        .io = io,
        .stopping = &stopping,
        .deadline_ms = args.timeout * 1000,
        .configuration = configuration.value,
    }, args.version) catch |err| {
        std.debug.print("CRSUPDATE001: CRS candidate preparation failed ({t}). " ++
            "Hint: check publisher access, the version and resource bounds.\n", .{err});
        return 1;
    };
    defer candidate.deinit();
    if (args.output) |directory| {
        @import("crs_candidate.zig").write(io, directory, &candidate) catch |err| {
            std.debug.print("CRSCLI003: candidate directory could not be written ({t}). " ++
                "Hint: select a new directory inside an operator-owned parent; " ++
                "a partial candidate is not active protection.\n", .{err});
            return 1;
        };
    }
    var output_buffer: [1024]u8 = undefined;
    var output = std.Io.File.stdout().writer(io, &output_buffer);
    report(&output.interface, candidate.package.?) catch return outputFailed();
    if (args.output) |directory| output.interface.print(
        "Candidate directory: {s}\nActive protection: unchanged\n",
        .{directory},
    ) catch return outputFailed();
    output.interface.flush() catch return outputFailed();
    return 0;
}

fn report(writer: *Writer, package: *const crs.release_package.Package) Writer.Error!void {
    var version_buffer: [17]u8 = undefined;
    const version = package.version.write(&version_buffer) catch unreachable;
    try writer.print("CRS {s}\nStatus: verified candidate\nSHA-256: {s}\n" ++
        "Conditions: {d}\nPeak live compilation payload: {d} bytes\n", .{
        version,
        std.fmt.bytesToHex(&package.receipt.digest, .lower),
        package.program.conditions.len,
        package.bounded.peak,
    });
}

fn outputFailed() u8 {
    std.debug.print("CRSCLIWRITE: candidate report could not be delivered. " ++
        "Hint: check the output destination and repeat the check.\n", .{});
    return 1;
}

test "CRS checks reject ambiguous versions and bounded timeout mistakes" {
    const t = std.testing;
    const defaults = try parse(&.{"check"});
    try t.expect(defaults.version == null);
    try t.expectEqual(@as(u32, 120), defaults.timeout);
    const explicit = try parse(&.{ "check", "--version", "4.30.0", "--timeout", "300" });
    try t.expectEqual(@as(u16, 30), explicit.version.?.minor);
    const saved = try parse(&.{
        "check", "--configuration", "operator.conf", "--output", "new-candidate",
    });
    try t.expectEqualStrings("operator.conf", saved.configuration.?);
    try t.expectEqualStrings("new-candidate", saved.output.?);
    try t.expectError(error.InvalidCrsPath, parse(&.{ "check", "--output", "" }));
    try t.expectError(error.DuplicateCrsOption, parse(&.{
        "check", "--output", "first", "--output", "second",
    }));
    const cases = [_]struct { argv: []const []const u8, err: Error }{
        .{ .argv = &.{ "check", "--version" }, .err = error.MissingCrsValue },
        .{ .argv = &.{"activate"}, .err = error.InvalidCrsCommand },
        .{ .argv = &.{ "check", "--url", "https://evil.test" }, .err = error.UnknownCrsOption },
        .{ .argv = &.{ "check", "--version", "v4.30.0" }, .err = error.InvalidReleaseVersion },
        .{ .argv = &.{ "check", "--timeout", "301" }, .err = error.InvalidCrsTimeout },
        .{ .argv = &.{ "check", "--timeout", "0" }, .err = error.InvalidCrsTimeout },
        .{ .argv = &.{ "check", "--timeout", "-1" }, .err = error.InvalidCrsTimeout },
        .{
            .argv = &.{ "check", "--timeout", "1", "--timeout", "2" },
            .err = error.DuplicateCrsOption,
        },
        .{
            .argv = &.{ "check", "--version", "4.30.0", "--version", "4.31.0" },
            .err = error.DuplicateCrsOption,
        },
    };
    for (cases) |case| try t.expectError(case.err, parse(case.argv));
}
