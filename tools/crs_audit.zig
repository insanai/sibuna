//! Offline CRS source inventory. This command never enables runtime protection.
const std = @import("std");
const crs = @import("crs");
const Io = std.Io;
const maximum_file_bytes = 8 * 1024 * 1024;
const maximum_files = 256;
const maximum_line_bytes = 64 * 1024;

pub fn main(init: std.process.Init) !u8 {
    var out_buffer: [4096]u8 = undefined;
    var out_file = Io.File.stdout().writerStreaming(init.io, &out_buffer);
    const out = &out_file.interface;
    defer out.flush() catch {};
    var err_buffer: [4096]u8 = undefined;
    var err_file = Io.File.stderr().writerStreaming(init.io, &err_buffer);
    const err_out = &err_file.interface;
    defer err_out.flush() catch {};
    return run(init, out, err_out) catch |err| {
        try err_out.print("CRS001: Cannot inventory this release: {t}.\n", .{err});
        try err_out.writeAll("Check the extracted stock release and its source limits.\n");
        return 1;
    };
}

fn run(init: std.process.Init, out: *Io.Writer, err_out: *Io.Writer) !u8 {
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const path = args.next() orelse {
        try err_out.writeAll("usage: zig build crs-audit -- <release-directory> [--regex]\n");
        return 2;
    };
    const regex_option = args.next();
    const regex_requested = if (regex_option) |value|
        std.mem.eql(u8, value, "--regex")
    else
        false;
    if ((regex_option != null and !regex_requested) or args.next() != null) {
        return error.TooManyArguments;
    }
    var root = try Io.Dir.cwd().openDir(init.io, path, .{});
    defer root.close(init.io);
    var arena: std.heap.ArenaAllocator = .init(init.gpa);
    defer arena.deinit();
    const allocator = arena.allocator();
    const inventory = try allocator.create(crs.inventory.Inventory);
    inventory.* = .{};
    const scratch = try allocator.alloc(u8, maximum_line_bytes);
    var compiler = crs.compiler.Compiler.init(allocator, .{});
    defer compiler.deinit();
    var audit: Audit = .{
        .io = init.io,
        .allocator = allocator,
        .root = root,
        .scratch = scratch,
        .inventory = inventory,
        .compiler = &compiler,
        .err_out = err_out,
    };
    try audit.file("crs-setup.conf.example");
    const names = try ruleNames(init.io, allocator, root);
    for (names) |name| {
        const file_path = try std.fmt.allocPrint(allocator, "rules/{s}", .{name});
        try audit.file(file_path);
    }
    var plan = compiler.finish() catch |err| {
        if (compiler.fault) |site| try sourceError(err_out, site.path, site.line, err);
        return err;
    };
    defer plan.deinit();
    if (regex_requested) try auditRegex(allocator, &plan, out, err_out);
    const message = "Validated source plan: {d} conditions; " ++
        "runtime support remains unavailable.\n";
    try out.print(message, .{plan.conditions.len});
    var digest: [32]u8 = undefined;
    audit.hash.final(&digest);
    try out.writeAll("Source inventory; executable CRS compatibility is not asserted.\n");
    try out.print("Files: {d}; framed source SHA-256: {x}\n", .{ names.len + 1, &digest });
    inline for (@typeInfo(crs.syntax.Directive).@"union".field_names, 0..) |field, index| {
        try out.print("{s}: {d}\n", .{ field, inventory.directives[index] });
    }
    try printNames(out, "Operators", &inventory.operators);
    try printNames(out, "Actions", &inventory.actions);
    try printNames(out, "Transforms", &inventory.transforms);
    return 0;
}

fn ruleNames(io: Io, allocator: std.mem.Allocator, root: Io.Dir) ![][]const u8 {
    var rules = try root.openDir(io, "rules", .{ .iterate = true });
    defer rules.close(io);
    var names: std.ArrayList([]const u8) = .empty;
    var iterator = rules.iterate();
    while (try iterator.next(io)) |entry| {
        if (!std.mem.endsWith(u8, entry.name, ".conf")) continue;
        if (entry.kind != .file) return error.UnexpectedRuleEntry;
        if (names.items.len == maximum_files - 1) return error.TooManyFiles;
        try names.append(allocator, try allocator.dupe(u8, entry.name));
    }
    if (names.items.len == 0) return error.NoRuleFiles;
    std.mem.sort([]const u8, names.items, {}, struct {
        fn less(_: void, left: []const u8, right: []const u8) bool {
            return std.mem.lessThan(u8, left, right);
        }
    }.less);
    return names.toOwnedSlice(allocator);
}

const Audit = struct {
    io: Io,
    allocator: std.mem.Allocator,
    root: Io.Dir,
    scratch: []u8,
    inventory: *crs.inventory.Inventory,
    compiler: *crs.compiler.Compiler,
    err_out: *Io.Writer,
    hash: std.crypto.hash.sha2.Sha256 = .init(.{}),
    bytes_read: usize = 0,

    fn file(self: *Audit, path: []const u8) !void {
        const bytes = try self.root.readFileAlloc(
            self.io,
            path,
            self.allocator,
            .limited(maximum_file_bytes),
        );
        defer self.allocator.free(bytes);
        if (bytes.len > 32 * 1024 * 1024 - self.bytes_read) return error.SourceTooLarge;
        self.bytes_read += bytes.len;
        self.compiler.addSource(path, bytes) catch |err| {
            if (self.compiler.fault) |site| {
                try sourceError(self.err_out, site.path, site.line, err);
            }
            return err;
        };
        var lengths: [16]u8 = undefined;
        std.mem.writeInt(u64, lengths[0..8], path.len, .big);
        std.mem.writeInt(u64, lengths[8..16], bytes.len, .big);
        self.hash.update(&lengths);
        self.hash.update(path);
        self.hash.update(bytes);
        var reader: crs.source.Reader = .{ .source = bytes };
        while (reader.next(self.scratch) catch |err| {
            try sourceError(self.err_out, path, reader.fault.line, err);
            return err;
        }) |line| {
            const directive = crs.syntax.parse(line.bytes) catch |err| {
                try sourceError(self.err_out, path, line.location.line, err);
                return err;
            };
            self.inventory.add(directive) catch |err| {
                try sourceError(self.err_out, path, line.location.line, err);
                return err;
            };
        }
    }
};

fn sourceError(out: *Io.Writer, path: []const u8, line: usize, err: anyerror) !void {
    try out.print("CRS002: {s}:{d}: {t}. No rules were activated.\n", .{ path, line, err });
}

fn printNames(out: *Io.Writer, label: []const u8, names: *crs.inventory.Names) !void {
    std.mem.sort(crs.inventory.NameCount, names.entries[0..names.size], {}, struct {
        fn less(_: void, left: crs.inventory.NameCount, right: crs.inventory.NameCount) bool {
            return std.mem.lessThan(u8, left.name(), right.name());
        }
    }.less);
    try out.print("{s} ({d} names):\n", .{ label, names.size });
    for (names.entries[0..names.size]) |*entry| {
        try out.print("  {s}: {d}\n", .{ entry.name(), entry.count });
    }
}

fn auditRegex(
    allocator: std.mem.Allocator,
    plan: *const crs.model.Plan,
    out: *Io.Writer,
    err_out: *Io.Writer,
) !void {
    var count: usize = 0;
    var failures: usize = 0;
    var largest: usize = 0;
    var groups: usize = 0;
    for (plan.conditions) |condition| {
        const expression = condition.expression orelse continue;
        if (expression.kind != .rx) continue;
        count += 1;
        var program = crs.regex.compile(allocator, expression.argument, .{}) catch |err| {
            failures += 1;
            try sourceError(err_out, condition.site.path, condition.site.line, err);
            continue;
        };
        defer program.deinit();
        largest = @max(largest, program.instructions.len);
        groups = @max(groups, program.groups);
    }
    try out.print(
        "Regex compilation: {d}/{d}; maximum {d} states, {d} groups.\n",
        .{ count - failures, count, largest, groups },
    );
    if (failures != 0) return error.IncompatibleRegex;
}
