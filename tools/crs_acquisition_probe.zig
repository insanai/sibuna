//! Native acquisition qualification adapter; never linked into the daemon.
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
    const kind = args.next() orelse return error.MissingKind;
    const encoded = args.next() orelse return error.MissingInput;
    if (args.next() != null or encoded.len % 2 != 0 or encoded.len > 64 * 1024)
        return error.InputLimit;
    const input = try init.gpa.alloc(u8, encoded.len / 2);
    defer init.gpa.free(input);
    _ = try std.fmt.hexToBytes(input, encoded);
    const entries = try init.gpa.alloc(crs.variables.Entry, 1024);
    defer init.gpa.free(entries);
    const storage = try init.gpa.alloc(u8, 256 * 1024);
    defer init.gpa.free(storage);
    const scratch = try init.gpa.alloc(u8, 64 * 1024);
    defer init.gpa.free(scratch);
    var builder = crs.acquired_values.Builder.init(entries, storage);
    var budget: crs.work.Budget = .{ .remaining = 16_000_000 };
    if (std.mem.eql(u8, kind, "json")) {
        var bits: [8]u8 = undefined;
        var frames: [64]crs.json_acquisition.Frame = undefined;
        try crs.json_acquisition.parse(input, &builder, .{
            .value = scratch[0 .. 32 * 1024],
            .path = scratch[32 * 1024 ..],
            .bits = &bits,
            .frames = &frames,
        }, &budget);
    } else if (std.mem.eql(u8, kind, "xml")) {
        var frames: [64]crs.xml_acquisition.Frame = undefined;
        var attributes: [256]crs.xml_acquisition.Attribute = undefined;
        var bindings: [256]crs.xml_acquisition.Binding = undefined;
        try crs.xml_acquisition.parse(input, &builder, .{
            .text = scratch[0 .. 32 * 1024],
            .value = scratch[32 * 1024 ..],
            .frames = &frames,
            .attributes = &attributes,
            .bindings = &bindings,
        }, &budget);
    } else if (std.mem.eql(u8, kind, "multipart")) {
        try crs.multipart_acquisition.parse(input, "B", &builder, .{
            .name = scratch[0 .. 16 * 1024],
            .filename = scratch[16 * 1024 .. 32 * 1024],
            .extended = scratch[32 * 1024 ..],
        }, .{}, &budget);
    } else {
        const origin: crs.acquired_values.Origin = if (std.mem.eql(u8, kind, "query"))
            .query
        else if (std.mem.eql(u8, kind, "form"))
            .form
        else
            return error.InvalidKind;
        try crs.form_acquisition.parse(input, origin, &builder, .{
            .key = scratch[0 .. 32 * 1024],
            .value = scratch[32 * 1024 ..],
        }, &budget);
    }
    try emit(&builder, out);
    return 0;
}

fn emit(builder: *const crs.acquired_values.Builder, out: *Io.Writer) !void {
    for ((try builder.view()).entries) |entry| {
        const tag = switch (entry.collection) {
            .args => "arg",
            .files => "file",
            .files_combined_size => "size",
            .xml => if (entry.xml.? == .element) "xml-element" else "xml-attribute",
            else => continue,
        };
        try out.print("{s}\t", .{tag});
        for (entry.key) |byte| try out.print("{x:0>2}", .{byte});
        try out.writeByte('\t');
        for (entry.value) |byte| try out.print("{x:0>2}", .{byte});
        try out.writeByte('\n');
    }
}
