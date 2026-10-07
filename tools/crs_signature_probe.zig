//! Development receipt probe. Runtime update services use the same native verifier.
const std = @import("std");
const crs = @import("crs");
const Io = std.Io;

pub fn main(init: std.process.Init) !u8 {
    var buffer: [4096]u8 = undefined;
    var file = Io.File.stdout().writerStreaming(init.io, &buffer);
    defer file.interface.flush() catch {};
    return run(init, &file.interface) catch |err| {
        try file.interface.print("rejected {t}\n", .{err});
        return 1;
    };
}

fn run(init: std.process.Init, out: *Io.Writer) !u8 {
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const archive_path = args.next() orelse return error.MissingArchive;
    const signature_path = args.next() orelse return error.MissingSignature;
    const clock = args.next() orelse return error.MissingClock;
    if (args.next() != null) return error.TooManyArguments;
    const now = try std.fmt.parseInt(u64, clock, 10);
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
    var scratch: crs.release_signature.Scratch = .{};
    const verifier = try crs.release_signature.Verifier.init(&scratch);
    const receipt = try verifier.verify(archive, signature, now, &scratch);
    try out.print("verified {x} {d}\n", .{ &receipt.digest, receipt.created });
    return 0;
}
