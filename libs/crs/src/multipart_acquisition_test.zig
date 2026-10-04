const std = @import("std");
const multipart = @import("multipart_acquisition.zig");
const heads = @import("multipart_head.zig");
const values = @import("acquired_values.zig");
const variables = @import("variables.zig");
const work = @import("work.zig");
const State = struct {
    entries: [64]variables.Entry = undefined,
    bytes: [2048]u8 = undefined,
    name: [128]u8 = undefined,
    filename: [128]u8 = undefined,
    extended: [128]u8 = undefined,
    builder: values.Builder = undefined,
    budget: work.Budget = .{ .remaining = 100000 },

    fn init(self: *State) void {
        self.builder = values.Builder.init(&self.entries, &self.bytes);
        self.budget.remaining = 100000;
    }

    fn scratch(self: *State) heads.Scratch {
        return .{ .name = &self.name, .filename = &self.filename, .extended = &self.extended };
    }

    fn parse(self: *State, input: []const u8) !void {
        try multipart.parse(input, "B", &self.builder, self.scratch(), .{}, &self.budget);
    }
};

const body = "--B\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\none\r\n" ++
    "--B\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"a.txt\"\r\n" ++
    "Content-Type: application/octet-stream\r\n\r\nfile\x00\r\n--Bx\r\n" ++
    "--B\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\ntwo\r\n--B--\r\n";

test "multipart duplicates and file metadata retain identity without file payload copies" {
    var state: State = .{};
    state.init();
    try state.parse(body);
    const view = try state.builder.view();
    try view.require(.files);
    try view.require(.args_post);
    try view.require(.multipart_part_headers);
    var files: usize = 0;
    var args: usize = 0;
    for (view.entries) |entry| switch (entry.collection) {
        .files => {
            files += 1;
            try std.testing.expectEqualStrings("upload", entry.key);
            try std.testing.expectEqualStrings("a.txt", entry.value);
        },
        .args => {
            try std.testing.expectEqualStrings("q", entry.key);
            try std.testing.expectEqualStrings(if (args == 0) "one" else "two", entry.value);
            args += 1;
        },
        .files_combined_size => try std.testing.expectEqualStrings("11", entry.value),
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 1), files);
    try std.testing.expectEqual(@as(usize, 2), args);
    // File data stays in immutable entity storage, absent from the field pool.
    const saved = state.bytes[0..state.builder.byte_used];
    try std.testing.expect(std.mem.indexOf(u8, saved, "file\x00") == null);
}

test "empty multipart, preamble, epilogue and transport padding remain bounded" {
    var state: State = .{};
    state.init();
    try state.parse("preamble\r\n--B-- \t\r\nepilogue");
    try (try state.builder.view()).require(.files);
    try std.testing.expectEqual(@as(usize, 2), state.builder.used);
    state.init();
    try state.parse("--B--");
    try std.testing.expectEqualStrings("0", state.entries[0].value);
}

test "malformed or incomplete multipart cannot expose complete partial collections" {
    var state: State = .{};
    state.init();
    try std.testing.expectError(error.MultipartMissingClose, state.parse(body[0 .. body.len - 9]));
    try std.testing.expectError(error.AcquisitionFailed, state.builder.view());
    state.init();
    try std.testing.expectError(error.InvalidMultipartHead, state.parse(
        "--B\r\nContent-Disposition: form-data; name=q; name=x\r\n\r\nx\r\n--B--\r\n",
    ));
    state.init();
    try std.testing.expectError(error.UnsupportedPartEncoding, state.parse(
        "--B\r\nContent-Disposition: form-data; name=q\r\n" ++
            "Content-Transfer-Encoding: base64\r\n\r\nYQ==\r\n--B--\r\n",
    ));
    state.init();
    try std.testing.expectError(error.MultipartPartLimit, multipart.parse(
        body,
        "B",
        &state.builder,
        state.scratch(),
        .{ .parts = 1 },
        &state.budget,
    ));
    state.init();
    try std.testing.expectError(error.MultipartHeadLimit, multipart.parse(
        body,
        "B",
        &state.builder,
        state.scratch(),
        .{ .head_bytes = 10 },
        &state.budget,
    ));
}

test "quoted disposition and matching UTF-8 extended filenames preserve backend identity" {
    var state: State = .{};
    state.init();
    const head = "Content-Disposition: form-data; name=\"f\\\"\"; " ++
        "filename=\"café.txt\"; filename*=UTF-8''caf%C3%A9.txt";
    const part = try heads.parse(head, state.scratch(), &state.budget);
    try std.testing.expectEqualStrings("f\"", part.name);
    try std.testing.expectEqualStrings("café.txt", part.filename.?);
    try std.testing.expectError(error.InvalidMultipartHead, heads.parse(
        "Content-Disposition: form-data; name=f; filename=a; filename*=UTF-8''b",
        state.scratch(),
        &state.budget,
    ));
    try std.testing.expectError(error.UnsupportedFilenameEncoding, heads.parse(
        "Content-Disposition: form-data; name=f; filename=a; filename*=ISO-8859-1''a",
        state.scratch(),
        &state.budget,
    ));
}
