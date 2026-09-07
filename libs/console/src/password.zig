const std = @import("std");
const argon2 = std.crypto.pwhash.argon2;
const Bytes = @import("console_protocol").Bytes;

/// One reserved workspace and one nonblocking verifier, regardless of source address.
/// Address/account throttles are additional controls, never substitutes for this memory bound.
pub const Password = struct {
    workspace: []u8,
    allocator: std.mem.Allocator,
    busy: std.atomic.Value(bool) = .init(false),
    pub const workspace_bytes = 20 * 1024 * 1024;
    pub const prefix = "$argon2id$v=19$m=19456,t=2,p=1$";
    pub const Error = error{ Busy, InvalidPassword, InvalidHash, HashFailed, OutOfMemory };

    pub fn init(allocator: std.mem.Allocator) error{OutOfMemory}!Password {
        return .{ .workspace = try allocator.alloc(u8, workspace_bytes), .allocator = allocator };
    }

    pub fn deinit(self: *Password) void {
        std.debug.assert(!self.busy.load(.acquire));
        std.crypto.secureZero(u8, self.workspace);
        self.allocator.free(self.workspace);
        self.* = undefined;
    }

    pub fn hash(self: *Password, io: std.Io, password: []const u8) Error!Bytes(255) {
        if (password.len < 12 or password.len > 128) return error.InvalidPassword;
        if (self.busy.cmpxchgStrong(false, true, .acquire, .monotonic) != null) return error.Busy;
        defer self.release();
        var fixed = std.heap.FixedBufferAllocator.init(self.workspace);
        var output: [255]u8 = undefined;
        const encoded = argon2.strHash(password, .{
            .allocator = fixed.allocator(),
            .params = .{ .t = 2, .m = 19 * 1024, .p = 1 },
        }, &output, io) catch return error.HashFailed;
        return Bytes(255).init(encoded) catch return error.HashFailed;
    }

    pub fn verify(
        self: *Password,
        io: std.Io,
        password: []const u8,
        hash_text: []const u8,
    ) Error!void {
        if (password.len > 128) return error.InvalidPassword;
        // Reject stored PHC parameters before invoking a parser that can allocate for them.
        if (hash_text.len > 255 or !std.mem.startsWith(u8, hash_text, prefix))
            return error.InvalidHash;
        if (self.busy.cmpxchgStrong(false, true, .acquire, .monotonic) != null) return error.Busy;
        defer self.release();
        var fixed = std.heap.FixedBufferAllocator.init(self.workspace);
        argon2.strVerify(hash_text, password, .{ .allocator = fixed.allocator() }, io) catch
            return error.InvalidPassword;
    }

    fn release(self: *Password) void {
        std.crypto.secureZero(u8, self.workspace);
        self.busy.store(false, .release);
    }
};

test "Argon2id fixed workspace verifies and refuses unsafe PHC parameters" {
    const t = std.testing;
    var passwords = try Password.init(t.allocator);
    defer passwords.deinit();
    const hash = try passwords.hash(t.io, "a long passphrase");
    try t.expect(std.mem.startsWith(u8, hash.slice(), Password.prefix));
    try passwords.verify(t.io, "a long passphrase", hash.slice());
    try t.expectError(error.InvalidPassword, passwords.verify(t.io, "wrong", hash.slice()));
    try t.expectError(error.InvalidHash, passwords.verify(
        t.io,
        "anything",
        "$argon2id$v=19$m=99999999,t=2,p=1$invalid$invalid",
    ));
    passwords.busy.store(true, .release);
    try t.expectError(error.Busy, passwords.hash(t.io, "a long passphrase"));
    passwords.busy.store(false, .release);
}
