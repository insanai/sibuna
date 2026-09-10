const std = @import("std");

pub const Context = struct {
    request: *std.http.Server.Request,
    io: std.Io,
    peer: std.Io.net.IpAddress,
    stream: std.Io.net.Stream,
    subscribers: *std.atomic.Value(u16),
    deadline: *std.atomic.Value(i64),
    pub const Error = std.http.Server.Request.ExpectContinueError || error{
        TooLarge,
        ReadFailed,
        InvalidRequest,
        EndOfStream,
    };

    /// Duplicate security-sensitive headers are rejected instead of selecting one value.
    pub fn header(self: *Context, name: []const u8) error{InvalidRequest}!?[]const u8 {
        var result: ?[]const u8 = null;
        var it = self.request.iterateHeaders();
        while (it.next()) |h| {
            if (!std.ascii.eqlIgnoreCase(h.name, name)) continue;
            if (result != null) return error.InvalidRequest;
            result = h.value;
        }
        return result;
    }

    pub fn body(self: *Context, output: []u8) Error![]const u8 {
        self.extend(30);
        if (self.request.head.content_length) |length| {
            if (length > output.len) return error.TooLarge;
        }
        var transfer: [4096]u8 = undefined;
        const reader = try self.request.readerExpectContinue(&transfer);
        const n = try reader.readSliceShort(output);
        if (n == output.len) {
            _ = reader.takeByte() catch |err| switch (err) {
                error.EndOfStream => return output,
                else => return err,
            };
            return error.TooLarge;
        }
        return output[0..n];
    }

    pub fn extend(self: *Context, seconds: i64) void {
        const now: i64 = @intCast(@divTrunc(
            std.Io.Clock.awake.now(self.io).nanoseconds,
            std.time.ns_per_s,
        ));
        self.deadline.store(now + seconds, .release);
    }

    /// A reply that must never share the console's origin or run operator content under
    /// the console's policy: sandboxed, no script, no network, no framing, never cached.
    pub fn respondIsolated(
        self: *Context,
        status: std.http.Status,
        content_type: []const u8,
        content: []const u8,
    ) Error!void {
        const headers = [_]std.http.Header{
            .{ .name = "Content-Type", .value = content_type },
            .{ .name = "Cache-Control", .value = "no-store" },
            .{ .name = "X-Content-Type-Options", .value = "nosniff" },
            .{ .name = "Referrer-Policy", .value = "no-referrer" },
            .{
                .name = "Content-Security-Policy",
                .value = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src 'self'",
            },
        };
        self.extend(30);
        self.request.respond(content, .{
            .status = status,
            .extra_headers = &headers,
        }) catch return error.WriteFailed;
    }

    pub fn respond(
        self: *Context,
        status: std.http.Status,
        content_type: []const u8,
        content: []const u8,
        extra: []const std.http.Header,
    ) Error!void {
        return self.respondCached(status, content_type, content, "no-store", extra);
    }

    /// Sensitive replies are never stored; the shell revalidates, and content-addressed
    /// assets are immutable for a year because a new build names them differently.
    pub fn respondCached(
        self: *Context,
        status: std.http.Status,
        content_type: []const u8,
        content: []const u8,
        cache_control: []const u8,
        extra: []const std.http.Header,
    ) Error!void {
        std.debug.assert(extra.len <= 4);
        var headers: [10]std.http.Header = undefined;
        const common = [_]std.http.Header{
            .{ .name = "Content-Type", .value = content_type },
            .{ .name = "Cache-Control", .value = cache_control },
            .{ .name = "X-Content-Type-Options", .value = "nosniff" },
            .{ .name = "Referrer-Policy", .value = "no-referrer" },
            .{ .name = "X-Frame-Options", .value = "DENY" },
            .{
                .name = "Content-Security-Policy",
                .value = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; " ++
                    "style-src 'self'; img-src 'self' data:; connect-src 'self'; " ++
                    "object-src 'none'; base-uri 'none'; " ++
                    "frame-ancestors 'none'; form-action 'self'",
            },
        };
        @memcpy(headers[0..common.len], &common);
        @memcpy(headers[common.len..][0..extra.len], extra);
        self.extend(30);
        try self.request.respond(content, .{
            .status = status,
            .keep_alive = false,
            .extra_headers = headers[0 .. common.len + extra.len],
        });
    }
};
