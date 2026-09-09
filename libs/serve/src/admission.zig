const std = @import("std");

/// Listener-owned accounting. The acceptor serializes admission and release; peer slots
/// are separate from browser slots, so neither peer nor browser streams consume HTTP reserve.
pub const Admission = struct {
    pub const Kind = enum { http, browser, peer };
    max_slots: u16 = 96,
    http_reserved: u16 = 16,
    max_browsers: u16 = 64,
    max_peers: u16 = 16,
    http: u16 = 0,
    browsers: u16 = 0,
    peers: u16 = 0,
    stopping: bool = false,

    pub fn validate(self: Admission) error{InvalidCapacity}!void {
        if (self.max_slots < 16 or self.max_slots > 256) return error.InvalidCapacity;
        if (self.http_reserved < 16 or self.http_reserved > self.max_slots)
            return error.InvalidCapacity;
        if (self.max_browsers > 64 or
            @as(u32, self.max_browsers) + self.max_peers >
                self.max_slots - self.http_reserved or self.max_peers > 64)
            return error.InvalidCapacity;
    }

    pub fn acquire(self: *Admission, kind: Kind) error{ Full, Stopping }!void {
        std.debug.assert(self.http + self.browsers + self.peers <= self.max_slots);
        if (self.stopping) return error.Stopping;
        switch (kind) {
            .peer => {
                if (self.peers == self.max_peers or
                    self.http + self.browsers + self.peers == self.max_slots) return error.Full;
                self.peers += 1;
            },
            .http => {
                if (self.http + self.browsers + self.peers == self.max_slots) return error.Full;
                self.http += 1;
            },
            .browser => {
                if (self.browsers == self.max_browsers or
                    self.http + self.browsers + self.peers == self.max_slots) return error.Full;
                self.browsers += 1;
            },
        }
    }

    /// A successful upgrade transfers an already admitted HTTP connection atomically.
    pub fn upgrade(self: *Admission, kind: Kind) error{ Full, Stopping }!void {
        std.debug.assert(self.http > 0 and kind != .http);
        self.http -= 1;
        errdefer self.http += 1;
        try self.acquire(kind);
    }

    pub fn release(self: *Admission, kind: Kind) void {
        const count = switch (kind) {
            .http => &self.http,
            .browser => &self.browsers,
            .peer => &self.peers,
        };
        std.debug.assert(count.* > 0);
        count.* -= 1;
    }
};

test "browser and peer saturation retain reserved HTTP capacity" {
    const t = std.testing;
    var admission: Admission = .{};
    try admission.validate();
    for (0..64) |_| try admission.acquire(.browser);
    for (0..16) |_| try admission.acquire(.peer);
    try t.expectError(error.Full, admission.acquire(.browser));
    try t.expectError(error.Full, admission.acquire(.peer));
    for (0..16) |_| try admission.acquire(.http);
    try t.expectError(error.Full, admission.acquire(.http));
    try t.expectError(error.Full, admission.upgrade(.browser));
    try t.expectEqual(@as(u16, 16), admission.http);
    admission.release(.browser);
    try admission.upgrade(.browser);
    try t.expectEqual(@as(u16, 15), admission.http);
    admission.stopping = true;
    try t.expectError(error.Stopping, admission.acquire(.http));
}

test "larger listener cannot expand browser subscription quota" {
    try std.testing.expectError(error.InvalidCapacity, (Admission{
        .max_slots = 256,
        .max_browsers = 65,
    }).validate());
}
