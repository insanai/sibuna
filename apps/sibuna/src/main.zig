//! Sibuna Daemon Entry Point

const std = @import("std");
const core = @import("core");
const crypto = @import("crypto");
const net = @import("net");
const policy = @import("policy");
const challenge = @import("challenge");
const store = @import("store");

pub fn main() !void {
    std.debug.print("Sibuna Web AI Firewall v0.1.0\n", .{});
}
