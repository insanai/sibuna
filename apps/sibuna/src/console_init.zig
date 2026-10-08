//! Local initialization runs before listeners and never borrows a running daemon's DB.
//! Persistent retains ownership; the command submits typed work and drives storage ticks.
const std = @import("std");
const core = @import("core");
const policy = @import("policy");
const console = @import("console");
const server = @import("server.zig");
const Persistent = @import("persistent.zig").Persistent;
const p = console.protocol;

pub fn run(gpa: std.mem.Allocator, io: std.Io, cfg: core.Config, username: []const u8) !u8 {
    if (cfg.data_dir == null) return error.StorageRequired;
    if (!p.validUsername(username)) return error.InvalidUsername;
    const engine = try gpa.create(policy.Engine);
    defer gpa.destroy(engine);
    engine.initInPlace(cfg.default_difficulty);
    engine.waf_enabled = cfg.waf;
    const slot = try gpa.create(server.EngineSlot);
    defer gpa.destroy(slot);
    slot.* = .{ .engine = engine };
    const state = try gpa.create(server.AppState);
    defer gpa.destroy(state);
    var seed: [32]u8 = undefined;
    io.random(&seed);
    defer std.crypto.secureZero(u8, &seed);
    state.init(cfg, slot, &seed);
    const owner = try Persistent.open(gpa, io, cfg, state, null);
    defer owner.stop();
    const status = try request(owner, .setup_status);
    if (status != .setup_required) return error.InvalidStorageReply;
    if (!status.setup_required) return error.AlreadyInitialized;
    var passwords = try console.Password.init(gpa);
    defer passwords.deinit();
    var random: [24]u8 = undefined;
    io.random(&random);
    defer std.crypto.secureZero(u8, &random);
    var password = std.fmt.bytesToHex(random, .lower);
    defer std.crypto.secureZero(u8, &password);
    var hash = try passwords.hash(io, &password);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&hash));
    const now: u64 = @intCast(@max(0, @divTrunc(
        std.Io.Clock.real.now(io).nanoseconds,
        std.time.ns_per_s,
    )));
    const result = try request(owner, .{ .bootstrap = .{
        .username = try p.Bytes(64).init(username),
        .password_hash = hash,
        .must_change = true,
        .password_expires = now + 3600,
    } });
    if (result != .command_recorded) return error.InitializationConflict;
    std.debug.print(
        "Console administrator created: {s}\n" ++
            "Temporary console password (expires in one hour): {s}\n" ++
            "Start Sibuna with --console, sign in, and change this password.\n",
        .{ username, password },
    );
    return 0;
}

fn request(owner: *Persistent, operation: p.StorageRequest) !p.StorageResult {
    const ticket = try owner.console_mailbox.submit(owner.io, operation, .urgent);
    try owner.tick();
    const result = (try owner.console_mailbox.poll(owner.io, ticket)) orelse
        return error.StorageUnavailable;
    try result.checkAvailable();
    return result;
}

pub fn execute(gpa: std.mem.Allocator, io: std.Io, cfg: core.Config, username: []const u8) u8 {
    return run(gpa, io, cfg, username) catch |err| {
        const diagnostic = console.diagnostics.startup(err);
        std.debug.print("{s}: local initialization failed ({t}). Hint: {s}\n", .{
            diagnostic.code, err, diagnostic.hint,
        });
        return 1;
    };
}
