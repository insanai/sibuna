//! Process-level smoke test for the stateless gateway role.

const std = @import("std");
const Io = std.Io;
const zaxonlite = @import("zaxonlite");

const secret = "gateway-test-secret-at-least-32-bytes";

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer args.deinit();
    _ = args.next();
    const zaxon = args.next() orelse return 2;

    var random: [8]u8 = undefined;
    io.random(&random);
    const root = try std.fmt.allocPrint(
        gpa,
        ".zig-cache/tmp/zx-gateway-{x}",
        .{std.mem.readInt(u64, &random, .little)},
    );
    defer gpa.free(root);
    try Io.Dir.cwd().createDirPath(io, root);
    defer Io.Dir.cwd().deleteTree(io, root) catch {};
    const auth = try std.fmt.allocPrint(gpa, "{s}/auth", .{root});
    defer gpa.free(auth);
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = auth,
        .data = secret,
        .flags = .{ .permissions = @fromBackingInt(@intCast(0o600)) },
    });
    const backend_port = try freePort(io);
    const gateway_port = try freePort(io);

    var backend = try spawnBackend(gpa, io, zaxon, root, auth, backend_port);
    defer backend.kill(io);
    var gateway = try spawnGateway(
        gpa,
        io,
        zaxon,
        auth,
        backend_port,
        gateway_port,
    );
    defer gateway.kill(io);

    const endpoint = zaxonlite.client.Endpoint{
        .host = "127.0.0.1",
        .port = gateway_port,
    };
    var elapsed: u64 = 0;
    while (elapsed < 10_000) : (elapsed += 100) {
        const connection = zaxonlite.client.Connection.openWithSecret(
            gpa,
            io,
            endpoint,
            secret,
        ) catch {
            io.sleep(.fromMilliseconds(100), .awake) catch {};
            continue;
        };
        const response = connection.call(
            "{\"op\":\"exec\",\"sql\":\"create table gateway_test(v text)\"}",
        ) catch {
            connection.close();
            continue;
        };
        defer gpa.free(response);
        connection.close();
        if (std.mem.indexOf(u8, response, "\"ok\":true") != null) {
            std.debug.print("gateway: end-to-end authenticated RPC passed\n", .{});
            return 0;
        }
    }
    return error.GatewayTimeout;
}

fn spawnBackend(
    gpa: std.mem.Allocator,
    io: Io,
    zaxon: []const u8,
    root: []const u8,
    auth: []const u8,
    port: u16,
) !std.process.Child {
    const directory = try std.fmt.allocPrint(gpa, "{s}/backend", .{root});
    defer gpa.free(directory);
    const listen = try std.fmt.allocPrint(gpa, "127.0.0.1:{d}", .{port});
    defer gpa.free(listen);
    return std.process.spawn(io, .{
        .argv = &.{
            zaxon,                 "serve",               "--data",      directory, "--node", "1",
            "--listen",            listen,                "--auth-file", auth,      "--sync", "os",
            "--enable-failpoints", "--insecure-test-tcp",
        },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
}

fn spawnGateway(
    gpa: std.mem.Allocator,
    io: Io,
    zaxon: []const u8,
    auth: []const u8,
    backend_port: u16,
    gateway_port: u16,
) !std.process.Child {
    const listen = try std.fmt.allocPrint(gpa, "127.0.0.1:{d}", .{gateway_port});
    defer gpa.free(listen);
    const peer = try std.fmt.allocPrint(
        gpa,
        "1@127.0.0.1:{d}/data-voter",
        .{backend_port},
    );
    defer gpa.free(peer);
    return std.process.spawn(io, .{
        .argv = &.{
            zaxon,         "serve",   "--data",   ".",    "--node", "99",
            "--role",      "gateway", "--listen", listen, "--peer", peer,
            "--auth-file", auth,
        },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
}

fn freePort(io: Io) !u16 {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try address.listen(io, .{ .reuse_address = true });
    const port = listener.socket.address.getPort();
    listener.deinit(io);
    return port;
}
