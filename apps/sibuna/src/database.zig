const std = @import("std");
const zx = @import("zaxonlite");
const build_options = @import("build_options");

pub const Db = union(enum) {
    node: *zx.Node,
    embedded: if (build_options.cluster) *zx.Embedded else void,

    pub fn exec(self: Db, gpa: std.mem.Allocator, sql: []const u8) !void {
        switch (self) {
            .node => |n| {
                const z = try gpa.dupeZ(u8, sql);
                defer gpa.free(z);
                _ = try n.exec(z);
            },
            .embedded => |e| {
                if (!build_options.cluster) unreachable;
                _ = try e.exec(sql);
            },
        }
    }

    pub fn query(self: Db, gpa: std.mem.Allocator, sql: []const u8) !zx.QueryResult {
        return switch (self) {
            .node => |n| n.query(gpa, sql),
            .embedded => |e| if (build_options.cluster) e.query(gpa, sql) else unreachable,
        };
    }

    pub fn close(self: Db) void {
        switch (self) {
            .node => |n| n.close(),
            .embedded => |e| if (build_options.cluster) e.close(),
        }
    }

    /// Closes the store, bounding a cluster member's stop. Zaxonlite 0.6.2 bounds
    /// its own shutdown (0.6.1 could wait forever for a handler still parked on
    /// consensus); the bound stays as a safety net so a service manager never
    /// sees a hung stop. Returns false when the close was abandoned after
    /// `close_bound_ms`; every acknowledged write is durable either way.
    pub fn closeBounded(self: Db, io: std.Io) bool {
        switch (self) {
            .node => |n| n.close(),
            .embedded => |e| if (build_options.cluster) return closeEmbedded(io, e),
        }
        return true;
    }
};

const close_bound_ms: u64 = 15_000;
/// Global rather than stack-owned: an abandoned close thread may still complete
/// after `closeEmbedded` has returned.
var close_done = std.atomic.Value(bool).init(false);

fn closeEmbedded(io: std.Io, embedded: *zx.Embedded) bool {
    close_done.store(false, .release);
    const thread = std.Thread.spawn(.{}, closeTask, .{embedded}) catch {
        embedded.close();
        return true;
    };
    var waited_ms: u64 = 0;
    while (!close_done.load(.acquire)) {
        if (waited_ms >= close_bound_ms) {
            thread.detach();
            std.log.warn("storage: cluster member did not stop within {d} s; " ++
                "peer requests left waiting on consensus are abandoned", .{close_bound_ms / 1000});
            return false;
        }
        io.sleep(.fromMilliseconds(25), .awake) catch {};
        waited_ms += 25;
    }
    thread.join();
    return true;
}

fn closeTask(embedded: *zx.Embedded) void {
    embedded.close();
    close_done.store(true, .release);
}
