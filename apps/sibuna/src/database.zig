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
};
