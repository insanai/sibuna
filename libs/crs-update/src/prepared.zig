//! One owner for retrieved or reloaded source bytes and the stable compiled package.
//! Management jobs never retain a caller's borrowed editor or download buffers.
const std = @import("std");
const crs = @import("crs");
pub const Bytes = struct {
    buffer: []u8,
    value: []const u8,
};
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    archive: Bytes,
    signature: Bytes,
    configuration: Bytes,
    package: ?*crs.release_package.Package,

    /// Only the stable package transfers; source bytes remain owned for staging.
    pub fn takePackage(self: *Prepared) *crs.release_package.Package {
        const result = self.package.?;
        self.package = null;
        return result;
    }

    pub fn deinit(self: *Prepared) void {
        if (self.package) |package| package.deinit();
        self.allocator.free(self.configuration.buffer);
        self.allocator.free(self.signature.buffer);
        self.allocator.free(self.archive.buffer);
        self.* = undefined;
    }
};
