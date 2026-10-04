//! Off-path generation ownership. A stable generation owns its signed package and
//! initialized pool; successful creation transfers package ownership to the caller.
const std = @import("std");
const packages = @import("release_package.zig");
const pools = @import("transaction_pool.zig");
const slots = @import("transaction_slot.zig");
const config = @import("config.zig");
pub const Error = pools.Error || config.Error || std.mem.Allocator.Error || error{
    InvalidGenerationRevision,
};
pub const Options = struct {
    revision: u64,
    activation: config.Activation,
    observation: config.Observation,
    limits: slots.Limits = .{},
    slots: usize = 8,
    reservation: usize = 1024 * 1024 * 1024,
};
pub const Generation = struct {
    allocator: std.mem.Allocator,
    package: ?*packages.Package,
    options: Options,
    pool: pools.Pool = undefined,
    pool_live: bool = false,

    /// On failure the caller retains the package. Disabled generations allocate
    /// no transaction pool and are valid without an artifact.
    pub fn create(
        allocator: std.mem.Allocator,
        package: ?*packages.Package,
        options: Options,
    ) Error!*Generation {
        if (options.revision == 0) return error.InvalidGenerationRevision;
        try options.activation.validate(options.observation, if (package != null)
            .executable
        else
            .absent);
        const self = try allocator.create(Generation);
        errdefer allocator.destroy(self);
        self.* = .{ .allocator = allocator, .package = package, .options = options };
        if (options.activation.mode != .off) {
            try self.pool.init(
                allocator,
                &package.?.program,
                options.limits,
                options.slots,
                options.reservation,
            );
            self.pool_live = true;
        }
        return self;
    }

    pub fn retire(self: *Generation) void {
        if (self.pool_live) self.pool.close();
    }

    pub fn drained(self: *const Generation) bool {
        return !self.pool_live or self.pool.drained();
    }

    pub fn deinit(self: *Generation) void {
        // Unpublished candidates also own open, empty pools. Closing here makes
        // their failure cleanup identical to retired-generation cleanup.
        self.retire();
        std.debug.assert(self.drained());
        const allocator = self.allocator;
        if (self.pool_live) self.pool.deinit();
        if (self.package) |package| package.deinit();
        allocator.destroy(self);
    }
};
