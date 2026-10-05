//! One joined engine worker follows filesystem-authorized immutable selections.
//! It has no console, storage or application-state dependency. Readers retain
//! their existing generation until a complete replacement can be published.
const std = @import("std");
const crs = @import("crs");
const local = @import("crs-update").local;
const Io = std.Io;
pub const Error = local.Error || crs.publication.Error || std.Thread.SpawnError;
const Pending = struct { source: local.Source, generation: *crs.generation.Generation };
pub const Owner = struct {
    allocator: std.mem.Allocator,
    io: Io,
    directory: Io.Dir,
    guard: Io.File,
    publisher: *crs.publication.Publisher,
    observation: crs.config.Observation,
    boot: local.Id,
    stopping: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,
    pending: ?Pending = null,
    applied: ?local.Source = null,
    receipt_confirmed: bool = false,
    attempted: ?local.Source = null,
    retry_after: i96 = 0,
    retry_seconds: u64 = 1,

    /// Startup applies durable intent before listeners. An empty explicit local
    /// store stays disabled and can receive its first later reviewed selection.
    pub fn start(
        allocator: std.mem.Allocator,
        io: Io,
        path: []const u8,
        publisher: *crs.publication.Publisher,
        observation: crs.config.Observation,
    ) Error!*Owner {
        const directory = try Io.Dir.cwd().openDir(io, path, .{
            .follow_symlinks = false,
            .iterate = true,
        });
        errdefer directory.close(io);
        const local_store: local.Store = .{
            .allocator = allocator,
            .io = io,
            .directory = directory,
        };
        const guard = try local_store.claimDaemon();
        errdefer guard.close(io);
        const self = try allocator.create(Owner);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .io = io,
            .directory = directory,
            .guard = guard,
            .publisher = publisher,
            .observation = observation,
            .boot = undefined,
        };
        io.random(&self.boot);
        if (std.mem.allEqual(u8, &self.boot, 0)) return error.InvalidLocalSource;
        errdefer self.clearPending();
        self.tick() catch |err| {
            self.failed(err);
            return err;
        };
        self.thread = try std.Thread.spawn(.{
            .stack_size = @import("net").stack.bytes(1024 * 1024),
        }, run, .{self});
        return self;
    }

    /// No file, package or publisher borrow outlives this join. The surrounding
    /// runtime destroys its publisher after listener readers have also stopped.
    pub fn stop(self: *Owner) void {
        self.stopping.store(true, .release);
        if (self.thread) |thread| thread.join();
        self.clearPending();
        self.guard.close(self.io);
        self.directory.close(self.io);
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
    }

    fn store(self: *Owner) local.Store {
        return .{ .allocator = self.allocator, .io = self.io, .directory = self.directory };
    }

    fn clearPending(self: *Owner) void {
        if (self.pending) |pending| pending.generation.deinit();
        self.pending = null;
    }

    fn tick(self: *Owner) Error!void {
        var locked = try self.store().lock(.shared);
        defer locked.deinit();
        const selected = try locked.selection() orelse {
            if (self.applied != null or (try locked.observation()) != null)
                return error.InvalidLocalSource;
            return;
        };
        if (self.applied) |applied| {
            if (std.meta.eql(applied, selected.current)) {
                if (self.receipt_confirmed) return;
                try self.record(&locked, applied, .applied, .none);
                self.receipt_confirmed = true;
                return;
            }
            if (selected.current.revision <= applied.revision) return error.LocalStoreConflict;
        }
        if (self.attempted == null or !std.meta.eql(self.attempted.?, selected.current)) {
            self.attempted = selected.current;
            self.retry_after = 0;
            self.retry_seconds = 1;
            self.clearPending();
        }
        if (Io.Clock.awake.now(self.io).nanoseconds < self.retry_after) return;
        if (self.pending == null) {
            try self.record(&locked, selected.current, .pending, .none);
            try self.prepare(&locked, selected.current);
        }
        if (self.stopping.load(.acquire)) return error.Canceled;
        // The shared selector lock fences writers and reclamation through this
        // publication. Busy pin cells retain the private candidate for retry.
        if (!std.meta.eql((try locked.selection()).?.current, selected.current))
            return error.LocalStoreConflict;
        std.debug.assert(std.meta.eql(self.pending.?.source, selected.current));
        try self.publisher.publish(self.pending.?.generation);
        self.pending = null;
        self.applied = selected.current;
        self.receipt_confirmed = false;
        self.retry_seconds = 1;
        try self.record(&locked, selected.current, .applied, .none);
        self.receipt_confirmed = true;
    }

    fn prepare(self: *Owner, locked: *const local.Locked, source: local.Source) Error!void {
        var candidate = try locked.load(source);
        defer candidate.deinit();
        const options = try candidate.manifest.options(self.observation);
        try crs.http_policy.validate(&candidate.prepared.package.?.program, options.activation);
        if (self.stopping.load(.acquire)) return error.Canceled;
        const generation = try crs.generation.Generation.create(
            self.allocator,
            candidate.prepared.package.?,
            options,
        );
        _ = candidate.prepared.takePackage();
        self.pending = .{ .source = source, .generation = generation };
    }

    fn record(
        self: *Owner,
        locked: *const local.Locked,
        source: local.Source,
        state: local.State,
        why: local.Reason,
    ) Error!void {
        return locked.record(.{
            .source = source,
            .boot = self.boot,
            .observed_at = try self.store().now(),
            .state = state,
            .reason = why,
        });
    }

    fn failed(self: *Owner, err: anyerror) void {
        if (err == error.LocalStoreBusy or self.stopping.load(.acquire)) return;
        self.retry_after = Io.Clock.awake.now(self.io).nanoseconds +
            @as(i96, self.retry_seconds) * std.time.ns_per_s;
        self.retry_seconds = @min(60, self.retry_seconds * 2);
        std.log.warn("CRSLOCAL001: local selection application unavailable ({t})", .{err});
        var locked = self.store().lock(.shared) catch return;
        defer locked.deinit();
        const selected = (locked.selection() catch return) orelse return;
        // A receipt failure after a successful publication is unconfirmed, not
        // a failed generation. The next tick retries the observed application.
        if (self.applied) |applied| if (std.meta.eql(applied, selected.current)) return;
        self.record(&locked, selected.current, .failed, reason(err)) catch |failure| {
            std.log.warn("CRSLOCAL002: local failure receipt unavailable ({t})", .{failure});
        };
    }

    fn run(self: *Owner) void {
        while (!self.stopping.load(.acquire)) {
            self.tick() catch |err| self.failed(err);
            Io.sleep(self.io, .fromSeconds(1), .awake) catch return;
        }
    }
};

fn reason(err: anyerror) local.Reason {
    return switch (err) {
        error.OutOfMemory, error.CompiledProgramLimit, error.PoolReservationLimit => .capacity,
        error.PublicationBusy, error.PublicationClosed, error.StaleGenerationRevision => {
            return .publication;
        },
        error.InvalidSignature, error.UntrustedSigner => .signature,
        error.InvalidLocalSource, error.FileNotFound, error.ArtifactFileLength => .source,
        else => .incompatible,
    };
}
