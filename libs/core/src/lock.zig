//! Adaptive mutual exclusion for the short critical sections on the request path.
//!
//! A pure spinlock is fastest only while every lock holder keeps its CPU. Connection threads
//! outnumber CPUs, so a holder can be preempted inside a few-instruction critical section;
//! every waiter then spins through its whole time slice while the holder waits behind them,
//! and a nanosecond section becomes a stall of tens of milliseconds for every request that
//! needs the lock. This lock spins briefly, because the holder is usually running and about
//! to release, and then parks on a futex so waiters hand their CPU back to the holder. That is
//! the adaptive design of glibc's `PTHREAD_MUTEX_ADAPTIVE_NP`, WebKit's `WTF::Lock` and Rust's
//! futex mutex. Uncontended it costs one compare-and-swap to lock and one swap to unlock, the
//! same as the spinlocks it replaces; a futex wake is paid only when a waiter parked.

const std = @import("std");
const Io = std.Io;

pub const Lock = struct {
    mutex: Io.Mutex = .init,

    /// Polls this many times while the holder is still running before parking. A critical
    /// section here is tens of nanoseconds, so a holder that has not released by then has
    /// most likely lost its CPU.
    const spin_limit = 100;

    pub fn lock(self: *Lock, io: Io) void {
        if (self.mutex.tryLock()) return;
        var spins: u32 = 0;
        while (spins < spin_limit and self.mutex.state.load(.monotonic) == .locked_once) {
            std.atomic.spinLoopHint();
            spins += 1;
        }
        self.mutex.lockUncancelable(io);
    }

    pub fn unlock(self: *Lock, io: Io) void {
        self.mutex.unlock(io);
    }
};

test "the lock excludes concurrent writers and parks waiters past the spin limit" {
    const Shared = struct {
        lock: Lock = .{},
        count: u64 = 0,

        fn work(self: *@This(), io: Io) void {
            for (0..20_000) |_| {
                self.lock.lock(io);
                defer self.lock.unlock(io);
                // A non-atomic read-modify-write loses updates unless the lock excludes.
                const seen = self.count;
                if (seen % 4096 == 0) std.Thread.yield() catch {};
                self.count = seen + 1;
            }
        }
    };
    var shared: Shared = .{};
    var threads: [8]std.Thread = undefined;
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, Shared.work, .{ &shared, std.testing.io });
    }
    for (threads) |thread| thread.join();
    try std.testing.expectEqual(@as(u64, 8 * 20_000), shared.count);
    try std.testing.expect(shared.lock.mutex.state.load(.monotonic) == .unlocked);
}
