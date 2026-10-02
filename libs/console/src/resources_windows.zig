//! Windows process gauges, sampled only by the console tick. API failures preserve absence.
const std = @import("std");
const w = std.os.windows;
const Sample = @import("resources.zig").Sample;

const Memory = extern struct {
    size: u32 = @sizeOf(Memory),
    faults: u32 = 0,
    peak_working_set: usize = 0,
    working_set: usize = 0,
    peak_paged_pool: usize = 0,
    paged_pool: usize = 0,
    peak_nonpaged_pool: usize = 0,
    nonpaged_pool: usize = 0,
    pagefile: usize = 0,
    peak_pagefile: usize = 0,
};

extern "kernel32" fn K32GetProcessMemoryInfo(w.HANDLE, *Memory, u32) callconv(.winapi) i32;
extern "kernel32" fn GetProcessTimes(
    w.HANDLE,
    *w.FILETIME,
    *w.FILETIME,
    *w.FILETIME,
    *w.FILETIME,
) callconv(.winapi) i32;

pub fn sample() Sample {
    var result: Sample = .{};
    const process = w.GetCurrentProcess();
    var memory: Memory = .{};
    if (K32GetProcessMemoryInfo(process, &memory, @sizeOf(Memory)) != 0) {
        result.rss_kib = memory.working_set / 1024;
        result.rss_max_kib = memory.peak_working_set / 1024;
    }
    var created: w.FILETIME = undefined;
    var exited: w.FILETIME = undefined;
    var kernel: w.FILETIME = undefined;
    var user: w.FILETIME = undefined;
    if (GetProcessTimes(process, &created, &exited, &kernel, &user) != 0)
        result.cpu_ms = (ticks(kernel) + ticks(user)) / 10_000;
    return result;
}

fn ticks(value: w.FILETIME) u64 {
    return @as(u64, value.dwHighDateTime) << 32 | value.dwLowDateTime;
}
