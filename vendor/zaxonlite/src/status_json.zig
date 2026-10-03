//! Serializes the fixed head of the server's status JSON: every field
//! before the membership-operation section. Split from the server so the
//! request surface stays within the file's code-size pin.

const std = @import("std");
const Io = std.Io;
const node_mod = @import("node.zig");
const server = @import("server.zig");
const writeJsonString = server.writeJsonString;

pub fn writeHead(
    out: *Io.Writer,
    status: node_mod.Status,
    leader: ?u32,
    phase: []const u8,
    quorum_available: bool,
    installation_state: []const u8,
    health: []const u8,
    failure: ?[]const u8,
) !void {
    const chain_hex = std.fmt.bytesToHex(status.chain, .lower);
    var failure_buffer: [130]u8 = undefined;
    const failure_json = if (failure) |message| blk: {
        const len = @min(message.len, failure_buffer.len - 2);
        failure_buffer[0] = '"';
        @memcpy(failure_buffer[1..][0..len], message[0..len]);
        failure_buffer[len + 1] = '"';
        break :blk failure_buffer[0 .. len + 2];
    } else "null";
    const ok = !std.mem.eql(u8, health, "failed");
    try out.print(
        "{{\"ok\":{},\"node_id\":{d},\"database_id\":\"{x:0>32}\"," ++
            "\"configuration_id\":{d},\"role\":\"{s}\"," ++
            "\"node_type\":\"{s}\",\"leader\":{?d}," ++
            "\"phase\":\"{s}\",\"quorum_available\":{}," ++
            "\"health\":\"{s}\",\"failure\":{s}," ++
            "\"installation_state\":\"{s}\",",
        .{
            ok,                 status.node_id,
            status.database_id, status.configuration_id,
            status.role,        status.node_type,
            leader,             phase,
            quorum_available,   health,
            failure_json,       installation_state,
        },
    );
    try out.print(
        "\"ballot\":{{\"round\":{d},\"priority\":{d},\"node\":{d}}}," ++
            "\"decided_slot\":{d},\"applied_slot\":{d}," ++
            "\"durable_state_slot\":{d},\"memory_floor\":{d}," ++
            "\"trim_decision_slot\":{d},\"chosen_trim_slot\":{d}," ++
            "\"trim_ignored\":{d},\"retained_first_slot\":{d}," ++
            "\"journal_records\":{d},\"journal_segment_count\":{d}," ++
            "\"journal_bytes\":{d},\"payload_retained_bytes\":{d}," ++
            "\"chain\":\"{s}\",\"page_size\":{d}," ++
            "\"fts5_enabled\":{}," ++
            "\"sqlite_vec_version\":\"{s}\"," ++
            "\"search_feature_version\":{d}," ++
            "\"simd_backend\":\"{s}\"," ++
            "\"mmap_size\":{d}," ++
            "\"candidate_hard_limit\":{d}," ++
            "\"write_gate\":\"fifo-v1\",\"trim_mode\":\"conservative\"," ++
            "\"typed_v1\":true,",
        .{
            status.ballot.round,           status.ballot.priority,
            status.ballot.node,            status.decided_slot,
            status.applied_slot,           status.durable_state_slot,
            status.memory_floor,           status.trim_decision_slot,
            status.chosen_trim_slot,       status.trim_ignored,
            status.retained_first_slot,    status.journal_records,
            status.journal_segment_count,  status.journal_bytes,
            status.payload_retained_bytes, &chain_hex,
            status.page_size,              status.fts5_enabled,
            status.sqlite_vec_version,     status.search_feature_version,
            status.simd_backend,           status.mmap_size,
            status.candidate_hard_limit,
        },
    );
}

pub fn writeMembershipOperation(
    out: *Io.Writer,
    pending: ?node_mod.Node.PendingOperation,
    installation_error: ?[]const u8,
) !void {
    try out.writeAll("\"operation_id\":");
    if (pending) |operation| {
        try out.print("{d}", .{operation.operation_id});
    } else {
        try out.writeAll("null");
    }
    try out.writeAll(",\"installation_error\":");
    if (installation_error) |message| {
        try writeJsonString(out, message);
    } else {
        try out.writeAll("null");
    }
}
