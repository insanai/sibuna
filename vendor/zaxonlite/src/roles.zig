//! Product node roles and their consensus/storage capabilities.
//!
//! Only roles with `votes` belong to the Paxos membership. Standbys and
//! read replicas learn the chosen log without changing quorum size. A
//! gateway owns no database state and only routes client traffic.

const std = @import("std");

pub const Role = enum(u8) {
    data_voter,
    witness,
    standby,
    read_replica,
    gateway,

    pub fn name(self: Role) []const u8 {
        return switch (self) {
            .data_voter => "data-voter",
            .witness => "witness",
            .standby => "standby",
            .read_replica => "read-replica",
            .gateway => "gateway",
        };
    }

    pub fn parse(text: []const u8) !Role {
        inline for (@typeInfo(Role).@"enum".field_names) |field_name| {
            const role: Role = @field(Role, field_name);
            if (std.mem.eql(u8, text, role.name())) return role;
        }
        return error.UnknownNodeRole;
    }

    pub fn capabilities(self: Role) Capabilities {
        return switch (self) {
            .data_voter => .{
                .votes = true,
                .campaigns = true,
                .stores_log = true,
                .materializes = true,
                .serves_reads = true,
                .serves_writes = true,
                .promotion_eligible = true,
            },
            .witness => .{
                .votes = true,
                .campaigns = false,
                .stores_log = true,
                .materializes = false,
                .serves_reads = false,
                .serves_writes = false,
                .promotion_eligible = false,
            },
            .standby => .{
                .votes = false,
                .campaigns = false,
                .stores_log = true,
                .materializes = true,
                .serves_reads = true,
                .serves_writes = false,
                .promotion_eligible = true,
            },
            .read_replica => .{
                .votes = false,
                .campaigns = false,
                .stores_log = true,
                .materializes = true,
                .serves_reads = true,
                .serves_writes = false,
                .promotion_eligible = false,
            },
            .gateway => .{
                .votes = false,
                .campaigns = false,
                .stores_log = false,
                .materializes = false,
                .serves_reads = false,
                .serves_writes = false,
                .promotion_eligible = false,
            },
        };
    }
};

pub const Capabilities = struct {
    votes: bool,
    campaigns: bool,
    stores_log: bool,
    materializes: bool,
    serves_reads: bool,
    serves_writes: bool,
    promotion_eligible: bool,
};

test "roles keep learners out of the Paxos voter set" {
    try std.testing.expect(Role.data_voter.capabilities().votes);
    try std.testing.expect(Role.witness.capabilities().votes);
    try std.testing.expect(!Role.standby.capabilities().votes);
    try std.testing.expect(!Role.read_replica.capabilities().votes);
    try std.testing.expect(!Role.gateway.capabilities().stores_log);
}

test "role names round trip" {
    inline for (@typeInfo(Role).@"enum".field_names) |field_name| {
        const role: Role = @field(Role, field_name);
        try std.testing.expectEqual(role, try Role.parse(role.name()));
    }
    try std.testing.expectError(error.UnknownNodeRole, Role.parse("leader"));
}
