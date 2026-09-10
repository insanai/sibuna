const p = @import("console_protocol");
const wire = p.rule_hit_history;
pub const Inputs = struct {
    key: p.rule_hits.Key = .{},
    node: u32 = 1,
    minutes: u32 = 60,
    offset: u32 = 0,
    mode: enum { previous, edit } = .previous,
    edit_at: u64 = 0,
    before_revision: p.Bytes(20) = .{},
    after_revision: p.Bytes(20) = .{},
};
pub const Model = struct {
    open: bool = false,
    started: bool = false,
    busy: bool = false,
    inputs: Inputs = .{},
    windows: [2]wire.Window = @splat(.{ .request = .{
        .key = .{},
        .node = 0,
        .from_minute = 0,
        .until_minute = 0,
    } }),
    ticket: u64 = 0,
    side: usize = 0,
    remaining: u8 = 0,
    message: p.Bytes(256) = .{},

    pub fn clear(self: *Model) void {
        self.open = false;
        self.started = false;
        self.busy = false;
        self.inputs = .{};
        for (&self.windows) |*window| window.* = .{ .request = .{
            .key = .{},
            .node = 0,
            .from_minute = 0,
            .until_minute = 0,
        } };
        self.ticket = 0;
        self.remaining = 0;
        self.side = 0;
        self.message = .{};
    }
};
