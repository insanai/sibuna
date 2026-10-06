//! Execute a prepared full-match program once, after chain truth is established.
const std = @import("std");
const prepared = @import("action_compile.zig");
const saved = @import("action_state.zig");
const context = @import("evaluation_context.zig");
const macros = @import("macros.zig");
const work = @import("work.zig");
const buffers = @import("buffers.zig");
pub const Program = prepared.Program;
pub const compile = prepared.compile;
pub const compileCandidate = prepared.compileCandidate;
pub const State = saved.State;
pub const Error = prepared.Error || saved.Error || context.Error || error{InvalidUnwind};
pub const Frame = struct {
    context: *context.Context,
    state: *State,
    pieces: [][]const u8,
    key_output: []u8,
    value_output: []u8,
    budget: *work.Budget,
};

pub fn execute(program: *const Program, frame: Frame) Error!void {
    return executeChain(&.{program.*}, &.{0}, frame);
}

/// The verified chain evaluator supplies adjacent descending indices. Its links
/// share one rule message, so tags append while later root metadata can overwrite.
pub fn executeChain(programs: []const Program, unwind: []const usize, frame: Frame) Error!void {
    if (frame.state.failed or frame.context.failed) return error.TransactionFailed;
    errdefer {
        frame.state.poison();
        frame.context.poison();
    }
    assertDisjoint(frame);
    if (unwind.len == 0 or unwind.len > 256) return error.InvalidUnwind;
    const first = unwind[0];
    if (first >= programs.len) return error.InvalidUnwind;
    const leaf = &programs[first];
    var previous = first;
    for (unwind, 0..) |index, position| {
        if (index >= programs.len) return error.InvalidUnwind;
        if (position != 0 and (previous == 0 or index != previous - 1))
            return error.InvalidUnwind;
        if (programs[index].id != leaf.id or programs[index].phase != leaf.phase)
            return error.InvalidUnwind;
        previous = index;
    }
    const publish = !programs[unwind[unwind.len - 1]].multi_match;
    if (publish and frame.state.event_used == frame.state.events.len) return error.EventLimit;
    try frame.budget.debit(unwind.len);
    var event: saved.Event = .{ .id = leaf.id, .phase = leaf.phase };
    const tag_start = frame.state.tag_used;
    for (unwind) |index| {
        const program = &programs[index];
        for (program.steps) |*step| try executeStep(step, program.default_deny, &event, frame);
    }
    event.tags = frame.state.tags[tag_start..frame.state.tag_used];
    if (frame.state.tag_templates.len != 0)
        event.tag_templates = frame.state.tag_templates[tag_start..frame.state.tag_used];
    if (publish) {
        frame.state.events[frame.state.event_used] = event;
        frame.state.event_used += 1;
    }
}

fn executeStep(
    step: *const prepared.Step,
    default_deny: bool,
    event: *saved.Event,
    frame: Frame,
) Error!void {
    try frame.budget.debit(1);
    switch (step.*) {
        .control => |*program| {
            try frame.state.control.apply(program, frame.budget);
            // Parser selection is visible to following rules and macro expansion
            // in this phase. These labels have static lifetime, like the control.
            if (program.operation == .processor) {
                const processor = frame.state.control.processor;
                frame.context.setProcessor(switch (processor) {
                    .automatic => null,
                    .urlencoded => "URLENCODED",
                    .json => "JSON",
                    .xml => "XML",
                });
            }
        },
        .write => |*program| {
            const view = try frame.context.view(frame.budget);
            try program.execute(.{
                .store = frame.context.store,
                .view = &view,
                .pieces = frame.pieces,
                .key_output = frame.key_output,
                .value_output = frame.value_output,
                .budget = frame.budget,
            });
        },
        .binding => |*binding| {
            const key = try expand(&binding.key, frame);
            const owned = try frame.state.save(key, frame.budget);
            frame.state.bindings[@backingInt(binding.namespace)] = owned;
        },
        .message => |*program| {
            event.message = try frame.state.save(try expand(program, frame), frame.budget);
            event.message_template = program.source;
        },
        .data => |*program| {
            event.data = try frame.state.save(try expand(program, frame), frame.budget);
        },
        .tag => |*program| try frame.state.appendTagTemplate(
            try expand(program, frame),
            program.source,
            frame.budget,
        ),
        .severity => |value| {
            event.severity = value;
            frame.state.highest_severity = @min(frame.state.highest_severity, @as(u8, value));
        },
        .status => |value| frame.state.status = value,
        .save => |value| event.save = value,
        .audit => |value| {
            event.no_audit = !value;
            event.save = value;
        },
        .deny => frame.state.deny(event),
        .pass => {},
        .block => if (default_deny) {
            frame.state.deny(event);
        },
    }
}

fn expand(program: *const macros.Program, frame: Frame) Error![]const u8 {
    const view = try frame.context.view(frame.budget);
    return program.expand(.{
        .view = &view,
        .pieces = frame.pieces,
        .output = frame.value_output,
        .budget = frame.budget,
    });
}

fn assertDisjoint(frame: Frame) void {
    const state = frame.state;
    const ctx = frame.context;
    const regions = [_][]const u8{
        std.mem.sliceAsBytes(frame.pieces),
        frame.key_output,
        frame.value_output,
        std.mem.sliceAsBytes(state.control.exclusions),
        std.mem.sliceAsBytes(state.events),
        std.mem.sliceAsBytes(state.tags),
        std.mem.sliceAsBytes(state.tag_templates),
        state.bytes,
        std.mem.sliceAsBytes(ctx.scratch.view),
        std.mem.sliceAsBytes(ctx.scratch.matched),
        ctx.scratch.bytes,
        std.mem.sliceAsBytes(ctx.store.entries),
        ctx.store.bytes,
        std.mem.sliceAsBytes(ctx.acquired.entries),
    };
    buffers.assertExclusive(&regions);
}

test {
    _ = @import("post_actions_test.zig");
}
