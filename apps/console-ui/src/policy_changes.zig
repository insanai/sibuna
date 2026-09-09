//! Compare canonical editor fields. The review owns its serialized draft; rendered slices
//! borrow bounded local forms only until this call returns. Nothing here submits a mutation.
const std = @import("std");
const html = @import("html");
const Form = @import("policy_form.zig").Form;
const Writer = std.Io.Writer;
const State = @import("state.zig").State;
const Change = struct { label: []const u8, before: []const u8, after: []const u8 };
const fields = .{
    "id",
    "name",
    "action",
    "enabled",
    "priority",
    "path",
    "user_agent",
    "headers",
    "cidrs",
    "algorithm",
    "difficulty",
    "weight",
    "limit_rate",
    "limit_window",
    "limit_ban",
};
const labels = .{
    "Rule ID",
    "Rule name",
    "Action",
    "Enabled",
    "Priority",
    "Path pattern",
    "User-agent pattern",
    "Header matchers",
    "Client networks",
    "Challenge algorithm",
    "Challenge difficulty",
    "Weight",
    "Burst requests",
    "Pacing window (seconds)",
    "Local ban (seconds)",
};

fn changes(before: ?*const Form, after: *const Form, output: *[fields.len]Change) []const Change {
    var count: usize = 0;
    inline for (fields, labels) |field, label| {
        const old = if (before) |form| @field(form, field).slice() else "";
        const new = @field(after, field).slice();
        if (!std.mem.eql(u8, old, new)) {
            output[count] = .{ .label = label, .before = old, .after = new };
            count += 1;
        }
    }
    return output[0..count];
}

pub fn render(w: *Writer, state: *const State) Writer.Error!void {
    const model = &state.policies.manager;
    const busy = state.policies.busy or state.policies.testing;
    const disabled = busy or state.policies.stale or !state.allows(.manage_policy);
    var before: Form = undefined;
    var after: Form = undefined;
    after.load(model.review.slice()) catch return unavailable(w);
    if (model.baseline.len != 0) before.load(model.baseline.slice()) catch return unavailable(w);
    var rows: [fields.len]Change = undefined;
    const changed = changes(if (model.baseline.len == 0) null else &before, &after, &rows);
    try html.render(w, @embedFile("snippets/policy-change-review.html"), .{
        .revision = model.committed.slice(),
        .kind = if (model.baseline.len == 0) "New rule" else "Existing rule",
    });
    for (changed) |row| try html.render(
        w,
        "<tr><th scope=\"row\">{{ label }}</th><td class=\"whitespace-pre-wrap break-all\">" ++
            "{{ before }}</td><td class=\"whitespace-pre-wrap break-all\">{{ after }}</td></tr>",
        .{
            .label = row.label,
            .before = if (row.before.len == 0) "Not set" else row.before,
            .after = if (row.after.len == 0) "Not set" else row.after,
        },
    );
    if (changed.len == 0) try html.render(
        w,
        "<tr><td colspan=\"3\">No field changes. Return to the editor to make a change.</td></tr>",
        .{},
    );
    try html.render(w, "</tbody></table></div>", .{});
    if (state.policies.stale and state.allows(.manage_policy)) {
        if (model.baseline.len != 0) {
            try html.render(w, @embedFile("snippets/policy-change-rebase.html"), .{
                .busy = if (busy) " disabled" else "",
            });
        } else try html.render(
            w,
            "<p>Return to the editor and export this new draft before refreshing " ++
                "Managed rules. " ++
                "Re-import it after reviewing the current catalog.</p>",
            .{},
        );
    }
    try html.render(w, @embedFile("snippets/policy-change-actions.html"), .{
        .confirm = if (disabled or changed.len == 0) " disabled" else "",
        .back = if (busy) " disabled" else "",
    });
}

fn unavailable(w: *Writer) Writer.Error!void {
    try html.render(w, "<p>Change review is unavailable. Refresh and reopen the rule.</p>", .{});
}
