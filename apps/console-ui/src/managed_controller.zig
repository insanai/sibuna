//! Managed policy requests share one dispatch-local context. The entry point owns state,
//! command buffers and the generation; this controller retains no borrowed references.
const std = @import("std");
const p = @import("console_protocol");
const string = @import("events_state.zig").string;
pub const Controller = struct {
    state: *@import("state.zig").State,
    out: @import("transport.zig").Outbox,
    generation: *u32,

    pub fn fromAudit(self: Controller, name: []const u8) !bool {
        if (!equal(name, "audit-policy-review")) return false;
        const state = self.state;
        if (state.phase != .audit or !state.allows(.manage_policy) or
            state.audit.busy or !state.audit.has_detail) return true;
        const selected = state.audit.detail.row.policyRevision() orelse return true;
        const model = &state.policies;
        const manager = &model.manager;
        state.phase = .policies;
        state.message = .{};
        model.busy = false;
        model.testing = false;
        model.decision = .{};
        manager.active = true;
        manager.view = .history;
        manager.snapshot = .{};
        manager.baseline = .{};
        manager.review = .{};
        manager.id = selected.id;
        const revision = try std.fmt.bufPrint(
            &manager.historical.data,
            "{d}",
            .{selected.revision},
        );
        manager.historical.len = revision.len;
        // Obtain today's document and revision before requesting the immutable history row.
        try self.post("baseline", .{ .kind = "document", .id = manager.id.slice() });
        return true;
    }

    pub fn action(self: Controller, name: []const u8, fields: std.json.Value) !bool {
        const state = self.state;
        if (!state.fullAccess() or state.phase != .policies or
            !std.mem.startsWith(u8, name, "managed-")) return false;
        const model = &state.policies;
        const manager = &model.manager;
        if (model.busy or model.testing) return true;
        if (manager.review.len != 0 and !equal(name, "managed-confirm") and
            !equal(name, "managed-back") and !equal(name, "managed-refresh") and
            !equal(name, "managed-rebase")) return true;
        manager.active = true;
        state.message = .{};
        model.decision = .{};
        if (try self.reviewAction(name, fields)) return true;
        if (try @import("workflow_controller.zig").action(self, name, fields)) return true;
        if (equal(name, "managed-refresh")) {
            manager.review = .{};
            manager.view = .catalog;
            manager.snapshot = .{};
            manager.next = .{};
            try self.post("catalog", .{ .kind = "catalog" });
        } else if (equal(name, "managed-new")) {
            if (!state.allows(.manage_policy) or manager.committed.len == 0) return true;
            manager.form.clear();
            manager.baseline = .{};
            manager.id = .{};
            manager.historical = .{};
            manager.view = .editor;
            try self.out.emit(.{ .op = "focus", .selector = "#managed-editor", .top = true });
        } else if (equal(name, "managed-next")) {
            try self.next();
        } else if (std.mem.startsWith(u8, name, "managed-open:")) {
            manager.id = try p.Bytes(128).init(name[13..]);
            manager.historical = .{};
            try self.post("document", .{
                .kind = "document",
                .id = manager.id.slice(),
                .committed = manager.committed.slice(),
            });
        } else if (std.mem.startsWith(u8, name, "managed-history:")) {
            manager.id = try p.Bytes(128).init(name[16..]);
            manager.historical = .{};
            try self.post("history", .{
                .kind = "history",
                .id = manager.id.slice(),
                .committed = manager.committed.slice(),
            });
        } else if (std.mem.startsWith(u8, name, "managed-version:")) {
            manager.historical = try p.Bytes(20).init(name[16..]);
            try self.post("baseline", .{
                .kind = "document",
                .id = manager.id.slice(),
                .committed = manager.committed.slice(),
            });
        }
        return true;
    }

    fn reviewAction(self: Controller, name: []const u8, fields: std.json.Value) !bool {
        const state = self.state;
        const model = &state.policies;
        const manager = &model.manager;
        if (manager.view != .editor) return false;
        if (equal(name, "managed-save")) {
            if (!state.allows(.manage_policy) or model.stale) return true;
            var document: p.Bytes(4096) = undefined;
            if (!try self.captureDocument(fields, &document)) return true;
            manager.review = document;
            try self.out.emit(.{
                .op = "focus",
                .selector = "#policy-change-review",
                .top = true,
            });
        } else if (equal(name, "managed-back")) {
            manager.review = .{};
            try self.out.emit(.{ .op = "focus", .selector = "#managed-editor", .top = true });
        } else if (equal(name, "managed-rebase")) {
            if (!state.allows(.manage_policy) or !model.stale or
                manager.review.len == 0 or manager.baseline.len == 0) return true;
            try self.post("rebase", .{ .kind = "document", .id = manager.id.slice() });
        } else if (equal(name, "managed-confirm")) {
            if (!state.allows(.manage_policy) or model.stale or
                manager.review.len == 0) return true;
            try self.post("save", .{
                .expected_revision = manager.committed.slice(),
                .document = manager.review.slice(),
            });
        } else return false;
        return true;
    }

    fn next(self: Controller) !void {
        const model = &self.state.policies;
        const manager = &model.manager;
        if (model.stale or manager.next.len == 0) return;
        if (manager.view == .catalog) {
            try self.post("catalog", .{
                .kind = "catalog",
                .after = manager.next.slice(),
                .committed = manager.committed.slice(),
            });
        } else try self.post("history", .{
            .kind = "history",
            .id = manager.id.slice(),
            .before = manager.next.slice(),
            .committed = manager.committed.slice(),
        });
    }

    pub fn captureDocument(
        self: Controller,
        fields: std.json.Value,
        output: *p.Bytes(4096),
    ) !bool {
        const state = self.state;
        const manager = &state.policies.manager;
        manager.form.capture(fields) catch {
            self.message("A rule field is too long. Shorten it and try again.");
            try self.out.emit(.{ .op = "focus", .selector = "#console-message" });
            return false;
        };
        if (manager.id.len != 0 and !equal(manager.id.slice(), manager.form.id.slice())) {
            self.message(
                "An existing rule's ID cannot change. Create a new rule for a different ID.",
            );
            return false;
        }
        manager.form.document(output) catch |err| {
            self.message(if (err == error.InvalidRuleLimit)
                @import("policy_limits.zig").invalid_message
            else
                "Check numbers, headers and networks. Rule documents must fit within 4 KiB.");
            try self.out.emit(.{ .op = "focus", .selector = "#console-message" });
            return false;
        };
        return true;
    }

    pub fn transfer(self: Controller, name: []const u8, fields: std.json.Value) !bool {
        const state = self.state;
        var document: p.Bytes(4096) = undefined;
        const workflow = @import("policy_transfer.zig");
        const result = workflow.apply(state, name, fields, &document) catch |err| {
            self.message(if (err == error.InvalidRuleLimit)
                @import("policy_limits.zig").invalid_message
            else
                "Check the rule JSON, field types and ID. No rule was imported or saved.");
            try self.out.emit(.{ .op = "focus", .selector = "#console-message" });
            return true;
        };
        switch (result) {
            .ignored => return false,
            .imported => {
                self.message("Draft imported. Review and preview it before saving.");
                state.message_success = true;
                try self.out.emit(.{ .op = "focus", .selector = "#managed-editor", .top = true });
            },
            .exported => try self.out.emit(.{
                .op = "save-text",
                .filename = "sibuna-rule.json",
                .text = document.slice(),
            }),
        }
        return true;
    }

    pub fn inspection(self: Controller, name: []const u8, fields: std.json.Value) !bool {
        const state = self.state;
        if (!equal(name, "inspection-save")) return false;
        const model = &state.policies;
        if (state.phase != .policies or !state.allows(.manage_policy) or
            model.busy or model.testing or model.stale) return true;
        const draft = @import("inspection_form.zig").submit(model.page.slice(), fields) catch {
            self.message(
                "Refresh the applied revision, choose all four modes and confirm your review.",
            );
            return true;
        };
        model.inspection_draft = draft.modes;
        try self.post("inspection", .{
            .expected_revision = draft.revision.slice(),
            .document = draft.document.slice(),
        });
        return true;
    }

    pub fn post(self: Controller, kind: []const u8, body: anytype) !void {
        const state = self.state;
        self.generation.* +%= 1;
        var buffer: [48]u8 = undefined;
        const id = try std.fmt.bufPrint(&buffer, "managed-{s}-{d}", .{ kind, self.generation.* });
        state.policies.busy = true;
        try self.out.post(
            id,
            if (equal(kind, "save"))
                "/console/api/policies/edit"
            else if (equal(kind, "inspection"))
                "/console/api/inspection/edit"
            else if (equal(kind, "order"))
                "/console/api/policies/order"
            else if (equal(kind, "replay"))
                "/console/api/policies/replay"
            else if (equal(kind, "import-chunk"))
                "/console/api/policies/import/chunk"
            else if (equal(kind, "import-commit"))
                "/console/api/policies/import/commit"
            else
                "/console/api/policies/read",
            body,
        );
    }

    pub fn response(self: Controller, id: []const u8, body: std.json.Value) !void {
        const state = self.state;
        const model = &state.policies;
        const manager = &model.manager;
        if (try @import("workflow_controller.zig").response(self, id, body)) return;
        const revision = string(body, "committed");
        _ = try std.fmt.parseInt(u64, revision, 10);
        manager.committed = try p.Bytes(20).init(revision);
        model.stale = false;
        if (std.mem.startsWith(u8, id, "managed-rebase-")) {
            try manager.baseline.set(string(body, "document"));
            self.message(
                "Current rule reloaded. Review the updated comparison before confirming.",
            );
            return self.out.emit(.{ .op = "focus", .selector = "#policy-change-review" });
        }
        if (std.mem.startsWith(u8, id, "managed-baseline-")) {
            try manager.baseline.set(string(body, "document"));
            return self.post("document", .{
                .kind = "document",
                .id = manager.id.slice(),
                .revision = manager.historical.slice(),
                .committed = manager.committed.slice(),
            });
        }
        if (std.mem.startsWith(u8, id, "managed-inspection-")) {
            model.stale = true;
            self.message(
                "Inspection modes saved. Refresh to review this node's applied settings.",
            );
            state.message_success = true;
            return self.out.emit(.{ .op = "focus", .selector = "#console-message" });
        }
        if (std.mem.startsWith(u8, id, "managed-save-")) {
            manager.id = manager.form.id;
            manager.historical = .{};
            manager.baseline = manager.review;
            manager.review = .{};
            self.message("Rule saved. Check Applied rules for this node's loaded revision.");
            state.message_success = true;
            return self.out.emit(.{ .op = "focus", .selector = "#console-message" });
        }
        if (std.mem.startsWith(u8, id, "managed-document-")) {
            var candidate: @import("policy_form.zig").Form = undefined;
            const source = string(body, "document");
            try candidate.load(source);
            manager.review = .{};
            if (manager.historical.len == 0) try manager.baseline.set(source);
            manager.form = candidate;
            manager.id = manager.form.id;
            manager.view = .editor;
        } else {
            var writer: std.Io.Writer = .fixed(&manager.snapshot.data);
            try std.json.Stringify.value(body, .{}, &writer);
            manager.snapshot.len = writer.buffered().len;
            manager.next = try p.Bytes(128).init(string(body, "next"));
            manager.view = if (std.mem.startsWith(u8, id, "managed-history-"))
                .history
            else
                .catalog;
        }
        state.message = .{};
        try self.out.emit(.{
            .op = "focus",
            .top = true,
            .selector = if (manager.view == .editor) "#managed-editor" else "main h1",
        });
    }

    pub fn message(self: Controller, text: []const u8) void {
        self.state.message_success = false;
        self.state.message = p.Bytes(256).init(text) catch unreachable;
    }
};

fn equal(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

test {
    _ = @import("policy_changes_test.zig");
}
