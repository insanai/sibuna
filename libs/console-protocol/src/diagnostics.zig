//! Fixed native/Wasm hints. No transport, storage, credentials or internal error traces.
const std = @import("std");
pub const schema_hint = "The console schema is newer than this binary " ++
    "or its version marker is invalid. " ++
    "Use the release that wrote it or a newer compatible release on every node. " ++
    "Keep the data directory; do not downgrade or edit its schema marker.";

pub fn responseHint(status: u16, code: []const u8) []const u8 {
    // These statuses prove a refusal; a route-family label must not call it an outage
    // or imply that a write might have committed.
    if (status == 400 or status == 401 or status == 403)
        return refusalHint(status);
    if (std.mem.eql(u8, code, "CONSOLESCHEMA"))
        return schema_hint;
    if (std.mem.eql(u8, code, "CONSOLE004"))
        return "The console could not complete this request. Ask the operator to inspect its log.";
    if (std.mem.eql(u8, code, "CONSOLECRS") and status == 409)
        return "Refresh the candidates and saved revision before retrying. " ++
            "Use an administrator session. Verified candidates require a separate selection; " ++
            "a committed selection remains pending until each node reports application.";
    if (std.mem.eql(u8, code, "RANKHISTORY"))
        return "Retained ranking read failed. Check access, period and storage health, " ++
            "then restart the scan. Missing archives are not zero traffic.";
    if (std.mem.eql(u8, code, "CONSOLEPEERQUERY"))
        return "The selected node could not supply this view. Check peer health and retry. " ++
            "Unavailable history is not zero traffic.";
    if (std.mem.eql(u8, code, "TIMELINE001"))
        return "History changed. Reload the latest page.";
    if (std.mem.eql(u8, code, "CONSOLEQUORUM"))
        return "Storage is unavailable; a write may have an unknown outcome. " ++
            "Check storage and quorum health. Refresh the saved state before retrying a mutation.";
    if (std.mem.eql(u8, code, "CONSOLENODE"))
        return "Refresh the node state and inspect the operation receipt before retrying. " ++
            "A pending completion does not mean the local effect failed.";
    if (std.mem.eql(u8, code, "CONSOLEAUDIT404"))
        return "This audit record is unavailable. Refresh; retention may have removed it.";
    if (std.mem.eql(u8, code, "CONSOLESECURITY"))
        return "Narrow the findings period or select one node, then retry. " ++
            "If access changed, sign in again.";
    if (std.mem.eql(u8, code, "CONSOLEAUDIT"))
        return "Narrow the audit filters or sign in again, then retry.";
    if (std.mem.eql(u8, code, "CONSOLEMUTATION"))
        return "Wait up to one minute; a session permits sixty management mutations per minute.";
    if (std.mem.eql(u8, code, "CONSOLETOKENFULL"))
        return "Revoke unused credentials or remove inactive tokens, then retry.";
    if (std.mem.eql(u8, code, "CONSOLETOKEN409"))
        return "Refresh the token list and expected revision before retrying.";
    if (std.mem.eql(u8, code, "CONSOLETOKEN403"))
        return "Use an administrator session and complete required two-factor setup.";
    if (std.mem.eql(u8, code, "CONSOLE2FAKEY"))
        return "This node has no matching console key for two-factor. Use an unused " ++
            "recovery code, or ask an administrator to configure the key or reset two-factor.";
    if (std.mem.eql(u8, code, "CONSOLETOKENS"))
        return "Outcome unknown. Query the token list before retrying.";
    return refusalHint(status);
}

fn refusalHint(status: u16) []const u8 {
    return switch (status) {
        400 => "Check the request fields, format and size before retrying.",
        401 => "Sign in again with your password and, if enabled, a current code.",
        403 => "Your account cannot perform this action. " ++
            "Complete required setup or ask an administrator.",
        404 => "This item is unavailable. Refresh the page; it may have been removed.",
        409 => "The saved state changed or this operation is not allowed. " ++
            "Refresh before retrying.",
        413 => "Reduce the request size to this route's limit, then retry.",
        429 => "The request limit was reached. Wait before retrying.",
        503 => "This service could not complete the request. " ++
            "Check its status and saved state before retrying a change.",
        else => "The request could not be completed. Ask the operator to inspect the console log.",
    };
}

test "refusal hints never imply storage loss and every hint fits the UI" {
    const t = std.testing;
    const codes = [_][]const u8{
        "CONSOLESCHEMA", "CONSOLEQUORUM", "CONSOLECRS", "CONSOLETOKENS",
        "CONSOLENODE",   "CONSOLE2FAKEY", "CONSOLE004", "unknown",
    };
    for (codes) |code| {
        for ([_]u16{ 0, 400, 401, 403, 404, 409, 413, 429, 503 }) |status| {
            const hint = responseHint(status, code);
            try t.expect(hint.len <= 256);
            if (status == 400 or status == 401 or status == 403) {
                try t.expect(std.mem.indexOf(u8, hint, "quorum") == null);
                try t.expect(std.mem.indexOf(u8, hint, "Outcome unknown") == null);
            }
        }
    }
    const outage = responseHint(503, "CONSOLEQUORUM");
    try t.expect(std.mem.indexOf(u8, outage, "unknown outcome") != null);
}
