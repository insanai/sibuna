//! Typed source contracts. These tags recognize constructs, not executable support.
const std = @import("std");
const selection = @import("selectors.zig");

pub const Phase = enum(u3) {
    request_headers = 1,
    request_body = 2,
    response_headers = 3,
    response_body = 4,
    logging = 5,
};

pub const Operator = enum {
    begins_with,
    contains,
    detect_sqli,
    detect_xss,
    ends_with,
    eq,
    ge,
    gt,
    ip_match,
    lt,
    pm,
    pm_from_file,
    rx,
    streq,
    unconditional_match,
    validate_byte_range,
    validate_url_encoding,
    validate_utf8_encoding,
    within,
};

pub const operators = std.StaticStringMap(Operator).initComptime(.{
    .{ "beginsWith", .begins_with },
    .{ "contains", .contains },
    .{ "detectSQLi", .detect_sqli },
    .{ "detectXSS", .detect_xss },
    .{ "endsWith", .ends_with },
    .{ "eq", .eq },
    .{ "ge", .ge },
    .{ "gt", .gt },
    .{ "ipMatch", .ip_match },
    .{ "lt", .lt },
    .{ "pm", .pm },
    .{ "pmFromFile", .pm_from_file },
    .{ "rx", .rx },
    .{ "streq", .streq },
    .{ "unconditionalMatch", .unconditional_match },
    .{ "validateByteRange", .validate_byte_range },
    .{ "validateUrlEncoding", .validate_url_encoding },
    .{ "validateUtf8Encoding", .validate_utf8_encoding },
    .{ "within", .within },
});

pub const Transform = enum {
    base64_decode,
    cmd_line,
    compress_whitespace,
    css_decode,
    escape_seq_decode,
    hex_encode,
    html_entity_decode,
    js_decode,
    length,
    lowercase,
    none,
    normalize_path,
    normalize_path_win,
    remove_comments_char,
    remove_nulls,
    remove_whitespace,
    replace_comments,
    sha1,
    url_decode_uni,
    utf8_to_unicode,
};

pub const transforms = std.StaticStringMap(Transform).initComptime(.{
    .{ "base64Decode", .base64_decode },
    .{ "cmdLine", .cmd_line },
    .{ "compressWhitespace", .compress_whitespace },
    .{ "cssDecode", .css_decode },
    .{ "escapeSeqDecode", .escape_seq_decode },
    .{ "hexEncode", .hex_encode },
    .{ "htmlEntityDecode", .html_entity_decode },
    .{ "jsDecode", .js_decode },
    .{ "length", .length },
    .{ "lowercase", .lowercase },
    .{ "none", .none },
    .{ "normalizePath", .normalize_path },
    .{ "normalizePathWin", .normalize_path_win },
    .{ "removeCommentsChar", .remove_comments_char },
    .{ "removeNulls", .remove_nulls },
    .{ "removeWhitespace", .remove_whitespace },
    .{ "replaceComments", .replace_comments },
    .{ "sha1", .sha1 },
    .{ "urlDecodeUni", .url_decode_uni },
    .{ "utf8toUnicode", .utf8_to_unicode },
});

pub const ActionKind = enum {
    audit_log,
    block,
    capture,
    chain,
    control,
    deny,
    id,
    init_collection,
    log,
    log_data,
    message,
    multi_match,
    no_audit_log,
    no_log,
    pass,
    phase,
    set_var,
    severity,
    skip_after,
    status,
    transform,
    tag,
    version,
};

pub const actions = std.StaticStringMap(ActionKind).initComptime(.{
    .{ "auditlog", .audit_log },
    .{ "block", .block },
    .{ "capture", .capture },
    .{ "chain", .chain },
    .{ "ctl", .control },
    .{ "deny", .deny },
    .{ "id", .id },
    .{ "initcol", .init_collection },
    .{ "log", .log },
    .{ "logdata", .log_data },
    .{ "msg", .message },
    .{ "multiMatch", .multi_match },
    .{ "noauditlog", .no_audit_log },
    .{ "nolog", .no_log },
    .{ "pass", .pass },
    .{ "phase", .phase },
    .{ "setvar", .set_var },
    .{ "severity", .severity },
    .{ "skipAfter", .skip_after },
    .{ "status", .status },
    .{ "t", .transform },
    .{ "tag", .tag },
    .{ "ver", .version },
});

pub const Site = struct {
    path: []const u8,
    line: usize,
};

pub const Action = struct {
    kind: ActionKind,
    value: ?[]const u8,
    transform: ?Transform = null,
};

pub const Expression = struct {
    kind: Operator,
    argument: []const u8,
    negated: bool,
};

pub const Condition = struct {
    site: Site,
    /// A continuation inherits its root ID and phase; root is a stable row index.
    id: u32,
    root: usize,
    phase: Phase,
    selectors: []const u8,
    targets: []const selection.Selector,
    expression: ?Expression,
    actions: []const Action,
    inherited_actions: []const Action,
    chain_next: ?usize = null,
    skip_to: ?usize = null,
};

pub const Marker = struct {
    site: Site,
    name: []const u8,
    position: usize,
};

pub const TargetUpdate = struct {
    site: Site,
    id: u32,
    selectors: []const u8,
    targets: []const selection.Selector,
    root: ?usize = null,
};

pub const Limits = struct {
    source_bytes: usize = 32 * 1024 * 1024,
    compiled_bytes: usize = 64 * 1024 * 1024,
    path_bytes: usize = 4096,
    files: usize = 256,
    logical_line: usize = 64 * 1024,
    conditions: usize = 4096,
    chain: usize = 256,
    actions_per_condition: usize = 256,
    selectors_per_condition: usize = 128,
    markers: usize = 4096,
    target_updates: usize = 4096,
};

pub const Plan = struct {
    /// All slices, including locations and action values, borrow this arena.
    arena: std.heap.ArenaAllocator,
    conditions: []Condition,
    markers: []const Marker,
    updates: []TargetUpdate,
    defaults: [5]?[]const Action,
    signature: ?[]const u8,

    /// Structural validation is insufficient to enable a security engine.
    pub const executable = false;

    pub fn deinit(self: *Plan) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
