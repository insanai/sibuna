//! The signature and word tables of the semantic WAF, exactly as in the Zig engine.

/// Strong path traversal and local file inclusion signatures.
pub(crate) const TRAVERSAL: [&str; 17] = [
    "../",
    "..\\",
    "..%2f",
    "..%5c",
    "%2e%2e",
    "%252e",
    "..;/",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self",
    "win.ini",
    "boot.ini",
    "/etc/hosts",
    "id_rsa",
    ".htaccess",
    "web.config",
    "/windows/system32",
];

/// Strong SQL injection signatures.
pub(crate) const SQLI: [&str; 28] = [
    "union select",
    "union all select",
    "union distinct select",
    "information_schema",
    "sleep(",
    "benchmark(",
    "load_file(",
    "into outfile",
    "into dumpfile",
    "xp_cmdshell",
    "pg_sleep(",
    "waitfor delay",
    "; drop table",
    "; delete from",
    "; truncate ",
    "@@version",
    "' or '1'='1",
    "\" or \"1\"=\"1",
    "' or 1=1",
    "\" or 1=1",
    "or 1=1--",
    "or 1=1#",
    "' and '1'='1",
    "extractvalue(",
    "updatexml(",
    "group_concat(",
    "sqlite_master",
    "sysobjects",
];

/// Strong cross-site scripting signatures.
pub(crate) const XSS: [&str; 18] = [
    "<script",
    "</script",
    "javascript:",
    "vbscript:",
    "data:text/html",
    "<iframe",
    "<object",
    "<embed",
    "<applet",
    "<meta http-equiv",
    "expression(",
    "document.cookie",
    "document.write",
    "eval(atob",
    "<base href",
    "srcdoc=",
    "<svg/onload",
    "<img src=x onerror",
];

/// Strong command injection and template injection signatures.
pub(crate) const RCE: [&str; 26] = [
    "/bin/sh",
    "/bin/bash",
    "/bin/zsh",
    "cmd.exe",
    "powershell",
    "/dev/tcp/",
    "shell_exec(",
    "passthru(",
    "proc_open(",
    "popen(",
    "system(",
    "pcntl_exec(",
    "wscript.shell",
    "${ifs}",
    "$ifs$",
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%=7*7%>",
    "${jndi:",
    "%24%7bjndi",
    "__import__(",
    "subprocess.",
    "os.system",
    "runtime.getruntime",
    "processbuilder",
];

/// Whole-word SQL keywords counted by the structural SQL detector (the detector matches them
/// in `structure::keyword_name`; a test keeps both lists equal).
#[cfg(test)]
pub(crate) const SQL_KEYWORDS: [&str; 21] = [
    "select", "union", "insert", "update", "delete", "drop", "from", "where", "having", "order",
    "group", "exec", "declare", "cast", "concat", "char", "convert", "table", "values", "limit",
    "offset",
];

/// Tags that can host script; with an event-handler attribute they make an XSS finding.
pub(crate) const XSS_TAGS: [&str; 24] = [
    "svg", "img", "body", "video", "audio", "math", "details", "marquee", "input", "form",
    "style", "link", "table", "div", "span", "a", "button", "select", "textarea", "iframe",
    "frame", "frameset", "object", "embed",
];

/// Command names that make a shell separator before them a command injection.
pub(crate) const SHELL_COMMANDS: [&str; 40] = [
    "cat", "ls", "id", "whoami", "wget", "curl", "nc", "ncat", "bash", "sh", "python", "python3",
    "perl", "php", "ruby", "rm", "chmod", "chown", "echo", "uname", "ping", "nslookup", "dig",
    "sleep", "telnet", "ftp", "tftp", "base64", "printf", "env", "set", "kill", "netstat",
    "ifconfig", "ipconfig", "net", "type", "dir", "del", "mkdir",
];

/// Headers whose grammar legitimately holds `*/*`, `;q=`, quotes and slashes. Their values
/// are machine-generated content negotiation, so scanning them yields only false positives.
pub(crate) const STRUCTURAL_HEADERS: [&str; 32] = [
    "accept",
    "accept-encoding",
    "accept-language",
    "accept-charset",
    "content-type",
    "content-length",
    "host",
    "connection",
    "cache-control",
    "pragma",
    "range",
    "if-none-match",
    "if-modified-since",
    "if-match",
    "if-range",
    "te",
    "transfer-encoding",
    "upgrade-insecure-requests",
    "dnt",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "sec-gpc",
    "priority",
    "x-forwarded-proto",
    "x-forwarded-port",
    "keep-alive",
    "origin",
];
