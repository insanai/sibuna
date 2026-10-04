//! First-party asset facade. The embedded dictionary retains libinjection's BSD license.
pub const bytes = @embedFile("sqli-table.bin");
pub const xss = @import("xss_tables.zig");
