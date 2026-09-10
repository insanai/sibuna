//! Version 28 fences binaries that do not apply configurable retention. The existing
//! settings/audit transaction is retained; these guards also protect replicated writes.
const std = @import("std");
const catalog = @import("console_protocol").settings.catalog;
pub const sql = guards();

fn guards() []const u8 {
    var cases: []const u8 = "";
    for (catalog) |entry| {
        if (entry.group != .retention) continue;
        cases = cases ++ std.fmt.comptimePrint(" WHEN '{s}' THEN {d}", .{
            entry.key, entry.maximum,
        });
    }
    const condition = " WHEN NEW.key LIKE 'retention.%' AND (length(NEW.value) " ++
        "NOT BETWEEN 1 AND 7 OR NEW.value GLOB '*[^0-9]*' OR CAST(NEW.value AS INTEGER) " ++
        "NOT BETWEEN 1 AND CASE NEW.key" ++ cases ++ " ELSE 0 END) " ++
        "BEGIN SELECT RAISE(ABORT,'invalid retention setting'); END;";
    return "CREATE TRIGGER console_retention_insert BEFORE INSERT ON console_settings" ++
        condition ++ "CREATE TRIGGER console_retention_update BEFORE UPDATE ON console_settings" ++
        condition ++ "DROP TABLE console_schema;" ++
        "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=28));" ++
        "INSERT INTO console_schema VALUES(28);";
}
