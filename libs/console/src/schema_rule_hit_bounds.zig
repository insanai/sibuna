//! A conservative boundary for older rollups avoids an unbounded migration UPDATE. Their
//! zero marker means the whole bucket, until newly created buckets carry an exact last minute.
const previous = @import("schema_rule_hits.zig");
pub const sql =
    "ALTER TABLE console_rule_hit_rollups " ++
    "ADD COLUMN through_minute INTEGER NOT NULL DEFAULT 0;" ++
    "DROP TRIGGER console_rule_hit_hour;DROP TRIGGER console_rule_hit_day;" ++
    previous.rollup("hour", "60", true) ++ previous.rollup("day", "1440", true) ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=32));" ++
    "INSERT INTO console_schema VALUES(32);";
