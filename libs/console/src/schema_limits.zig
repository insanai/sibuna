pub const sql =
    "ALTER TABLE console_policy_stage ADD COLUMN limit_config TEXT;" ++
    "DROP TRIGGER console_policy_commit;" ++ @import("schema_policy.zig").commit(true) ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=11));" ++
    "INSERT INTO console_schema VALUES(11);";
