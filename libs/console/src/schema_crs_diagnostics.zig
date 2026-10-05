//! Additive, bounded failure metadata. Sources and policy bytes stay private.
pub const sql =
    "ALTER TABLE console_crs_jobs ADD COLUMN diagnostic TEXT " ++
    "CHECK(diagnostic IS NULL OR length(diagnostic)<=2048);" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=43));" ++
    "INSERT INTO console_schema VALUES(43);";
