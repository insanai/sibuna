//! NULL retains honest absence for historical scalar findings; detail reads stay separate.
pub const sql =
    "ALTER TABLE console_crs_evidence ADD COLUMN detail TEXT " ++
    "CHECK(detail IS NULL OR length(detail)<=4096);" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=44));" ++
    "INSERT INTO console_schema VALUES(44);";
