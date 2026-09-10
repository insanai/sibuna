//! Node-scoped history must not scan other issuers to find its next archive.
pub const sql =
    "CREATE INDEX console_rank_node_time ON console_rank_archives(node,minute,digest);" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=30));" ++
    "INSERT INTO console_schema VALUES(30);";
