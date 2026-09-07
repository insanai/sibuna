//! Sidecar metadata leaves historical forensic rows, FTS and vectors intact.
pub const sql =
    "CREATE TABLE console_incident_evidence(" ++
    "incident_id INTEGER PRIMARY KEY REFERENCES security_incidents(id) ON DELETE CASCADE," ++
    "version INTEGER NOT NULL CHECK(version=1)," ++
    "selected_status INTEGER NOT NULL CHECK(selected_status BETWEEN 100 AND 599)," ++
    "query_bytes INTEGER NOT NULL CHECK(query_bytes BETWEEN 0 AND 4294967295)," ++
    "body_bytes INTEGER NOT NULL CHECK(body_bytes BETWEEN 0 AND 4294967295)," ++
    "declared_body_bytes INTEGER NOT NULL CHECK(declared_body_bytes BETWEEN 0 AND 4294967295)," ++
    "truncated INTEGER NOT NULL CHECK(truncated BETWEEN 0 AND 255));" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=6));" ++
    "INSERT INTO console_schema VALUES(6);";
