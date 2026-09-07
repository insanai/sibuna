//! Index existing incident metadata without rewriting forensic, FTS or vector content.
pub const sql =
    "CREATE INDEX IF NOT EXISTS console_incident_time ON security_incidents(recorded_at,id);" ++
    "CREATE INDEX IF NOT EXISTS console_incident_category " ++
    "ON security_incidents(violation_category,recorded_at,id);" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=5));" ++
    "INSERT INTO console_schema VALUES(5);";
