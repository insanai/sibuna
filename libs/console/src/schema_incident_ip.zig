//! Address investigations need an address-first index; a newest-first time scan exhausts
//! the fixed statement budget once one client's incidents age behind newer traffic.
pub const sql =
    "CREATE INDEX console_incident_ip ON security_incidents(client_ip,recorded_at,id);" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=45));" ++
    "INSERT INTO console_schema VALUES(45);";
