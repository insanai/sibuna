//! Version 39 retains opt-in, redacted request and response heads beside an incident. The
//! heads are stored hex-encoded so the interface can render them under a chosen charset;
//! rows are removed with their incident. Without the capture flag no row is written.
pub const sql =
    "CREATE TABLE console_incident_heads(" ++
    "incident_id INTEGER PRIMARY KEY REFERENCES security_incidents(id) ON DELETE CASCADE," ++
    "version INTEGER NOT NULL CHECK(version=1)," ++
    "request_head TEXT NOT NULL CHECK(length(request_head)<=4096)," ++
    "response_head TEXT NOT NULL CHECK(length(response_head)<=2048)," ++
    "request_truncated INTEGER NOT NULL CHECK(request_truncated IN (0,1))," ++
    "response_truncated INTEGER NOT NULL CHECK(response_truncated IN (0,1)));" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=39));" ++
    "INSERT INTO console_schema VALUES(39);";
