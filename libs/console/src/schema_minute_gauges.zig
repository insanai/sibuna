//! Version 37 admits the SBM2 minute payload (three resource gauges behind presence bits).
//! SQLite cannot alter a CHECK, so the table is rebuilt in place with the same keys and
//! indexes; existing SBM1 rows are copied unchanged and stay readable.
pub const sql =
    "CREATE TABLE console_minutes_v37 (node INTEGER NOT NULL,boot TEXT NOT NULL," ++
    "epoch INTEGER NOT NULL,minute INTEGER NOT NULL,start_ms INTEGER NOT NULL," ++
    "end_ms INTEGER NOT NULL,sealed INTEGER NOT NULL,payload TEXT NOT NULL," ++
    "PRIMARY KEY(node,boot,epoch,minute),CHECK(node>=0 AND epoch>0 AND minute>=0)," ++
    "CHECK(length(boot)=32 AND length(payload) IN (304,352))," ++
    "CHECK(end_ms>start_ms AND sealed IN (0,1))) WITHOUT ROWID;" ++
    "INSERT INTO console_minutes_v37 SELECT node,boot,epoch,minute,start_ms,end_ms,sealed," ++
    "payload FROM console_minutes;" ++
    "DROP TABLE console_minutes;" ++
    "ALTER TABLE console_minutes_v37 RENAME TO console_minutes;" ++
    "CREATE INDEX console_minutes_time ON console_minutes(minute,node,boot,epoch);" ++
    "CREATE INDEX console_minutes_node_time ON console_minutes(node,minute,boot,epoch);" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=37));" ++
    "INSERT INTO console_schema VALUES(37);";
