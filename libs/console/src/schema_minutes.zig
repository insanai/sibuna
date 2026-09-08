//! Counter bytes use a versioned encoding; indexed metadata never coerces unsigned counters.
pub const sql =
    "CREATE TABLE console_minutes (node INTEGER NOT NULL,boot TEXT NOT NULL," ++
    "epoch INTEGER NOT NULL,minute INTEGER NOT NULL,start_ms INTEGER NOT NULL," ++
    "end_ms INTEGER NOT NULL,sealed INTEGER NOT NULL,payload TEXT NOT NULL," ++
    "PRIMARY KEY(node,boot,epoch,minute),CHECK(node>=0 AND epoch>0 AND minute>=0)," ++
    "CHECK(length(boot)=32 AND length(payload)=304)," ++
    "CHECK(end_ms>start_ms AND sealed IN (0,1))) WITHOUT ROWID;" ++
    "CREATE INDEX console_minutes_time ON console_minutes(minute,node,boot,epoch);" ++
    "CREATE INDEX console_minutes_node_time ON console_minutes(node,minute,boot,epoch);" ++
    "ALTER TABLE console_schema RENAME TO console_schema_v11;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=12));" ++
    "INSERT INTO console_schema VALUES(12);DROP TABLE console_schema_v11;";
