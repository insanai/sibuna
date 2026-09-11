//! Version 36 retains challenge observations per minute and partition. The payload is a
//! versioned fixed encoding (SBC1); indexed metadata never coerces unsigned counters.
pub const sql =
    "CREATE TABLE console_challenge_minutes (node INTEGER NOT NULL,boot TEXT NOT NULL," ++
    "epoch INTEGER NOT NULL,minute INTEGER NOT NULL,start_ms INTEGER NOT NULL," ++
    "end_ms INTEGER NOT NULL,sealed INTEGER NOT NULL,payload TEXT NOT NULL," ++
    "PRIMARY KEY(node,boot,epoch,minute),CHECK(node>=0 AND epoch>0 AND minute>=0)," ++
    "CHECK(length(boot)=32 AND length(payload) BETWEEN 256 AND 1792 " ++
    "AND (length(payload)-256)%192=0)," ++
    "CHECK(end_ms>start_ms AND sealed IN (0,1))) WITHOUT ROWID;" ++
    "CREATE INDEX console_challenge_minutes_time ON " ++
    "console_challenge_minutes(minute,node,boot,epoch);" ++
    "CREATE INDEX console_challenge_minutes_node_time ON " ++
    "console_challenge_minutes(node,minute,boot,epoch);" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=36));" ++
    "INSERT INTO console_schema VALUES(36);";
