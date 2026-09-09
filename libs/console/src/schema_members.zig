//! Version 19 adds the replicated membership table. Each node writes only its own row:
//! at start, every minute, and after every successfully applied policy rebuild. Rows are
//! facts about their writer; consoles never probe addresses read from this table.
pub const sql =
    "CREATE TABLE console_nodes(" ++
    "node INTEGER PRIMARY KEY CHECK(node>0)," ++
    "address TEXT NOT NULL CHECK(length(address)<=64)," ++
    "console_url TEXT NOT NULL DEFAULT '' CHECK(length(console_url)<=128)," ++
    "version TEXT NOT NULL CHECK(length(version)<=32)," ++
    "boot TEXT NOT NULL CHECK(length(boot)=32)," ++
    "first_seen INTEGER NOT NULL,last_seen INTEGER NOT NULL CHECK(last_seen>=first_seen)," ++
    "applied_revision INTEGER NOT NULL DEFAULT 0," ++
    "control_revision INTEGER NOT NULL DEFAULT 0," ++
    "applied_slot INTEGER NOT NULL DEFAULT 0,decided_slot INTEGER NOT NULL DEFAULT 0," ++
    "draining INTEGER NOT NULL DEFAULT 0 CHECK(draining IN (0,1))) WITHOUT ROWID;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=19));" ++
    "INSERT INTO console_schema VALUES(19);";
