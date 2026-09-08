//! Chunks are invisible until their fully validated archive index is published.
pub const sql =
    "CREATE TABLE console_rank_usage(id INTEGER PRIMARY KEY CHECK(id=1)," ++
    "bytes INTEGER NOT NULL);" ++
    "INSERT INTO console_rank_usage VALUES(1,0);" ++
    "CREATE TABLE console_rank_pending(digest TEXT PRIMARY KEY,total_bytes INTEGER NOT NULL," ++
    "charge INTEGER NOT NULL,created_at INTEGER NOT NULL);" ++
    "CREATE TABLE console_rank_chunks(digest TEXT NOT NULL,ordinal INTEGER NOT NULL," ++
    "payload TEXT NOT NULL,PRIMARY KEY(digest,ordinal));" ++
    "CREATE TABLE console_rank_archives(digest TEXT PRIMARY KEY,node INTEGER NOT NULL," ++
    "boot TEXT NOT NULL,minute INTEGER NOT NULL,total_bytes INTEGER NOT NULL," ++
    "charge INTEGER NOT NULL,created_at INTEGER NOT NULL,UNIQUE(node,boot,minute));" ++
    "CREATE INDEX console_rank_time ON console_rank_archives(minute,digest);" ++
    "CREATE INDEX console_rank_pending_time ON console_rank_pending(created_at,digest);" ++
    "CREATE TRIGGER console_rank_reserved AFTER INSERT ON console_rank_pending BEGIN " ++
    "UPDATE console_rank_usage SET bytes=bytes+NEW.charge WHERE id=1; END;" ++
    "CREATE TRIGGER console_rank_abandoned AFTER DELETE ON console_rank_pending " ++
    "WHEN NOT EXISTS(SELECT 1 FROM console_rank_archives WHERE digest=OLD.digest) BEGIN " ++
    "DELETE FROM console_rank_chunks WHERE digest=OLD.digest;" ++
    "UPDATE console_rank_usage SET bytes=bytes-OLD.charge WHERE id=1; END;" ++
    "CREATE TRIGGER console_rank_published AFTER INSERT ON console_rank_archives BEGIN " ++
    "DELETE FROM console_rank_pending WHERE digest=NEW.digest; END;" ++
    "CREATE TRIGGER console_rank_expired AFTER DELETE ON console_rank_archives BEGIN " ++
    "DELETE FROM console_rank_chunks WHERE digest=OLD.digest;" ++
    "UPDATE console_rank_usage SET bytes=bytes-OLD.charge WHERE id=1; END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=9));" ++
    "INSERT INTO console_schema VALUES(9);";
