//! Additive staging tables. A single pointer update publishes a complete generation;
//! its trigger writes a redacted audit event in the same database transaction.
pub const sql =
    "CREATE TABLE IF NOT EXISTS console_geo_generations (" ++
    "digest TEXT PRIMARY KEY,source_version TEXT NOT NULL,ranges INTEGER NOT NULL," ++
    "actor INTEGER NOT NULL,created_at INTEGER NOT NULL);" ++
    "CREATE TABLE IF NOT EXISTS console_geo_chunks (" ++
    "digest TEXT NOT NULL,ordinal INTEGER NOT NULL,payload TEXT NOT NULL," ++
    "PRIMARY KEY(digest,ordinal));" ++
    "CREATE TABLE IF NOT EXISTS console_geo_active (" ++
    "id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL DEFAULT 0," ++
    "digest TEXT NOT NULL DEFAULT '',loaded_at INTEGER NOT NULL DEFAULT 0," ++
    "actor INTEGER NOT NULL DEFAULT 0);" ++
    "INSERT OR IGNORE INTO console_geo_active(id) VALUES(1);" ++
    "CREATE TRIGGER IF NOT EXISTS console_geo_activated " ++
    "AFTER UPDATE ON console_geo_active BEGIN " ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at) " ++
    "VALUES(NEW.actor,'geoip.activate',NEW.revision,NEW.loaded_at); END;";
