//! Versioned additive schema. The owner serializes migration before serving console work.
pub const version = 4;
pub const rotation_v4 = @import("schema_rotation.zig").sql;
pub const bootstrap_v3 = @import("schema_bootstrap.zig").sql;
pub const auth_v2 = @import("schema_auth.zig").sql;
pub const sql = @import("geo_schema.zig").sql ++
    "CREATE TABLE IF NOT EXISTS console_schema (version INTEGER PRIMARY KEY CHECK(version=1));" ++
    "INSERT OR IGNORE INTO console_schema VALUES(1);" ++
    "CREATE TABLE IF NOT EXISTS console_users (" ++
    "id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL," ++
    "role TEXT NOT NULL CHECK(role IN ('viewer','operator','admin')), " ++
    "revision INTEGER NOT NULL DEFAULT 1, disabled INTEGER NOT NULL DEFAULT 0," ++
    "must_change INTEGER NOT NULL DEFAULT 0, modified_at INTEGER NOT NULL," ++
    "modified_by INTEGER NOT NULL DEFAULT 0);" ++
    "CREATE TABLE IF NOT EXISTS console_sessions (" ++
    "digest TEXT PRIMARY KEY, user_id INTEGER NOT NULL, revision INTEGER NOT NULL," ++
    "csrf_digest TEXT NOT NULL, created_at INTEGER NOT NULL, expires INTEGER NOT NULL);" ++
    "CREATE INDEX IF NOT EXISTS console_sessions_expiry ON console_sessions(expires);" ++
    "CREATE INDEX IF NOT EXISTS console_sessions_user ON console_sessions(user_id);" ++
    "CREATE TABLE IF NOT EXISTS console_audit (" ++
    "id INTEGER PRIMARY KEY, actor INTEGER NOT NULL, action TEXT NOT NULL," ++
    "subject INTEGER NOT NULL, recorded_at INTEGER NOT NULL);" ++
    "CREATE INDEX IF NOT EXISTS console_audit_time ON console_audit(recorded_at,id);" ++
    "CREATE TRIGGER IF NOT EXISTS console_user_created AFTER INSERT ON console_users BEGIN " ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at) " ++
    "VALUES(NEW.modified_by,'user.create',NEW.id,NEW.modified_at); END;" ++
    "CREATE TRIGGER IF NOT EXISTS console_user_updated AFTER UPDATE ON console_users BEGIN " ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at) " ++
    "VALUES(NEW.modified_by,'user.update',NEW.id,NEW.modified_at);" ++
    "DELETE FROM console_sessions WHERE user_id=NEW.id; END;" ++
    "CREATE TRIGGER IF NOT EXISTS console_session_created " ++
    "AFTER INSERT ON console_sessions BEGIN " ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at) " ++
    "VALUES(NEW.user_id,'session.create',NEW.user_id,NEW.created_at); END;";
