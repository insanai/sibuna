//! Version 3 adds expiring local bootstrap credentials and audited explicit sign-out.
pub const sql =
    "ALTER TABLE console_users ADD COLUMN password_expires INTEGER NOT NULL DEFAULT 0;" ++
    "ALTER TABLE console_sessions ADD COLUMN ended_at INTEGER;" ++
    "CREATE TRIGGER console_session_ended AFTER UPDATE OF ended_at ON console_sessions " ++
    "WHEN NEW.ended_at IS NOT NULL BEGIN " ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at) " ++
    "VALUES(NEW.user_id,'session.logout',NEW.user_id,NEW.ended_at);" ++
    "DELETE FROM console_sessions WHERE digest=NEW.digest; END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=3));" ++
    "INSERT INTO console_schema VALUES(3);";
