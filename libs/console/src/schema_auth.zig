//! Version 2 is one owner-executed transaction. Existing application and forensic tables
//! are untouched. Old console binaries reject the new schema marker before serving work.
pub const sql =
    "ALTER TABLE console_sessions ADD COLUMN idle_expires INTEGER NOT NULL DEFAULT 0;" ++
    "ALTER TABLE console_sessions ADD COLUMN mfa_step INTEGER;" ++
    "ALTER TABLE console_sessions ADD COLUMN recovery_slot INTEGER;" ++
    "UPDATE console_sessions SET expires=MIN(expires,created_at+43200)," ++
    "idle_expires=MIN(expires,created_at+1800);" ++
    "CREATE TABLE console_totp (user_id INTEGER PRIMARY KEY," ++
    "envelope TEXT NOT NULL CHECK(length(envelope)=120)," ++
    "key_id TEXT NOT NULL CHECK(length(key_id)=64)," ++
    "revision INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN(0,1))," ++
    "expires INTEGER NOT NULL, last_step INTEGER," ++
    "recovery_digests TEXT NOT NULL DEFAULT '' CHECK(length(recovery_digests) IN(0,640))," ++
    "recovery_used INTEGER NOT NULL DEFAULT 0 CHECK(recovery_used BETWEEN 0 AND 1023)," ++
    "modified_at INTEGER NOT NULL);" ++
    "CREATE TRIGGER console_totp_enabled AFTER UPDATE ON console_totp " ++
    "WHEN NEW.enabled=1 AND OLD.enabled=0 BEGIN " ++
    "UPDATE console_users SET revision=revision+1,modified_by=id," ++
    "modified_at=NEW.modified_at WHERE id=NEW.user_id;" ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at) " ++
    "VALUES(NEW.user_id,'totp.enable',NEW.user_id,NEW.modified_at); END;" ++
    "CREATE TRIGGER console_totp_consumed AFTER INSERT ON console_sessions BEGIN " ++
    "UPDATE console_totp SET last_step=COALESCE(NEW.mfa_step,last_step)," ++
    "recovery_used=recovery_used | CASE WHEN NEW.recovery_slot IS NULL THEN 0 " ++
    "ELSE (1 << NEW.recovery_slot) END WHERE user_id=NEW.user_id AND enabled=1; END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=2));" ++
    "INSERT INTO console_schema VALUES(2);";
