//! The existing session table becomes the shared credential registry. A token reference
//! distinguishes bearer credentials from cookies while preserving atomic user revocation.
//! Token insertion does not count as a login, consume a factor or emit a session audit.
//! Version 15 fixes eight capabilities; adding capability bits requires a new migration.

pub const sql =
    "CREATE TABLE console_tokens(id INTEGER PRIMARY KEY AUTOINCREMENT," ++
    "digest TEXT NOT NULL UNIQUE CHECK(length(digest)=64)," ++
    "label TEXT NOT NULL CHECK(length(CAST(label AS BLOB)) BETWEEN 1 AND 64)," ++
    "role TEXT NOT NULL CHECK(role IN ('viewer','operator','admin'))," ++
    "scopes INTEGER NOT NULL CHECK(scopes BETWEEN 1 AND 255)," ++
    "auth_revision INTEGER NOT NULL CHECK(auth_revision>0)," ++
    "created_by INTEGER NOT NULL,created_at INTEGER NOT NULL CHECK(created_at>=0)," ++
    "expires_at INTEGER CHECK(expires_at IS NULL OR expires_at>created_at)," ++
    "disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN(0,1))," ++
    "revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0)," ++
    "modified_by INTEGER NOT NULL,modified_at INTEGER NOT NULL," ++
    "remove_requested INTEGER NOT NULL DEFAULT 0 CHECK(remove_requested IN(0,1)));" ++
    "CREATE INDEX console_tokens_creator ON console_tokens(created_by,id);" ++
    "ALTER TABLE console_sessions ADD COLUMN token_id INTEGER;" ++
    "CREATE UNIQUE INDEX console_sessions_token ON console_sessions(token_id) " ++
    "WHERE token_id IS NOT NULL;" ++
    cookieTriggers() ++ tokenTriggers() ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=15));" ++
    "INSERT INTO console_schema VALUES(15);";

fn cookieTriggers() []const u8 {
    return "DROP TRIGGER console_login_recorded;" ++
        "CREATE TRIGGER console_login_recorded AFTER INSERT ON console_sessions " ++
        "WHEN NEW.token_id IS NULL BEGIN " ++
        "INSERT INTO console_user_activity VALUES(NEW.user_id,NEW.created_at) " ++
        "ON CONFLICT(user_id) DO UPDATE SET " ++
        "last_login=MAX(last_login,excluded.last_login); END;" ++
        "DROP TRIGGER console_session_created;" ++
        "CREATE TRIGGER console_session_created AFTER INSERT ON console_sessions " ++
        "WHEN NEW.token_id IS NULL BEGIN " ++
        "INSERT INTO console_audit(actor,action,subject,recorded_at) " ++
        "VALUES(NEW.user_id,'session.create',NEW.user_id,NEW.created_at); END;" ++
        "DROP TRIGGER console_totp_consumed;" ++
        "CREATE TRIGGER console_totp_consumed AFTER INSERT ON console_sessions " ++
        "WHEN NEW.token_id IS NULL BEGIN " ++
        "UPDATE console_totp SET last_step=COALESCE(NEW.mfa_step,last_step)," ++
        "recovery_used=recovery_used | CASE WHEN NEW.recovery_slot IS NULL THEN 0 " ++
        "ELSE (1 << NEW.recovery_slot) END WHERE user_id=NEW.user_id AND enabled=1; END;";
}

fn tokenTriggers() []const u8 {
    return "CREATE TRIGGER console_token_created AFTER INSERT ON console_tokens BEGIN " ++
        "INSERT INTO console_sessions(digest,user_id,revision,csrf_digest,created_at," ++
        "expires,idle_expires,token_id) VALUES(NEW.digest,NEW.created_by,NEW.auth_revision," ++
        "printf('%064d',0),NEW.created_at,COALESCE(NEW.expires_at,9223372036854775807)," ++
        "COALESCE(NEW.expires_at,9223372036854775807),NEW.id);" ++
        "INSERT INTO console_audit(actor,action,subject,recorded_at,actor_role,after_summary) " ++
        "VALUES(NEW.created_by,'token.create',NEW.id,NEW.created_at,'admin'," ++ summary("NEW") ++
        "); END;" ++
        immutable() ++
        "CREATE TRIGGER console_token_changed AFTER UPDATE ON console_tokens BEGIN " ++
        "DELETE FROM console_sessions WHERE token_id=NEW.id;" ++
        "INSERT INTO console_audit(actor,action,subject,recorded_at,actor_role," ++
        "before_summary,after_summary) VALUES(NEW.modified_by," ++
        "CASE WHEN NEW.remove_requested=1 THEN 'token.remove' ELSE 'token.revoke' END," ++
        "NEW.id,NEW.modified_at,'admin'," ++ summary("OLD") ++ "," ++ summary("NEW") ++ ");" ++
        "DELETE FROM console_tokens WHERE id=NEW.id AND remove_requested=1; END;" ++
        "CREATE TRIGGER console_token_deleted AFTER DELETE ON console_tokens BEGIN " ++
        "DELETE FROM console_sessions WHERE token_id=OLD.id; END;";
}

fn immutable() []const u8 {
    return "CREATE TRIGGER console_token_immutable BEFORE UPDATE ON console_tokens " ++
        "WHEN NEW.id!=OLD.id OR NEW.digest!=OLD.digest OR NEW.label!=OLD.label " ++
        "OR NEW.role!=OLD.role OR NEW.scopes!=OLD.scopes " ++
        "OR NEW.created_by!=OLD.created_by OR NEW.created_at!=OLD.created_at " ++
        "OR NEW.auth_revision!=OLD.auth_revision OR NEW.expires_at IS NOT OLD.expires_at " ++
        "OR NEW.revision!=OLD.revision+1 OR NEW.disabled!=1 " ++
        "OR (OLD.disabled=1 AND NEW.remove_requested=0) " ++
        "BEGIN SELECT RAISE(ABORT,'immutable token authority'); END;";
}

fn summary(comptime alias: []const u8) []const u8 {
    return "json_object('label'," ++ alias ++ ".label,'role'," ++ alias ++ ".role," ++
        "'scopes'," ++ alias ++ ".scopes,'expires'," ++ alias ++ ".expires_at," ++
        "'disabled'," ++ alias ++ ".disabled,'revision'," ++ alias ++ ".revision)";
}
