//! Account activity is separate from authorization rows: a login must not revoke sessions.
//! Existing historical login timestamps and audit summaries remain NULL (not recorded).
pub const sql =
    "CREATE TABLE console_user_activity(user_id INTEGER PRIMARY KEY,last_login INTEGER " ++
    "NOT NULL CHECK(last_login>=0));" ++
    "CREATE TRIGGER console_login_recorded AFTER INSERT ON console_sessions BEGIN " ++
    "INSERT INTO console_user_activity VALUES(NEW.user_id,NEW.created_at) " ++
    "ON CONFLICT(user_id) DO UPDATE SET last_login=MAX(last_login,excluded.last_login); END;" ++
    "ALTER TABLE console_audit ADD COLUMN actor_role TEXT;" ++
    "ALTER TABLE console_audit ADD COLUMN before_summary TEXT;" ++
    "ALTER TABLE console_audit ADD COLUMN after_summary TEXT;" ++
    "DROP TRIGGER console_user_created;" ++
    "DROP TRIGGER console_user_updated;" ++
    "CREATE TRIGGER console_user_created AFTER INSERT ON console_users BEGIN " ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at,actor_role,after_summary) " ++
    "VALUES(NEW.modified_by,'user.create',NEW.id,NEW.modified_at," ++
    "(SELECT role FROM console_users WHERE id=NEW.modified_by)," ++
    "json_object('username',NEW.username,'role',NEW.role,'disabled',NEW.disabled," ++
    "'must_change',NEW.must_change,'revision',NEW.revision)); END;" ++
    "CREATE TRIGGER console_user_updated AFTER UPDATE ON console_users BEGIN " ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at,actor_role," ++
    "before_summary,after_summary) VALUES(NEW.modified_by," ++
    "CASE WHEN OLD.disabled!=NEW.disabled THEN CASE WHEN NEW.disabled=1 " ++
    "THEN 'user.disable' ELSE 'user.enable' END WHEN OLD.role!=NEW.role THEN 'user.role' " ++
    "WHEN OLD.password_hash!=NEW.password_hash THEN CASE WHEN NEW.must_change=1 " ++
    "THEN 'user.password_reset' ELSE 'user.password_change' END ELSE 'user.revoke' END," ++
    "NEW.id,NEW.modified_at,(SELECT role FROM console_users WHERE id=NEW.modified_by)," ++
    "json_object('username',OLD.username,'role',OLD.role,'disabled',OLD.disabled," ++
    "'must_change',OLD.must_change,'revision',OLD.revision)," ++
    "json_object('username',NEW.username,'role',NEW.role,'disabled',NEW.disabled," ++
    "'must_change',NEW.must_change,'revision',NEW.revision));" ++
    "DELETE FROM console_sessions WHERE user_id=NEW.id; END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=14));" ++
    "INSERT INTO console_schema VALUES(14);";
