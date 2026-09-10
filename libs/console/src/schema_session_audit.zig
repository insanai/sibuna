//! Version 33 records the signed-in role on session audit rows so the Audit page shows
//! who acted; refused sign-ins are inserted by the storage owner, not by a trigger.
pub const sql =
    "DROP TRIGGER console_session_created;" ++
    "CREATE TRIGGER console_session_created AFTER INSERT ON console_sessions " ++
    "WHEN NEW.token_id IS NULL BEGIN " ++
    "INSERT INTO console_audit(actor,actor_role,action,subject,recorded_at) " ++
    "SELECT NEW.user_id,u.role,'session.create',NEW.user_id,NEW.created_at " ++
    "FROM console_users u WHERE u.id=NEW.user_id; END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=33));" ++
    "INSERT INTO console_schema VALUES(33);";
