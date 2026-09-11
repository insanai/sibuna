//! Version 34 records where a credential was used: sessions keep the client address and a
//! User-Agent digest, and authentication audit rows (sign-in, sign-out, refusal) carry the
//! client address. Other mutations leave it NULL, which readers show as not recorded.
pub const sql =
    "ALTER TABLE console_sessions ADD COLUMN client_ip TEXT;" ++
    "ALTER TABLE console_sessions ADD COLUMN user_agent_hash TEXT;" ++
    "ALTER TABLE console_audit ADD COLUMN client_ip TEXT;" ++
    "DROP TRIGGER console_session_created;" ++
    "CREATE TRIGGER console_session_created AFTER INSERT ON console_sessions " ++
    "WHEN NEW.token_id IS NULL BEGIN " ++
    "INSERT INTO console_audit(actor,actor_role,action,subject,recorded_at,client_ip) " ++
    "SELECT NEW.user_id,u.role,'session.create',NEW.user_id,NEW.created_at,NEW.client_ip " ++
    "FROM console_users u WHERE u.id=NEW.user_id; END;" ++
    "DROP TRIGGER console_session_ended;" ++
    "CREATE TRIGGER console_session_ended AFTER UPDATE OF ended_at ON console_sessions " ++
    "WHEN NEW.ended_at IS NOT NULL BEGIN " ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at,client_ip) " ++
    "VALUES(NEW.user_id,'session.logout',NEW.user_id,NEW.ended_at,NEW.client_ip);" ++
    "DELETE FROM console_sessions WHERE digest=NEW.digest; END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=34));" ++
    "INSERT INTO console_schema VALUES(34);";
