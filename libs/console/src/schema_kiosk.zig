//! Version 20 adds read-only kiosk sessions: a session kind and one-time exchange grants.
//! A grant stores only the SHA-256 of its code, is bound to the granting user's revision,
//! must be exchanged within ten minutes and yields a session that expires with the grant.
pub const sql =
    "ALTER TABLE console_sessions ADD COLUMN kind TEXT NOT NULL DEFAULT 'browser' " ++
    "CHECK(kind IN ('browser','kiosk'));" ++
    "CREATE TABLE console_kiosk_grants(digest TEXT PRIMARY KEY CHECK(length(digest)=64)," ++
    "user_id INTEGER NOT NULL,revision INTEGER NOT NULL," ++
    "label TEXT NOT NULL DEFAULT '' CHECK(length(label)<=64)," ++
    "created_at INTEGER NOT NULL,use_by INTEGER NOT NULL,expires INTEGER NOT NULL," ++
    "consumed_at INTEGER) WITHOUT ROWID;" ++
    "CREATE TRIGGER console_kiosk_capacity BEFORE INSERT ON console_kiosk_grants " ++
    "WHEN (SELECT COUNT(*) FROM console_kiosk_grants WHERE consumed_at IS NULL " ++
    "AND use_by>NEW.created_at)>=64 BEGIN SELECT RAISE(ABORT,'kiosk grant capacity'); END;" ++
    "CREATE TRIGGER console_kiosk_granted AFTER INSERT ON console_kiosk_grants BEGIN " ++
    "INSERT INTO console_audit(actor,action,subject,target,recorded_at) " ++
    "VALUES(NEW.user_id,'kiosk.grant',NEW.user_id,NEW.label,NEW.created_at); END;" ++
    "CREATE TRIGGER console_kiosk_exchanged AFTER UPDATE OF consumed_at " ++
    "ON console_kiosk_grants WHEN NEW.consumed_at IS NOT NULL BEGIN " ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at) " ++
    "VALUES(NEW.user_id,'kiosk.exchange',NEW.user_id,NEW.consumed_at); END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=20));" ++
    "INSERT INTO console_schema VALUES(20);";
