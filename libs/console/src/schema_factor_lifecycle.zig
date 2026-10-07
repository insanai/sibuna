//! Second factors can be turned off by their owner or reset by another administrator, and
//! recovery codes can be replaced. Turning a factor off ends the account's sessions through
//! the user revision, like enabling one. The actor is recorded beside the change.
pub const sql =
    "ALTER TABLE console_totp ADD COLUMN modified_by INTEGER;" ++
    "CREATE TRIGGER console_totp_disabled AFTER UPDATE ON console_totp " ++
    "WHEN OLD.enabled=1 AND NEW.enabled=0 BEGIN " ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at,client_ip) " ++
    "VALUES(COALESCE(NEW.modified_by,NEW.user_id),CASE WHEN COALESCE(NEW.modified_by," ++
    "NEW.user_id)=NEW.user_id THEN 'totp.disable' ELSE 'totp.reset' END,NEW.user_id," ++
    "NEW.modified_at,NEW.client_ip);" ++
    "UPDATE console_users SET revision=revision+1," ++
    "modified_by=COALESCE(NEW.modified_by,NEW.user_id),modified_at=NEW.modified_at," ++
    "client_ip=NEW.client_ip WHERE id=NEW.user_id; END;" ++
    "CREATE TRIGGER console_totp_recovery AFTER UPDATE ON console_totp " ++
    "WHEN OLD.enabled=1 AND NEW.enabled=1 " ++
    "AND OLD.recovery_digests!=NEW.recovery_digests BEGIN " ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at,client_ip) " ++
    "VALUES(NEW.user_id,'totp.recovery',NEW.user_id,NEW.modified_at,NEW.client_ip); END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=46));" ++
    "INSERT INTO console_schema VALUES(46);";
