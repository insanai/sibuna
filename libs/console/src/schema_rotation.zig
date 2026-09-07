//! One statement stages a password replacement; its trigger revokes and rotates atomically.
//! Only digests enter the journal. The staging row is deleted before the transaction commits.
pub const sql =
    "CREATE TABLE console_password_rotation(id INTEGER PRIMARY KEY CHECK(id=1)," ++
    "user_id INTEGER NOT NULL,password_hash TEXT NOT NULL,digest TEXT NOT NULL," ++
    "csrf_digest TEXT NOT NULL,recorded_at INTEGER NOT NULL);" ++
    "CREATE TRIGGER console_password_rotated AFTER INSERT ON console_password_rotation BEGIN " ++
    "UPDATE console_users SET password_hash=NEW.password_hash,revision=revision+1," ++
    "must_change=0,password_expires=0,modified_at=NEW.recorded_at,modified_by=id " ++
    "WHERE id=NEW.user_id;" ++
    "INSERT INTO console_sessions(digest,user_id,revision,csrf_digest,created_at,expires," ++
    "idle_expires) SELECT NEW.digest,id,revision,NEW.csrf_digest,NEW.recorded_at," ++
    "NEW.recorded_at+43200,NEW.recorded_at+1800 FROM console_users WHERE id=NEW.user_id;" ++
    "DELETE FROM console_password_rotation WHERE id=NEW.id; END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=4));" ++
    "INSERT INTO console_schema VALUES(4);";
