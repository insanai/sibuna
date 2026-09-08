//! A single DELETE keeps forensic indexes and sidecars in the same transaction.
pub const sql =
    "CREATE TABLE console_job_leases(" ++
    "job TEXT PRIMARY KEY CHECK(job='retention'),node INTEGER NOT NULL CHECK(node>=0)," ++
    "boot TEXT NOT NULL CHECK(length(boot)=32),fence INTEGER NOT NULL CHECK(fence>0)," ++
    "expires INTEGER NOT NULL CHECK(expires>=0)) WITHOUT ROWID;" ++
    "CREATE INDEX console_sessions_deadline ON console_sessions" ++
    "(MIN(expires,idle_expires),digest);" ++
    "CREATE TRIGGER console_incident_deleted AFTER DELETE ON security_incidents BEGIN " ++
    "INSERT INTO incidents_fts(incidents_fts,rowid,path,offending_payload) " ++
    "VALUES('delete',OLD.id,OLD.path,OLD.offending_payload);" ++
    "DELETE FROM incidents_vec WHERE item_id=OLD.id;" ++
    "DELETE FROM console_incident_evidence WHERE incident_id=OLD.id; END;" ++
    // Old console-disabled binaries do not consult console_schema. Their existing base
    // format gate must also prevent row-derived incident identities after retention.
    "UPDATE sibuna_meta SET value='2' WHERE key='policy_format' AND CAST(value AS INTEGER)<2;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=13));" ++
    "INSERT INTO console_schema VALUES(13);";
