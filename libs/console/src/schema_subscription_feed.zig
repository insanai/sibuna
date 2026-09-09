//! Audit cursors must remain monotonic even if retention removes every audit row. The
//! durable receipt and any adjusted row ID commit with the original audit insertion.
pub const sql =
    "INSERT INTO sibuna_meta(key,value) SELECT 'console_audit_cursor',COALESCE(MAX(id),0) " ++
    "FROM console_audit;" ++
    "CREATE TRIGGER console_audit_cursor AFTER INSERT ON console_audit BEGIN " ++
    "SELECT CASE WHEN (SELECT CAST(value AS INTEGER) FROM sibuna_meta " ++
    "WHERE key='console_audit_cursor')=9223372036854775807 " ++
    "THEN RAISE(ABORT,'audit cursor exhausted') END;" ++
    "UPDATE sibuna_meta SET value=MAX(CAST(value AS INTEGER)+1,NEW.id) " ++
    "WHERE key='console_audit_cursor';" ++
    "UPDATE console_audit SET id=(SELECT CAST(value AS INTEGER) FROM sibuna_meta " ++
    "WHERE key='console_audit_cursor') WHERE id=NEW.id; END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=27));" ++
    "INSERT INTO console_schema VALUES(27);";
