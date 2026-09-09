//! One conditional stage insert commits settings, revision history and a redacted audit.
pub const sql =
    "CREATE TABLE console_inspection_history(revision INTEGER PRIMARY KEY," ++
    "actor INTEGER NOT NULL,recorded_at INTEGER NOT NULL,document TEXT NOT NULL," ++
    "previous_document TEXT NOT NULL);" ++
    "CREATE TABLE console_inspection_stage(id INTEGER PRIMARY KEY CHECK(id=1)," ++
    "actor INTEGER NOT NULL,recorded_at INTEGER NOT NULL,expected_revision INTEGER NOT NULL," ++
    "document TEXT NOT NULL,previous_document TEXT NOT NULL," ++
    "path_traversal TEXT NOT NULL,sqli TEXT NOT NULL,xss TEXT NOT NULL,rce TEXT NOT NULL);" ++
    commit(false) ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=10));" ++
    "INSERT INTO console_schema VALUES(10);";

pub fn commit(comptime audit: bool) []const u8 {
    return "CREATE TRIGGER console_inspection_commit AFTER INSERT " ++
        "ON console_inspection_stage BEGIN " ++
        "INSERT INTO policy_inspection VALUES(1,NEW.path_traversal,NEW.sqli,NEW.xss,NEW.rce) " ++
        "ON CONFLICT(id) DO UPDATE SET path_traversal=excluded.path_traversal," ++
        "sqli=excluded.sqli," ++
        "xss=excluded.xss,rce=excluded.rce;" ++
        "INSERT INTO console_inspection_history VALUES(NEW.expected_revision+1,NEW.actor," ++
        "NEW.recorded_at,NEW.document,NEW.previous_document);" ++
        (if (audit) @import("schema_policy_audit.zig").inspection_record else legacy_record) ++
        "DELETE FROM console_inspection_stage WHERE id=NEW.id; END;";
}

const legacy_record =
    "INSERT INTO console_audit(actor,action,subject,recorded_at,target) " ++
    "VALUES(NEW.actor,'inspection.edit',NEW.expected_revision+1," ++
    "NEW.recorded_at,'inspection');";
