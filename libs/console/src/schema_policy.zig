//! Staging, policy revision and redacted audit commit in one SQLite/replicated statement.
pub const sql =
    "ALTER TABLE console_audit ADD COLUMN target TEXT;" ++
    "CREATE TABLE console_policy_history(policy_id TEXT NOT NULL,revision INTEGER NOT NULL," ++
    "actor INTEGER NOT NULL,recorded_at INTEGER NOT NULL,document TEXT NOT NULL," ++
    "kind TEXT NOT NULL CHECK(kind IN ('baseline','edit')),PRIMARY KEY(policy_id,revision));" ++
    "CREATE INDEX console_policy_history_time ON console_policy_history(recorded_at);" ++
    "CREATE INDEX console_policies_order ON policies(priority,name,id);" ++
    "CREATE TABLE console_policy_stage(id INTEGER PRIMARY KEY CHECK(id=1)," ++
    "actor INTEGER NOT NULL,recorded_at INTEGER NOT NULL,expected_revision INTEGER NOT NULL," ++
    "document TEXT NOT NULL,previous_document TEXT,policy_id TEXT NOT NULL,name TEXT NOT NULL," ++
    "priority INTEGER NOT NULL,enabled INTEGER NOT NULL,path_pattern TEXT,ua_pattern TEXT," ++
    "action TEXT NOT NULL,difficulty INTEGER,algorithm TEXT,weight INTEGER NOT NULL," ++
    "header_matchers TEXT,cidr_matchers TEXT);" ++ commit(false) ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=8));" ++
    "INSERT INTO console_schema VALUES(8);";

/// The false branch preserves migration 8 exactly; later schema versions extend the stage.
pub fn commit(comptime limits: bool) []const u8 {
    return "CREATE TRIGGER console_policy_commit AFTER INSERT ON console_policy_stage BEGIN " ++
        "INSERT INTO console_policy_history SELECT NEW.policy_id,NEW.expected_revision,0," ++
        "NEW.recorded_at,NEW.previous_document,'baseline' " ++
        "WHERE NEW.previous_document IS NOT NULL " ++
        "AND NOT EXISTS(SELECT 1 FROM console_policy_history WHERE policy_id=NEW.policy_id);" ++
        "INSERT INTO policies(id,name,priority,enabled,path_pattern,ua_pattern," ++
        "action,difficulty," ++
        "algorithm,weight,header_matchers,cidr_matchers,created_at,updated_at" ++
        (if (limits) ",limit_config" else "") ++ ") VALUES(" ++
        "NEW.policy_id,NEW.name,NEW.priority,NEW.enabled," ++
        "NEW.path_pattern,NEW.ua_pattern,NEW.action," ++
        "NEW.difficulty,NEW.algorithm,NEW.weight,NEW.header_matchers,NEW.cidr_matchers," ++
        "NEW.recorded_at,NEW.recorded_at" ++ (if (limits) ",NEW.limit_config" else "") ++
        ") ON CONFLICT(id) DO UPDATE SET name=excluded.name," ++
        "priority=excluded.priority,enabled=excluded.enabled," ++
        "path_pattern=excluded.path_pattern," ++
        "ua_pattern=excluded.ua_pattern,action=excluded.action,difficulty=excluded.difficulty," ++
        "algorithm=excluded.algorithm,weight=excluded.weight," ++
        "header_matchers=excluded.header_matchers," ++
        "cidr_matchers=excluded.cidr_matchers,updated_at=excluded.updated_at" ++
        (if (limits) ",limit_config=excluded.limit_config" else "") ++ ";" ++
        "INSERT INTO console_policy_history VALUES(" ++
        "NEW.policy_id,NEW.expected_revision+1,NEW.actor," ++
        "NEW.recorded_at,NEW.document,'edit');" ++
        "INSERT INTO console_audit(actor,action,subject,recorded_at,target) " ++
        "VALUES(NEW.actor,'policy.edit',NEW.expected_revision+1,NEW.recorded_at,NEW.policy_id);" ++
        "DELETE FROM console_policy_stage WHERE id=NEW.id; END;";
}
