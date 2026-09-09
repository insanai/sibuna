//! Version 17 records future edit context inside the same mutation transaction. Historical
//! absence remains NULL. Never copy policy matchers, names or credentials into audit summaries.
pub const sql =
    "ALTER TABLE console_policy_stage ADD COLUMN actor_role TEXT " ++
    "CHECK(actor_role IN ('operator','admin'));" ++
    "ALTER TABLE console_inspection_stage ADD COLUMN actor_role TEXT " ++
    "CHECK(actor_role IN ('operator','admin'));" ++
    "DROP TRIGGER console_policy_commit;" ++
    @import("schema_policy.zig").auditedCommit() ++
    "DROP TRIGGER console_inspection_commit;" ++
    @import("schema_inspection.zig").commit(true) ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=17));" ++
    "INSERT INTO console_schema VALUES(17);";

pub const policy_record =
    "INSERT INTO console_audit(actor,action,subject,recorded_at,target,actor_role," ++
    "before_summary,after_summary) VALUES(NEW.actor,'policy.edit',NEW.expected_revision+1," ++
    "NEW.recorded_at,NEW.policy_id,NEW.actor_role," ++
    "CASE WHEN NEW.previous_document IS NULL THEN NULL ELSE " ++
    summary("NEW.previous_document") ++ " END," ++ summary("NEW.document") ++ ");";

// The inspection document is a canonical object of exactly four validated mode names.
pub const inspection_record =
    "INSERT INTO console_audit(actor,action,subject,recorded_at,target,actor_role," ++
    "before_summary,after_summary) VALUES(NEW.actor,'inspection.edit',NEW.expected_revision+1," ++
    "NEW.recorded_at,'inspection',NEW.actor_role,NEW.previous_document,NEW.document);";

fn summary(comptime source: []const u8) []const u8 {
    return "json_object('action',json_extract(" ++ source ++ ",'$.action')," ++
        "'enabled',COALESCE(json_extract(" ++ source ++ ",'$.enabled'),1)," ++
        "'priority',COALESCE(json_extract(" ++ source ++ ",'$.priority'),100)," ++
        "'difficulty',json_extract(" ++ source ++ ",'$.difficulty')," ++
        "'algorithm',json_extract(" ++ source ++ ",'$.algorithm')," ++
        "'weight',COALESCE(json_extract(" ++ source ++ ",'$.weight'),0)," ++
        "'rate',json_extract(" ++ source ++ ",'$.limits.rate')," ++
        "'window_seconds',json_extract(" ++ source ++ ",'$.limits.window_seconds')," ++
        "'ban_seconds',json_extract(" ++ source ++ ",'$.limits.ban_seconds')," ++
        "'selectors_redacted',CASE WHEN " ++
        "json_extract(" ++ source ++ ",'$.path') IS NOT NULL OR " ++
        "json_extract(" ++ source ++ ",'$.user_agent') IS NOT NULL OR " ++
        "EXISTS(SELECT 1 FROM json_each(" ++ source ++ ",'$.headers')) OR " ++
        "EXISTS(SELECT 1 FROM json_each(" ++ source ++ ",'$.cidrs')) THEN 1 ELSE 0 END)";
}
