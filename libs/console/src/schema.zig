//! Versioned additive schema. The owner serializes migration before serving console work.
pub const version = 30;
pub const transport_v25 = @import("schema_notification_transport.zig").sql;
pub const deliveries_v24 = @import("schema_deliveries.zig").sql;
pub const workflows_v23 = @import("schema_workflows.zig").sql;
pub const pages_v22 = @import("schema_pages.zig").sql;
pub const notifications_v21 = @import("schema_notifications.zig").sql;
pub const kiosk_v20 = @import("schema_kiosk.zig").sql;
pub const members_v19 = @import("schema_members.zig").sql;
pub const geo_provider_v18 = @import("schema_geo_provider.zig").sql;
pub const policy_audit_v17 = @import("schema_policy_audit.zig").sql;
pub const nodes_v16 = @import("schema_nodes.zig").sql;
pub const tokens_v15 = @import("schema_tokens.zig").sql;
pub const users_v14 = @import("schema_users.zig").sql;
pub const retention_v13 = @import("schema_retention.zig").sql;
pub const minutes_v12 = @import("schema_minutes.zig").sql;
pub const limits_v11 = @import("schema_limits.zig").sql;
pub const inspection_v10 = @import("schema_inspection.zig").sql;
pub const rankings_v9 = @import("schema_rankings.zig").sql;
pub const policy_v8 = @import("schema_policy.zig").sql;
pub const campaign_v7 = @import("schema_campaign.zig").sql;
pub const evidence_v6 = @import("schema_evidence.zig").sql;
pub const events_v5 = @import("schema_events.zig").sql;
pub const rotation_v4 = @import("schema_rotation.zig").sql;
pub const bootstrap_v3 = @import("schema_bootstrap.zig").sql;
pub const auth_v2 = @import("schema_auth.zig").sql;
pub const sql = @import("geo_schema.zig").sql ++
    "CREATE TABLE IF NOT EXISTS console_schema (version INTEGER PRIMARY KEY CHECK(version=1));" ++
    "INSERT OR IGNORE INTO console_schema VALUES(1);" ++
    "CREATE TABLE IF NOT EXISTS console_users (" ++
    "id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL," ++
    "role TEXT NOT NULL CHECK(role IN ('viewer','operator','admin')), " ++
    "revision INTEGER NOT NULL DEFAULT 1, disabled INTEGER NOT NULL DEFAULT 0," ++
    "must_change INTEGER NOT NULL DEFAULT 0, modified_at INTEGER NOT NULL," ++
    "modified_by INTEGER NOT NULL DEFAULT 0);" ++
    "CREATE TABLE IF NOT EXISTS console_sessions (" ++
    "digest TEXT PRIMARY KEY, user_id INTEGER NOT NULL, revision INTEGER NOT NULL," ++
    "csrf_digest TEXT NOT NULL, created_at INTEGER NOT NULL, expires INTEGER NOT NULL);" ++
    "CREATE INDEX IF NOT EXISTS console_sessions_expiry ON console_sessions(expires);" ++
    "CREATE INDEX IF NOT EXISTS console_sessions_user ON console_sessions(user_id);" ++
    "CREATE TABLE IF NOT EXISTS console_audit (" ++
    "id INTEGER PRIMARY KEY, actor INTEGER NOT NULL, action TEXT NOT NULL," ++
    "subject INTEGER NOT NULL, recorded_at INTEGER NOT NULL);" ++
    "CREATE INDEX IF NOT EXISTS console_audit_time ON console_audit(recorded_at,id);" ++
    "CREATE TRIGGER IF NOT EXISTS console_user_created AFTER INSERT ON console_users BEGIN " ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at) " ++
    "VALUES(NEW.modified_by,'user.create',NEW.id,NEW.modified_at); END;" ++
    "CREATE TRIGGER IF NOT EXISTS console_user_updated AFTER UPDATE ON console_users BEGIN " ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at) " ++
    "VALUES(NEW.modified_by,'user.update',NEW.id,NEW.modified_at);" ++
    "DELETE FROM console_sessions WHERE user_id=NEW.id; END;" ++
    "CREATE TRIGGER IF NOT EXISTS console_session_created " ++
    "AFTER INSERT ON console_sessions BEGIN " ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at) " ++
    "VALUES(NEW.user_id,'session.create',NEW.user_id,NEW.created_at); END;";

// One ordered catalog serves owner upgrades and historical migration fixtures.
pub const migrations = [_][]const u8{
    auth_v2,
    bootstrap_v3,
    rotation_v4,
    events_v5,
    evidence_v6,
    campaign_v7,
    policy_v8,
    rankings_v9,
    inspection_v10,
    limits_v11,
    minutes_v12,
    retention_v13,
    users_v14,
    tokens_v15,
    nodes_v16,
    policy_audit_v17,
    geo_provider_v18,
    members_v19,
    kiosk_v20,
    notifications_v21,
    pages_v22,
    workflows_v23,
    deliveries_v24,
    transport_v25,
    @import("schema_country_refresh.zig").sql,
    @import("schema_subscription_feed.zig").sql,
    @import("schema_settings_retention.zig").sql,
    @import("schema_event_country.zig").sql,
    @import("schema_ranking_history.zig").sql,
};

comptime {
    if (migrations.len + 1 != version) @compileError("Incomplete console migration catalog");
}
