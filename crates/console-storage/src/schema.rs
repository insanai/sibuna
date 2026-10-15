//! The console's schema: the component `console` of `sibuna_schema` (SID 0011), whose
//! version 1 is the baseline of SID 0013 with every console table and index.
//!
//! The daemon passes [`CONSOLE`] in `Hooks::migrations` when it runs the console; a node
//! built without the console neither applies nor refuses it. A later change to a console
//! table is a new [`Migration`] appended to [`CONSOLE`], never an edit of version 1 once a
//! release has shipped it.

mod postgres;
mod sqlite;

use sibuna_storage::{Migration, MigrationSet};

/// The console's migrations, applied after the core schema.
pub const CONSOLE: MigrationSet =
    MigrationSet { component: "console", migrations: &CONSOLE_MIGRATIONS };

const CONSOLE_MIGRATIONS: [Migration; 1] =
    [Migration { version: 1, sqlite: sqlite::V1, postgres: postgres::V1 }];

/// The tables version 1 creates, in the order of SID 0013, "Tables". Tests compare the
/// database's catalogue with this list.
pub const TABLES: [&str; 33] = [
    "console_users",
    "console_sessions",
    "console_totp",
    "console_kiosk_grants",
    "console_tokens",
    "console_audit",
    "console_audit_cursor",
    "console_settings",
    "console_job_leases",
    "console_policy_history",
    "console_inspection_history",
    "console_reputation_sources",
    "console_country_chunks",
    "console_pages",
    "console_notifications",
    "console_notification_events",
    "console_notification_deliveries",
    "console_nodes",
    "console_commands",
    "console_geo_generations",
    "console_geo_chunks",
    "console_geo_active",
    "console_minutes",
    "console_challenge_minutes",
    "console_challenge_records",
    "console_challenge_difficulty",
    "console_rank_usage",
    "console_rank_archives",
    "console_rule_hits",
    "console_rule_hit_rollups",
    "console_incident_evidence",
    "console_incident_heads",
    "console_incident_country",
];
