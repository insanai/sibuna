//! Version 25 makes syslog transport explicit. Preserve the old suffix convention once
//! on upgrade; labels never control transport afterward. Audit remains redacted.
pub const sql =
    "ALTER TABLE console_notifications ADD COLUMN transport TEXT NOT NULL DEFAULT 'udp' " ++
    "CHECK(transport IN ('udp','tcp'));" ++
    "UPDATE console_notifications SET transport='tcp' " ++
    "WHERE kind='syslog' AND substr(label,-3)='tcp';" ++
    "DROP TRIGGER console_notification_created;" ++
    "DROP TRIGGER console_notification_changed;" ++
    "CREATE TRIGGER console_notification_created AFTER INSERT ON console_notifications " ++
    "BEGIN INSERT INTO console_audit(actor,actor_role,action,subject,target,recorded_at," ++
    "after_summary) VALUES(NEW.created_by,'admin','notification.create',NEW.id,NEW.label," ++
    "NEW.created_at," ++ summary("NEW") ++ "); END;" ++
    "CREATE TRIGGER console_notification_changed AFTER UPDATE OF kind,transport,label,target," ++
    "events,cooldown_seconds,enabled,secret_envelope ON console_notifications BEGIN " ++
    "INSERT INTO console_audit(actor,actor_role,action,subject,target,recorded_at," ++
    "before_summary,after_summary) VALUES(NEW.modified_by,'admin','notification.change'," ++
    "NEW.id,NEW.label,NEW.modified_at," ++ summary("OLD") ++ "," ++ summary("NEW") ++ "); END;" ++
    "CREATE TRIGGER console_notification_tested AFTER INSERT ON console_audit " ++
    "WHEN NEW.action='notification.test_result' BEGIN UPDATE console_notifications " ++
    "SET last_attempt_at=NEW.recorded_at," ++
    "last_outcome=json_extract(NEW.after_summary,'$.outcome')," ++
    "last_detail=json_extract(NEW.after_summary,'$.detail') WHERE id=NEW.subject AND " ++
    "revision=json_extract(NEW.after_summary,'$.revision'); END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=25));" ++
    "INSERT INTO console_schema VALUES(25);";

fn summary(comptime row: []const u8) []const u8 {
    return "json_object('kind'," ++ row ++ ".kind,'transport'," ++ row ++
        ".transport,'events'," ++ row ++ ".events,'cooldown'," ++ row ++
        ".cooldown_seconds,'enabled'," ++ row ++ ".enabled,'host'," ++ row ++
        ".target_host,'secret',CASE WHEN " ++ row ++
        ".secret_envelope IS NULL THEN 'none' ELSE 'set' END)";
}
