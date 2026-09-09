//! Version 21 adds operator settings, bounded notification destinations, the replicated
//! event queue and a second singleton job lease for the cluster notifier. Secrets are stored
//! sealed under the console key; audit summaries carry only kind, label, events and host.
pub const sql =
    "CREATE TABLE console_settings(key TEXT PRIMARY KEY CHECK(length(key) BETWEEN 1 AND 64)," ++
    "value TEXT NOT NULL CHECK(length(CAST(value AS BLOB))<=1024)," ++
    "revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0)," ++
    "updated_at INTEGER NOT NULL,updated_by INTEGER NOT NULL) WITHOUT ROWID;" ++
    "CREATE TRIGGER console_setting_changed AFTER INSERT ON console_settings BEGIN " ++
    "INSERT INTO console_audit(actor,actor_role,action,subject,target,recorded_at," ++
    "after_summary) VALUES(NEW.updated_by,'admin','setting.change',NEW.revision,NEW.key," ++
    "NEW.updated_at,json_object('value',NEW.value)); END;" ++
    "CREATE TRIGGER console_setting_updated AFTER UPDATE ON console_settings BEGIN " ++
    "INSERT INTO console_audit(actor,actor_role,action,subject,target,recorded_at," ++
    "before_summary,after_summary) VALUES(NEW.updated_by,'admin','setting.change'," ++
    "NEW.revision,NEW.key,NEW.updated_at,json_object('value',OLD.value)," ++
    "json_object('value',NEW.value)); END;" ++
    "CREATE TABLE console_notifications(id INTEGER PRIMARY KEY AUTOINCREMENT," ++
    "kind TEXT NOT NULL CHECK(kind IN ('webhook','syslog'))," ++
    "label TEXT NOT NULL CHECK(length(CAST(label AS BLOB)) BETWEEN 1 AND 64)," ++
    "target TEXT NOT NULL CHECK(length(target) BETWEEN 1 AND 256)," ++
    "target_host TEXT NOT NULL CHECK(length(target_host)<=128)," ++
    "secret_envelope TEXT CHECK(secret_envelope IS NULL OR length(secret_envelope)<=256)," ++
    "events INTEGER NOT NULL CHECK(events BETWEEN 1 AND 15)," ++
    "cooldown_seconds INTEGER NOT NULL CHECK(cooldown_seconds BETWEEN 0 AND 86400)," ++
    "enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1))," ++
    "revision INTEGER NOT NULL DEFAULT 1,created_by INTEGER NOT NULL," ++
    "created_at INTEGER NOT NULL,modified_by INTEGER NOT NULL,modified_at INTEGER NOT NULL," ++
    "last_attempt_at INTEGER,last_outcome TEXT CHECK(last_outcome IN ('delivered','failed'))," ++
    "last_detail TEXT CHECK(last_detail IS NULL OR length(last_detail)<=96));" ++
    "CREATE TRIGGER console_notification_capacity BEFORE INSERT ON console_notifications " ++
    "WHEN (SELECT COUNT(*) FROM console_notifications)>=8 " ++
    "BEGIN SELECT RAISE(ABORT,'notification capacity'); END;" ++
    "CREATE TRIGGER console_notification_created AFTER INSERT ON console_notifications " ++
    "BEGIN INSERT INTO console_audit(actor,actor_role,action,subject,target,recorded_at," ++
    "after_summary) VALUES(NEW.created_by,'admin','notification.create',NEW.id,NEW.label," ++
    "NEW.created_at,json_object('kind',NEW.kind,'events',NEW.events,'cooldown'," ++
    "NEW.cooldown_seconds,'enabled',NEW.enabled,'host',NEW.target_host,'secret'," ++
    "CASE WHEN NEW.secret_envelope IS NULL THEN 'none' ELSE 'set' END)); END;" ++
    "CREATE TRIGGER console_notification_changed AFTER UPDATE OF kind,label,target,events," ++
    "cooldown_seconds,enabled,secret_envelope ON console_notifications BEGIN " ++
    "INSERT INTO console_audit(actor,actor_role,action,subject,target,recorded_at," ++
    "before_summary,after_summary) VALUES(NEW.modified_by,'admin','notification.change'," ++
    "NEW.id,NEW.label,NEW.modified_at,json_object('kind',OLD.kind,'events',OLD.events," ++
    "'cooldown',OLD.cooldown_seconds,'enabled',OLD.enabled,'host',OLD.target_host,'secret'," ++
    "CASE WHEN OLD.secret_envelope IS NULL THEN 'none' ELSE 'set' END)," ++
    "json_object('kind',NEW.kind,'events',NEW.events,'cooldown',NEW.cooldown_seconds," ++
    "'enabled',NEW.enabled,'host',NEW.target_host,'secret'," ++
    "CASE WHEN NEW.secret_envelope IS NULL THEN 'none' ELSE 'set' END)); END;" ++
    "CREATE TRIGGER console_notification_removed AFTER DELETE ON console_notifications " ++
    "BEGIN INSERT INTO console_audit(actor,actor_role,action,subject,target,recorded_at," ++
    "before_summary) VALUES(OLD.modified_by,'admin','notification.remove',OLD.id,OLD.label," ++
    "OLD.modified_at,json_object('kind',OLD.kind,'host',OLD.target_host)); END;" ++
    "CREATE TABLE console_notification_events(id INTEGER PRIMARY KEY AUTOINCREMENT," ++
    "node INTEGER NOT NULL,boot TEXT NOT NULL CHECK(length(boot)=32)," ++
    "sequence INTEGER NOT NULL,event TEXT NOT NULL CHECK(event IN " ++
    "('denial_spike','ban','node_unhealthy','leader_change'))," ++
    "raised_at INTEGER NOT NULL,detail TEXT NOT NULL CHECK(length(detail)<=128)," ++
    "delivered_at INTEGER,attempts INTEGER NOT NULL DEFAULT 0," ++
    "UNIQUE(node,boot,sequence));" ++
    "CREATE TRIGGER console_notification_events_bound BEFORE INSERT " ++
    "ON console_notification_events WHEN (SELECT COUNT(*) FROM console_notification_events " ++
    "WHERE delivered_at IS NULL)>=256 BEGIN SELECT RAISE(ABORT,'notification queue full'); " ++
    "END;" ++
    "CREATE TABLE console_job_leases_v21(job TEXT PRIMARY KEY " ++
    "CHECK(job IN ('retention','notifier')),node INTEGER NOT NULL CHECK(node>=0)," ++
    "boot TEXT NOT NULL CHECK(length(boot)=32),fence INTEGER NOT NULL CHECK(fence>0)," ++
    "expires INTEGER NOT NULL CHECK(expires>=0)) WITHOUT ROWID;" ++
    "INSERT INTO console_job_leases_v21 SELECT job,node,boot,fence,expires " ++
    "FROM console_job_leases;" ++
    "DROP TABLE console_job_leases;" ++
    "ALTER TABLE console_job_leases_v21 RENAME TO console_job_leases;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=21));" ++
    "INSERT INTO console_schema VALUES(21);";
