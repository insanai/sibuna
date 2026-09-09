//! Version 24 records attempts per destination. Triggers commit scheduling state, parent
//! completion and redacted destination outcomes together with each guarded mutation.
const fanout =
    "INSERT INTO console_notification_deliveries(event_id,destination_id,revision) " ++
    "SELECT e.id,n.id,n.revision FROM console_notification_events e " ++
    "JOIN console_notifications n ON n.enabled=1 AND (n.events & CASE e.event " ++
    "WHEN 'denial_spike' THEN 1 WHEN 'ban' THEN 2 WHEN 'node_unhealthy' THEN 4 ELSE 8 END)!=0 " ++
    "WHERE e.delivered_at IS NULL";
pub const sql =
    "CREATE TABLE console_notification_deliveries(id INTEGER PRIMARY KEY AUTOINCREMENT," ++
    "event_id INTEGER NOT NULL,destination_id INTEGER NOT NULL,revision INTEGER NOT NULL," ++
    "state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN " ++
    "('pending','sending','delivered','failed','skipped'))," ++
    "attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 3)," ++
    "next_attempt_at INTEGER NOT NULL DEFAULT 0,claim_fence INTEGER,claim_expires INTEGER," ++
    "updated_at INTEGER NOT NULL DEFAULT 0,detail TEXT NOT NULL DEFAULT '' " ++
    "CHECK(length(detail)<=96),UNIQUE(event_id,destination_id));" ++
    "CREATE INDEX console_delivery_due ON console_notification_deliveries(state," ++
    "next_attempt_at,id);" ++
    "CREATE INDEX console_delivery_destination ON console_notification_deliveries" ++
    "(destination_id,revision,state);" ++
    fanout ++ ";" ++
    "UPDATE console_notification_events SET delivered_at=raised_at WHERE delivered_at " ++
    "IS NULL AND NOT EXISTS(SELECT 1 FROM console_notification_deliveries d " ++
    "WHERE d.event_id=console_notification_events.id);" ++
    // Establish the new bound for pre-v24 stores, whose completed queue was unbounded.
    "DELETE FROM console_notification_events WHERE delivered_at IS NOT NULL AND id NOT IN(" ++
    "SELECT id FROM console_notification_events WHERE delivered_at IS NOT NULL " ++
    "ORDER BY delivered_at DESC,id DESC LIMIT 3840);" ++
    "CREATE TRIGGER console_delivery_enqueued AFTER INSERT ON console_notification_events " ++
    "BEGIN " ++ fanout ++ " AND e.id=NEW.id;" ++
    "UPDATE console_notification_events SET delivered_at=raised_at WHERE id=NEW.id " ++
    "AND NOT EXISTS(SELECT 1 FROM console_notification_deliveries WHERE event_id=NEW.id); END;" ++
    "CREATE TRIGGER console_delivery_changed AFTER UPDATE ON console_notification_deliveries " ++
    "BEGIN UPDATE console_notifications SET last_attempt_at=NEW.updated_at " ++
    "WHERE id=NEW.destination_id AND revision=NEW.revision AND NEW.state='sending';" ++
    "UPDATE console_notifications SET last_outcome=CASE WHEN NEW.state='delivered' " ++
    "THEN 'delivered' ELSE 'failed' END,last_detail=NEW.detail WHERE id=NEW.destination_id " ++
    "AND revision=NEW.revision AND NEW.state IN ('pending','delivered','failed');" ++
    "INSERT INTO console_audit(actor,actor_role,action,subject,target,recorded_at," ++
    "after_summary) SELECT 0,'admin','notification.delivery',NEW.destination_id," ++
    "COALESCE((SELECT label FROM console_notifications WHERE id=NEW.destination_id)," ++
    "'removed destination'),NEW.updated_at,json_object('event',NEW.event_id," ++
    "'attempt',NEW.attempts,'outcome',NEW.state,'detail',NEW.detail) " ++
    "WHERE OLD.state='sending' AND NEW.state!='sending';" ++
    "UPDATE console_notification_events SET delivered_at=NEW.updated_at WHERE id=NEW.event_id " ++
    "AND delivered_at IS NULL AND NOT EXISTS(SELECT 1 FROM console_notification_deliveries " ++
    "WHERE event_id=NEW.event_id AND state IN ('pending','sending')); END;" ++
    "CREATE TRIGGER console_delivery_retargeted AFTER UPDATE OF revision " ++
    "ON console_notifications BEGIN UPDATE console_notification_deliveries SET " ++
    "state='skipped',updated_at=NEW.modified_at,detail='destination changed' " ++
    "WHERE destination_id=NEW.id AND revision!=NEW.revision AND " ++
    "state IN ('pending','sending'); END;" ++
    "CREATE TRIGGER console_delivery_removed AFTER DELETE ON console_notifications " ++
    "BEGIN UPDATE console_notification_deliveries SET state='skipped'," ++
    "updated_at=OLD.modified_at,detail='destination removed' WHERE destination_id=OLD.id " ++
    "AND state IN ('pending','sending'); END;" ++
    "CREATE TRIGGER console_delivery_pruned AFTER DELETE ON console_notification_events " ++
    "BEGIN DELETE FROM console_notification_deliveries WHERE event_id=OLD.id; END;" ++
    "CREATE INDEX console_notification_completed ON " ++
    "console_notification_events(delivered_at,id);" ++
    "DROP TRIGGER console_notification_events_bound;" ++
    "CREATE TRIGGER console_notification_events_bound BEFORE INSERT " ++
    "ON console_notification_events BEGIN " ++
    "DELETE FROM console_notification_events WHERE id IN(SELECT id " ++
    "FROM console_notification_events WHERE delivered_at IS NOT NULL AND " ++
    "(delivered_at<NEW.raised_at-604800 OR " ++
    "(SELECT COUNT(*) FROM console_notification_events)>=4096) " ++
    "ORDER BY delivered_at,id LIMIT 16);" ++
    "SELECT CASE WHEN (SELECT COUNT(*) FROM console_notification_events WHERE delivered_at " ++
    "IS NULL)>=256 OR (SELECT COUNT(*) FROM console_notification_events)>=4096 " ++
    "THEN RAISE(ABORT,'notification queue full') END; END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=24));" ++
    "INSERT INTO console_schema VALUES(24);";
