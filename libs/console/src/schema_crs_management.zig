//! A bounded candidate ledger. Triggers couple redacted audit to intent and
//! selection. Applied receipts never rewrite the committed selection.
pub const sql =
    "CREATE TABLE console_crs_jobs(" ++
    "id TEXT PRIMARY KEY CHECK(length(id)=32),actor INTEGER NOT NULL," ++
    "client_ip TEXT,kind TEXT NOT NULL CHECK(kind IN ('check','update','mode','rollback'))," ++
    "expected_revision INTEGER NOT NULL CHECK(expected_revision>=0)," ++
    "state TEXT NOT NULL " ++
    "CHECK(state IN ('preparing','verified','selected','failed','canceled','retired'))," ++
    "created_at INTEGER NOT NULL,expires INTEGER NOT NULL,verified_at " ++
    "INTEGER,completed_at INTEGER," ++
    "manifest TEXT CHECK(manifest IS NULL OR length(manifest)<=1024)," ++
    "clone TEXT,reason TEXT NOT NULL DEFAULT 'none' " ++
    "CHECK(reason IN ('none','canceled','download','signature','incompatible','capacity'," ++
    "'publication','storage'))) WITHOUT ROWID;" ++
    "CREATE TABLE console_crs_chunks(" ++
    "job TEXT NOT NULL,file TEXT NOT NULL CHECK(file IN " ++
    "('archive','signature','configuration'))," ++
    "ordinal INTEGER NOT NULL CHECK(ordinal>=0 AND ordinal<4096)," ++
    "bytes TEXT NOT NULL CHECK(length(bytes)>0 AND length(bytes)<=4096)," ++
    "PRIMARY KEY(job,file,ordinal)) WITHOUT ROWID;" ++
    "CREATE TABLE console_crs_selection(id INTEGER PRIMARY KEY CHECK(id=1)," ++
    "revision INTEGER NOT NULL CHECK(revision>=0),job TEXT,previous TEXT," ++
    "selected_at INTEGER NOT NULL,actor INTEGER NOT NULL,client_ip TEXT);" ++
    "INSERT INTO console_crs_selection VALUES(1,0,NULL,NULL,0,0,NULL);" ++
    "CREATE TABLE console_crs_applied(node INTEGER PRIMARY KEY CHECK(node>0)," ++
    "boot TEXT NOT NULL CHECK(length(boot)=32),revision INTEGER NOT NULL CHECK(revision>0)," ++
    "applied INTEGER NOT NULL CHECK(applied IN (0,1)),reason TEXT NOT NULL," ++
    "observed_at INTEGER NOT NULL);" ++
    "CREATE TRIGGER console_crs_job_created AFTER INSERT ON console_crs_jobs BEGIN " ++
    "INSERT INTO console_audit(actor,actor_role,action,subject,target,recorded_at," ++
    "after_summary,client_ip) VALUES(NEW.actor,'admin','crs.intent',NEW.expected_revision," ++
    "NEW.id,NEW.created_at,json_object('kind',NEW.kind,'state',NEW.state),NEW.client_ip);" ++
    "INSERT INTO console_crs_chunks(job,file,ordinal,bytes) " ++
    "SELECT NEW.id,file,ordinal,bytes FROM console_crs_chunks WHERE job=NEW.clone; END;" ++
    "CREATE TRIGGER console_crs_job_deleted AFTER DELETE ON console_crs_jobs BEGIN " ++
    "DELETE FROM console_crs_chunks WHERE job=OLD.id; END;" ++
    "CREATE TRIGGER console_crs_job_completed AFTER UPDATE OF state ON console_crs_jobs " ++
    "WHEN OLD.state!=NEW.state AND NEW.state IN ('verified','failed','canceled') BEGIN " ++
    "INSERT INTO console_audit(actor,actor_role,action,subject,target,recorded_at," ++
    "after_summary,client_ip) VALUES(NEW.actor,'admin','crs.'||NEW.state," ++
    "NEW.expected_revision,NEW.id,COALESCE(NEW.completed_at,NEW.verified_at,NEW.created_at)," ++
    "json_object('kind',NEW.kind,'state',NEW.state,'reason',NEW.reason),NEW.client_ip); END;" ++
    "CREATE TRIGGER console_crs_selected AFTER UPDATE OF revision ON console_crs_selection " ++
    "WHEN NEW.revision!=OLD.revision BEGIN " ++
    "UPDATE console_crs_jobs SET state='selected' WHERE id=NEW.job;" ++
    "INSERT INTO console_audit(actor,actor_role,action,subject,target,recorded_at," ++
    "before_summary,after_summary,client_ip) VALUES(NEW.actor,'admin','crs.select'," ++
    "NEW.revision,NEW.job,NEW.selected_at,json_object('revision',OLD.revision,'job',OLD.job)," ++
    "json_object('revision',NEW.revision,'job',NEW.job),NEW.client_ip); END;" ++
    "CREATE TRIGGER console_crs_receipt_inserted AFTER INSERT ON console_crs_applied BEGIN " ++
    receipt_audit ++ " END;" ++
    "CREATE TRIGGER console_crs_receipt_changed AFTER UPDATE ON console_crs_applied BEGIN " ++
    receipt_audit ++ " END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=42));" ++
    "INSERT INTO console_schema VALUES(42);";

// The effect has already happened. This transaction records its completion, using
// the selection's authenticated actor rather than claiming an anonymous edit.
const receipt_audit =
    "INSERT INTO console_audit(actor,actor_role,action,subject,target,recorded_at," ++
    "after_summary,client_ip) SELECT actor,'admin','crs.applied',NEW.revision,job," ++
    "NEW.observed_at,json_object('node',NEW.node,'boot',NEW.boot,'applied',NEW.applied," ++
    "'reason',NEW.reason),client_ip FROM console_crs_selection " ++
    "WHERE id=1 AND revision=NEW.revision;";
