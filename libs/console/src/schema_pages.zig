//! Version 22 stores operator-edited response templates. A stage row commits the page,
//! its audit record (digests and sizes only, never the markup) and a policy version bump
//! together, so the next storage tick rebuilds the engine with the new template.
pub const sql =
    "CREATE TABLE console_pages(kind TEXT PRIMARY KEY CHECK(kind IN " ++
    "('challenge','denied','rate_limited','banned','overloaded'))," ++
    "html TEXT NOT NULL CHECK(length(CAST(html AS BLOB))<=16384)," ++
    "sha256 TEXT NOT NULL CHECK(length(sha256)=64),revision INTEGER NOT NULL DEFAULT 1," ++
    "updated_at INTEGER NOT NULL,updated_by INTEGER NOT NULL) WITHOUT ROWID;" ++
    "CREATE TABLE console_page_stage(id INTEGER PRIMARY KEY CHECK(id=1)," ++
    "actor INTEGER NOT NULL,actor_role TEXT NOT NULL,recorded_at INTEGER NOT NULL," ++
    "kind TEXT NOT NULL,expected_revision INTEGER NOT NULL,reset INTEGER NOT NULL," ++
    "html TEXT,sha256 TEXT,bytes INTEGER NOT NULL,previous_sha256 TEXT," ++
    "previous_bytes INTEGER);" ++
    "CREATE TRIGGER console_page_commit AFTER INSERT ON console_page_stage BEGIN " ++
    "INSERT INTO console_pages(kind,html,sha256,revision,updated_at,updated_by) " ++
    "SELECT NEW.kind,NEW.html,NEW.sha256,NEW.expected_revision+1,NEW.recorded_at,NEW.actor " ++
    "WHERE NEW.reset=0 ON CONFLICT(kind) DO UPDATE SET html=excluded.html," ++
    "sha256=excluded.sha256,revision=excluded.revision,updated_at=excluded.updated_at," ++
    "updated_by=excluded.updated_by;" ++
    "DELETE FROM console_pages WHERE kind=NEW.kind AND NEW.reset=1;" ++
    "INSERT INTO console_audit(actor,actor_role,action,subject,target,recorded_at," ++
    "before_summary,after_summary) VALUES(NEW.actor,NEW.actor_role," ++
    "CASE WHEN NEW.reset=1 THEN 'page.reset' ELSE 'page.edit' END,NEW.expected_revision+1," ++
    "NEW.kind,NEW.recorded_at,CASE WHEN NEW.previous_sha256 IS NULL THEN NULL ELSE " ++
    "json_object('sha256',NEW.previous_sha256,'bytes',NEW.previous_bytes) END," ++
    "CASE WHEN NEW.reset=1 THEN NULL ELSE json_object('sha256',NEW.sha256,'bytes',NEW.bytes) " ++
    "END);" ++
    "UPDATE sibuna_meta SET value=CAST(value AS INTEGER)+1 WHERE key='policy_version';" ++
    "DELETE FROM console_page_stage WHERE id=NEW.id; END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=22));" ++
    "INSERT INTO console_schema VALUES(22);";
