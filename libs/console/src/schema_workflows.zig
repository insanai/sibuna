//! Version 23 adds the policy workflows: reputation provenance columns, one-row stage
//! tables whose commit triggers write the mutation, its history rows and its audit record
//! together, and chunk tables for country prefixes and imported documents. Every commit
//! sets the policy version to the caller's expected revision plus one explicitly, because
//! the base row triggers would bump it once per touched row.
const version = "UPDATE sibuna_meta SET value=NEW.expected_revision+1 WHERE key='policy_version';";
pub const sql =
    "ALTER TABLE ip_reputation ADD COLUMN source TEXT NOT NULL DEFAULT '' " ++
    "CHECK(length(source)<=32);" ++
    "ALTER TABLE ip_reputation ADD COLUMN note TEXT NOT NULL DEFAULT '' " ++
    "CHECK(length(CAST(note AS BLOB))<=128);" ++
    "ALTER TABLE ip_reputation ADD COLUMN geo_generation TEXT CHECK(geo_generation IS NULL " ++
    "OR length(geo_generation)=64);" ++
    // Ordering: swap or nudge two adjacent rules in one revision.
    "CREATE TABLE console_policy_order_stage(id INTEGER PRIMARY KEY CHECK(id=1)," ++
    "actor INTEGER NOT NULL,actor_role TEXT NOT NULL,recorded_at INTEGER NOT NULL," ++
    "expected_revision INTEGER NOT NULL,policy_id TEXT NOT NULL,priority INTEGER NOT NULL," ++
    "document TEXT NOT NULL,other_id TEXT NOT NULL,other_priority INTEGER NOT NULL," ++
    "other_document TEXT NOT NULL);" ++
    "CREATE TRIGGER console_policy_order_commit AFTER INSERT ON console_policy_order_stage " ++
    "BEGIN UPDATE policies SET priority=NEW.priority,updated_at=NEW.recorded_at " ++
    "WHERE id=NEW.policy_id;" ++
    "UPDATE policies SET priority=NEW.other_priority,updated_at=NEW.recorded_at " ++
    "WHERE id=NEW.other_id;" ++
    "INSERT INTO console_policy_history VALUES(NEW.policy_id,NEW.expected_revision+1," ++
    "NEW.actor,NEW.recorded_at,NEW.document,'edit');" ++
    "INSERT INTO console_policy_history VALUES(NEW.other_id,NEW.expected_revision+1," ++
    "NEW.actor,NEW.recorded_at,NEW.other_document,'edit');" ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at,target,actor_role," ++
    "after_summary) VALUES(NEW.actor,'policy.order',NEW.expected_revision+1,NEW.recorded_at," ++
    "NEW.policy_id,NEW.actor_role,json_object('priority',NEW.priority));" ++
    version ++ "DELETE FROM console_policy_order_stage WHERE id=NEW.id; END;" ++
    // Reputation prefixes: one edit or removal per revision.
    "CREATE TABLE console_reputation_stage(id INTEGER PRIMARY KEY CHECK(id=1)," ++
    "actor INTEGER NOT NULL,actor_role TEXT NOT NULL,recorded_at INTEGER NOT NULL," ++
    "expected_revision INTEGER NOT NULL,prefix TEXT NOT NULL,score INTEGER NOT NULL," ++
    "banned_until INTEGER,note TEXT NOT NULL,source TEXT NOT NULL,remove INTEGER NOT NULL);" ++
    "CREATE TRIGGER console_reputation_commit AFTER INSERT ON console_reputation_stage BEGIN " ++
    "DELETE FROM ip_reputation WHERE ip_or_cidr=NEW.prefix AND NEW.remove=1;" ++
    "INSERT INTO ip_reputation(ip_or_cidr,reputation_score,banned_until,trigger_rule,hits," ++
    "last_seen,source,note) SELECT NEW.prefix,NEW.score,NEW.banned_until,'console',0," ++
    "NEW.recorded_at,NEW.source,NEW.note WHERE NEW.remove=0 " ++
    "ON CONFLICT(ip_or_cidr) DO UPDATE SET reputation_score=excluded.reputation_score," ++
    "banned_until=excluded.banned_until,trigger_rule='console',last_seen=excluded.last_seen," ++
    "source=excluded.source,note=excluded.note,geo_generation=NULL;" ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at,target,actor_role," ++
    "after_summary) VALUES(NEW.actor,CASE WHEN NEW.remove=1 THEN 'reputation.remove' " ++
    "ELSE 'reputation.edit' END,NEW.expected_revision+1,NEW.recorded_at,NEW.prefix," ++
    "NEW.actor_role,CASE WHEN NEW.remove=1 THEN NULL ELSE json_object('score',NEW.score," ++
    "'expires',NEW.banned_until) END);" ++
    version ++ "DELETE FROM console_reputation_stage WHERE id=NEW.id; END;" ++
    // Country blocks: prefixes arrive in chunks, then one commit row applies them all.
    "CREATE TABLE console_country_stage(digest TEXT NOT NULL CHECK(length(digest)=64)," ++
    "ordinal INTEGER NOT NULL,prefix TEXT NOT NULL CHECK(length(prefix) BETWEEN 1 AND 48)," ++
    "recorded_at INTEGER NOT NULL,PRIMARY KEY(digest,ordinal)) WITHOUT ROWID;" ++
    "CREATE TABLE console_country_commit(id INTEGER PRIMARY KEY CHECK(id=1)," ++
    "actor INTEGER NOT NULL,actor_role TEXT NOT NULL,recorded_at INTEGER NOT NULL," ++
    "expected_revision INTEGER NOT NULL,digest TEXT NOT NULL,count INTEGER NOT NULL," ++
    "country TEXT NOT NULL CHECK(length(country)=2),score INTEGER NOT NULL," ++
    "banned_until INTEGER,geo_generation TEXT NOT NULL);" ++
    "CREATE TRIGGER console_country_apply AFTER INSERT ON console_country_commit BEGIN " ++
    "INSERT INTO ip_reputation(ip_or_cidr,reputation_score,banned_until,trigger_rule,hits," ++
    "last_seen,source,note,geo_generation) SELECT prefix,NEW.score,NEW.banned_until," ++
    "'console',0,NEW.recorded_at,'console:country:'||NEW.country,'',NEW.geo_generation " ++
    "FROM console_country_stage WHERE digest=NEW.digest ORDER BY ordinal " ++
    "ON CONFLICT(ip_or_cidr) DO UPDATE SET reputation_score=excluded.reputation_score," ++
    "banned_until=excluded.banned_until,trigger_rule='console',last_seen=excluded.last_seen," ++
    "source=excluded.source,note='',geo_generation=excluded.geo_generation;" ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at,target,actor_role," ++
    "after_summary) VALUES(NEW.actor,'reputation.country',NEW.expected_revision+1," ++
    "NEW.recorded_at,NEW.country,NEW.actor_role,json_object('count',NEW.count,'score'," ++
    "NEW.score,'expires',NEW.banned_until,'sha256',NEW.geo_generation));" ++
    "DELETE FROM console_country_stage WHERE digest=NEW.digest;" ++
    version ++ "DELETE FROM console_country_commit WHERE id=NEW.id; END;" ++
    // Set import: canonical columns per staged document, then one atomic replacement.
    "CREATE TABLE console_policy_import_stage(digest TEXT NOT NULL CHECK(length(digest)=64)," ++
    "ordinal INTEGER NOT NULL,recorded_at INTEGER NOT NULL,document TEXT NOT NULL," ++
    "policy_id TEXT NOT NULL,name TEXT NOT NULL,priority INTEGER NOT NULL," ++
    "enabled INTEGER NOT NULL,path_pattern TEXT,ua_pattern TEXT,action TEXT NOT NULL," ++
    "difficulty INTEGER,algorithm TEXT,weight INTEGER NOT NULL,header_matchers TEXT," ++
    "cidr_matchers TEXT,limit_config TEXT,PRIMARY KEY(digest,ordinal)) WITHOUT ROWID;" ++
    "CREATE TABLE console_policy_import_commit(id INTEGER PRIMARY KEY CHECK(id=1)," ++
    "actor INTEGER NOT NULL,actor_role TEXT NOT NULL,recorded_at INTEGER NOT NULL," ++
    "expected_revision INTEGER NOT NULL,digest TEXT NOT NULL,count INTEGER NOT NULL);" ++
    "CREATE TRIGGER console_policy_import_apply AFTER INSERT ON console_policy_import_commit " ++
    "BEGIN DELETE FROM policies;" ++
    "INSERT INTO policies(id,name,priority,enabled,path_pattern,ua_pattern,action," ++
    "difficulty,algorithm,weight,header_matchers,cidr_matchers,created_at,updated_at," ++
    "limit_config) SELECT policy_id,name,priority,enabled,path_pattern,ua_pattern,action," ++
    "difficulty,algorithm,weight,header_matchers,cidr_matchers,NEW.recorded_at," ++
    "NEW.recorded_at,limit_config FROM console_policy_import_stage WHERE digest=NEW.digest " ++
    "ORDER BY ordinal;" ++
    "INSERT INTO console_policy_history SELECT policy_id,NEW.expected_revision+1,NEW.actor," ++
    "NEW.recorded_at,document,'edit' FROM console_policy_import_stage WHERE digest=NEW.digest;" ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at,target,actor_role," ++
    "after_summary) VALUES(NEW.actor,'policy.import',NEW.expected_revision+1,NEW.recorded_at," ++
    "NEW.digest,NEW.actor_role,json_object('count',NEW.count,'sha256',NEW.digest));" ++
    "DELETE FROM console_policy_import_stage WHERE digest=NEW.digest;" ++
    version ++ "DELETE FROM console_policy_import_commit WHERE id=NEW.id; END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=23));" ++
    "INSERT INTO console_schema VALUES(23);";
