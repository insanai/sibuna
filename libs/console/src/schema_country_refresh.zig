//! Version 26 replaces a reviewed country's owned set and audits removals atomically.
//! Existing v23 provenance is sufficient; no reputation row is rewritten during migration.
pub const sql =
    "CREATE INDEX console_country_owner ON ip_reputation(source,ip_or_cidr);" ++
    // Replacement membership probes must fit the query budget at the 1,024-prefix bound.
    "CREATE INDEX console_country_membership ON console_country_stage(digest,prefix);" ++
    "DROP TRIGGER console_country_apply;" ++
    "CREATE TRIGGER console_country_apply AFTER INSERT ON console_country_commit BEGIN " ++
    "INSERT INTO console_audit(actor,action,subject,recorded_at,target,actor_role," ++
    "before_summary,after_summary) VALUES(NEW.actor,'reputation.country'," ++
    "NEW.expected_revision+1,NEW.recorded_at,NEW.country,NEW.actor_role," ++
    "(SELECT json_object('count',COUNT(*),'sha256',MIN(geo_generation),'removed'," ++
    "COALESCE(SUM(CASE WHEN NOT EXISTS(SELECT 1 FROM console_country_stage c " ++
    "WHERE c.digest=NEW.digest AND c.prefix=r.ip_or_cidr) THEN 1 ELSE 0 END),0)) " ++
    "FROM ip_reputation r WHERE source='console:country:'||NEW.country)," ++
    "json_object('count',NEW.count,'score',NEW.score,'expires',NEW.banned_until," ++
    "'sha256',NEW.geo_generation));" ++
    "DELETE FROM ip_reputation WHERE source='console:country:'||NEW.country AND NOT EXISTS " ++
    "(SELECT 1 FROM console_country_stage c WHERE c.digest=NEW.digest " ++
    "AND c.prefix=ip_reputation.ip_or_cidr);" ++
    "INSERT INTO ip_reputation(ip_or_cidr,reputation_score,banned_until,trigger_rule,hits," ++
    "last_seen,source,note,geo_generation) SELECT prefix,NEW.score,NEW.banned_until," ++
    "'console',0,NEW.recorded_at,'console:country:'||NEW.country,'',NEW.geo_generation " ++
    "FROM console_country_stage WHERE digest=NEW.digest ORDER BY ordinal " ++
    "ON CONFLICT(ip_or_cidr) DO UPDATE SET reputation_score=excluded.reputation_score," ++
    "banned_until=excluded.banned_until,trigger_rule='console',last_seen=excluded.last_seen," ++
    "source=excluded.source,note='',geo_generation=excluded.geo_generation;" ++
    "DELETE FROM console_country_stage WHERE digest=NEW.digest;" ++
    "UPDATE sibuna_meta SET value=NEW.expected_revision+1 WHERE key='policy_version';" ++
    "DELETE FROM console_country_commit WHERE id=NEW.id; END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=26));" ++
    "INSERT INTO console_schema VALUES(26);";
