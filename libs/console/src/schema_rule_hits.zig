//! Insert triggers make observation and rollup changes atomic, including replicated retries.
//! Null counts propagate exhaustion; SQLite's floating-point integer overflow is never a count.
pub const columns = "node,boot,sequence,rule_key,generation,revision,name,minute," ++
    "utc_start,utc_end,start_ms,end_ms,observed_ms,observations,complete,gap,unconfirmed,hits";
pub const sql =
    "CREATE TABLE console_rule_hits (node INTEGER NOT NULL,boot TEXT NOT NULL," ++
    "sequence INTEGER NOT NULL,rule_key TEXT NOT NULL,generation INTEGER NOT NULL," ++
    "revision INTEGER NOT NULL,name TEXT NOT NULL,minute INTEGER NOT NULL," ++
    "utc_start INTEGER NOT NULL,utc_end INTEGER NOT NULL,start_ms INTEGER NOT NULL," ++
    "end_ms INTEGER NOT NULL,observed_ms INTEGER NOT NULL,observations INTEGER NOT NULL," ++
    "complete INTEGER NOT NULL,gap INTEGER NOT NULL,unconfirmed INTEGER NOT NULL," ++
    "hits INTEGER CHECK(hits>=0),guard INTEGER NOT NULL DEFAULT 1 CHECK(guard=1)," ++
    "PRIMARY KEY(node,boot,sequence,rule_key));" ++
    "CREATE INDEX console_rule_hits_history " ++
    "ON console_rule_hits(rule_key,node,minute,boot,sequence);" ++
    "CREATE INDEX console_rule_hits_revision " ++
    "ON console_rule_hits(rule_key,node,revision,minute,boot,sequence);" ++
    "CREATE INDEX console_rule_hits_retention ON console_rule_hits(minute);" ++
    "CREATE TABLE console_rule_hit_rollups (grain INTEGER NOT NULL,node INTEGER NOT NULL," ++
    "boot TEXT NOT NULL,generation INTEGER NOT NULL,rule_key TEXT NOT NULL," ++
    "bucket INTEGER NOT NULL,revision INTEGER NOT NULL,name TEXT NOT NULL," ++
    "hits INTEGER CHECK(hits>=0),observed_ms INTEGER NOT NULL,intervals INTEGER NOT NULL," ++
    "complete INTEGER NOT NULL,gaps INTEGER NOT NULL,unconfirmed INTEGER NOT NULL," ++
    "PRIMARY KEY(grain,node,boot,generation,rule_key,bucket));" ++
    "CREATE INDEX console_rule_rollup_history " ++
    "ON console_rule_hit_rollups(rule_key,node,grain,bucket,boot,generation);" ++
    "CREATE INDEX console_rule_rollup_retention ON console_rule_hit_rollups(bucket,grain);" ++
    rollup("hour", "60", false) ++ rollup("day", "1440", false) ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=31));" ++
    "INSERT INTO console_schema VALUES(31);";

pub fn rollup(
    comptime name: []const u8,
    comptime grain: []const u8,
    comptime bounded: bool,
) []const u8 {
    return "CREATE TRIGGER console_rule_hit_" ++ name ++
        " AFTER INSERT ON console_rule_hits BEGIN " ++
        "INSERT INTO console_rule_hit_rollups VALUES(" ++ grain ++
        ",NEW.node,NEW.boot,NEW.generation,NEW.rule_key,NEW.minute/" ++ grain ++ "*" ++ grain ++
        ",NEW.revision,NEW.name,NEW.hits,NEW.observed_ms,1,NEW.complete,NEW.gap," ++
        "NEW.unconfirmed" ++ (if (bounded) ",NEW.minute" else "") ++
        ") ON CONFLICT(grain,node,boot,generation,rule_key,bucket) " ++
        "DO UPDATE SET hits=CASE WHEN hits IS NULL OR excluded.hits IS NULL OR " ++
        "hits>9223372036854775807-excluded.hits THEN NULL ELSE hits+excluded.hits END," ++
        "observed_ms=MIN(9223372036854775807-excluded.observed_ms,observed_ms)+" ++
        "excluded.observed_ms,intervals=MIN(intervals,9223372036854775806)+1," ++
        "complete=MIN(complete,9223372036854775806)+excluded.complete," ++
        "gaps=MIN(gaps,9223372036854775806)+excluded.gaps," ++
        "unconfirmed=MAX(unconfirmed,excluded.unconfirmed)" ++ (if (bounded)
        ",through_minute=MAX(CASE WHEN through_minute=0 THEN bucket+grain-1 " ++
            "ELSE through_minute END,excluded.through_minute)"
    else
        "") ++ "; END;";
}

/// A replay changes no data. A conflicting identity fails the entire bounded insert, including
/// any earlier rows and their rollup triggers; it can never rewrite recorded observations.
pub const conflict = " ON CONFLICT(node,boot,sequence,rule_key) DO UPDATE SET guard=CASE WHEN " ++
    "generation IS excluded.generation AND revision IS excluded.revision AND " ++
    "name IS excluded.name AND minute IS excluded.minute AND utc_start IS excluded.utc_start " ++
    "AND utc_end IS excluded.utc_end AND start_ms IS excluded.start_ms AND " ++
    "end_ms IS excluded.end_ms AND observed_ms IS excluded.observed_ms AND " ++
    "observations IS excluded.observations AND complete IS excluded.complete AND " ++
    "gap IS excluded.gap AND unconfirmed IS excluded.unconfirmed AND hits IS excluded.hits " ++
    "THEN 1 ELSE 0 END";
