//! Additive sidecar; the owning incident transaction commits all scalar evidence.
//! Explicit deletion also works when a legacy connection disables foreign keys.
pub const sql =
    "CREATE TABLE console_crs_evidence(" ++
    "incident_id INTEGER PRIMARY KEY REFERENCES security_incidents(id) ON DELETE CASCADE," ++
    "rule_id INTEGER NOT NULL CHECK(rule_id BETWEEN 0 AND 4294967295)," ++
    "phase INTEGER NOT NULL CHECK(phase BETWEEN 1 AND 5)," ++
    "severity INTEGER NOT NULL CHECK(severity BETWEEN 0 AND 7)," ++
    "revision TEXT NOT NULL CHECK(length(revision) BETWEEN 1 AND 20 " ++
    "AND revision NOT GLOB '*[^0-9]*' AND revision!='0')," ++
    "source_digest TEXT NOT NULL CHECK(length(source_digest)=64 " ++
    "AND source_digest NOT GLOB '*[^0-9a-f]*')," ++
    "enforcing INTEGER NOT NULL CHECK(enforcing IN (0,1))," ++
    "denied INTEGER NOT NULL CHECK(denied IN (0,1))," ++
    "would_deny INTEGER NOT NULL CHECK(would_deny IN (0,1))," ++
    "coverage INTEGER NOT NULL CHECK(coverage BETWEEN 0 AND 6)," ++
    "selected_status INTEGER NOT NULL CHECK(selected_status=0 OR " ++
    "selected_status BETWEEN 100 AND 599)," ++
    "blocking_paranoia INTEGER NOT NULL CHECK(blocking_paranoia BETWEEN 1 AND 4)," ++
    "detection_paranoia INTEGER NOT NULL CHECK(detection_paranoia " ++
    "BETWEEN blocking_paranoia AND 4)," ++
    "CHECK(denied=0 OR (enforcing=1 AND selected_status BETWEEN 400 AND 599)));" ++
    "CREATE INDEX console_crs_rule ON console_crs_evidence(rule_id,incident_id);" ++
    "CREATE TRIGGER console_crs_incident_deleted AFTER DELETE ON security_incidents BEGIN " ++
    "DELETE FROM console_crs_evidence WHERE incident_id=OLD.id; END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=41));" ++
    "INSERT INTO console_schema VALUES(41);";
