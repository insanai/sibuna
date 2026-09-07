//! Membership pagination needs a campaign-first index rather than scanning unrelated history.
pub const sql =
    "CREATE INDEX console_incident_campaign " ++
    "ON security_incidents(campaign_id,recorded_at,id);" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=7));" ++
    "INSERT INTO console_schema VALUES(7);";
