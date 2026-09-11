//! Version 40 records how the response side of captured heads was observed, so an empty
//! response head never claims a local answer by default. Existing rows keep state zero,
//! which readers label as not recorded; no historical evidence is reinterpreted.
pub const sql =
    "ALTER TABLE console_incident_heads ADD COLUMN response_state INTEGER NOT NULL " ++
    "DEFAULT 0 CHECK(response_state BETWEEN 0 AND 4);" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=40));" ++
    "INSERT INTO console_schema VALUES(40);";
