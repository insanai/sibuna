//! Version 18 records which provider published a country generation and the per-file
//! publisher digests. Historical generations were DB-IP archives with one source file.
pub const sql =
    "ALTER TABLE console_geo_generations ADD COLUMN provider TEXT NOT NULL DEFAULT 'dbip' " ++
    "CHECK(provider IN ('dbip','user-country'));" ++
    "ALTER TABLE console_geo_generations ADD COLUMN source_digests TEXT NOT NULL DEFAULT '' " ++
    "CHECK(length(source_digests) IN (0,64,129));" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=18));" ++
    "INSERT INTO console_schema VALUES(18);";
