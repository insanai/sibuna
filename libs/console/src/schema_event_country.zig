//! Missing sidecars remain not recorded; a null country with a generation is Unknown.
//! The digest is retained even after old GeoIP chunks are pruned.
pub const sql =
    "CREATE TABLE console_incident_country(" ++
    "incident_id INTEGER PRIMARY KEY REFERENCES security_incidents(id) ON DELETE CASCADE," ++
    "country TEXT CHECK(country IS NULL OR country GLOB '[A-Z][A-Z]')," ++
    "generation TEXT NOT NULL CHECK(length(generation)=64));" ++
    "CREATE INDEX console_incident_country_code " ++
    "ON console_incident_country(country,incident_id);" ++
    "CREATE TRIGGER console_incident_country_delete AFTER DELETE ON security_incidents BEGIN " ++
    "DELETE FROM console_incident_country WHERE incident_id=OLD.id; END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=29));" ++
    "INSERT INTO console_schema VALUES(29);";
