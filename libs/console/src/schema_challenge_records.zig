//! Version 38 retains per-address challenge records and adaptive-difficulty transitions.
//! Records are bounded data-plane observations; the queue loss counter travels with each
//! batch. Both tables are pruned with the challenge-minute cadence at seven days.
pub const sql =
    "CREATE TABLE console_challenge_records (id INTEGER PRIMARY KEY AUTOINCREMENT," ++
    "node INTEGER NOT NULL,boot TEXT NOT NULL,second INTEGER NOT NULL,ip TEXT NOT NULL," ++
    "outcome INTEGER NOT NULL,cause INTEGER NOT NULL,algorithm INTEGER NOT NULL," ++
    "parameter INTEGER NOT NULL,openings INTEGER NOT NULL,duration_ms INTEGER," ++
    "CHECK(node>=0 AND second>=0 AND length(boot)=32 AND length(ip) BETWEEN 1 AND 48)," ++
    "CHECK(outcome IN (0,1,2) AND cause BETWEEN 0 AND 255));" ++
    "CREATE INDEX console_challenge_records_time ON console_challenge_records(second,id);" ++
    "CREATE INDEX console_challenge_records_cause ON " ++
    "console_challenge_records(cause,second,id);" ++
    "CREATE INDEX console_challenge_records_ip ON console_challenge_records(ip,second,id);" ++
    "CREATE TABLE console_challenge_difficulty (node INTEGER NOT NULL,boot TEXT NOT NULL," ++
    "second INTEGER NOT NULL,previous_bits INTEGER NOT NULL,bits INTEGER NOT NULL," ++
    "rate_256 INTEGER NOT NULL,PRIMARY KEY(node,boot,second)," ++
    "CHECK(length(boot)=32 AND previous_bits BETWEEN 0 AND 255 AND bits BETWEEN 0 AND 255)) " ++
    "WITHOUT ROWID;" ++
    "CREATE INDEX console_challenge_difficulty_time ON " ++
    "console_challenge_difficulty(second,node,boot);" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=38));" ++
    "INSERT INTO console_schema VALUES(38);";
