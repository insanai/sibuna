//! Command receipts retain intent separately from the nontransactional local effect.
//! A process restart leaves unresolved old-boot intents visibly uncertain.
pub const sql =
    "CREATE TABLE console_commands(" ++
    "id TEXT PRIMARY KEY CHECK(length(id)=32),node INTEGER NOT NULL CHECK(node>0)," ++
    "boot TEXT NOT NULL CHECK(length(boot)=32),actor INTEGER NOT NULL,actor_role TEXT NOT NULL," ++
    "kind TEXT NOT NULL CHECK(kind IN ('drain','resume','clear_local_bans'))," ++
    "expected_revision INTEGER NOT NULL CHECK(expected_revision>=0)," ++
    "state TEXT NOT NULL DEFAULT 'intent' CHECK(state IN ('intent','applied','rejected'))," ++
    "requested_at INTEGER NOT NULL,completed_at INTEGER,applied_revision INTEGER," ++
    "cleared_entries INTEGER) WITHOUT ROWID;" ++
    "CREATE INDEX console_commands_node ON console_commands(node,requested_at,id);" ++
    "CREATE TRIGGER console_command_intent AFTER INSERT ON console_commands BEGIN " ++
    "INSERT INTO console_audit(actor,actor_role,action,subject,target,recorded_at," ++
    "after_summary) " ++
    "VALUES(NEW.actor,NEW.actor_role,'node.command.intent',NEW.node,NEW.id,NEW.requested_at," ++
    "json_object('command',NEW.kind,'revision',NEW.expected_revision,'state','intent'));" ++
    "END;" ++
    "CREATE TRIGGER console_command_completed AFTER UPDATE OF state ON console_commands " ++
    "WHEN OLD.state='intent' AND NEW.state!='intent' BEGIN " ++
    "INSERT INTO console_audit(actor,actor_role,action,subject,target,recorded_at," ++
    "after_summary) " ++
    "VALUES(NEW.actor,NEW.actor_role,'node.command.'||NEW.state,NEW.node,NEW.id," ++
    "NEW.completed_at,json_object('command',NEW.kind,'state',NEW.state,'revision'," ++
    "NEW.applied_revision,'cleared_entries',NEW.cleared_entries)); END;" ++
    "DROP TABLE console_schema;" ++
    "CREATE TABLE console_schema(version INTEGER PRIMARY KEY CHECK(version=16));" ++
    "INSERT INTO console_schema VALUES(16);";
