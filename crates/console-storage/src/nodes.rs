//! Node membership and local node commands: S30, S31, and the reads of the nodes page.
//!
//! | Id  | Invariant                                                     | Function             |
//! |-----|---------------------------------------------------------------|----------------------|
//! | S30 | a command is recorded as an intent with `node.command.intent` | [`request_command`]  |
//! |     | before any local effect, within 4,096 commands per node       |                      |
//! | S31 | a command leaves `intent` once, to `applied` or `rejected`,   | [`complete_command`] |
//! |     | with `node.command.applied` or `node.command.rejected`; an    |                      |
//! |     | identical repeated completion changes nothing                 |                      |
//!
//! Each node writes only its own membership row, with [`announce`]: at start, every 60
//! seconds and after every applied rebuild. A row states facts about its writer; the
//! console never probes an address read from it. A row carries the policy revision its
//! node applied; the Zaxonlite log frontiers `applied_slot` and `decided_slot` are gone
//! (SID 0013, review of 2026-10-15), and the members this module returns carry zeros in
//! the protocol's fields of those names.
//!
//! The local effect of a command (drain, resume, clearing the ban table) is the daemon's:
//! storage records the intent before it and the completion after it, and a durable intent
//! alone never proves an effect. A receipt whose intent has no completion therefore reads
//! as `uncertain`.
//!
//! # Changes from the Zig version
//!
//! - The triggers `console_command_intent` and `console_command_completed` are
//!   [`request_command`] and [`complete_command`]. A completion's audit row has neither
//!   actor nor role (SID 0013: no account acted); Zig repeated the requester's.
//! - A full command table answers [`ConsoleStorageError::Capacity`], where Zig's single
//!   conditional insert could only answer `unavailable`. A command needs its node's
//!   membership row (a foreign key now); without one it is a conflict.
//! - The receipts a request prunes keep the intents of the boot in the node's membership
//!   row, where Zig compared with the daemon's own boot; the two agree once the node has
//!   announced itself, which it does at start.
//! - A membership heartbeat whose clock stepped back keeps `last_seen` at `first_seen`
//!   instead of failing the schema's check and retrying.

use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::nodes::{self, Command, Kind, Member, Receipt, State};
use sibuna_console_protocol::{Action, Principal, Role, Text};
use sibuna_encoding::hex;
use sibuna_storage::{Param, Sql, StorageError, Transaction};

use crate::access::{self, Credential, Need};
use crate::audit::summary::Summary;
use crate::audit::{self, AuditAction, AuditRow};
use crate::error::ConsoleStorageError;
use crate::leases::MAX_NODE;
use crate::lock::{CapacityLock, lock_capacity};
use crate::row::{self, Fields};

/// The most commands storage keeps per node.
pub const MAX_COMMANDS: u64 = nodes::COMMAND_CAPACITY as u64;
/// How long a command's receipt is kept, in seconds.
pub const RECEIPT_SECONDS: u64 = nodes::RECEIPT_DAYS as u64 * 86_400;
/// Expired receipts a command request deletes at most before it counts.
const PRUNE_ROWS: u64 = 16;
/// The longest software version a membership row holds, in bytes.
pub const MAX_VERSION: usize = 32;

/// What a node command requires: an operator's browser session with its CSRF digest.
const CONTROL: Need = Need::mutation(Action::ControlNode, None);
/// What the nodes page's reads require: any role, in a browser session.
const READ: Need = Need::read(None);

/// The state of a stored command: the `CHECK` of `console_commands.state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommandState {
    /// Recorded before the local effect; nothing is known of the effect yet.
    Intent,
    /// The node applied the command.
    Applied,
    /// The node refused the command (its grant expired or was revoked first).
    Rejected,
}

impl CommandState {
    /// Returns the stored name.
    pub fn as_str(self) -> &'static str {
        match self {
            CommandState::Intent => "intent",
            CommandState::Applied => "applied",
            CommandState::Rejected => "rejected",
        }
    }

    /// Returns the state stored as `name`, if any.
    pub fn parse(name: &str) -> Option<CommandState> {
        match name {
            "intent" => Some(CommandState::Intent),
            "applied" => Some(CommandState::Applied),
            "rejected" => Some(CommandState::Rejected),
            _ => None,
        }
    }
}

// ---- Membership ----------------------------------------------------------------------------

/// The facts a node announces about itself. Borrowed text; build it with struct-update
/// syntax from `Announcement::default()`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Announcement<'a> {
    /// The node, 1 to [`MAX_NODE`].
    pub node: u32,
    /// The node's management address, or `local` for a single node; 1 to 64 bytes.
    pub address: &'a str,
    /// The node's console link: empty, or a plain origin that [`nodes::safe_url`] accepts.
    pub console_url: &'a str,
    /// The node's software version, 1 to [`MAX_VERSION`] bytes.
    pub version: &'a str,
    /// The node's current boot; never all zeros.
    pub boot: [u8; 16],
    /// The policy revision the node has applied.
    pub applied_revision: u64,
    /// The node's control revision (one per applied command).
    pub control_revision: u64,
    /// The node is draining.
    pub draining: bool,
}

fn validate_announcement(input: &Announcement<'_>) -> Result<(), ConsoleStorageError> {
    let valid = (1..=MAX_NODE).contains(&input.node)
        && (1..=nodes::MAX_ADDRESS).contains(&input.address.len())
        && (input.console_url.is_empty() || nodes::safe_url(input.console_url))
        && (1..=MAX_VERSION).contains(&input.version.len())
        && input.boot != [0; 16]
        && input.applied_revision <= row::MAX_INTEGER
        && input.control_revision <= row::MAX_INTEGER;
    if valid { Ok(()) } else { Err(ConsoleStorageError::InvalidInput("announcement")) }
}

// `last_seen` never falls below `first_seen`, so a clock stepped back does not fail the
// heartbeat; `first_seen` is kept on every update.
const ANNOUNCE: Sql = Sql::both(
    "INSERT INTO console_nodes (node, address, console_url, version, boot, first_seen, \
     last_seen, applied_revision, control_revision, draining) \
     VALUES ($1, $2, $3, $4, $5, $6, $6, $7, $8, ($9 <> 0)) \
     ON CONFLICT (node) DO UPDATE SET address = excluded.address, \
     console_url = excluded.console_url, version = excluded.version, boot = excluded.boot, \
     last_seen = CASE WHEN excluded.last_seen > console_nodes.first_seen \
     THEN excluded.last_seen ELSE console_nodes.first_seen END, \
     applied_revision = excluded.applied_revision, \
     control_revision = excluded.control_revision, draining = excluded.draining",
);

/// Writes the membership row of `input.node` at `now`: inserts it, or updates every fact
/// but `first_seen`. A node calls it only for itself. Borrows `input`.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a node outside 1 to [`MAX_NODE`],
/// an address or version outside its bounds, a link that is not a plain origin, an
/// all-zero boot or a number above 2^63 - 1; and with the driver's error.
pub async fn announce(
    tx: &mut Transaction,
    input: &Announcement<'_>,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    validate_announcement(input)?;
    let params: [Param<'_>; 9] = [
        i64::from(input.node).into(),
        input.address.into(),
        input.console_url.into(),
        input.version.into(),
        input.boot.as_slice().into(),
        row::int(now)?.into(),
        row::int(input.applied_revision)?.into(),
        row::int(input.control_revision)?.into(),
        i64::from(input.draining).into(),
    ];
    tx.execute(ANNOUNCE, &params).await?;
    Ok(())
}

/// The members of the cluster as storage knows them, with the committed policy revision
/// to compare their applied revisions with. The console adds its own node id and its
/// consensus snapshot to make the protocol's `nodes::Page`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Membership {
    /// The committed policy revision.
    pub committed: u64,
    /// At most [`nodes::MAX_MEMBERS`] members, by node id.
    pub members: Vec<Member>,
}

const MEMBERS: Sql = Sql::both(
    "SELECT node, address, console_url, version, boot, first_seen, last_seen, \
     applied_revision, control_revision, draining FROM console_nodes ORDER BY node LIMIT $1",
);
const COMMITTED: Sql = Sql::both("SELECT revision FROM policy_revision WHERE id = 1");

fn decode_member(mut fields: Fields) -> Result<Member, ConsoleStorageError> {
    let node = fields.integer("node")?;
    let address = fields.text("address")?;
    let address = Text::from_string(address).map_err(|_| fields.invalid("address"))?;
    let url = fields.text("console_url")?;
    // A link from a replicated row is rendered only when it is a plain origin.
    let url = if nodes::safe_url(&url) { url } else { String::new() };
    let console_url = Text::from_string(url).map_err(|_| fields.invalid("console_url"))?;
    let version = fields.text("version")?;
    let version = Text::from_string(version).map_err(|_| fields.invalid("version"))?;
    let boot = hex_text(&fields.array::<16>("boot")?);
    Ok(Member {
        node,
        address,
        console_url,
        version,
        boot,
        first_seen: fields.integer("first_seen")?,
        last_seen: fields.integer("last_seen")?,
        applied_revision: fields.integer("applied_revision")?,
        control_revision: fields.integer("control_revision")?,
        applied_slot: 0,
        decided_slot: 0,
        draining: fields.flag("draining")?,
    })
}

/// Returns 16 bytes as 32 lowercase hexadecimal digits.
fn hex_text(bytes: &[u8; 16]) -> Text<32> {
    // 16 bytes are always 32 digits, within the capacity.
    Text::from_string(hex::encode(bytes)).unwrap_or_default()
}

/// Reads every membership row (at most [`nodes::MAX_MEMBERS`]) and the committed policy
/// revision, without a credential: the live `nodes` topic rechecks its subscribers itself.
///
/// Fails with [`StorageError::MissingPolicyRevision`] when the revision row is gone, with
/// [`StorageError::InvalidRow`] for a row the types cannot hold, and with the driver's
/// error.
pub async fn load_members(tx: &mut Transaction) -> Result<Membership, ConsoleStorageError> {
    let cells = row::first(tx.fetch_all(COMMITTED, &[]).await?)
        .ok_or(StorageError::MissingPolicyRevision)?;
    let committed = Fields::new(cells, "policy_revision").integer("revision")?;
    let limit = row::int(nodes::MAX_MEMBERS as u64)?;
    let members = tx
        .fetch_all(MEMBERS, &[limit.into()])
        .await?
        .into_iter()
        .map(|cells| decode_member(Fields::new(cells, "console_nodes")))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Membership { committed, members })
}

/// Reads the membership for the nodes page: any role, in a browser session.
///
/// Fails like [`access::authorize_in`] and [`load_members`].
pub async fn query_members(
    tx: &mut Transaction,
    credential: &Credential,
    now: u64,
) -> Result<Membership, ConsoleStorageError> {
    access::authorize_in(tx, credential, READ, now).await?;
    load_members(tx).await
}

// ---- Commands ------------------------------------------------------------------------------

/// One row of `console_commands`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CommandRow {
    id: [u8; 16],
    node: u32,
    boot: [u8; 16],
    kind: Kind,
    expected_revision: u64,
    state: CommandState,
    requested_at: u64,
    completed_at: Option<u64>,
    applied_revision: Option<u64>,
    cleared_entries: Option<u32>,
}

impl CommandRow {
    /// Returns the receipt the console shows: an intent without a completion is
    /// `uncertain`, because it cannot establish that an effect occurred.
    fn receipt(&self) -> Receipt {
        Receipt {
            id: hex_text(&self.id),
            boot: hex_text(&self.boot),
            node: self.node,
            kind: self.kind,
            state: match self.state {
                CommandState::Intent => State::Uncertain,
                CommandState::Applied => State::Applied,
                CommandState::Rejected => State::Rejected,
            },
            expected_revision: self.expected_revision,
            applied_revision: self.applied_revision,
            cleared_entries: self.cleared_entries,
            requested_at: self.requested_at,
            completed_at: self.completed_at,
            completion_persisted: self.state != CommandState::Intent,
        }
    }
}

const COMMAND: Sql = Sql {
    sqlite: "SELECT id, node, boot, kind, expected_revision, state, requested_at, completed_at, \
             applied_revision, cleared_entries FROM console_commands WHERE id = $1",
    postgres: "SELECT id, node, boot, kind, expected_revision, state, requested_at, \
               completed_at, applied_revision, cleared_entries FROM console_commands \
               WHERE id = $1 FOR UPDATE",
};

/// Reads command `id`, locking it on PostgreSQL.
async fn lock_command(
    tx: &mut Transaction,
    id: &[u8; 16],
) -> Result<Option<CommandRow>, ConsoleStorageError> {
    let Some(cells) = row::first(tx.fetch_all(COMMAND, &[id.as_slice().into()]).await?) else {
        return Ok(None);
    };
    let mut fields = Fields::new(cells, "console_commands");
    Ok(Some(CommandRow {
        id: fields.array("id")?,
        node: fields.integer("node")?,
        boot: fields.array("boot")?,
        kind: fields.parsed("kind", Kind::from_name)?,
        expected_revision: fields.integer("expected_revision")?,
        state: fields.parsed("state", CommandState::parse)?,
        requested_at: fields.integer("requested_at")?,
        completed_at: fields.optional_integer("completed_at")?,
        applied_revision: fields.optional_integer("applied_revision")?,
        cleared_entries: fields.optional_integer("cleared_entries")?,
    }))
}

/// Reads the receipt of command `id`, without a credential, for the daemon that runs the
/// command: a retry of a stored operation returns its receipt and never repeats the effect.
///
/// Fails with [`StorageError::InvalidRow`] for a row the types cannot hold and with the
/// driver's error.
pub async fn load_command(
    tx: &mut Transaction,
    id: &[u8; 16],
) -> Result<Option<Receipt>, ConsoleStorageError> {
    Ok(lock_command(tx, id).await?.map(|row| row.receipt()))
}

/// Reads the receipt of command `input.id` for an operator's browser session (the
/// protocol's `NodeCommandRead`). The credential is `credential`; `input.auth` is not read.
///
/// Fails like [`access::authorize_in`] with a read, with [`ConsoleStorageError::Conflict`]
/// when no command has the id (as in Zig), and with the driver's error.
pub async fn read_command(
    tx: &mut Transaction,
    credential: &Credential,
    input: &nodes::Read,
    now: u64,
) -> Result<Receipt, ConsoleStorageError> {
    access::authorize_in(tx, credential, READ, now).await?;
    load_command(tx, &input.id).await?.ok_or(ConsoleStorageError::Conflict)
}

/// What [`request_command`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Requested {
    /// The intent is recorded; the daemon may now run the command once and complete it.
    /// The receipt is the intent's, in state [`State::Intent`].
    Recorded(Receipt),
    /// The operation id was stored before with the same node, boot, kind and expected
    /// revision: this is a retry, and the stored receipt answers it without a new effect.
    Existing(Receipt),
}

const MEMBER: Sql = Sql::both("SELECT node FROM console_nodes WHERE node = $1");
const COUNT: Sql =
    Sql::both("SELECT CAST(COUNT(*) AS BIGINT) FROM console_commands WHERE node = $1");
const INSERT: Sql = Sql::both(
    "INSERT INTO console_commands (id, node, boot, kind, actor, actor_role, expected_revision, \
     requested_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
);

fn validate_command(input: &Command, now: u64) -> Result<(), ConsoleStorageError> {
    if nodes::validate(input).is_err() || input.node > MAX_NODE {
        return Err(ConsoleStorageError::InvalidInput("command"));
    }
    if input.expires <= now || input.expires - now > nodes::COMMAND_SECONDS {
        return Err(ConsoleStorageError::InvalidInput("command expiry"));
    }
    Ok(())
}

/// Records command `input` as an intent of the operator `credential` names (S30), before
/// the daemon runs it: deletes up to 16 of the node's receipts older than
/// [`RECEIPT_SECONDS`] (never an intent of the node's current boot), inserts the command
/// within [`MAX_COMMANDS`] per node, and writes `node.command.intent`. A retry with a
/// stored operation id returns the stored receipt instead. The daemon checks the node,
/// boot and control revision against its own state before it calls; `input.auth` is not
/// read.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for a command the protocol refuses, a
/// node above [`MAX_NODE`], or an expiry not within [`nodes::COMMAND_SECONDS`] after
/// `now`; like [`access::authorize_in`] (an operator's browser session with its CSRF
/// digest); with [`ConsoleStorageError::Conflict`] when the operation id names a different
/// command or the node has no membership row; with [`ConsoleStorageError::Capacity`] at
/// [`MAX_COMMANDS`] (Zig answered `unavailable`); and with the driver's error.
pub async fn request_command(
    tx: &mut Transaction,
    credential: &Credential,
    input: &Command,
    now: u64,
) -> Result<Requested, ConsoleStorageError> {
    if nodes::validate(input).is_err() || input.node > MAX_NODE {
        return Err(ConsoleStorageError::InvalidInput("command"));
    }
    let principal = access::authorize_in(tx, credential, CONTROL, now).await?;
    lock_capacity(tx, CapacityLock::Commands).await?;
    if let Some(stored) = lock_command(tx, &input.id).await? {
        let same = stored.node == input.node
            && stored.boot == input.boot
            && stored.kind == input.kind
            && stored.expected_revision == input.expected_revision;
        return if same {
            Ok(Requested::Existing(stored.receipt()))
        } else {
            Err(ConsoleStorageError::Conflict)
        };
    }
    validate_command(input, now)?;
    let node = i64::from(input.node);
    if tx.fetch_all(MEMBER, &[node.into()]).await?.is_empty() {
        return Err(ConsoleStorageError::Conflict);
    }
    let before = now.saturating_sub(RECEIPT_SECONDS);
    delete_commands(tx, Some(input.node), before, PRUNE_ROWS).await?;
    let cells = row::first(tx.fetch_all(COUNT, &[node.into()]).await?).unwrap_or_default();
    if Fields::new(cells, "console_commands").integer::<u64>("count")? >= MAX_COMMANDS {
        return Err(ConsoleStorageError::Capacity);
    }
    let role = access::account_role(&principal);
    let params: [Param<'_>; 8] = [
        input.id.as_slice().into(),
        node.into(),
        input.boot.as_slice().into(),
        input.kind.name().into(),
        row::int(principal.actor)?.into(),
        role.name().into(),
        row::int(input.expected_revision)?.into(),
        row::int(now)?.into(),
    ];
    tx.execute(INSERT, &params).await?;
    append_intent(tx, &principal, role, credential, input, now).await?;
    let intent = CommandRow {
        id: input.id,
        node: input.node,
        boot: input.boot,
        kind: input.kind,
        expected_revision: input.expected_revision,
        state: CommandState::Intent,
        requested_at: now,
        completed_at: None,
        applied_revision: None,
        cleared_entries: None,
    };
    Ok(Requested::Recorded(Receipt { state: State::Intent, ..intent.receipt() }))
}

async fn append_intent(
    tx: &mut Transaction,
    principal: &Principal,
    role: Role,
    credential: &Credential,
    input: &Command,
    now: u64,
) -> Result<(), ConsoleStorageError> {
    let after = Summary::new()
        .text("command", input.kind.name())
        .int("revision", input.expected_revision)
        .text("state", CommandState::Intent.as_str())
        .finish();
    let row = AuditRow {
        actor_role: Some(role),
        subject: Some(u64::from(input.node)),
        target: Some(hex::encode(&input.id)),
        client_ip: credential.client.clone(),
        after: Some(after),
        ..AuditRow::by(principal, AuditAction::NodeCommandIntent, now)
    };
    audit::append_audit(tx, &row).await.map(|_| ())
}

/// The outcome of a command as the daemon that ran it reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    /// The operation id.
    pub id: [u8; 16],
    /// The boot that ran it.
    pub boot: [u8; 16],
    /// [`CommandState::Applied`] or [`CommandState::Rejected`].
    pub state: CommandState,
    /// When the effect completed, in Unix seconds.
    pub completed_at: u64,
    /// The control revision after applying.
    pub applied_revision: Option<u64>,
    /// Ban entries cleared; only for `clear_local_bans`.
    pub cleared_entries: Option<u32>,
}

/// What [`complete_command`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completed {
    /// The intent became the completion, and its audit row was written.
    Recorded,
    /// The same completion was stored before (an acknowledgment lost after commit).
    Unchanged,
}

const COMPLETE: Sql = Sql::both(
    "UPDATE console_commands SET state = $2, completed_at = $3, applied_revision = $4, \
     cleared_entries = $5 WHERE id = $1 AND state = 'intent'",
);

/// Records the completion of command `input.id` (S31): the intent becomes `applied` or
/// `rejected` once and writes `node.command.applied` or `node.command.rejected` without an
/// actor; an identical repeated completion changes nothing. Borrows `input`.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for the state `intent`, a time or
/// revision above 2^63 - 1, a completion before the request, or cleared entries for
/// another kind than `clear_local_bans`; with [`ConsoleStorageError::Conflict`] when no
/// command has the id, its boot differs, or another completion is stored; and with the
/// driver's error.
pub async fn complete_command(
    tx: &mut Transaction,
    input: &Completion,
) -> Result<Completed, ConsoleStorageError> {
    if input.state == CommandState::Intent {
        return Err(ConsoleStorageError::InvalidInput("a completion is applied or rejected"));
    }
    let completed_at = row::int(input.completed_at)?;
    let applied_revision = row::optional_int(input.applied_revision)?;
    let stored = lock_command(tx, &input.id)
        .await?
        .filter(|stored| stored.boot == input.boot)
        .ok_or(ConsoleStorageError::Conflict)?;
    if (input.cleared_entries.is_some() && stored.kind != Kind::ClearLocalBans)
        || input.completed_at < stored.requested_at
    {
        return Err(ConsoleStorageError::InvalidInput("completion"));
    }
    if stored.state != CommandState::Intent {
        let same = stored.state == input.state
            && stored.completed_at == Some(input.completed_at)
            && stored.applied_revision == input.applied_revision
            && stored.cleared_entries == input.cleared_entries;
        return if same { Ok(Completed::Unchanged) } else { Err(ConsoleStorageError::Conflict) };
    }
    let params: [Param<'_>; 5] = [
        input.id.as_slice().into(),
        input.state.as_str().into(),
        completed_at.into(),
        applied_revision.into(),
        input.cleared_entries.map(i64::from).into(),
    ];
    if tx.execute(COMPLETE, &params).await? != 1 {
        return Err(ConsoleStorageError::Conflict);
    }
    let action = match input.state {
        CommandState::Applied => AuditAction::NodeCommandApplied,
        _ => AuditAction::NodeCommandRejected,
    };
    let after = Summary::new()
        .text("command", stored.kind.name())
        .text("state", input.state.as_str())
        .optional_int("revision", input.applied_revision)
        .optional_int("cleared_entries", input.cleared_entries.map(u64::from))
        .finish();
    let row = AuditRow {
        subject: Some(u64::from(stored.node)),
        target: Some(hex::encode(&input.id)),
        after: Some(after),
        ..AuditRow::new(action, input.completed_at)
    };
    audit::append_audit(tx, &row).await?;
    Ok(Completed::Recorded)
}

const DELETE: Sql = Sql {
    sqlite: "DELETE FROM console_commands WHERE id IN (SELECT c.id FROM console_commands c \
             WHERE c.requested_at < $1 AND ($3 IS NULL OR c.node = $3) \
             AND NOT (c.state = 'intent' AND EXISTS (SELECT 1 FROM console_nodes n \
             WHERE n.node = c.node AND n.boot = c.boot)) \
             ORDER BY c.requested_at, c.id LIMIT $2)",
    postgres: "DELETE FROM console_commands WHERE id IN (SELECT c.id FROM console_commands c \
               WHERE c.requested_at < $1 AND ($3 IS NULL OR c.node = $3) \
               AND NOT (c.state = 'intent' AND EXISTS (SELECT 1 FROM console_nodes n \
               WHERE n.node = c.node AND n.boot = c.boot)) \
               ORDER BY c.requested_at, c.id LIMIT $2 FOR UPDATE OF c SKIP LOCKED)",
};

async fn delete_commands(
    tx: &mut Transaction,
    node: Option<u32>,
    before: u64,
    limit: u64,
) -> Result<u64, ConsoleStorageError> {
    let params: [Param<'_>; 3] =
        [row::int(before)?.into(), row::int(limit)?.into(), node.map(i64::from).into()];
    Ok(tx.execute(DELETE, &params).await?)
}

/// Deletes at most `limit` commands requested before `before`, oldest first, and returns
/// how many: the retention job's pass over node commands, with `before` set to now minus
/// [`RECEIPT_SECONDS`]. An intent of its node's current boot is kept, because the daemon
/// that recorded it may still complete it.
///
/// Fails with [`ConsoleStorageError::InvalidInput`] for numbers above 2^63 - 1 and with
/// the driver's error.
pub async fn prune_commands(
    tx: &mut Transaction,
    before: u64,
    limit: u64,
) -> Result<u64, ConsoleStorageError> {
    delete_commands(tx, None, before, limit).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_round_trip_through_their_names() {
        for state in [CommandState::Intent, CommandState::Applied, CommandState::Rejected] {
            assert_eq!(CommandState::parse(state.as_str()), Some(state));
        }
        assert_eq!(CommandState::parse("uncertain"), None);
    }

    #[test]
    fn announcements_are_bounded() {
        let valid = Announcement {
            node: 1,
            address: "local",
            version: "0.1.0",
            boot: [1; 16],
            ..Announcement::default()
        };
        assert!(validate_announcement(&valid).is_ok());
        let linked = Announcement { console_url: "https://console.example", ..valid };
        assert!(validate_announcement(&linked).is_ok());
        for bad in [
            Announcement { node: 0, ..valid },
            Announcement { node: MAX_NODE + 1, ..valid },
            Announcement { address: "", ..valid },
            Announcement { console_url: "javascript:alert(1)", ..valid },
            Announcement { version: "", ..valid },
            Announcement { boot: [0; 16], ..valid },
            Announcement { applied_revision: u64::MAX, ..valid },
        ] {
            assert!(validate_announcement(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn commands_expire_within_thirty_seconds() {
        let command =
            Command { id: [1; 16], boot: [2; 16], node: 1, expires: 130, ..Command::default() };
        assert!(validate_command(&command, 100).is_ok());
        assert!(validate_command(&Command { expires: 100, ..command.clone() }, 100).is_err());
        assert!(validate_command(&Command { expires: 131, ..command.clone() }, 100).is_err());
        assert!(validate_command(&Command { node: MAX_NODE + 1, ..command }, 100).is_err());
    }

    #[test]
    fn intents_read_as_uncertain() {
        let row = CommandRow {
            id: [0xab; 16],
            node: 1,
            boot: [1; 16],
            kind: Kind::Drain,
            expected_revision: 0,
            state: CommandState::Intent,
            requested_at: 5,
            completed_at: None,
            applied_revision: None,
            cleared_entries: None,
        };
        let receipt = row.receipt();
        assert_eq!(receipt.state, State::Uncertain);
        assert!(!receipt.completion_persisted);
        assert_eq!(receipt.id.as_str(), "ab".repeat(16));
        let applied = CommandRow { state: CommandState::Applied, ..row }.receipt();
        assert_eq!(applied.state, State::Applied);
        assert!(applied.completion_persisted);
    }
}
