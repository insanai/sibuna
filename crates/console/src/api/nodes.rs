//! The routes `nodes/local`, `nodes`, `nodes/command` and `nodes/command/read` (Zig's
//! `node_routes.zig` and `console_node_read.zig`).
//!
//! Local commands act only on the serving node, through [`crate::nodes::Commands`]. The
//! membership page combines the stored member rows with this console's probes of
//! configured peers, the peers' direct reports, and the storage snapshot: without a
//! consensus log, SQLite reports itself as the single leader and PostgreSQL as unknown,
//! `quorum` says the database answered, and terms and slots are 0 (decision 3 of the port,
//! SID 0007).

use std::fmt::{self, Write};

use sibuna_console_protocol::codec::{Decode, DecodeError, Encode, Fields, Path, field};
use sibuna_console_protocol::nodes::{self, Command, Kind, Page, Status, Storage};
use sibuna_console_storage::nodes::{Membership, query_members, read_command};
use sibuna_json::{Value, Writer};
use sibuna_serve::Context;
use sibuna_storage::Dialect;

use super::policies::spend;
use crate::dispatch::Call;
use crate::http::body::read_json;
use crate::http::{RouteError, reply};
use crate::limits::Spend;
use crate::nodes::{hex_id, node_error};
use crate::routes::Handler;
use crate::shared::Shared;

/// Serves `call.route`, one of this module's routes, after the dispatcher's checks.
///
/// Fails with 429 `CONSOLEQUERY` past the query allowance (reads only) and with
/// `CONSOLENODE` for refused or unanswered requests.
pub fn handle(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    if call.route.handler != Handler::NodeCommand {
        spend(shared, call, Spend::Query, "CONSOLEQUERY")?;
    }
    match call.route.handler {
        Handler::NodeStatus => status(shared, context, call),
        Handler::NodesMembers => members(shared, context, call),
        Handler::NodeCommand => command(shared, context, call),
        Handler::NodeCommandRead => read(shared, context, call),
        _ => Err(RouteError::Unavailable),
    }
}

/// Reads the membership with the caller's credential, and whether the database is SQLite.
fn membership(shared: &Shared, call: &Call) -> Result<(Membership, bool), RouteError> {
    let credential = call.credential(shared)?;
    let now = call.now;
    shared
        .storage
        .transact(move |tx| {
            Box::pin(async move {
                let single = tx.dialect() == Dialect::Sqlite;
                Ok((query_members(tx, &credential, now).await?, single))
            })
        })
        .map_err(|failure| node_error(&failure))
}

/// `nodes/local`: this node's control status, with a fresh operation id for its next
/// command.
fn status(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let (membership, _) = membership(shared, call)?;
    let mut operation = [0u8; 16];
    while operation == [0; 16] {
        operation = crate::random::array().map_err(|_| RouteError::Unavailable)?;
    }
    let commands = &shared.commands;
    let status = Status {
        operation_id: hex_id(&operation),
        node: shared.identity.node_id,
        boot: hex_id(&shared.identity.boot),
        control_revision: commands.control_revision(),
        draining: shared.node.is_draining(),
        connections: shared.node.connection_count(),
        active_ban_entries: shared.node.active_bans(call.now).unwrap_or(0),
        committed: membership.committed,
        applied: shared.node.applied_revision(),
        observed_at: call.now,
        uptime_ms: commands.uptime_ms(),
        completion_pending: commands.is_pending(),
        ..Status::default()
    };
    Ok(reply::json(context, &status)?)
}

/// `nodes`: the membership page with probes and peer reports.
fn members(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let (membership, single) = membership(shared, call)?;
    let node = shared.identity.node_id;
    // The database answered this request, so the last round trip succeeded.
    let storage = Storage {
        role: if single { nodes::Role::Single } else { nodes::Role::Unknown },
        leader: single.then_some(node),
        quorum: true,
        observed_at: call.now,
        ..Storage::default()
    };
    let page = Page {
        self_node: node,
        committed: membership.committed,
        storage,
        members: membership.members,
    };
    let mut probes = Vec::new();
    shared.probes.snapshot(&mut probes);
    let mut peers = Vec::new();
    shared.peers.reports(call.now, &mut peers);
    let reply = MembersReply { page: &page, probes: &probes, peers: &peers, now: call.now };
    Ok(reply::json(context, &reply)?)
}

/// The membership reply in Zig's shape.
struct MembersReply<'a> {
    page: &'a Page,
    probes: &'a [nodes::Probe],
    peers: &'a [nodes::Peer],
    now: u64,
}

impl Encode for MembersReply<'_> {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "page", self.page)?;
        field(json, "probes", self.probes)?;
        field(json, "peers", self.peers)?;
        field(json, "observed_at", &self.now)?;
        json.end_object()
    }
}

/// Parses an operation id or boot: 32 hex digits, not all zeros.
fn identifier(text: &str) -> Result<[u8; 16], RouteError> {
    let mut bytes = [0u8; 16];
    if text.len() != 32
        || sibuna_encoding::hex::decode_to_slice(text.as_bytes(), &mut bytes).is_err()
    {
        return Err(RouteError::BadRequest);
    }
    if bytes == [0; 16] {
        return Err(RouteError::BadRequest);
    }
    Ok(bytes)
}

/// The body of `nodes/command`.
struct CommandForm {
    id: String,
    boot: String,
    node: u32,
    expected_revision: String,
    kind: Kind,
}

impl Decode for CommandForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<CommandForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = CommandForm {
            id: fields.required("id")?,
            boot: fields.required("boot")?,
            node: fields.required("node")?,
            expected_revision: fields.required("expected_revision")?,
            kind: fields.required("kind")?,
        };
        fields.finish()?;
        Ok(form)
    }
}

/// `nodes/command`: one local command, valid for [`nodes::COMMAND_SECONDS`].
fn command(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let mut body = [0u8; 1024];
    let form: CommandForm = read_json(context, &mut body)?;
    let command = Command {
        auth: call.auth(shared)?,
        id: identifier(&form.id)?,
        boot: identifier(&form.boot)?,
        node: form.node,
        expected_revision: super::policies::decimal(&form.expected_revision)?,
        expires: call.now.saturating_add(nodes::COMMAND_SECONDS),
        kind: form.kind,
    };
    let credential = call.credential(shared)?;
    let receipt = shared.commands.execute(shared, &credential, &command)?;
    Ok(reply::json(context, &receipt)?)
}

/// The body of `nodes/command/read`.
struct ReadForm {
    id: String,
}

impl Decode for ReadForm {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<ReadForm, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let form = ReadForm { id: fields.required("id")? };
        fields.finish()?;
        Ok(form)
    }
}

/// `nodes/command/read`: a command's receipt; an unrecorded completion of this console
/// reads as it was shown.
fn read(shared: &Shared, context: &mut Context<'_>, call: &Call) -> Result<(), RouteError> {
    let mut body = [0u8; 128];
    let form: ReadForm = read_json(context, &mut body)?;
    let input = nodes::Read { auth: call.auth(shared)?, id: identifier(&form.id)? };
    let id = input.id;
    let credential = call.credential(shared)?;
    let now = call.now;
    let stored = shared
        .storage
        .transact(move |tx| {
            Box::pin(async move { read_command(tx, &credential, &input, now).await })
        })
        .map_err(|failure| node_error(&failure))?;
    let receipt = shared.commands.pending_receipt(&id).unwrap_or(stored);
    Ok(reply::json(context, &receipt)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sibuna_console_protocol::codec::from_json;

    #[test]
    fn identifiers_are_32_hex_digits_and_never_zero() {
        assert_eq!(identifier(&"0a".repeat(16)), Ok([10; 16]));
        assert_eq!(identifier(&"0".repeat(32)), Err(RouteError::BadRequest));
        assert_eq!(identifier(&"0a".repeat(15)), Err(RouteError::BadRequest));
        assert_eq!(identifier(&"zz".repeat(16)), Err(RouteError::BadRequest));
        let form: CommandForm = from_json(
            br#"{"id":"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a","boot":"07070707070707070707070707070707",
            "node":1,"expected_revision":"7","kind":"clear_local_bans"}"#,
        )
        .unwrap();
        assert_eq!(form.kind, Kind::ClearLocalBans);
    }
}
