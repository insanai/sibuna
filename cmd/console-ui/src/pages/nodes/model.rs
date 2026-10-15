//! The Nodes page's state and the validation of its replies (`nodes_state.zig`).

use sibuna_console_protocol::Text;
use sibuna_console_protocol::codec::{Decode, Fields, Path, decode_list};
use sibuna_console_protocol::nodes::{
    self, Kind, MAX_PROBES, Member, Peer, Probe, Receipt, State as Effect, Status, Storage,
};
use sibuna_json::Value;

use crate::error::UiError;

/// The most local ban entries a node reports.
const MAX_BAN_ENTRIES: u64 = 4096;

/// The largest control revision; a command must be able to raise it by one.
pub const MAX_REVISION: u64 = i64::MAX as u64;

/// What the newest status or command request does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Busy {
    /// Nothing is in flight.
    #[default]
    Idle,
    /// Reads the local node's status.
    Status,
    /// Sends a command.
    Command,
    /// Reads a command's receipt.
    Receipt,
}

/// A command the operator previewed: its identity is the operation id, the boot and the
/// control revision the operator saw, kept across retries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Input {
    /// The operation id as hex.
    pub id: Text<32>,
    /// The target boot as hex.
    pub boot: Text<32>,
    /// The target node.
    pub node: u32,
    /// The control revision the operator saw.
    pub revision: u64,
    /// What to do.
    pub kind: Kind,
}

/// The replicated cluster view: member rows, this console's probes and the direct
/// telemetry of management peers. Requested on its own ticket, so a slow or failed
/// member page never fences commands.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Peers {
    /// The node serving this console.
    pub self_node: u32,
    /// The committed policy revision.
    pub committed: u64,
    /// The local consensus state.
    pub storage: Storage,
    /// At most `nodes::MAX_MEMBERS` members, in reply order.
    pub members: Vec<Member>,
    /// At most `nodes::MAX_PROBES` probes.
    pub probes: Vec<Probe>,
    /// At most `nodes::MAX_PROBES` peers' direct telemetry.
    pub direct: Vec<Peer>,
    /// When the view arrived, in browser seconds.
    pub received_at: u64,
    /// A view has arrived.
    pub loaded: bool,
    /// A member page request is in flight.
    pub busy: bool,
}

/// Returns true for 32 hex digits that are not all zero.
pub fn is_identifier(text: &str) -> bool {
    text.len() == 32
        && text.bytes().all(|byte| byte.is_ascii_hexdigit())
        && text.bytes().any(|byte| byte != b'0')
}

/// Reads and checks a local status reply.
///
/// # Errors
///
/// [`UiError::InvalidResponse`] for a malformed status, node zero, too many ban entries,
/// an exhausted revision or an invalid boot or operation id.
pub fn read_status(body: &Value<'_>) -> Result<Status, UiError> {
    let status = Status::decode(body, Path::Root)?;
    if status.node == 0
        || u64::from(status.active_ban_entries) > MAX_BAN_ENTRIES
        || status.control_revision > MAX_REVISION
        || !is_identifier(status.boot.as_str())
        || !is_identifier(status.operation_id.as_str())
    {
        return Err(UiError::InvalidResponse);
    }
    Ok(status)
}

/// Reads and checks a member view (`/console/api/nodes` or a live `nodes` view). Every
/// row and probe must validate before the view replaces the old one, so a transient
/// failure cannot blank the cluster view. Members outside the `page` object other than
/// the known ones are ignored, as Zig ignored them.
///
/// # Errors
///
/// [`UiError::InvalidResponse`] for a malformed view, a zero or repeated node, an unsafe
/// console link, or peer telemetry whose boot, counters and age disagree.
pub fn read_members(body: &Value<'_>) -> Result<Peers, UiError> {
    let mut outer = Fields::new(body, Path::Root)?;
    let page: nodes::Page = outer.required("page")?;
    let probes =
        outer.required_with("probes", |value, path| decode_list(value, path, MAX_PROBES))?;
    let _observed: u64 = outer.required("observed_at")?;
    let direct: Vec<Peer> =
        outer.or_with("peers", Vec::new(), |value, path| decode_list(value, path, MAX_PROBES))?;
    if page.self_node == 0 {
        return Err(UiError::InvalidResponse);
    }
    let member_valid = |(index, member): (usize, &Member)| {
        let link = member.console_url.as_str();
        member.node != 0
            && (link.is_empty() || nodes::safe_url(link))
            && !page.members[..index].iter().any(|seen| seen.node == member.node)
    };
    let probe_valid = |probe: &Probe| probe.node != 0;
    let peer_valid = |(index, peer): (usize, &Peer)| {
        peer.node != 0
            && peer.node != page.self_node
            && peer.boot.is_none() == peer.requests.is_none()
            && peer.requests.is_none() == peer.age_seconds.is_none()
            && peer.boot.as_ref().is_none_or(|boot| is_identifier(boot.as_str()))
            && !direct[..index].iter().any(|seen| seen.node == peer.node)
    };
    if !page.members.iter().enumerate().all(member_valid)
        || !probes.iter().all(probe_valid)
        || !direct.iter().enumerate().all(peer_valid)
    {
        return Err(UiError::InvalidResponse);
    }
    Ok(Peers {
        self_node: page.self_node,
        committed: page.committed,
        storage: page.storage,
        members: page.members,
        probes,
        direct,
        received_at: 0,
        loaded: true,
        busy: false,
    })
}

/// Reads a receipt and checks that it answers `pending` and that its state and effect
/// agree: an intent cannot establish a local effect, even if a malformed reply carries
/// completion fields.
///
/// # Errors
///
/// [`UiError::InvalidResponse`] for a malformed or contradictory receipt, or one of
/// another operation.
pub fn read_receipt(body: &Value<'_>, pending: &Input) -> Result<Receipt, UiError> {
    let receipt = Receipt::decode(body, Path::Root)?;
    let same = receipt.id == pending.id
        && receipt.boot == pending.boot
        && receipt.node == pending.node
        && receipt.kind == pending.kind
        && receipt.expected_revision == pending.revision;
    let terminal = matches!(receipt.state, Effect::Applied | Effect::Rejected);
    let completion =
        receipt.completed_at.is_some() == terminal && (!receipt.completion_persisted || terminal);
    let effect = if receipt.state == Effect::Applied {
        pending.revision < MAX_REVISION
            && receipt.applied_revision == Some(pending.revision + 1)
            && receipt.cleared_entries.is_some() == (receipt.kind == Kind::ClearLocalBans)
    } else {
        receipt.applied_revision.is_none() && receipt.cleared_entries.is_none()
    };
    let cleared = u64::from(receipt.cleared_entries.unwrap_or(0)) <= MAX_BAN_ENTRIES;
    if !same || !completion || !effect || !cleared {
        return Err(UiError::InvalidResponse);
    }
    Ok(receipt)
}
