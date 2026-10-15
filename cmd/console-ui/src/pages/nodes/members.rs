//! The replicated member rows, the unobserved probes and the management peers' live
//! telemetry (`nodes_page.zig` `members`, `peer_page.zig`), and the gauge sparklines of
//! the serving node.
//!
//! Ephemeral peer observations stay separate from replicated membership and probe
//! health; a counter that was never observed reads as such, never as zero.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::codec::WireEnum;
use sibuna_console_protocol::nodes::{Health, Member, Peer, PeerStatus};

use super::{Nodes, Peers};
use crate::format;
use crate::render::{Html, value};
use crate::snippets;
use crate::state::State;

/// The health a member shows: the serving node is the live node rendering this page and
/// is never probed; any other member takes its probe's verdict.
fn health(peers: &Peers, member: &Member) -> Health {
    let initial = if member.node == peers.self_node { Health::Healthy } else { Health::Unknown };
    peers
        .probes
        .iter()
        .filter(|probe| probe.node == member.node)
        .fold(initial, |_, probe| probe.health)
}

/// The sort key of a member: unhealthy first, then unobserved, then healthy; the leader
/// leads its group; then by node id.
fn order(peers: &Peers, member: &Member) -> (u8, bool, bool, u32) {
    let rank = match health(peers, member) {
        Health::Down => 0,
        Health::Degraded => 1,
        Health::Unknown => 2,
        Health::Healthy => 3,
    };
    let leader = peers.storage.leader == Some(member.node);
    (rank, member.last_seen != 0, !leader, member.node)
}

/// Draws the member rows.
pub(super) fn render(model: &Nodes, state: &State, out: &mut Html<'_>) -> fmt::Result {
    let peers = &model.peers;
    if !peers.loaded {
        return out.write_str("<p class=\"sb-note\">Cluster membership not loaded yet.</p>");
    }
    out.write_str("<h2>Members</h2><p role=\"status\">")?;
    value(out, &peers.members.len())?;
    out.write_str(" member rows \u{b7} ")?;
    value(out, &peers.probes.len())?;
    out.write_str(" probed peers \u{b7} leader ")?;
    value(out, &peers.storage.leader.unwrap_or(0))?;
    out.write_str(" \u{b7} quorum ")?;
    out.write_str(if peers.storage.quorum { "available" } else { "not established" })?;
    out.write_str(" \u{b7} page age ")?;
    value(out, &state.browser_time.saturating_sub(peers.received_at))?;
    out.write_str(" s</p>")?;
    // An insertion sort over at most nine rows: the standard library's stable sort would
    // add about 14 KB of code to the module for this one list.
    let mut sorted: Vec<&Member> = Vec::with_capacity(peers.members.len());
    for member in &peers.members {
        let key = order(peers, member);
        let at = sorted.iter().position(|placed| order(peers, placed) > key);
        sorted.insert(at.unwrap_or(sorted.len()), member);
    }
    for member in sorted {
        member_row(peers, member, out)?;
    }
    for probe in &peers.probes {
        if peers.members.iter().any(|member| member.node == probe.node) {
            continue;
        }
        out.write_str("<section class=\"sb-panel\"><h2>Node ")?;
        value(out, &probe.node)?;
        out.write_str(
            " \u{b7} unobserved</h2><p>Configured for probing but no membership row has been \
             replicated. Counters are unavailable, not zero.</p></section>",
        )?;
    }
    Ok(())
}

fn member_row(peers: &Peers, member: &Member, out: &mut Html<'_>) -> fmt::Result {
    let own = member.node == peers.self_node;
    let probe = peers.probes.iter().rfind(|probe| probe.node == member.node).map(|probe| {
        format!(
            "{}, {} ms, {} requests since last probe",
            probe.health.name(),
            probe.latency_ms,
            probe.requests
        )
    });
    let health = if own {
        "serving this console"
    } else {
        match health(peers, member) {
            Health::Healthy => "healthy",
            Health::Degraded => "degraded (draining)",
            Health::Down => "unreachable",
            Health::Unknown => "not probed",
        }
    };
    let summary = if member.draining {
        "Draining: new connections are refused."
    } else if own {
        "This node."
    } else {
        "Announced through replicated storage."
    };
    let leader = peers.storage.leader == Some(member.node);
    let behind = member.applied_revision < peers.committed;
    snippets::render_nodes_member(
        out,
        &snippets::NodesMemberValues {
            node: &member.node,
            health: &health,
            leader: &if leader { " \u{b7} leader" } else { "" },
            summary: &summary,
            address: &member.address.as_str(),
            version: &member.version.as_str(),
            applied: &member.applied_revision,
            ack: &if behind { "behind committed" } else { "applied" },
            seen: &if member.last_seen == 0 { "never" } else { "recorded" },
            probe: &probe.as_deref().unwrap_or("not configured"),
        },
    )?;
    if !member.console_url.is_empty() && !own {
        out.write_str("<a class=\"btn btn-sm\" href=\"")?;
        out.escaped(member.console_url.as_str())?;
        out.write_str("\" rel=\"noopener noreferrer\" target=\"_blank\">Open console</a>")?;
    }
    out.write_str("</section>")
}

/// Draws the management peers' live telemetry.
pub(super) fn render_peers(model: &Nodes, state: &State, out: &mut Html<'_>) -> fmt::Result {
    let peers = &model.peers;
    if !peers.loaded {
        return Ok(());
    }
    out.write_str(
        "<section class=\"sb-panel sb-users\" aria-labelledby=\"peer-telemetry\">\
         <h2 id=\"peer-telemetry\">Live peer telemetry</h2>",
    )?;
    if peers.direct.is_empty() {
        out.write_str("<p>No management peers configured.</p>")?;
    }
    let elapsed = state.browser_time.saturating_sub(peers.received_at);
    for peer in &peers.direct {
        peer_row(peer, elapsed, out)?;
    }
    out.write_str("</section>")
}

/// Returns `value` in decimal, or "not observed".
fn observed(value: Option<u64>) -> String {
    value.map_or_else(|| "not observed".to_owned(), |number| number.to_string())
}

fn peer_row(peer: &Peer, elapsed: u64, out: &mut Html<'_>) -> fmt::Result {
    let age = peer.age_seconds.map(|age| age.saturating_add(elapsed));
    let stale = age.is_some_and(|age| age >= 10);
    let status =
        if stale && peer.status == PeerStatus::Current { "stale" } else { peer.status.name() };
    snippets::render_peer_observation(
        out,
        &snippets::PeerObservationValues {
            node: &peer.node,
            status: &status,
            age: &observed(age),
            skew: &observed(peer.clock_skew_seconds),
            requests: &observed(peer.requests),
            loss: &observed(peer.sample_loss),
            memory: &observed(peer.rss_kib),
            cpu: &observed(peer.cpu_permille.map(u64::from)),
            boot: &peer.boot.as_ref().map_or("not observed", |boot| boot.as_str()),
            resets: &peer.resets,
            sequence: &peer.sequence,
            watermark: &peer.watermark,
        },
    )
}

/// Draws the sparkline of the serving node's resident memory (`memory`) or CPU over the
/// last 60 seconds of the live series (Zig's `outcome_sparkline.renderGauge`). Missing
/// seconds break the line.
pub(super) fn gauge_sparkline(
    state: &State,
    memory: bool,
    label: &str,
    out: &mut Html<'_>,
) -> fmt::Result {
    let Some(stats) = &state.stats else { return series(&[None; 60], label, out) };
    let mut points = [None; 60];
    for (index, point) in points.iter_mut().enumerate() {
        let second = stats.timestamp.saturating_sub(59 - index as u64);
        // `Series` indexes by the second modulo 60.
        let sample = &state.points[(second % 60) as usize];
        if sample.second != second {
            continue;
        }
        *point = if memory {
            sample.rss_kib.map(|kib| kib as f64)
        } else {
            sample.cpu_permille.map(|permille| f64::from(permille) / 10.0)
        };
    }
    series(&points, label, out)
}

fn series(points: &[Option<f64>; 60], label: &str, out: &mut Html<'_>) -> fmt::Result {
    let maximum = points.iter().flatten().fold(1.0_f64, |maximum, value| maximum.max(*value));
    let observed = points.iter().flatten().count();
    out.write_str(
        "<svg class=\"sb-sparkline\" viewBox=\"0 0 180 40\" role=\"img\" aria-label=\"",
    )?;
    out.escaped(label)?;
    out.write_str(", last 60 seconds; ")?;
    value(out, &observed)?;
    out.write_str(
        " observed intervals\"><path fill=\"none\" stroke=\"currentColor\" \
         stroke-width=\"1.5\" d=\"",
    )?;
    let mut connected = false;
    for (index, point) in points.iter().enumerate() {
        let Some(rate) = point else {
            connected = false;
            continue;
        };
        out.write_str(if connected { "L" } else { "M" })?;
        value(out, &(index * 3))?;
        out.write_str(",")?;
        format::decimal(out, 38.0 - rate / maximum * 36.0, 2)?;
        out.write_str(" ")?;
        connected = true;
    }
    out.write_str("\"/></svg>")
}
