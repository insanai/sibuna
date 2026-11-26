//! The admission settings of a frontend under attack (SID 0034): its caps, how it
//! refuses, its automatic bans and the packet budget of a UDP frontend.

use std::hash::{DefaultHasher, Hash, Hasher};
use std::io;
use std::time::Duration;

use sibuna_json::ObjectReader;

use crate::budget::Caps;
use crate::config::{Protocol, duration, field, invalid, number};

/// The most flows of one address that `max_flows_per_ip` may allow.
const MAX_PER_IP: usize = 1_000_000;
/// How long a tarpit holds a refused connection.
pub(crate) const TARPIT: Duration = Duration::from_secs(10);

/// How a refused TCP connection ends (`refuse`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Refuse {
    /// A reset: no orderly close, no `TIME_WAIT` state.
    #[default]
    Reset,
    /// An orderly close.
    Close,
    /// Held without reading for [`TARPIT`], then reset.
    Tarpit,
}

/// Automatic bans of a frontend (`auto_ban`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AutoBan {
    /// The strikes an address may collect in `window` before it is banned.
    pub strikes: u32,
    /// The window of the strikes.
    pub window: Duration,
    /// How long the ban lasts.
    pub ban: Duration,
}

/// What the admission of a frontend checks beyond its connection rate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Guard {
    pub caps: Caps,
    pub refuse: Refuse,
    pub auto_ban: Option<AutoBan>,
    /// The datagrams a second that a UDP frontend passes (`udp_defense.total_pps`).
    pub total_pps: Option<u32>,
}

/// A stable number for a frontend name, so that counts held under it survive a reload.
fn frontend_key(name: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    hasher.finish()
}

impl Guard {
    /// Reads `max_flows`, `max_flows_per_ip`, `refuse` and `auto_ban` of the frontend
    /// `name`. `node_limit` is `global.max_flows`; `total_pps` was read with
    /// `udp_defense`. Fails with a hint when a value is out of range or does not fit
    /// the protocol.
    pub fn parse(
        r: &mut ObjectReader<'_, '_>,
        name: &str,
        proto: Protocol,
        node_limit: usize,
        total_pps: Option<u32>,
    ) -> io::Result<Self> {
        let max_flows = optional(r, "max_flows", node_limit)?;
        let max_flows_per_ip = optional(r, "max_flows_per_ip", MAX_PER_IP)?;
        let refuse = match field(r.take_str("refuse"))? {
            None => Refuse::default(),
            Some(_) if proto == Protocol::Udp => {
                return Err(invalid(format!(
                    "{}: a UDP frontend drops what it refuses. Hint: remove refuse, or use it \
                     on a tcp or http frontend.",
                    r.field_path("refuse")
                )));
            }
            Some("reset") => Refuse::Reset,
            Some("close") => Refuse::Close,
            Some("tarpit") => Refuse::Tarpit,
            Some(other) => {
                return Err(invalid(format!(
                    "{}: expected reset, close or tarpit, found {other:?}. Hint: reset is \
                     the default and the cheapest.",
                    r.field_path("refuse")
                )));
            }
        };
        let auto_ban = auto_ban(r, proto)?;
        let caps = Caps { frontend: frontend_key(name), max_flows, max_flows_per_ip };
        Ok(Self { caps, refuse, auto_ban, total_pps })
    }
}

/// Reads an optional count from 1 to `max`.
fn optional(r: &mut ObjectReader<'_, '_>, key: &str, max: usize) -> io::Result<Option<usize>> {
    Ok(match number(r, key, 0, max)? {
        0 => None,
        n => Some(n),
    })
}

/// Reads `auto_ban`: `{strikes, window, ban}`. A UDP frontend may not ban by its own
/// refusals, since a spoofed source would ban the owner of the address.
fn auto_ban(r: &mut ObjectReader<'_, '_>, proto: Protocol) -> io::Result<Option<AutoBan>> {
    let Some(mut ban) = field(r.take_object("auto_ban"))? else { return Ok(None) };
    if proto == Protocol::Udp {
        return Err(invalid(format!(
            "{}: a UDP source address can be forged, so a ban by its refusals could ban the \
             owner of the address. Hint: remove auto_ban from the UDP frontend; bans from the \
             HTTP firewall and the operator still apply to it.",
            ban.path()
        )));
    }
    let strikes = number(&mut ban, "strikes", 0, 1_000_000)?;
    if strikes == 0 {
        return Err(invalid(format!(
            "{}: auto_ban needs strikes. Hint: write {{\"strikes\": 50, \"window\": \"10s\", \
             \"ban\": \"10m\"}}.",
            ban.path()
        )));
    }
    let window = span(&mut ban, "window", Duration::from_secs(10), Duration::from_secs(3600))?;
    let length = span(&mut ban, "ban", Duration::from_secs(600), Duration::from_secs(86_400))?;
    field(ban.finish())?;
    Ok(Some(AutoBan { strikes: strikes as u32, window, ban: length }))
}

/// Reads a duration from one second to `max`, or `default` when absent.
fn span(
    r: &mut ObjectReader<'_, '_>,
    key: &str,
    default: Duration,
    max: Duration,
) -> io::Result<Duration> {
    let Some(text) = field(r.take_str(key))? else { return Ok(default) };
    duration(text).filter(|d| (Duration::from_secs(1)..=max).contains(d)).ok_or_else(|| {
        invalid(format!(
            "{}: expected a duration from 1s to {}s, found {text:?}. Hint: write digits with \
             s, m or h, such as \"10s\".",
            r.field_path(key),
            max.as_secs()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_has_one_key_across_parses() {
        assert_eq!(frontend_key("web"), frontend_key("web"));
        assert_ne!(frontend_key("web"), frontend_key("api"));
    }
}
