//! The run-time commands of an operator as the mesh carries them (SID 0022).
//!
//! A command is one entry of a map from keys to numbers, merged by keeping the larger
//! number. The number starts with the Unix millisecond of the command, so the later
//! command for a key wins on every node, whatever the order of arrival.
//!
//! ```text
//!   command   key                          number
//!   member    a ADDRESS \n POOL/NAME       stamp << 17 | weight << 1 | present
//!   state     s POOL/NAME                  stamp << 1  | drained
//!   weight    w POOL/NAME                  stamp << 16 | weight
//! ```
//!
//! The keys sort with the members first. A node that returns is sent the map in that
//! order, so a server is added before its state and its weight are set.

use std::net::SocketAddr;

/// A command stamped further ahead of the receiver's clock than this is refused.
/// Without the bound one node with a wrong clock could overrule every later command.
pub(super) const AHEAD_MS: u64 = 60_000;

/// What an operator changed about one server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// The server was drained, or returned to rotation.
    State {
        /// The server takes no new flows.
        drained: bool,
    },
    /// The weight was set.
    Weight(u32),
    /// The server at `addr` was added with `weight`, or removed.
    Member {
        /// The address of the server.
        addr: SocketAddr,
        /// The weight it was added with. Zero for a removal.
        weight: u32,
        /// The server was added. False for a removal.
        present: bool,
    },
}

/// One run-time command of an operator, as a peer applies it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    /// The pool of the server.
    pub pool: String,
    /// The name of the server in its pool.
    pub name: String,
    /// What changed.
    pub change: Change,
}

/// The bits of a number below its stamp, by the first byte of the key.
fn shift(tag: u8) -> Option<u32> {
    match tag {
        b'a' => Some(17),
        b's' => Some(1),
        b'w' => Some(16),
        _ => None,
    }
}

/// The key and the number of `command`, issued at the Unix millisecond `stamp_ms`.
pub(super) fn encode(command: &Command, stamp_ms: u64) -> (Vec<u8>, u64) {
    let server = format!("{}/{}", command.pool, command.name);
    let weight = |weight: u32| u64::from(weight.min(0xffff));
    let (key, low, tag) = match command.change {
        Change::Member { addr, weight: w, present } => {
            (format!("a{addr}\n{server}"), weight(w) << 1 | u64::from(present), b'a')
        }
        Change::State { drained } => (format!("s{server}"), u64::from(drained), b's'),
        Change::Weight(w) => (format!("w{server}"), weight(w), b'w'),
    };
    let shift = shift(tag).unwrap_or(1);
    (key.into_bytes(), (stamp_ms << shift) | low)
}

/// A received number as it may be merged: `None` for a key of no known form, and for a
/// stamp too far ahead of `now_ms`.
pub(super) fn admit(key: &[u8], value: u64, now_ms: u64) -> Option<u64> {
    let shift = shift(*key.first()?)?;
    ((value >> shift) <= now_ms.saturating_add(AHEAD_MS)).then_some(value)
}

/// The command that an entry of the map states. `None` for an entry of no known form.
pub(super) fn decode(key: &[u8], value: u64) -> Option<Command> {
    let text = std::str::from_utf8(key.get(1..)?).ok()?;
    let (addr, server) = match key[0] {
        b'a' => {
            let (addr, server) = text.split_once('\n')?;
            (Some(addr.parse::<SocketAddr>().ok()?), server)
        }
        _ => (None, text),
    };
    let (pool, name) = server.split_once('/')?;
    let change = match (key[0], addr) {
        (b'a', Some(addr)) => Change::Member {
            addr,
            weight: ((value >> 1) & 0xffff) as u32,
            present: value & 1 == 1,
        },
        (b's', _) => Change::State { drained: value & 1 == 1 },
        (b'w', _) => Change::Weight((value & 0xffff) as u32),
        _ => return None,
    };
    Some(Command { pool: pool.to_owned(), name: name.to_owned(), change })
}

#[cfg(test)]
mod tests {
    use super::super::bans::Log;
    use super::*;

    fn command(change: Change) -> Command {
        Command { pool: "app".to_owned(), name: "a/b".to_owned(), change }
    }

    #[test]
    fn every_command_survives_its_entry() {
        let addr = "[2001:db8::1]:8080".parse().unwrap();
        let changes = [
            Change::State { drained: true },
            Change::State { drained: false },
            Change::Weight(65_535),
            Change::Member { addr, weight: 7, present: true },
            Change::Member { addr, weight: 0, present: false },
        ];
        for change in changes {
            let (key, value) = encode(&command(change), 1_800_000_000_000);
            assert!(key.len() <= super::super::bans::MAX_KEY);
            assert_eq!(decode(&key, value), Some(command(change)));
        }
        assert_eq!(decode(b"xapp/a", 1), None);
        assert_eq!(decode(b"anot-an-address\napp/a", 1), None);
        assert_eq!(decode(b"snostroke", 1), None);
    }

    #[test]
    fn the_later_command_wins_whatever_the_order_of_arrival() {
        let (key, drain) = encode(&command(Change::State { drained: true }), 1_000);
        let (_, ready) = encode(&command(Change::State { drained: false }), 2_000);
        for order in [[drain, ready], [ready, drain]] {
            let mut log = Log::new(4);
            for value in order {
                log.keep_larger(&key, value).unwrap();
            }
            assert_eq!(log.all(), [(key.clone().into_boxed_slice(), ready)]);
        }
        // Two commands in the same millisecond agree on every node: the drain wins.
        let (_, same) = encode(&command(Change::State { drained: false }), 1_000);
        assert!(drain > same);
        // A later, smaller weight beats an earlier, larger one.
        let (_, heavy) = encode(&command(Change::Weight(65_535)), 1_000);
        let (_, light) = encode(&command(Change::Weight(1)), 1_001);
        assert!(light > heavy);
    }

    #[test]
    fn a_stamp_far_ahead_of_the_clock_is_refused() {
        let now = 1_000_000;
        for change in [Change::State { drained: true }, Change::Weight(9)] {
            let (key, value) = encode(&command(change), now + AHEAD_MS);
            assert_eq!(admit(&key, value, now), Some(value));
            let (key, value) = encode(&command(change), now + AHEAD_MS + 1);
            assert_eq!(admit(&key, value, now), None);
        }
        assert_eq!(admit(b"xapp/a", 2, now), None);
        assert_eq!(admit(b"", 2, now), None);
    }

    #[test]
    fn a_full_map_refuses_a_new_key_and_still_updates_a_known_one() {
        let mut log = Log::new(1);
        log.keep_larger(b"sapp/a", 2).unwrap();
        assert_eq!(log.keep_larger(b"sapp/b", 9), Err(()));
        assert_eq!(log.keep_larger(b"sapp/a", 9), Ok(Some(9)));
    }
}
