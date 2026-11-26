//! The ban table of a node and its automatic bans (SID 0034).
//!
//! The packet worker, the accept threads and the HTTP firewall share one [`Defense`]. It
//! holds the ban table, the keyed hasher that both sides know a client by, the strikes
//! of automatic bans, and the feeds that hand bans to the peers of the mesh (SID 0022).
//! A client address is known by [`sibuna_cidr::client_key_bytes`] with IPv6 cut to
//! [`IPV6_PREFIX`], the bytes the firewall uses.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use sibuna_store::ban_table::BanTable;
use sibuna_store::limiter::{Limits, RateLimiter};
use sibuna_store::placement::{ClientHash, ClientHasher};

use crate::guard::AutoBan;
use crate::{BanFeed, LiftFeed, Mesh};

/// The prefix that an IPv6 client address is cut to, as in the HTTP firewall.
pub const IPV6_PREFIX: u8 = 64;
/// The cells of the strike counters.
const STRIKE_CELLS: usize = 65_536;

/// The bans of a node, shared by every path that admits a client.
pub struct Defense {
    bans: BanTable,
    hasher: ClientHasher,
    strikes: RateLimiter,
    ban_feed: OnceLock<BanFeed>,
    lift_feed: OnceLock<LiftFeed>,
    epoch: Instant,
}

impl Defense {
    /// A defense with an empty ban table of about `ban_slots` slots (see
    /// [`BanTable::with_capacity`]) and fresh secret keys. Never fails.
    pub fn new(ban_slots: usize) -> Self {
        Self {
            bans: BanTable::with_capacity(ban_slots),
            hasher: ClientHasher::new(),
            strikes: RateLimiter::with_cells(STRIKE_CELLS),
            ban_feed: OnceLock::new(),
            lift_feed: OnceLock::new(),
            epoch: Instant::now(),
        }
    }

    /// The ban table. A caller that bans by hash uses [`Defense::hasher`] for the hash.
    pub fn bans(&self) -> &BanTable {
        &self.bans
    }

    /// The keyed hasher of client keys, shared with the rate limiters of the firewall.
    pub fn hasher(&self) -> &ClientHasher {
        &self.hasher
    }

    /// Where a ban issued here goes to the peers, once the mesh shares bans.
    pub fn ban_feed(&self) -> Option<&BanFeed> {
        self.ban_feed.get()
    }

    /// Where a ban that the operator lifts goes to the peers.
    pub fn lift_feed(&self) -> Option<&LiftFeed> {
        self.lift_feed.get()
    }

    fn hash(&self, address: IpAddr) -> ClientHash {
        self.hasher.hash(&sibuna_cidr::client_key_bytes(address, IPV6_PREFIX))
    }

    /// True when the client at `address` is banned at the Unix second `now`.
    pub fn is_banned(&self, address: IpAddr, now: u64) -> bool {
        self.bans.is_banned_hashed(self.hash(address), now)
    }

    /// Bans the client at `address` until the Unix second `until` and tells the peers.
    /// Returns false when the table refused the ban: its probe window holds only bans
    /// in effect.
    pub fn ban(&self, address: IpAddr, until: u64, now: u64) -> bool {
        if self.bans.ban_hashed(self.hash(address), until, now).is_err() {
            return false;
        }
        if let Some(feed) = self.ban_feed.get() {
            feed.publish(&sibuna_cidr::client_key_bytes(address, IPV6_PREFIX), until);
        }
        true
    }

    /// Lifts the ban of the client at `address`, and with `share` tells the peers.
    pub fn lift(&self, address: IpAddr, share: bool) {
        let key = sibuna_cidr::client_key_bytes(address, IPV6_PREFIX);
        self.bans.lift_hashed(self.hasher.hash(&key));
        if let (true, Some(feed)) = (share, self.lift_feed.get()) {
            feed.publish(&key);
        }
    }

    /// Counts a strike of the client at `address` under `rule` of the frontend `scope`
    /// at the Unix second `now`. Returns true when the strike banned the address: it
    /// had more than `rule.strikes` strikes in `rule.window`.
    pub(crate) fn strike(&self, address: IpAddr, scope: u64, rule: AutoBan, now: u64) -> bool {
        let micros = self.epoch.elapsed().as_micros() as u64;
        let limits = Limits { rate: rule.strikes, window_ms: rule.window.as_micros() as u64 };
        let key = sibuna_cidr::client_key_bytes(address, IPV6_PREFIX);
        if !self.strikes.check_scoped(&key, scope, micros, limits).limited {
            return false;
        }
        self.ban(address, now.saturating_add(rule.ban.as_secs()), now)
    }

    /// Shares bans with the peers of `mesh`: a ban issued here goes to them, and a ban
    /// or a lift they issue enters the table here. A ban of a peer that the table
    /// refuses calls `refused`. Returns false when the mesh does not replicate bans. The
    /// first call that shares stays.
    pub fn share(
        self: &Arc<Self>,
        mesh: &Mesh,
        refused: impl Fn() + Send + Sync + 'static,
    ) -> bool {
        let defense = Arc::clone(self);
        let sink = Box::new(move |client: &[u8], until: u64| {
            let hash = defense.hasher.hash(client);
            if defense.bans.ban_hashed(hash, until, unix_now()).is_err() {
                refused();
            }
        });
        let Some(feed) = mesh.share_bans(sink) else { return false };
        let _ = self.ban_feed.set(feed);
        let defense = Arc::clone(self);
        let lift = move |client: &[u8]| defense.bans.lift_hashed(defense.hasher.hash(client));
        if let Some(feed) = mesh.share_lifts(Box::new(lift)) {
            let _ = self.lift_feed.set(feed);
        }
        true
    }
}

/// The Unix time in seconds, zero before 1970.
pub(crate) fn unix_now() -> u64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    since.map_or(0, |since| since.as_secs())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_ban_holds_for_every_spelling_of_an_address_and_its_prefix() {
        let defense = Defense::new(1024);
        let now = 1_000;
        assert!(defense.ban("192.0.2.7".parse().unwrap(), now + 60, now));
        assert!(defense.is_banned("::ffff:192.0.2.7".parse().unwrap(), now));
        assert!(!defense.is_banned("192.0.2.8".parse().unwrap(), now));
        assert!(!defense.is_banned("192.0.2.7".parse().unwrap(), now + 61));
        assert!(defense.ban("2001:db8:1:2::1".parse().unwrap(), now + 60, now));
        assert!(defense.is_banned("2001:db8:1:2:ffff::9".parse().unwrap(), now));
        defense.lift("2001:db8:1:2::5".parse().unwrap(), false);
        assert!(!defense.is_banned("2001:db8:1:2::1".parse().unwrap(), now));
    }

    #[test]
    fn strikes_within_the_rule_never_ban_and_one_more_does() {
        let defense = Defense::new(1024);
        let rule = AutoBan {
            strikes: 5,
            window: Duration::from_secs(3600),
            ban: Duration::from_secs(60),
        };
        let address = "198.51.100.1".parse().unwrap();
        for _ in 0..5 {
            assert!(!defense.strike(address, 1, rule, 100));
        }
        assert!(!defense.is_banned(address, 100));
        assert!(defense.strike(address, 1, rule, 100));
        assert!(defense.is_banned(address, 100));
        assert!(!defense.is_banned(address, 161));
        // Another frontend counts its own strikes.
        let other = "198.51.100.2".parse().unwrap();
        assert!(!defense.strike(other, 2, rule, 100));
    }
}
