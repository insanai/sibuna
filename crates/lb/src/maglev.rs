//! Deterministic weighted Maglev. Only the configuration thread builds permutations.

use std::net::SocketAddr;

use sibuna_crypto::wyhash::hash;

use crate::config::Server;

// Prime, so every nonzero stride visits the entire table.
const SIZE: usize = 65537;
const EMPTY: u8 = u8::MAX;

pub(crate) struct Table {
    slots: Box<[u8]>,
    pub factor: u32,
    pub weight: u32,
}

impl Table {
    /// Servers are already in stable name order. Backups take no primary slots.
    pub fn build(servers: &[Server], factor: u32) -> Option<Self> {
        let mut permutations = Vec::new();
        let mut weight = 0;
        for (index, server) in servers.iter().enumerate().filter(|(_, s)| !s.backup) {
            let key = server.name.as_bytes();
            let offset = (hash(0, key) % SIZE as u64) as usize;
            let stride = 1 + (hash(1, key) % (SIZE - 1) as u64) as usize;
            permutations.push((index as u8, offset, stride, server.weight, 0i64));
            weight += server.weight;
        }
        if permutations.is_empty() {
            return None;
        }
        let mut slots = vec![EMPTY; SIZE].into_boxed_slice();
        for _ in 0..SIZE {
            let mut best = 0;
            for i in 0..permutations.len() {
                permutations[i].4 += i64::from(permutations[i].3);
                if permutations[i].4 > permutations[best].4 {
                    best = i;
                }
            }
            let (index, next, stride, _, credit) = &mut permutations[best];
            *credit -= i64::from(weight);
            while slots[*next] != EMPTY {
                *next = (*next + *stride) % SIZE;
            }
            slots[*next] = *index;
            *next = (*next + *stride) % SIZE;
        }
        Some(Self { slots, weight, factor })
    }

    pub fn primary(&self, peer: SocketAddr, vip: SocketAddr) -> usize {
        fn endpoint(addr: SocketAddr) -> [u8; 18] {
            let mut key = [0; 18];
            let ip = match addr.ip() {
                std::net::IpAddr::V4(ip) => ip.to_ipv6_mapped(),
                std::net::IpAddr::V6(ip) => ip,
            };
            key[..16].copy_from_slice(&ip.octets());
            key[16..].copy_from_slice(&addr.port().to_be_bytes());
            key
        }
        let key = hash(hash(2, &endpoint(vip)), &endpoint(peer));
        usize::from(self.slots[(key % SIZE as u64) as usize])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weighted_primary_table_is_reproducible_and_excludes_backups() {
        let make = |name: &str, weight, backup| Server {
            name: name.into(),
            addr: ([127, 0, 0, 1], 443).into(),
            weight,
            limit: 20,
            backup,
            remote: false,
            via: None,
            healthy: None,
            info: None,
        };
        let servers = [make("alpha", 1, false), make("beta", 3, false), make("gamma", 5, true)];
        let table = Table::build(&servers, 125).expect("two primaries");
        assert_eq!(table.slots, Table::build(&servers, 125).expect("two primaries").slots);
        let alpha = table.slots.iter().filter(|&&id| id == 0).count();
        assert!(alpha.abs_diff(SIZE / 4) <= 1);
        assert!(table.slots.iter().all(|id| *id < 2));
    }
}
