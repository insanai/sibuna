//! Sticky sessions (SID 0019): the token of a server in a cookie, and the ranking of
//! servers for a client address.
//!
//! A token is a keyed hash of the pool name and the server name. It names a server to
//! the edge and to nobody else: a client cannot compute the token of a server it was not
//! given, so it cannot address the servers of a pool one by one.

use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;

use sibuna_crypto::{blake3, wyhash};

/// The length of a token: 16 hexadecimal digits, 64 bits of the hash.
pub(crate) const TOKEN_LEN: usize = 16;

/// The token of one server, as it stands in the cookie.
pub(crate) type Token = [u8; TOKEN_LEN];

/// The key of the sticky tokens of one edge.
#[derive(Clone)]
pub(crate) struct Key {
    bytes: [u8; blake3::KEY_LEN],
    /// A short name of the key, so that a cached token knows the key it was made with.
    pub tag: u64,
}

impl Key {
    /// Derives the key from the challenge seed of the node. Nodes that share the seed
    /// accept each other's cookies.
    pub fn derive(seed: &[u8]) -> Self {
        Self::new(blake3::derive_key("sibuna 2026-11 sticky session cookie", seed))
    }

    fn new(bytes: [u8; blake3::KEY_LEN]) -> Self {
        Self { bytes, tag: wyhash::hash(5, &bytes) }
    }

    /// The token of the server `server` of the pool `pool`.
    pub fn token(&self, pool: &str, server: &str) -> Token {
        let mut hasher = blake3::Hasher::new_keyed(&self.bytes);
        // The length keeps ("ab", "c") and ("a", "bc") apart.
        hasher.update(&(pool.len() as u64).to_le_bytes());
        hasher.update(pool.as_bytes());
        hasher.update(server.as_bytes());
        let digest = hasher.finalize();
        let mut token = [0; TOKEN_LEN];
        for (pair, byte) in token.as_chunks_mut::<2>().0.iter_mut().zip(digest) {
            *pair = [hex(byte >> 4), hex(byte & 15)];
        }
        token
    }
}

/// A key that lasts as long as the process, until the node's seed replaces it.
impl Default for Key {
    fn default() -> Self {
        let random = RandomState::new();
        let mut bytes = [0; blake3::KEY_LEN];
        for (index, chunk) in bytes.as_chunks_mut::<8>().0.iter_mut().enumerate() {
            *chunk = random.hash_one(index).to_le_bytes();
        }
        Self::new(bytes)
    }
}

fn hex(nibble: u8) -> u8 {
    b"0123456789abcdef"[usize::from(nibble & 15)]
}

/// The value of the cookie `name` in the `Cookie` fields `fields` of a request, when it
/// has the form of a token. The first such cookie counts.
pub(crate) fn presented<'a>(fields: &[&'a [u8]], name: &str) -> Option<&'a [u8]> {
    let pairs = fields.iter().flat_map(|field| field.split(|&byte| byte == b';'));
    pairs
        .filter_map(|pair| {
            let pair = pair.trim_ascii();
            let value = pair.strip_prefix(name.as_bytes())?.strip_prefix(b"=")?;
            (value.len() == TOKEN_LEN).then_some(value)
        })
        .next()
}

/// Appends the `Set-Cookie` line that gives a client the token of its server.
pub(crate) fn write_cookie(out: &mut Vec<u8>, name: &str, token: &Token, secure: bool) {
    out.extend_from_slice(b"Set-Cookie: ");
    out.extend_from_slice(name.as_bytes());
    out.push(b'=');
    out.extend_from_slice(token);
    out.extend_from_slice(b"; Path=/; HttpOnly; SameSite=Lax");
    if secure {
        out.extend_from_slice(b"; Secure");
    }
    out.extend_from_slice(b"\r\n");
}

/// The bytes of a client address without its port. An IPv4 address and its IPv6-mapped
/// form are one client.
pub(crate) fn client_bytes(address: IpAddr) -> [u8; 16] {
    match address {
        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(ip, |v4| v4.to_ipv6_mapped()).octets(),
    }
}

/// The distance of the server `server` from `client` in weighted rendezvous hashing.
/// The server with the smallest [`Distance`] is the client's own.
///
/// Each server draws a uniform number from the client and its own name. The classic
/// rule picks the largest `-weight / ln(draw)`. We compare `-log2(draw) / weight`
/// instead, in integers, so that every node ranks alike whatever its processor.
///
/// `seed` is the [`rank_seed`] of the server. It is computed once for each server, so
/// that ranking a pool costs one hash per server and not two.
pub(crate) fn distance(client: &[u8; 16], seed: u64, weight: u32) -> Distance {
    let draw = wyhash::hash(seed, client);
    // `draw | 1` keeps the logarithm defined. 64 - log2 is positive and at most 64.
    let cost = (64 << 16) - log2_q16(draw | 1);
    Distance { cost, weight: u64::from(weight.max(1)) }
}

/// The part of a server's draw that depends on its name alone.
pub(crate) fn rank_seed(server: &str) -> u64 {
    wyhash::hash(3, server.as_bytes())
}

/// A cost divided by a weight, compared without division.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Distance {
    cost: u64,
    weight: u64,
}

impl Distance {
    /// Whether `self` is strictly nearer than `other`.
    pub fn nearer_than(&self, other: &Self) -> bool {
        // cost < 2^23 and weight < 2^17, so the products fit.
        self.cost * other.weight < other.cost * self.weight
    }
}

/// The binary logarithm of `value` with 16 fractional bits. `value` is not zero.
fn log2_q16(value: u64) -> u64 {
    let whole = u64::from(63 - value.leading_zeros());
    // The mantissa in [1, 2) with 31 fractional bits, so that its square fits.
    let mut mantissa = (value << (63 - whole)) >> 32;
    let mut fraction = 0;
    for _ in 0..16 {
        mantissa = (mantissa * mantissa) >> 31;
        fraction <<= 1;
        if mantissa >= 1 << 32 {
            mantissa >>= 1;
            fraction |= 1;
        }
    }
    (whole << 16) | fraction
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn a_token_depends_on_the_key_the_pool_and_the_server() {
        let key = Key::derive(b"seed one");
        let token = key.token("app", "a");
        assert!(token.iter().all(u8::is_ascii_hexdigit));
        assert_eq!(token, Key::derive(b"seed one").token("app", "a"));
        assert_ne!(token, key.token("app", "b"));
        assert_ne!(token, key.token("api", "a"));
        assert_ne!(token, Key::derive(b"seed two").token("app", "a"));
        assert_ne!(key.token("ab", "c"), key.token("a", "bc"));
        // Without a seed each process has a key of its own.
        assert_ne!(Key::default().token("app", "a"), Key::default().token("app", "a"));
        assert_ne!(Key::default().tag, Key::default().tag);
    }

    #[test]
    fn the_cookie_is_found_among_others_and_must_look_like_a_token() {
        let fields: [&[u8]; 2] =
            [b"theme=dark; xsibuna_srv=0123456789abcdef", b" sibuna_srv=00112233aabbccdd ;a=b"];
        assert_eq!(presented(&fields, "sibuna_srv"), Some(&b"00112233aabbccdd"[..]));
        assert_eq!(presented(&fields, "theme"), None);
        assert_eq!(presented(&fields, "missing"), None);
        assert_eq!(presented(&[b"sibuna_srv=short"], "sibuna_srv"), None);
        assert_eq!(presented(&[], "sibuna_srv"), None);
        let mut line = Vec::new();
        write_cookie(&mut line, "sid", b"00112233aabbccdd", false);
        assert_eq!(line, b"Set-Cookie: sid=00112233aabbccdd; Path=/; HttpOnly; SameSite=Lax\r\n");
        line.clear();
        write_cookie(&mut line, "sid", b"00112233aabbccdd", true);
        assert!(line.ends_with(b"; SameSite=Lax; Secure\r\n"));
    }

    #[test]
    fn the_logarithm_is_exact_on_powers_of_two_and_monotone() {
        for bit in 0..64 {
            assert_eq!(log2_q16(1 << bit), bit << 16);
        }
        // log2(3) = 1.58496...
        assert_eq!(log2_q16(3) >> 8, (1.584_962_5_f64 * 256.0) as u64);
        let mut last = 0;
        for value in (1..2_000_000u64).step_by(997).chain([u64::MAX - 1, u64::MAX]) {
            let log = log2_q16(value);
            assert!(log >= last, "{value}");
            last = log;
        }
    }

    /// The nearest of `servers` (name and weight) for client number `client`.
    fn nearest(servers: &[(&str, u32)], client: u32) -> usize {
        let address = client_bytes(IpAddr::from(client.to_be_bytes()));
        let mut best = 0;
        for index in 1..servers.len() {
            let candidate = distance(&address, rank_seed(servers[index].0), servers[index].1);
            if candidate.nearer_than(&distance(
                &address,
                rank_seed(servers[best].0),
                servers[best].1,
            )) {
                best = index;
            }
        }
        best
    }

    #[test]
    fn rendezvous_ranking_follows_the_weights_and_moves_only_the_clients_of_a_lost_server() {
        let servers = [("a", 1), ("b", 2), ("c", 1)];
        let mut counts = [0usize; 3];
        for client in 0..20_000 {
            counts[nearest(&servers, client)] += 1;
        }
        // Shares of 1/4, 1/2 and 1/4, within three percent of the clients.
        assert!(counts[0].abs_diff(5_000) < 600, "{counts:?}");
        assert!(counts[1].abs_diff(10_000) < 600, "{counts:?}");
        assert!(counts[2].abs_diff(5_000) < 600, "{counts:?}");
        let without_c = [("a", 1), ("b", 2)];
        for client in 0..20_000 {
            let before = nearest(&servers, client);
            if before != 2 {
                assert_eq!(nearest(&without_c, client), before);
            }
        }
        // The port is no part of the client, and a mapped address is the same client.
        let v4: IpAddr = "192.0.2.9".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.9".parse().unwrap();
        assert_eq!(client_bytes(v4), client_bytes(mapped));
    }
}
