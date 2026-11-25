//! Screening by source address at accept (SID 0031): a connection from outside the listed
//! networks is closed before it takes a slot, a thread or a byte of parsing.
//!
//! A [`Screen`] is plain data of a fixed size, so [`crate::Options`] stays `Copy`. An empty
//! screen admits every address.

use std::net::IpAddr;

/// The most networks one screen holds.
pub const MAX_NETWORKS: usize = 32;

/// One network: an address in the 128-bit space (IPv4 as IPv4-mapped IPv6) and the length
/// of its prefix there.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Network {
    address: [u8; 16],
    bits: u8,
}

/// The networks a listener serves. Empty: every address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Screen {
    networks: [Network; MAX_NETWORKS],
    count: u8,
}

/// Why a network was not added to a [`Screen`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreenError {
    /// The text is not `ADDRESS/BITS` with a prefix length that fits the address.
    Invalid,
    /// The screen holds [`MAX_NETWORKS`] networks.
    Full,
}

impl std::fmt::Display for ScreenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ScreenError::Invalid => "a network is written ADDRESS/BITS, such as 10.0.0.0/24",
            ScreenError::Full => "a screen holds at most 32 networks",
        })
    }
}

impl std::error::Error for ScreenError {}

impl Screen {
    /// A screen of `networks`, each `ADDRESS/BITS`. Borrows the texts.
    ///
    /// # Errors
    ///
    /// [`ScreenError::Invalid`] for a text that is no network and [`ScreenError::Full`]
    /// past [`MAX_NETWORKS`].
    pub fn load_networks<S: AsRef<str>>(networks: &[S]) -> Result<Screen, ScreenError> {
        let mut screen = Screen::default();
        for network in networks {
            screen.allow(network.as_ref())?;
        }
        Ok(screen)
    }

    /// Adds the network `text`, `ADDRESS/BITS`.
    ///
    /// # Errors
    ///
    /// As [`Screen::load_networks`]. The screen is unchanged on failure.
    pub fn allow(&mut self, text: &str) -> Result<(), ScreenError> {
        let (address, bits) = text.rsplit_once('/').ok_or(ScreenError::Invalid)?;
        let address: IpAddr = address.parse().map_err(|_| ScreenError::Invalid)?;
        if bits.is_empty() || !bits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ScreenError::Invalid);
        }
        let bits: u8 = bits.parse().map_err(|_| ScreenError::Invalid)?;
        let (limit, offset) = if address.is_ipv4() { (32, 96) } else { (128, 0) };
        if bits > limit {
            return Err(ScreenError::Invalid);
        }
        let slot = self.networks.get_mut(usize::from(self.count)).ok_or(ScreenError::Full)?;
        *slot = Network { address: normalized(address), bits: bits + offset };
        self.count += 1;
        Ok(())
    }

    /// Whether the screen lists no network, and so admits every address.
    pub fn is_open(&self) -> bool {
        self.count == 0
    }

    /// Whether a connection from `peer` is served. An IPv4 address and its IPv4-mapped
    /// IPv6 form are the same address.
    pub fn admits(&self, peer: IpAddr) -> bool {
        if self.is_open() {
            return true;
        }
        let peer = normalized(peer);
        self.networks.iter().take(usize::from(self.count)).any(|network| network.holds(&peer))
    }
}

impl Network {
    fn holds(&self, peer: &[u8; 16]) -> bool {
        let whole = usize::from(self.bits / 8);
        // `bits` is at most 128, so `whole` is at most 16 and the slices are in bounds.
        if self.address.get(..whole) != peer.get(..whole) {
            return false;
        }
        let tail = self.bits % 8;
        if tail == 0 {
            return true;
        }
        let mask = 0xffu8 << (8 - tail);
        match (self.address.get(whole), peer.get(whole)) {
            (Some(expected), Some(actual)) => expected & mask == actual & mask,
            _ => false,
        }
    }
}

fn normalized(address: IpAddr) -> [u8; 16] {
    match address {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn an_empty_screen_admits_everyone() {
        let screen = Screen::default();
        assert!(screen.is_open());
        assert!(screen.admits(ip("203.0.113.9")) && screen.admits(ip("2001:db8::1")));
    }

    #[test]
    fn a_screen_admits_only_its_networks() {
        let screen = Screen::load_networks(&["10.99.0.0/25", "2001:db8::2/127"]).unwrap();
        assert!(screen.admits(ip("10.99.0.1")));
        assert!(screen.admits(ip("::ffff:10.99.0.1")), "the mapped form is the same address");
        assert!(!screen.admits(ip("10.99.0.128")));
        assert!(screen.admits(ip("2001:db8::3")));
        assert!(!screen.admits(ip("2001:db8::4")));
        assert!(!screen.admits(ip("127.0.0.1")));
    }

    #[test]
    fn networks_parse_strictly_and_the_screen_is_bounded() {
        for invalid in ["10.0.0.0", "10.0.0.0/33", "::1/129", "10.0.0.0/+8", "x/8", "10.0.0.0/"] {
            assert_eq!(Screen::default().allow(invalid), Err(ScreenError::Invalid), "{invalid}");
        }
        let mut screen = Screen::default();
        for index in 0..MAX_NETWORKS {
            screen.allow(&format!("10.0.{index}.0/24")).unwrap();
        }
        assert_eq!(screen.allow("10.1.0.0/24"), Err(ScreenError::Full));
        assert!(screen.admits(ip("10.0.31.7")) && !screen.admits(ip("10.1.0.7")));
    }
}
