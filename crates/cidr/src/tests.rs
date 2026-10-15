//! Tests of the parsers against Zig 0.16 and of the trie, including the Zig suite.

use std::net::{IpAddr, Ipv4Addr};

use crate::{
    IPV4_MAPPED_PREFIX, ParseError, Prefix, PrefixTrie, TrieError, mapped_key, parse_cidr,
    parse_ip,
};

/// `parseIp` of `radix_trie.zig` built with Zig 0.16 std: the input and the mapped key.
const ZIG_IP_VECTORS: &[(&[u8], Option<u128>)] = &[
    (b"1.2.3.4", Some(0x00000000_00000000_0000ffff_01020304)),
    (b"0.0.0.0", Some(0x00000000_00000000_0000ffff_00000000)),
    (b"255.255.255.255", Some(0x00000000_00000000_0000ffff_ffffffff)),
    (b"256.0.0.1", None),
    (b"1.2.3", None),
    (b"1.2.3.4.5", None),
    (b"", None),
    (b".", None),
    (b"1..2.3", None),
    (b"01.2.3.4", Some(0x00000000_00000000_0000ffff_01020304)),
    (b"001.002.003.004", Some(0x00000000_00000000_0000ffff_01020304)),
    (b"0000000001.2.3.4", Some(0x00000000_00000000_0000ffff_01020304)),
    (b"+1.2.3.4", Some(0x00000000_00000000_0000ffff_01020304)),
    (b"-0.2.3.4", Some(0x00000000_00000000_0000ffff_00020304)),
    (b"-1.2.3.4", None),
    (b"-00.1.1.1", Some(0x00000000_00000000_0000ffff_00010101)),
    (b"1_0.0.0.1", Some(0x00000000_00000000_0000ffff_0a000001)),
    (b"1__0.0.0.1", Some(0x00000000_00000000_0000ffff_0a000001)),
    (b"_1.0.0.1", None),
    (b"1_.0.0.1", None),
    (b"+_1.0.0.1", None),
    (b"+.1.1.1", None),
    (b" 1.2.3.4", None),
    (b"1.2.3.4 ", None),
    (b"1.2.3.4/8", None),
    (b"0x1.2.3.4", None),
    (b"1.2.3.a", None),
    (b"1.2.3.-0", Some(0x00000000_00000000_0000ffff_01020300)),
    (b"1.2.3.+5", Some(0x00000000_00000000_0000ffff_01020305)),
    (b"999.1.1.1", None),
    (b"::", Some(0x00000000_00000000_00000000_00000000)),
    (b"::1", Some(0x00000000_00000000_00000000_00000001)),
    (b"1::", Some(0x00010000_00000000_00000000_00000000)),
    (b"1:2:3:4:5:6:7:8", Some(0x00010002_00030004_00050006_00070008)),
    (b"1:2:3:4:5:6:7::", Some(0x00010002_00030004_00050006_00070000)),
    (b"::1:2:3:4:5:6:7", Some(0x00000001_00020003_00040005_00060007)),
    (b"::1:2:3:4:5:6:7:8", Some(0x00010002_00030004_00050006_00070008)),
    (b"1::2:3:4:5:6:7:8", Some(0x00010002_00030004_00050006_00070008)),
    (b"1:2:3:4:5:6:7:8:9", None),
    (b"1:2:3:4:5:6:7:8::", None),
    (b"1:::2", None),
    (b":1", None),
    (b"1:", None),
    (b"1:2", None),
    (b":", None),
    (b"2001:db8::1", Some(0x20010db8_00000000_00000000_00000001)),
    (b"2001:DB8::1", Some(0x20010db8_00000000_00000000_00000001)),
    (b"2001:0db8:0000:0000:0000:0000:0000:0001", Some(0x20010db8_00000000_00000000_00000001)),
    (b"12345::1", None),
    (b"00000::1", None),
    (b"fe80::1%eth0", None),
    (b"fe80::1%", None),
    (b"::ffff:1.2.3.4", Some(0x00000000_00000000_0000ffff_01020304)),
    (b"::FFFF:1.2.3.4", Some(0x00000000_00000000_0000ffff_01020304)),
    (b"::ffff:01.2.3.4", None),
    (b"::ffff:1.2.3", None),
    (b"::ffff:c0a8:164", None),
    (b"::ffff:0:0", None),
    (b"::ffff", Some(0x00000000_00000000_00000000_0000ffff)),
    (b"::ffff:", None),
    (b"::1.2.3.4", None),
    (b"64:ff9b::1.2.3.4", None),
    (b"0:0:0:0:0:ffff:1.2.3.4", None),
    (b"0:0:0:0:0:ffff:c0a8:164", Some(0x00000000_00000000_0000ffff_c0a80164)),
    (b"::ffff:255.255.255.255", Some(0x00000000_00000000_0000ffff_ffffffff)),
    (b"::ffff:256.1.1.1", None),
    (b"::ffff:1.2.3.4.5", None),
    (b"1::2::3", None),
    (b"g::1", None),
    (b"::g", None),
    (b"1:2:3:4:5:6:7:8%x", None),
    (b"a:b:c:d:e:f:a:b", Some(0x000a000b_000c000d_000e000f_000a000b)),
    (b"fffff::", None),
    (b"ffff::", Some(0xffff0000_00000000_00000000_00000000)),
    (b"1:2:3:4:5:6::7:8", Some(0x00010002_00030004_00050006_00070008)),
    (b"::0:0:0:0:0:0:0:0", Some(0x00000000_00000000_00000000_00000000)),
    (b"0::0", Some(0x00000000_00000000_00000000_00000000)),
    (b"1:2::", Some(0x00010002_00000000_00000000_00000000)),
    (b"::2:", None),
    (b"[::1]", None),
    (b"::1 ", None),
];

/// A parsed prefix as Zig reported it: the masked key and the length in the key space.
type ZigPrefix = (u128, u8);

/// `parseCidr` of `radix_trie.zig` built with Zig 0.16 std: the input and the prefix.
const ZIG_CIDR_VECTORS: &[(&[u8], Option<ZigPrefix>)] = &[
    (b"10.0.0.0/8", Some((0x00000000_00000000_0000ffff_0a000000, 104))),
    (b"10.0.0.0/33", None),
    (b"10.0.0/8", None),
    (b"2001:db8::/129", None),
    (b"1.2.3.4/8/2", None),
    (b"203.0.113.9/24", Some((0x00000000_00000000_0000ffff_cb007100, 120))),
    (b"10.0.0.0/", None),
    (b"10.0.0.0/+8", Some((0x00000000_00000000_0000ffff_0a000000, 104))),
    (b"10.0.0.0/08", Some((0x00000000_00000000_0000ffff_0a000000, 104))),
    (b"10.0.0.0/0_8", Some((0x00000000_00000000_0000ffff_0a000000, 104))),
    (b"10.0.0.0/-0", Some((0x00000000_00000000_0000ffff_00000000, 96))),
    (b"10.0.0.0/0", Some((0x00000000_00000000_0000ffff_00000000, 96))),
    (b"0.0.0.0/0", Some((0x00000000_00000000_0000ffff_00000000, 96))),
    (b"::/0", Some((0x00000000_00000000_00000000_00000000, 0))),
    (b"::ffff:10.0.0.0/104", Some((0x00000000_00000000_0000ffff_0a000000, 104))),
    (b"::ffff:10.0.0.0/129", None),
    (b"fe80::1", Some((0xfe800000_00000000_00000000_00000001, 128))),
    (b"1.2.3.4", Some((0x00000000_00000000_0000ffff_01020304, 128))),
    (b"2001:db8::/32", Some((0x20010db8_00000000_00000000_00000000, 32))),
    (b"2001:db8:1::/48", Some((0x20010db8_00010000_00000000_00000000, 48))),
    (b"/8", None),
    (b"10.0.0.0//8", None),
    (b"10.0.0.0/ 8", None),
    (b"10.0.0.0/256", None),
    (b"2001:db8::/128", Some((0x20010db8_00000000_00000000_00000000, 128))),
    (b"2001:db8::/000128", Some((0x20010db8_00000000_00000000_00000000, 128))),
    (b"bogus", None),
    (b"bogus/8", None),
    (b"10.0.0.255/31", Some((0x00000000_00000000_0000ffff_0a0000fe, 127))),
];

#[test]
fn parse_ip_matches_zig_vectors() {
    for &(text, expected) in ZIG_IP_VECTORS {
        let actual = parse_ip(text).ok().map(mapped_key);
        assert_eq!(actual, expected, "{:?}", String::from_utf8_lossy(text));
    }
}

#[test]
fn parse_cidr_matches_zig_vectors() {
    for &(text, expected) in ZIG_CIDR_VECTORS {
        let actual = parse_cidr(text).ok().map(|p| (u128::from(p.address()), p.length()));
        assert_eq!(actual, expected, "{:?}", String::from_utf8_lossy(text));
    }
}

/// The generator of the differential test; the same LCG runs in the Zig program that
/// produced the expected counts and hash.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

fn fold(hash: u64, value: u64) -> u64 {
    (hash ^ value).wrapping_mul(0x100000001b3)
}

/// Parses 200,000 texts glued from address-like tokens with both parsers and folds every
/// result into a hash. The expected counts and hash come from the same generator run over
/// `radix_trie.zig`'s `parseIp` and `parseCidr` built with Zig 0.16 std.
#[test]
fn parsers_agree_with_zig_on_generated_texts() {
    const TOKENS: [&str; 30] = [
        "1", "0", "00", "255", "256", "ff", "FFFF", "fffff", ":", "::", ".", "/", "8", "32",
        "128", "+", "-0", "-", "_", "1_0", "::ffff:", "%", "a", "12", "0db8", "1.2.3.4", "10",
        " ", "g", "9",
    ];
    let mut rng = Lcg(2026);
    let mut hash: u64 = 0xcbf29ce484222325;
    let (mut ip_ok, mut cidr_ok) = (0, 0);
    let mut text = Vec::new();
    for _ in 0..200_000 {
        text.clear();
        for _ in 0..1 + rng.next() % 10 {
            text.extend_from_slice(TOKENS[(rng.next() % 30) as usize].as_bytes());
        }
        if let Ok(address) = parse_ip(&text) {
            ip_ok += 1;
            let key = mapped_key(address);
            hash = fold(fold(hash, key as u64), (key >> 64) as u64);
        } else {
            hash = fold(hash, 1);
        }
        if let Ok(prefix) = parse_cidr(&text) {
            cidr_ok += 1;
            let key = u128::from(prefix.address());
            hash = fold(fold(hash, key as u64), (key >> 64) as u64);
            hash = fold(hash, u64::from(prefix.length()));
        } else {
            hash = fold(hash, 2);
        }
    }
    assert_eq!((ip_ok, cidr_ok, hash), (3258, 3311, 0x6afd7478641b9694));
}

// Ported from radix_trie.zig: "parseCidr rejects malformed input".
#[test]
fn parse_cidr_rejects_malformed_input() {
    assert_eq!(parse_cidr(b"10.0.0.0/33"), Err(ParseError::InvalidPrefixLength));
    assert_eq!(parse_cidr(b"10.0.0/8"), Err(ParseError::InvalidIpv4));
    assert_eq!(parse_cidr(b"2001:db8::/129"), Err(ParseError::InvalidPrefixLength));
    assert_eq!(parse_cidr(b"1.2.3.4/8/2"), Err(ParseError::ExtraSlash));
    let p = parse_cidr(b"203.0.113.9/24").unwrap();
    assert_eq!(p.length(), 120);
    assert_eq!(u128::from(p.address()), IPV4_MAPPED_PREFIX | 0xcb00_7100);
}

// Ported from rule.zig: "cidr matcher verifies IPv4 and IPv6 subnets" (the arithmetic of
// `CidrMatcher` is `Prefix::contains`).
#[test]
fn prefix_contains_ipv4_and_ipv6_subnets() {
    let ip = |text: &[u8]| parse_ip(text).unwrap();
    let cidr = parse_cidr(b"192.168.1.0/24").unwrap();
    assert!(cidr.contains(ip(b"192.168.1.50")));
    assert!(!cidr.contains(ip(b"192.168.2.1")));
    let v6 = parse_cidr(b"2a02:1234::/32").unwrap();
    assert!(v6.contains(ip(b"2a02:1234:5::9")));
    assert!(!v6.contains(ip(b"2a02:1235::1")));
    assert!(!v6.contains(ip(b"192.168.1.50")));
    assert!(parse_cidr(b"bogus").is_err());
    // A plain mask: ::/0 contains IPv4 addresses, as in Zig.
    assert!(parse_cidr(b"::/0").unwrap().contains(ip(b"192.168.1.50")));
}

#[test]
fn prefix_new_counts_length_in_the_address_family() {
    let v4 = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
    let p = Prefix::new(v4, 8).unwrap();
    assert_eq!((p.length(), p.mask()), (104, !0u128 << 24));
    assert_eq!(p, parse_cidr(b"10.0.0.0/8").unwrap());
    assert_eq!(Prefix::new(v4, 33), Err(ParseError::InvalidPrefixLength));
    assert_eq!(Prefix::new(parse_ip(b"::").unwrap(), 0).unwrap().mask(), 0);
    assert_eq!(parse_ip(b"::ffff:1.2.3.4").map(mapped_key), parse_ip(b"1.2.3.4").map(mapped_key));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Allow,
    Deny,
    Challenge,
}

// Ported from radix_trie.zig: "radix trie CIDR longest prefix matching for IPv4 and IPv6".
#[test]
fn longest_prefix_matching_for_ipv4_and_ipv6() {
    let mut trie = PrefixTrie::new();
    trie.insert_cidr(b"10.0.0.0/8", Action::Challenge).unwrap();
    trie.insert_cidr(b"10.1.2.0/24", Action::Allow).unwrap();
    trie.insert_cidr(b"192.168.1.100/32", Action::Deny).unwrap();
    trie.insert_cidr(b"2001:db8::/32", Action::Deny).unwrap();
    trie.insert_cidr(b"2001:db8:1::/48", Action::Allow).unwrap();
    trie.insert_cidr(b"fe80::1", Action::Challenge).unwrap();

    assert_eq!(trie.lookup_str(b"10.5.6.7"), Some(&Action::Challenge));
    assert_eq!(trie.lookup_str(b"10.1.2.55"), Some(&Action::Allow));
    assert_eq!(trie.lookup_str(b"192.168.1.100"), Some(&Action::Deny));
    assert_eq!(trie.lookup_str(b"192.168.1.101"), None);
    assert_eq!(trie.lookup_str(b"2001:db8:ffff::1"), Some(&Action::Deny));
    assert_eq!(trie.lookup_str(b"2001:db8:1:2::3"), Some(&Action::Allow));
    assert_eq!(trie.lookup_str(b"fe80::1"), Some(&Action::Challenge));
    assert_eq!(trie.lookup_str(b"fe80::2"), None);
    assert_eq!(trie.lookup_str(b"not-an-ip"), None);
    // IPv4-mapped IPv6 literals resolve to the IPv4 entries.
    assert_eq!(trie.lookup_str(b"::ffff:192.168.1.100"), Some(&Action::Deny));

    trie.clear();
    assert_eq!(trie.lookup_str(b"10.5.6.7"), None);
    assert_eq!(trie.node_count(), 97);
}

// Ported from candidate.zig: "candidate refuses a reputation set that exhausts the shared
// trie". 128 host routes of about 128 nodes each exceed the 8,192-node default.
#[test]
fn host_routes_exhaust_the_default_capacity() {
    let mut trie = PrefixTrie::new();
    let mut result = Ok(None);
    for i in 1..=128u32 {
        let text = format!("{i:x}::1/128");
        result = trie.insert_cidr(text.as_bytes(), Action::Deny);
        if result.is_err() {
            break;
        }
    }
    assert_eq!(result, Err(TrieError::Full));
    assert!(trie.node_count() <= 8192);
}

#[test]
fn failed_insertions_leave_the_trie_unchanged() {
    let mut trie = PrefixTrie::with_max_nodes(97 + 20).unwrap();
    trie.insert_cidr(b"10.0.0.0/16", 1).unwrap();
    assert_eq!(trie.node_count(), 97 + 16);
    assert_eq!(trie.insert_cidr(b"10.0.0.0/24", 2), Err(TrieError::Full));
    assert_eq!(trie.node_count(), 97 + 16);
    assert_eq!(trie.lookup_str(b"10.0.0.1"), Some(&1));
    assert_eq!(trie.insert_cidr(b"10.0.0.0/20", 3), Ok(None));
    assert_eq!(trie.insert_cidr(b"10.0.0.0/20", 4), Ok(Some(3)));
    assert_eq!(
        trie.insert_cidr(b"10.0.0.0/40", 5),
        Err(TrieError::InvalidCidr(ParseError::InvalidPrefixLength))
    );
    assert!(PrefixTrie::<u8>::with_max_nodes(96).is_err());
    assert_eq!(PrefixTrie::<u8>::with_max_nodes(97).unwrap().max_nodes(), 97);
}

#[test]
fn ipv4_default_route_matches_every_ipv4_address() {
    // Zig never read the value at the IPv4 subtree's root; see the crate documentation.
    let mut trie = PrefixTrie::new();
    trie.insert_cidr(b"0.0.0.0/0", Action::Deny).unwrap();
    assert_eq!(trie.lookup_str(b"1.2.3.4"), Some(&Action::Deny));
    assert_eq!(trie.lookup_str(b"::ffff:1.2.3.4"), Some(&Action::Deny));
    assert_eq!(trie.lookup_str(b"::1"), None);
    trie.insert_cidr(b"1.2.0.0/16", Action::Allow).unwrap();
    assert_eq!(trie.lookup_str(b"1.2.3.4"), Some(&Action::Allow));
}

#[test]
fn ipv6_prefixes_apply_to_ipv4_only_as_the_catch_all() {
    // As in Zig: `::/64` covers `::ffff:0:0/96` but is an IPv6 rule; `::/0` covers all.
    let mut trie = PrefixTrie::new();
    trie.insert_cidr(b"::/64", Action::Allow).unwrap();
    assert_eq!(trie.lookup_str(b"1.2.3.4"), None);
    assert_eq!(trie.lookup_str(b"::5"), Some(&Action::Allow));
    trie.insert_cidr(b"::/0", Action::Challenge).unwrap();
    assert_eq!(trie.lookup_str(b"1.2.3.4"), Some(&Action::Challenge));
    assert_eq!(trie.lookup_str(b"2001:db8::1"), Some(&Action::Challenge));
}
