use std::collections::BTreeMap;
use std::net::IpAddr;

use super::*;

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn verdict(set: &ReputationSet, text: &str) -> Option<Action> {
    set.lookup(ip(text)).map(|(_, action)| action)
}

#[test]
fn exact_addresses_are_found_set_again_and_removed() {
    let mut builder = ReputationBuilder::new();
    builder.set(b"192.0.2.1", Action::Deny, None).unwrap();
    builder.set(b"2001:db8::7/128", Action::Allow, None).unwrap();
    let (set, refused) = builder.publish();
    assert_eq!(refused, None);
    assert_eq!(set.lookup(ip("192.0.2.1")), Some((128, Action::Deny)));
    // An IPv4 address and its mapped IPv6 form are one key.
    assert_eq!(verdict(&set, "::ffff:192.0.2.1"), Some(Action::Deny));
    assert_eq!(verdict(&set, "2001:db8::7"), Some(Action::Allow));
    assert_eq!(verdict(&set, "192.0.2.2"), None);
    builder.set(b"192.0.2.1/32", Action::Allow, None).unwrap();
    builder.remove(b"2001:db8::7").unwrap();
    let (next, _) = builder.publish();
    assert_eq!(verdict(&next, "192.0.2.1"), Some(Action::Allow));
    assert_eq!(verdict(&next, "2001:db8::7"), None);
    // The earlier set is unchanged: it shares nothing that changed.
    assert_eq!(verdict(&set, "192.0.2.1"), Some(Action::Deny));
    assert_eq!(builder.len(), 1);
}

#[test]
fn ranges_answer_by_the_longest_prefix_and_an_address_beats_any_range() {
    let mut builder = ReputationBuilder::new();
    builder.set(b"10.0.0.0/8", Action::Deny, None).unwrap();
    builder.set(b"10.1.0.0/16", Action::Allow, None).unwrap();
    builder.set(b"10.1.2.3", Action::Deny, None).unwrap();
    let (set, _) = builder.publish();
    assert_eq!(set.lookup(ip("10.9.9.9")), Some((104, Action::Deny)));
    assert_eq!(set.lookup(ip("10.1.9.9")), Some((112, Action::Allow)));
    assert_eq!(set.lookup(ip("10.1.2.3")), Some((128, Action::Deny)));
    builder.remove(b"10.1.0.0/16").unwrap();
    let (set, _) = builder.publish();
    assert_eq!(set.lookup(ip("10.1.9.9")), Some((104, Action::Deny)));
}

#[test]
fn rows_with_another_verdict_or_text_are_refused_alone() {
    let mut builder = ReputationBuilder::new();
    assert_eq!(
        builder.set(b"192.0.2.1", Action::Challenge, None),
        Err(ReputationError::InvalidAction)
    );
    assert!(matches!(
        builder.set(b"not an address", Action::Deny, None),
        Err(ReputationError::InvalidCidr(_))
    ));
    builder.set(b"192.0.2.9", Action::Deny, None).unwrap();
    assert_eq!(builder.len(), 1);
}

#[test]
fn entries_end_at_their_time_without_a_rebuild() {
    let mut builder = ReputationBuilder::new();
    builder.set(b"192.0.2.1", Action::Deny, Some(100)).unwrap();
    builder.set(b"192.0.2.0/24", Action::Deny, Some(200)).unwrap();
    builder.set(b"192.0.2.2", Action::Deny, None).unwrap();
    assert_eq!(builder.expire(99), 0);
    assert_eq!(builder.expire(100), 1);
    let (set, _) = builder.publish();
    assert_eq!(set.lookup(ip("192.0.2.1")), Some((120, Action::Deny)));
    // A new end replaces the old one: the entry does not end at the old time.
    builder.set(b"192.0.2.0/24", Action::Deny, Some(300)).unwrap();
    assert_eq!(builder.expire(250), 0);
    assert_eq!(builder.expire(300), 1);
    let (set, _) = builder.publish();
    assert_eq!(verdict(&set, "192.0.2.1"), None);
    assert_eq!(verdict(&set, "192.0.2.2"), Some(Action::Deny));
}

#[test]
fn the_overlay_merges_at_its_bound_and_no_answer_changes() {
    let mut builder = ReputationBuilder::new();
    for i in 0..300u32 {
        builder
            .set(format!("10.0.{}.{}", i / 256, i % 256).as_bytes(), Action::Deny, None)
            .unwrap();
    }
    let (set, _) = builder.publish();
    // 300 keys passed the bound of 256 over an empty base: they were merged.
    assert_eq!(set.layer_sizes(), (300, 0));
    builder.remove(b"10.0.0.5").unwrap();
    let (set, _) = builder.publish();
    assert_eq!(set.layer_sizes(), (300, 1));
    assert_eq!(verdict(&set, "10.0.0.5"), None);
    assert_eq!(verdict(&set, "10.0.0.6"), Some(Action::Deny));
}

/// A naive model: every row in one map, answered by scanning for the longest prefix.
#[derive(Default)]
struct Model {
    rows: BTreeMap<(u128, u8), (Action, Option<u64>)>,
}

impl Model {
    fn lookup(&self, address: IpAddr) -> Option<(u8, Action)> {
        let key = mapped_key(address);
        let ipv4 = key >> 32 == IPV4_MAPPED_PREFIX >> 32;
        let mut best: Option<(u8, Action)> = None;
        for (&(network, length), &(action, _)) in &self.rows {
            // The trie lets IPv6 prefixes shorter than the IPv4 subtree apply to IPv4
            // addresses only as the catch-all `::/0`; our rows never use such prefixes.
            if ipv4 && length < 96 && length != 0 {
                continue;
            }
            let mask = if length == 0 { 0 } else { u128::MAX << (128 - u32::from(length)) };
            if key & mask == network && best.is_none_or(|(have, _)| length > have) {
                best = Some((length, action));
            }
        }
        best
    }
}

/// A small deterministic generator, so a failure repeats.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn random_changes_answer_as_the_naive_model_through_every_merge() {
    let mut rng = Rng(0x5eed_0033);
    let mut builder = ReputationBuilder::new();
    let mut model = Model::default();
    let mut now = 1_000u64;
    for step in 0..4_000 {
        let pick = rng.next();
        let address = format!("198.51.{}.{}", (pick >> 8) % 4, pick % 200);
        let length = [32u8, 32, 32, 24, 30][(pick >> 16) as usize % 5];
        let text = if length == 32 { address.clone() } else { format!("{address}/{length}") };
        let prefix = parse_cidr(text.as_bytes()).unwrap();
        let key = (u128::from(prefix.address()), prefix.length());
        match (pick >> 24) % 10 {
            0..=5 => {
                let action = if pick & 1 == 0 { Action::Deny } else { Action::Allow };
                let until = (pick & 2 == 0).then_some(now + (pick >> 32) % 50);
                builder.set(text.as_bytes(), action, until).unwrap();
                model.rows.insert(key, (action, until));
            }
            6..=7 => {
                builder.remove(text.as_bytes()).unwrap();
                model.rows.remove(&key);
            }
            _ => {
                now += 7;
                builder.expire(now);
                model.rows.retain(|_, (_, until)| until.is_none_or(|end| end > now));
            }
        }
        if step % 5 == 0 {
            let (set, refused) = builder.publish();
            assert_eq!(refused, None);
            for probe in 0..64u64 {
                let address = ip(&format!("198.51.{}.{}", probe % 4, (probe * 37) % 256));
                assert_eq!(set.lookup(address), model.lookup(address), "step {step}");
            }
        }
    }
    assert_eq!(builder.len(), model.rows.len());
}

/// The cost of one change, merges included, and of one lookup. Run with
/// `cargo test --release -p sibuna-policy cost_of_a_change -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement, not a check"]
fn cost_of_a_change_and_a_lookup() {
    use std::time::Instant;
    for &size in &[10_000u32, 100_000, 1_000_000] {
        let mut builder = ReputationBuilder::new();
        for i in 0..size {
            let address = std::net::Ipv4Addr::from(0x0a00_0000 | i).to_string();
            builder.set(address.as_bytes(), Action::Deny, None).unwrap();
        }
        let _ = builder.publish();
        let changes = 10_000u32;
        let start = Instant::now();
        let mut set = None;
        for i in 0..changes {
            let address = std::net::Ipv4Addr::from(0xc000_0000 | i).to_string();
            builder.set(address.as_bytes(), Action::Deny, None).unwrap();
            set = Some(builder.publish().0);
        }
        let per_change = start.elapsed().as_secs_f64() * 1e6 / f64::from(changes);
        let set = set.unwrap();
        let probes: Vec<IpAddr> =
            (0..1_000_000u32).map(|i| IpAddr::V4((0x0a00_0000 | (i * 7 % size)).into())).collect();
        let start = Instant::now();
        let mut found = 0usize;
        for &probe in &probes {
            found += usize::from(set.lookup(probe).is_some());
        }
        let per_lookup = start.elapsed().as_secs_f64() * 1e9 / probes.len() as f64;
        assert_eq!(found, probes.len());
        println!(
            "entries {size}: {per_change:.1} us per change and publication, {per_lookup:.0} ns \\
             per lookup, layers {:?}",
            set.layer_sizes()
        );
    }
}

/// The resident memory of a set of a million exact addresses. Run with
/// `cargo test --release -p sibuna-policy memory_of_a_million -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement, not a check"]
fn memory_of_a_million_addresses() {
    fn resident_kib() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let line = status.lines().find_map(|line| line.strip_prefix("VmRSS:"));
        line.and_then(|rest| rest.split_whitespace().next()?.parse().ok()).unwrap_or(0)
    }
    let before = resident_kib();
    let mut builder = ReputationBuilder::new();
    for i in 0..1_000_000u32 {
        let address = std::net::Ipv4Addr::from(0x0a00_0000 | i).to_string();
        builder.set(address.as_bytes(), Action::Deny, None).unwrap();
    }
    let (set, _) = builder.publish();
    drop(builder);
    let after = resident_kib();
    println!(
        "a million addresses: {} MiB resident, layers {:?}",
        (after - before) / 1024,
        set.layer_sizes()
    );
}
