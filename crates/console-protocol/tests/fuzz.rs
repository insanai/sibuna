//! Deterministic fuzzing of every decoder: mutated documents must never panic, every
//! accepted document must survive `decode(encode(x)) == x`, and every bound must hold.
//!
//! Seeds are the Zig golden vectors and Rust encodings. Each round mutates one seed, either
//! at the byte level (bit flips, truncation, duplication, splicing) or at the token level
//! (replacing a scalar, dropping or adding a member), which keeps many mutants valid JSON
//! so the decoders, not only the parser, are exercised.

// Test code: a failed expectation is a panic by design.
#![allow(clippy::unwrap_used)]

use std::fmt::Debug;

use sibuna_console_protocol::codec::{Decode, Encode, Path, from_json, to_json};
use sibuna_console_protocol::subscription_client::Client;
use sibuna_console_protocol::*;
use sibuna_json::{Limits, Value};

mod common;

use common::{Rng, mutate};

/// Decodes `value` as `T`; if it is accepted, checks the round trip and that encoding is
/// stable.
fn round_trip<T: Encode + Decode + PartialEq + Debug>(value: &Value<'_>) -> bool {
    let Ok(decoded) = T::decode(value, Path::Root) else { return false };
    let text = to_json(&decoded);
    let again: T = from_json(text.as_bytes()).unwrap_or_else(|error| panic!("{error}: {text}"));
    assert_eq!(again, decoded);
    assert_eq!(to_json(&again), text);
    true
}

type Check = fn(&Value<'_>) -> bool;

fn checks() -> Vec<Check> {
    vec![
        round_trip::<tokens::Page>,
        round_trip::<tokens::Row>,
        round_trip::<users::Page>,
        round_trip::<users::Row>,
        round_trip::<audit::Page>,
        round_trip::<audit::Detail>,
        round_trip::<events::Row>,
        round_trip::<events::Capture>,
        round_trip::<events::country::Mapping>,
        round_trip::<subscription_feed::Event>,
        round_trip::<incident_heads::Heads>,
        round_trip::<security::Page>,
        round_trip::<security::Request>,
        round_trip::<nodes::Summary>,
        round_trip::<nodes::Page>,
        round_trip::<nodes::Probe>,
        round_trip::<nodes::Peer>,
        round_trip::<nodes::Status>,
        round_trip::<nodes::Receipt>,
        round_trip::<notifications::SettingsPage>,
        round_trip::<notifications::Page>,
        round_trip::<minutes::Reply>,
        round_trip::<minutes::Request>,
        round_trip::<minutes::Status>,
        round_trip::<minute_summary::Part>,
        round_trip::<timeline::Page>,
        round_trip::<timeline::Query>,
        round_trip::<challenges::Snapshot>,
        round_trip::<challenge_minutes::Summary>,
        round_trip::<challenge_records::Page>,
        round_trip::<challenge_records::DifficultyPage>,
        round_trip::<rule_hit_history::Part>,
        round_trip::<rule_hit_history::Today>,
        round_trip::<rankings::Page>,
        round_trip::<ranking_history::Cursor>,
        round_trip::<ranking_history::Form>,
        round_trip::<StatsSnapshot>,
        round_trip::<dashboard::View>,
        round_trip::<dashboard::Rates>,
        round_trip::<Location>,
    ]
}

/// Seeds with the decoder that reads them: Zig golden vectors and Rust encodings.
fn seeds_with_checks() -> Vec<(Vec<u8>, Check)> {
    let golden: Vec<(&str, &str)> = include_str!("golden/zig-0.16.txt")
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .collect();
    let named: [(&str, Check); 36] = [
        ("tokens_page", round_trip::<tokens::Page>),
        ("users_page", round_trip::<users::Page>),
        ("audit_page", round_trip::<audit::Page>),
        ("audit_detail", round_trip::<audit::Detail>),
        ("events_row", round_trip::<events::Row>),
        ("events_row_plain", round_trip::<events::Row>),
        ("country_mapping", round_trip::<events::country::Mapping>),
        ("feed_event", round_trip::<subscription_feed::Event>),
        ("incident_heads", round_trip::<incident_heads::Heads>),
        ("security_page", round_trip::<security::Page>),
        ("security_request", round_trip::<security::Request>),
        ("nodes_summary", round_trip::<nodes::Summary>),
        ("nodes_page", round_trip::<nodes::Page>),
        ("nodes_probe", round_trip::<nodes::Probe>),
        ("nodes_peer", round_trip::<nodes::Peer>),
        ("nodes_status", round_trip::<nodes::Status>),
        ("nodes_receipt", round_trip::<nodes::Receipt>),
        ("settings_page", round_trip::<notifications::SettingsPage>),
        ("notifications_page", round_trip::<notifications::Page>),
        ("minutes_reply", round_trip::<minutes::Reply>),
        ("minutes_request", round_trip::<minutes::Request>),
        ("minutes_status", round_trip::<minutes::Status>),
        ("minute_summary_part", round_trip::<minute_summary::Part>),
        ("timeline_page", round_trip::<timeline::Page>),
        ("timeline_query", round_trip::<timeline::Query>),
        ("challenges_snapshot", round_trip::<challenges::Snapshot>),
        ("challenge_summary", round_trip::<challenge_minutes::Summary>),
        ("challenge_records_page", round_trip::<challenge_records::Page>),
        ("challenge_difficulty_page", round_trip::<challenge_records::DifficultyPage>),
        ("rule_hit_part", round_trip::<rule_hit_history::Part>),
        ("rule_hit_today", round_trip::<rule_hit_history::Today>),
        ("rankings_page", round_trip::<rankings::Page>),
        ("ranking_cursor", round_trip::<ranking_history::Cursor>),
        ("ranking_form", round_trip::<ranking_history::Form>),
        ("stats_snapshot", round_trip::<StatsSnapshot>),
        ("dashboard_view", round_trip::<dashboard::View>),
    ];
    let mut seeds: Vec<(Vec<u8>, Check)> = named
        .iter()
        .filter_map(|(name, check)| {
            let json = golden.iter().find(|(key, _)| key == name)?.1;
            Some((json.as_bytes().to_vec(), *check))
        })
        .collect();
    let rates = dashboard::Rates { requests: 0.5, ..Default::default() };
    let rust: [(String, Check); 5] = [
        (to_json(&tokens::Row::default()), round_trip::<tokens::Row>),
        (to_json(&users::Row::default()), round_trip::<users::Row>),
        (to_json(&events::Capture::default()), round_trip::<events::Capture>),
        (to_json(&rates), round_trip::<dashboard::Rates>),
        (to_json(&Location { lat: 1.5, lon: -2.25 }), round_trip::<Location>),
    ];
    seeds.extend(rust.into_iter().map(|(json, check)| (json.into_bytes(), check)));
    seeds
}

fn rounds() -> usize {
    std::env::var("SIBUNA_FUZZ_ROUNDS").ok().and_then(|text| text.parse().ok()).unwrap_or(100_000)
}

#[test]
fn decoders_never_panic_and_round_trip() {
    let seeded = seeds_with_checks();
    let documents: Vec<Vec<u8>> = seeded.iter().map(|(doc, _)| doc.clone()).collect();
    let checks = checks();
    let limits = Limits { max_input_bytes: 1 << 20, ..Limits::default() };
    let mut rng = Rng(0x5eed_1234_abcd_ef01);
    let mut accepted = vec![0usize; seeded.len()];
    for _ in 0..rounds() {
        let index = rng.below(seeded.len());
        // Mostly mutate the decoder's own seed; sometimes splice in another seed.
        let pool = if rng.below(8) == 0 {
            &documents[..]
        } else {
            std::slice::from_ref(&documents[index])
        };
        let doc = mutate(&mut rng, pool);
        let Ok(value) = sibuna_json::parse_with_limits(&doc, &limits) else { continue };
        accepted[index] += usize::from((seeded[index].1)(&value));
        // One other decoder sees the same document.
        checks[rng.below(checks.len())](&value);
    }
    for (count, (doc, _)) in accepted.iter().zip(&seeded) {
        assert!(*count > 0, "no mutant of {} was accepted", String::from_utf8_lossy(doc));
    }
}

/// The heavy run: every decoder reads each of 100,000 mutants. Run it with
/// `cargo test --release -- --ignored`.
#[test]
#[ignore]
fn every_decoder_reads_100k_mutants() {
    let documents: Vec<Vec<u8>> = seeds_with_checks().into_iter().map(|(doc, _)| doc).collect();
    let checks = checks();
    let mut rng = Rng(42);
    for _ in 0..100_000 {
        let doc = mutate(&mut rng, &documents);
        let _ = subscriptions::parse(&doc);
        let Ok(value) = sibuna_json::parse(&doc) else { continue };
        for check in &checks {
            check(&value);
        }
    }
}

#[test]
fn subscription_commands_are_bounded() {
    let seeds: Vec<Vec<u8>> = vec![
        concat!(
            r#"{"op":"filter","topic":"events","args":{"node":2,"module":"inspection","#,
            r#""category":"waf:sqli","country":"US","ip":"192.0.2.1","path_prefix":"/api"}}"#,
        )
        .as_bytes()
        .to_vec(),
        concat!(
            r#"{"op":"filter","topic":"audit","args":{"actor":"9007199254740993","#,
            r#""action":"policy.edit"}}"#,
        )
        .as_bytes()
        .to_vec(),
        br#"{"op":"ping"}"#.to_vec(),
        br#"{"op":"unsub","topic":"stats"}"#.to_vec(),
    ];
    let mut rng = Rng(7);
    let mut accepted = 0;
    for _ in 0..rounds() {
        let doc = mutate(&mut rng, &seeds);
        let Ok(command) = subscriptions::parse(&doc) else { continue };
        accepted += 1;
        assert!(subscriptions::validate(&command).is_ok());
        assert_eq!(subscriptions::parse(to_json(&command).as_bytes()), Ok(command.clone()));
        assert!(command.args.category.len() <= 32 && command.args.path_prefix.len() <= 128);
    }
    assert!(accepted > 100);
}

#[test]
fn archives_never_panic_and_reencode_exactly() {
    let mut archive = rankings_archive::Archive {
        identity: rankings_archive::Identity {
            node: 7,
            boot: [9; 16],
            queue_loss_start: 4,
            queue_loss_end: 6,
        },
        minute: ranking_storage::Minute {
            minute: Some(2),
            first_second: 120,
            last_second: 179,
            ..Default::default()
        },
    };
    for key in [&b"/a"[..], b"/b", b"/a", b"/c/d"] {
        archive.minute.paths.add(key).unwrap();
    }
    archive.minute.referrers.add(b"example.com").unwrap();
    let seed = rankings_archive::encode(&archive).unwrap();
    let seeds = [seed.clone(), seed[..seed.len() - 304].to_vec()];
    let mut rng = Rng(99);
    for _ in 0..rounds() {
        let mut doc = seeds[rng.below(2)].clone();
        for _ in 0..1 + rng.below(3) {
            match rng.below(3) {
                0 if !doc.is_empty() => {
                    let at = rng.below(doc.len());
                    doc[at] = rng.next() as u8;
                }
                1 => doc.truncate(rng.below(doc.len() + 1)),
                _ => {
                    let at = rng.below(doc.len() + 1);
                    doc.insert(at, rng.next() as u8);
                }
            }
        }
        if let Ok(decoded) = rankings_archive::decode(&doc)
            && doc.starts_with(b"SBR2")
        {
            assert_eq!(rankings_archive::encode(&decoded).unwrap(), doc);
        }
    }
}

#[test]
fn deltas_and_client_views_stay_consistent() {
    let seeds: Vec<Vec<u8>> = include_str!("golden/zig-0.16.txt")
        .lines()
        .filter_map(|line| line.split('\t').nth(1))
        .filter(|json| json.starts_with('{'))
        .map(|json| json.as_bytes().to_vec())
        .collect();
    let mut rng = Rng(1234);
    for _ in 0..rounds() / 4 {
        let previous = mutate(&mut rng, &seeds);
        let current = mutate(&mut rng, &seeds);
        let mut delta = String::new();
        let Ok(_) = json_delta::write(&previous, &current, &mut delta) else { continue };
        let state = sibuna_json::parse(&previous).unwrap();
        let patch = sibuna_json::parse(delta.as_bytes()).unwrap();
        let mut applied = String::new();
        json_delta::apply(&state, &patch, &mut applied).unwrap();
        // Zig rewrites an integral float such as 8.0 as 8, which then reads as an
        // integer; compare with the current document as Zig rewrote it.
        let empty = sibuna_json::parse(b"{\"set\":{},\"remove\":[]}").unwrap();
        let mut normalized = String::new();
        json_delta::apply(&sibuna_json::parse(&current).unwrap(), &empty, &mut normalized)
            .unwrap();
        let mut residue = String::new();
        let changed =
            json_delta::write(applied.as_bytes(), normalized.as_bytes(), &mut residue).unwrap();
        assert!(
            !changed,
            "{residue}\nprevious {}\ncurrent {}\ndelta {delta}\napplied {applied}",
            String::from_utf8_lossy(&previous),
            String::from_utf8_lossy(&current)
        );
    }
}

#[test]
fn client_frames_never_panic_and_views_stay_bounded() {
    let epoch = format!("{}:1", "a".repeat(32));
    let frames: Vec<Vec<u8>> = vec![
        format!(concat!(
            r#"{{"op":"snapshot_begin","topic":"stats","epoch":"{epoch}","seq":0,"#,
            r#""snapshot":true,"watermark":0,"parts":1}}"#,
        ), epoch = epoch),
        format!(concat!(
            r#"{{"op":"snapshot_chunk","topic":"stats","epoch":"{epoch}","seq":1,"#,
            r#""snapshot":true,"watermark":0,"part":0,"parts":1,"#,
            r#""data":"{{\"rows\":[{{\"id\":1}}],\"a\":1}}"}}"#,
        ), epoch = epoch),
        format!(concat!(
            r#"{{"op":"snapshot_end","topic":"stats","epoch":"{epoch}","seq":2,"snapshot":true,"#,
            r#""watermark":0}}"#,
        ), epoch = epoch),
        format!(concat!(
            r#"{{"op":"delta","topic":"stats","epoch":"{epoch}","seq":3,"snapshot":false,"#,
            r#""watermark":1,"part":0,"parts":1,"update":1,"kind":"patch","#,
            r#""data":"{{\"set\":{{\"b\":2}},\"remove\":[\"a\"]}}"}}"#,
        ), epoch = epoch),
        format!(concat!(
            r#"{{"op":"delta","topic":"stats","epoch":"{epoch}","seq":4,"snapshot":false,"#,
            r#""watermark":2,"part":0,"parts":1,"update":2,"kind":"row","#,
            r#""data":"{{\"id\":\"2\"}}"}}"#,
        ), epoch = epoch),
        format!(r#"{{"op":"gap","topic":"stats","epoch":"{epoch}","dropped":1}}"#),
    ]
    .into_iter()
    .map(String::into_bytes)
    .collect();
    let mut rng = Rng(555);
    let mut client = Client::new();
    for round in 0..rounds() {
        if round % 64 == 0 {
            client.reset();
        }
        let frame = if rng.below(3) == 0 {
            mutate(&mut rng, &frames)
        } else {
            frames[rng.below(frames.len())].clone()
        };
        let _ = client.receive_text(&frame);
        let view = client.view(Topic::Stats);
        assert!(view.len() <= subscriptions::SNAPSHOT_BYTES);
        if !view.is_empty() {
            assert!(
                sibuna_json::parse(view.as_bytes()).is_ok_and(|value| value.as_object().is_some())
            );
        }
    }
}

#[test]
fn locations_parse_or_refuse() {
    let mut rng = Rng(77);
    let alphabet = b"0123456789.,-+eEinfa ";
    for _ in 0..rounds() {
        let length = rng.below(70);
        let text: String =
            (0..length).map(|_| char::from(alphabet[rng.below(alphabet.len())])).collect();
        if let Ok(location) = Location::parse(&text) {
            assert!(location.is_valid());
        }
    }
}

/// A small snapshot: most streaming rounds mutate it, so the test stays fast in debug.
const MINIMAL_STATS: &str = concat!(
    r#"{"proxy_mode":"forward_auth","server_location":{"lat":1.5,"lon":2},"incident_geo":null,"#,
    r#""minute_history":{"available":true},"boot":"ABCDEFGHIJKLMNOP","requests":1,"admitted":1,"#,
    r#""challenged":0,"denied":0,"origin_4xx":0,"origin_5xx":0,"incidents":0,"#,
    r#""incidents_dropped":0,"sample_loss":0,"retention_failures":null,"#,
    r#""cluster_health":{"healthy":1},"cpu_permille":3,"sample_probability":[49,47,50],"#,
    r#""unknown_samples":0,"timestamp":5}"#,
);

#[test]
fn streaming_and_tree_snapshot_decoders_agree() {
    let golden = include_str!("golden/zig-0.16.txt");
    let seeds: Vec<Vec<u8>> = golden
        .lines()
        .filter(|line| line.starts_with("stats_snapshot") || line.starts_with("dashboard_view\t"))
        .filter_map(|line| line.split('\t').nth(1))
        .map(|json| json.as_bytes().to_vec())
        .chain(std::iter::repeat_n(MINIMAL_STATS.as_bytes().to_vec(), 12))
        .collect();
    let mut rng = Rng(0x57e4);
    let mut accepted = 0;
    for round in 0..rounds() {
        let doc = if round % 2 == 0 {
            mutate(&mut rng, &seeds)
        } else {
            common::mutate_gently(&mut rng, &seeds)
        };
        let streamed = StatsSnapshot::from_json(&doc);
        let tree = from_json::<StatsSnapshot>(&doc);
        match (&streamed, &tree) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a, b);
                accepted += 1;
            }
            (Err(_), Err(_)) => {}
            _ => panic!("{streamed:?} / {tree:?} for {}", String::from_utf8_lossy(&doc)),
        }
    }
    assert!(accepted > 1000, "{accepted}");
}
