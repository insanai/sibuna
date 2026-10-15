//! Differential tests against the Zig console: the same mutated inputs, the same verdicts.
//!
//! [`corpus`] generates mutated inputs deterministically: subscription commands for
//! `subscriptions.parse`, peer snapshots for `std.json.parseFromSlice(StatsSnapshot)`,
//! archives for `rankings_archive.decode`, and document pairs for `json_delta.write`.
//! `golden/differential.txt` holds the verdicts Zig 0.16's `libs/console-protocol` gave for
//! them, one line per input: the kind, then `!` and the error name, or the FNV-1a
//! fingerprint of Zig's re-encoded result.

// Test code: a failed expectation is a panic by design.
#![allow(clippy::unwrap_used)]

use sibuna_console_protocol::codec::{from_json, to_json};
use sibuna_console_protocol::rankings_archive::ArchiveError;
use sibuna_console_protocol::*;

mod common;

use common::{Rng, fnv1a, mutate, mutate_gently};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn command_seeds() -> Vec<Vec<u8>> {
    [
        concat!(
            r#"{"op":"filter","topic":"events","args":{"node":2,"module":"inspection","#,
            r#""category":"waf:sqli","country":"US","ip":"192.0.2.1","path_prefix":"/api"}}"#,
        ),
        concat!(
            r#"{"op":"filter","topic":"audit","args":{"actor":"9007199254740993","#,
            r#""action":"policy.edit"}}"#,
        ),
        r#"{"op":"sub","topic":"nodes","args":{"node":"7"}}"#,
        r#"{"op":3}"#,
        r#"{"op":"unsub","topic":"stats","args":{}}"#,
        r#"{"op":"sub","topic":"events","args":{"category":[115,113,108],"country":"unknown"}}"#,
    ]
    .iter()
    .map(|text| text.as_bytes().to_vec())
    .collect()
}

fn golden(name: &str) -> Vec<u8> {
    let line = include_str!("golden/zig-0.16.txt")
        .lines()
        .find(|line| line.starts_with(&format!("{name}\t")));
    line.and_then(|line| line.split('\t').nth(1)).unwrap().as_bytes().to_vec()
}

fn archive_seed() -> Vec<u8> {
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
    rankings_archive::encode(&archive).unwrap()
}

/// One corpus entry: its kind and input (two documents for a delta).
struct Entry {
    kind: &'static str,
    input: Vec<u8>,
    second: Vec<u8>,
}

/// The deterministic corpus. Changing this function changes the inputs, so the Zig
/// verdicts must then be regenerated (see `write_corpus`).
fn corpus() -> Vec<Entry> {
    let mut rng = Rng(0xd1ff);
    let mut entries = Vec::new();
    let mut add = |kind, input, second| entries.push(Entry { kind, input, second });
    let commands = command_seeds();
    for i in 0..4000 {
        let input = if i % 2 == 0 {
            mutate(&mut rng, &commands)
        } else {
            mutate_gently(&mut rng, &commands)
        };
        add("command", input, Vec::new());
    }
    let stats = vec![
        golden("stats_snapshot"),
        golden("stats_snapshot_zero"),
        MINIMAL_STATS.as_bytes().to_vec(),
    ];
    for i in 0..4000 {
        let input =
            if i % 2 == 0 { mutate(&mut rng, &stats) } else { mutate_gently(&mut rng, &stats) };
        add("stats", input, Vec::new());
    }
    let archive = archive_seed();
    for _ in 0..1000 {
        let mut doc = archive.clone();
        let at = rng.below(doc.len());
        match rng.below(3) {
            0 => doc[at] = rng.next() as u8,
            1 => doc.truncate(at),
            _ => doc.insert(at, rng.next() as u8),
        }
        add("archive", doc, Vec::new());
    }
    let documents = vec![
        golden("nodes_summary"),
        golden("delta_order_applied"),
        golden("minutes_status"),
        golden("delta_floats_applied"),
    ];
    for _ in 0..1000 {
        let previous = mutate_gently(&mut rng, &documents);
        let current = mutate(&mut rng, &documents);
        add("delta", previous, current);
    }
    entries
}

/// A peer snapshot with only the required fields and a few optional ones.
const MINIMAL_STATS: &str = concat!(
    r#"{"proxy_mode":"forward_auth","server_location":{"lat":1.5,"lon":2},"#,
    r#""boot":"ABCDEFGHIJKLMNOP","requests":1,"admitted":1,"challenged":0,"denied":0,"#,
    r#""origin_4xx":0,"origin_5xx":0,"incidents":0,"incidents_dropped":0,"sample_loss":0,"#,
    r#""cluster_health":{"healthy":1},"cpu_permille":3,"unknown_samples":0,"timestamp":5}"#,
);

/// Writes the corpus for the Zig evaluator. Run with `SIBUNA_CORPUS_OUT=<file> cargo test
/// --test differential -- --ignored`, evaluate it with Zig, and store Zig's verdicts in
/// `golden/differential.txt`.
#[test]
#[ignore]
fn write_corpus() {
    let Ok(path) = std::env::var("SIBUNA_CORPUS_OUT") else { return };
    let mut out = String::new();
    for entry in corpus() {
        out += &format!("{}\t{}\t{}\n", entry.kind, hex(&entry.input), hex(&entry.second));
    }
    std::fs::write(path, out).unwrap();
}

/// Rust's verdict in Zig's form: `!` and the error, or the FNV-1a fingerprint of the
/// re-encoded value.
fn verdict(entry: &Entry) -> String {
    let fingerprint = |text: &[u8]| format!("{:016x}", fnv1a(text));
    match entry.kind {
        "command" => match subscriptions::parse(&entry.input) {
            Ok(command) => fingerprint(to_json(&command).as_bytes()),
            Err(_) => "!InvalidCommand".into(),
        },
        "stats" => match from_json::<StatsSnapshot>(&entry.input) {
            Ok(snapshot) => {
                assert_eq!(StatsSnapshot::from_json(&entry.input).as_ref(), Ok(&snapshot));
                fingerprint(to_json(&snapshot).as_bytes())
            }
            Err(_) if StatsSnapshot::from_json(&entry.input).is_ok() => {
                "!streaming-disagrees".into()
            }
            Err(_) if non_finite_location(&entry.input) => "!non-finite".into(),
            Err(_) => "!".into(),
        },
        "archive" => match rankings_archive::decode(&entry.input) {
            Ok(archive) => fingerprint(&rankings_archive::encode(&archive).unwrap()),
            Err(ArchiveError::InvalidArchive) => "!InvalidArchive".into(),
            Err(ArchiveError::TooLarge) => "!TooLarge".into(),
        },
        _ => {
            let mut out = String::new();
            match json_delta::write(&entry.input, &entry.second, &mut out) {
                Ok(changed) => fingerprint(format!("{out}\t{changed}").as_bytes()),
                Err(_) => "!".into(),
            }
        }
    }
}

/// True when a snapshot's location holds a number Zig read as an infinity or NaN. Zig
/// accepted it and wrote it back as `inf` or `nan`, which is not JSON; the port refuses it
/// (a documented change), so these inputs are excluded from the comparison.
fn non_finite_location(input: &[u8]) -> bool {
    let Ok(value) = sibuna_json::parse(input) else { return false };
    let location = value.as_object().and_then(|object| object.get("server_location"));
    let Some(location) = location.and_then(|location| location.as_object()) else { return false };
    ["lat", "lon"].iter().filter_map(|key| location.get(key)).any(|coordinate| match coordinate {
        sibuna_json::Value::Number(number) => number.as_f64().is_err(),
        sibuna_json::Value::String(text) => {
            text.parse::<f64>().is_ok_and(|float| !float.is_finite())
        }
        _ => false,
    })
}

#[test]
fn rust_and_zig_agree_on_every_mutant() {
    let verdicts: Vec<&str> = include_str!("golden/differential.txt").lines().collect();
    let entries = corpus();
    assert_eq!(verdicts.len(), entries.len());
    let mut accepted = 0;
    for (entry, line) in entries.iter().zip(verdicts) {
        let (kind, zig) = line.split_once('\t').unwrap();
        assert_eq!(kind, entry.kind);
        let rust = verdict(entry);
        // Zig names the parse error; Rust's decoder reports a path instead, so for parsed
        // documents only the fact of refusal is compared.
        let agree = match rust.as_str() {
            "!" => zig.starts_with('!'),
            "!non-finite" => true,
            _ => rust == zig,
        };
        assert!(
            agree,
            "{} {:?}: rust {rust}, zig {zig}",
            entry.kind,
            String::from_utf8_lossy(&entry.input)
        );
        accepted += usize::from(!zig.starts_with('!'));
    }
    assert!(accepted > 1000, "{accepted}");
}

/// Frames of one subscription session: a two-part snapshot, patches, a row, a gap and a
/// new epoch.
fn session_frames() -> Vec<Vec<u8>> {
    let mut frames = first_epoch_frames(&format!("{}:1", "a".repeat(32)));
    frames.extend(second_epoch_frames(&format!("{}:7", "b".repeat(32))));
    frames.into_iter().map(String::into_bytes).collect()
}

/// The first epoch: a snapshot, patches, a row in two parts, and a gap.
fn first_epoch_frames(a: &str) -> Vec<String> {
    vec![
        format!(
            concat!(
                r#"{{"op":"snapshot_begin","topic":"stats","epoch":"{a}","seq":0,"#,
                r#""snapshot":true,"watermark":3,"parts":2}}"#,
            ),
            a = a
        ),
        format!(
            concat!(
                r#"{{"op":"snapshot_chunk","topic":"stats","epoch":"{a}","seq":1,"#,
                r#""snapshot":true,"watermark":3,"part":0,"parts":2,"#,
                r#""data":"{{\"rows\":[{{\"id\":1}}],\"x\":1.50,"}}"#,
            ),
            a = a
        ),
        format!(
            concat!(
                r#"{{"op":"snapshot_chunk","topic":"stats","epoch":"{a}","seq":2,"#,
                r#""snapshot":true,"watermark":3,"part":1,"parts":2,"data":"\"y\":[1,2],"#,
                r#"\"z\":null}}"}}"#,
            ),
            a = a
        ),
        format!(
            concat!(
                r#"{{"op":"snapshot_end","topic":"stats","epoch":"{a}","seq":3,"snapshot":true,"#,
                r#""watermark":3}}"#,
            ),
            a = a
        ),
        format!(
            concat!(
                r#"{{"op":"delta","topic":"stats","epoch":"{a}","seq":4,"snapshot":false,"#,
                r#""watermark":4,"part":0,"parts":1,"update":1,"kind":"patch","#,
                r#""data":"{{\"set\":{{\"w\":2e1,\"x\":1}},\"remove\":[\"rows\"]}}"}}"#,
            ),
            a = a
        ),
        format!(
            concat!(
                r#"{{"op":"delta","topic":"stats","epoch":"{a}","seq":5,"snapshot":false,"#,
                r#""watermark":5,"part":0,"parts":1,"update":2,"kind":"patch","#,
                r#""data":"{{\"set\":{{\"rows\":[]}},\"remove\":[\"y\"]}}"}}"#,
            ),
            a = a
        ),
        format!(
            concat!(
                r#"{{"op":"delta","topic":"stats","epoch":"{a}","seq":6,"snapshot":false,"#,
                r#""watermark":6,"part":0,"parts":2,"update":3,"kind":"row","data":"{{\"id\":"}}"#,
            ),
            a = a
        ),
        format!(
            concat!(
                r#"{{"op":"delta","topic":"stats","epoch":"{a}","seq":7,"snapshot":false,"#,
                r#""watermark":6,"part":1,"parts":2,"update":3,"kind":"row","#,
                r#""data":"\"9007199254740993\",\"v\":0.1}}"}}"#,
            ),
            a = a
        ),
        format!(r#"{{"op":"gap","topic":"stats","epoch":"{a}","dropped":"2"}}"#),
    ]
}

/// A second epoch that resumes after the gap, then a pong and the end of the session.
fn second_epoch_frames(b: &str) -> Vec<String> {
    vec![
        format!(
            concat!(
                r#"{{"op":"snapshot_begin","topic":"stats","epoch":"{b}","seq":0,"#,
                r#""snapshot":true,"watermark":"9","parts":1}}"#,
            ),
            b = b
        ),
        format!(
            concat!(
                r#"{{"op":"snapshot_chunk","topic":"stats","epoch":"{b}","seq":1,"#,
                r#""snapshot":true,"watermark":9,"part":0,"parts":1,"data":"{{\"rows\":[]}}"}}"#,
            ),
            b = b
        ),
        format!(
            concat!(
                r#"{{"op":"snapshot_end","topic":"stats","epoch":"{b}","seq":2,"snapshot":true,"#,
                r#""watermark":9}}"#,
            ),
            b = b
        ),
        String::from(r#"{"op":"pong"}"#),
        String::from(r#"{"error":"unauthorized"}"#),
    ]
}

/// Sessions of frames, mostly in order, some mutated, skipped or repeated.
fn sessions() -> Vec<Vec<Vec<u8>>> {
    let frames = session_frames();
    let mut rng = Rng(0x5e55);
    (0..500)
        .map(|_| {
            let mut session = Vec::new();
            let mut index = 0;
            while index < frames.len() && session.len() < 24 {
                let frame = match rng.below(10) {
                    0 => mutate_gently(&mut rng, std::slice::from_ref(&frames[index])),
                    1 => mutate(&mut rng, std::slice::from_ref(&frames[index])),
                    2 => frames[rng.below(frames.len())].clone(),
                    _ => frames[index].clone(),
                };
                session.push(frame);
                index += 1 + usize::from(rng.below(12) == 0);
            }
            session
        })
        .collect()
}

/// Writes the client corpus: one session per line, frames in hex separated by commas.
#[test]
#[ignore]
fn write_client_corpus() {
    let Ok(path) = std::env::var("SIBUNA_CLIENT_CORPUS_OUT") else { return };
    let lines: Vec<String> = sessions()
        .iter()
        .map(|session| session.iter().map(|frame| hex(frame)).collect::<Vec<_>>().join(","))
        .collect();
    std::fs::write(path, lines.join("\n") + "\n").unwrap();
}

/// The client's verdicts for one session in Zig's form: each frame's event or error, then
/// the view's fingerprint and the position.
fn client_verdict(session: &[Vec<u8>]) -> String {
    use sibuna_console_protocol::subscription_client::{Client, ClientError, Event};
    let mut client = Client::new();
    let mut out = Vec::new();
    for frame in session {
        out.push(match client.receive_text(frame) {
            Ok(Event::None) => "none".to_string(),
            Ok(Event::Unauthorized) => "unauthorized".to_string(),
            Ok(Event::Gap(topic)) => format!("gap:{}", codec::WireEnum::name(topic)),
            Ok(Event::Changed(topic)) => format!("changed:{}", codec::WireEnum::name(topic)),
            Err(ClientError::InvalidMessage) => "!InvalidMessage".to_string(),
            Err(ClientError::TooLarge) => "!TooLarge".to_string(),
        });
    }
    out.push(format!("{:016x}", fnv1a(client.view(Topic::Stats).as_bytes())));
    out.push(match client.position(Topic::Stats) {
        Some(position) => format!("{}/{}", position.sequence, position.watermark),
        None => "-".to_string(),
    });
    out.join(" ")
}

#[test]
fn rust_and_zig_clients_agree_on_every_session() {
    let verdicts: Vec<&str> = include_str!("golden/client-differential.txt").lines().collect();
    let sessions = sessions();
    assert_eq!(verdicts.len(), sessions.len());
    for (session, zig) in sessions.iter().zip(verdicts) {
        assert_eq!(
            client_verdict(session),
            zig,
            "{:?}",
            session.iter().map(|f| String::from_utf8_lossy(f)).collect::<Vec<_>>()
        );
    }
}
