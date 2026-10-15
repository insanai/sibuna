//! Timing of the hot encoders and decoders, the counterpart of the Zig baseline program
//! described in the crate documentation (same inputs, median of seven batches). Run with
//! `cargo test --release -p sibuna-console-protocol --test bench -- --ignored --nocapture`.

// Test code: a failed expectation is a panic by design.
#![allow(clippy::unwrap_used, clippy::print_stdout)]

use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

use sibuna_console_protocol::codec::{from_json, write_json};
use sibuna_console_protocol::space_saving::{Counter, Summary};
use sibuna_console_protocol::subscription_client::Client;
use sibuna_console_protocol::*;

fn golden(name: &str) -> &'static str {
    include_str!("golden/zig-0.16.txt")
        .lines()
        .find_map(|line| line.strip_prefix(name).and_then(|rest| rest.strip_prefix('\t')))
        .unwrap()
}

fn measure(name: &str, iterations: u64, mut body: impl FnMut(u64)) {
    let mut samples = [0f64; 7];
    body(0);
    for sample in &mut samples {
        let start = Instant::now();
        for i in 0..iterations {
            body(i);
        }
        *sample = start.elapsed().as_nanos() as f64 / iterations as f64;
    }
    samples.sort_by(f64::total_cmp);
    println!("{name}\t{:.1} ns/op", samples[3]);
}

#[test]
#[ignore]
fn hot_paths() {
    let view = golden("dashboard_view");
    let mut current = String::new();
    let mut out = String::with_capacity(65_536);
    measure("delta_write_dashboard_view", 20_000, |i| {
        current.clear();
        let (head, tail) = view.split_once("\"timestamp\":1700000000").unwrap();
        let _ = write!(current, "{head}\"timestamp\":{}{tail}", 1_700_000_000 + i % 7);
        out.clear();
        black_box(json_delta::write(view.as_bytes(), current.as_bytes(), &mut out).unwrap());
    });

    let snapshot: StatsSnapshot = from_json(golden("stats_snapshot").as_bytes()).unwrap();
    let mut scope = dashboard::Scope {
        available: true,
        count: 2,
        request_rate: Some(2.5),
        traffic_uncertainty: 9_007_199_254_740_993,
        ..dashboard::Scope::default()
    };
    scope.sources[0] = Some(dashboard::Source {
        status: nodes::PeerStatus::Current,
        age_seconds: Some(1),
        ..dashboard::Source::new(1)
    });
    scope.sources[1] = Some(dashboard::Source::new(2));
    let view_value = dashboard::View { scope, value: Some(snapshot) };
    measure("encode_dashboard_view", 50_000, |_| {
        out.clear();
        write_json(black_box(&view_value), &mut out).unwrap();
        black_box(out.len());
    });

    let stats = golden("stats_snapshot");
    measure("decode_stats_snapshot", 50_000, |_| {
        black_box(from_json::<StatsSnapshot>(black_box(stats.as_bytes())).unwrap());
    });

    measure("decode_stats_snapshot_streaming", 50_000, |_| {
        black_box(StatsSnapshot::from_json(black_box(stats.as_bytes())).unwrap());
    });
    measure("parse_stats_snapshot_only", 50_000, |_| {
        black_box(sibuna_json::parse(black_box(stats.as_bytes())).unwrap());
    });

    measure("pull_read_stats_snapshot_only", 50_000, |_| {
        let mut reader = sibuna_json::PullReader::new(black_box(stats.as_bytes()));
        let mut events = 0usize;
        while let Some(event) = reader.next().unwrap() {
            events += 1;
            black_box(&event);
        }
        black_box(events);
    });
    let parsed = sibuna_json::parse(stats.as_bytes()).unwrap();
    measure("decode_stats_snapshot_from_tree", 50_000, |_| {
        black_box(
            <StatsSnapshot as codec::Decode>::decode(black_box(&parsed), codec::Path::Root)
                .unwrap(),
        );
    });

    client_receive();
    sketches();
}

fn client_receive() {
    let epoch = format!("{}:1", "a".repeat(32));
    let mut client = Client::new();
    let begin = format!(
        concat!(
            r#"{{"op":"snapshot_begin","topic":"stats","epoch":"{epoch}","seq":0,"#,
            r#""snapshot":true,"watermark":0,"parts":1}}"#,
        ),
        epoch = epoch
    );
    client.receive_text(begin.as_bytes()).unwrap();
    let chunk = format!(
        concat!(
            r#"{{"op":"snapshot_chunk","topic":"stats","epoch":"{epoch}","seq":1,"#,
            r#""snapshot":true,"watermark":0,"part":0,"parts":1,"data":"{{\"rows\":[],"#,
            r#"\"requests\":1}}"}}"#,
        ),
        epoch = epoch
    );
    client.receive_text(chunk.as_bytes()).unwrap();
    let end = format!(
        concat!(
            r#"{{"op":"snapshot_end","topic":"stats","epoch":"{epoch}","seq":2,"snapshot":true,"#,
            r#""watermark":0}}"#,
        ),
        epoch = epoch
    );
    client.receive_text(end.as_bytes()).unwrap();
    let mut sequence = 3u64;
    let mut frame = String::new();
    measure("client_receive_delta", 20_000, |_| {
        frame.clear();
        let _ = write!(
            frame,
            concat!(
                r#"{{"op":"delta","topic":"stats","epoch":"{epoch}","seq":{sequence},"#,
                r#""snapshot":false,"watermark":{sequence},"part":0,"parts":1,"#,
                r#""update":{sequence},"kind":"patch","#,
                r#""data":"{{\"set\":{{\"requests\":{sequence},\"timestamp\":{sequence}}},"#,
                r#"\"remove\":[]}}"}}"#,
            ),
            epoch = epoch,
            sequence = sequence,
        );
        black_box(client.receive_text(frame.as_bytes()).unwrap());
        sequence += 1;
    });
}

fn sketches() {
    let keys: Vec<[u8; 32]> = (0..512)
        .map(|k| {
            let mut key = [b'p'; 32];
            let text = format!("/path/{k}");
            key[..text.len()].copy_from_slice(text.as_bytes());
            key
        })
        .collect();
    let mut sketch = Summary::new();
    for k in 0..1024 {
        sketch.add(&keys[k % 512]).unwrap();
    }
    measure("space_saving_add_full", 200_000, |i| {
        sketch.add(&keys[(i as usize * 7) % 512]).unwrap();
    });
    let mut other = Summary::new();
    for k in 0..1024 {
        other.add(&keys[(k * 3) % 512]).unwrap();
    }
    let mut merged = Summary::new();
    let mut candidates: Vec<Counter<128>> = Vec::with_capacity(512);
    measure("space_saving_merge_full", 2_000, |_| {
        merged.merge_into(black_box(&sketch), &other, &mut candidates).unwrap();
        black_box(&merged);
    });
}
