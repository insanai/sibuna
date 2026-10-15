//! Round trips of generated CSV text through the system `gzip`, and a throughput
//! measurement. Tests that need `gzip` skip themselves when it is not installed.
//!
//! Measure with: `cargo test --release -p sibuna-inflate --test throughput -- --ignored
//! --nocapture`.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Instant;

use sibuna_inflate::{Decoder, Format, Limits, Status, gunzip};

/// Returns about `size` bytes of DB-IP-like rows (`start,end,country`), deterministic.
fn csv_text(size: usize) -> Vec<u8> {
    const COUNTRIES: [&str; 12] =
        ["US", "DE", "FR", "GB", "JP", "CN", "IN", "BR", "NL", "SE", "AU", "ZZ"];
    let mut text = Vec::with_capacity(size + 64);
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut address: u32 = 1 << 24;
    while text.len() < size {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let end = address.wrapping_add((state % 4096) as u32 + 1);
        let [a, b, c, d] = address.to_be_bytes();
        let [e, f, g, h] = end.to_be_bytes();
        let country = COUNTRIES[(state >> 32) as usize % COUNTRIES.len()];
        writeln!(text, "{a}.{b}.{c}.{d},{e}.{f}.{g}.{h},{country}").expect("writing to a Vec");
        address = end.wrapping_add(1);
    }
    text
}

/// Compresses `data` with the system gzip at `level`, or returns `None` without it.
fn system_gzip(data: &[u8], level: u32) -> Option<Vec<u8>> {
    let mut child = Command::new("gzip")
        .arg(format!("-{level}"))
        .arg("-n")
        .arg("-c")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    let mut stdin = child.stdin.take()?;
    let input = data.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let output = child.wait_with_output().ok()?;
    writer.join().ok()?.ok()?;
    output.status.success().then_some(output.stdout)
}

#[test]
fn several_mib_round_trip() {
    let text = csv_text(4 << 20);
    for level in [1, 6, 9] {
        let Some(gz) = system_gzip(&text, level) else {
            eprintln!("gzip is not installed; skipping");
            return;
        };
        assert_eq!(gunzip(&gz, Limits::default()).unwrap(), text, "level {level}");
        // The same through 8 KiB input chunks and an 8 KiB output buffer.
        let mut decoder = Decoder::new(Format::Gzip, Limits::default());
        let mut buffer = [0u8; 8192];
        let mut output = Vec::new();
        let mut offset = 0;
        loop {
            let end = (offset + 8192).min(gz.len());
            let progress =
                decoder.decompress(&gz[offset..end], end == gz.len(), &mut buffer).unwrap();
            offset += progress.consumed;
            output.extend_from_slice(&buffer[..progress.written]);
            if progress.status == Status::Done {
                break;
            }
        }
        assert!(output == text, "level {level}: streamed output differs");
    }
}

/// Returns the best time in seconds of `runs` calls of `work`.
fn best_of(runs: usize, mut work: impl FnMut()) -> f64 {
    (0..runs)
        .map(|_| {
            let start = Instant::now();
            work();
            start.elapsed().as_secs_f64()
        })
        .fold(f64::INFINITY, f64::min)
}

#[test]
#[ignore = "measures throughput; run with --release --ignored --nocapture"]
fn measure_throughput() {
    let text = csv_text(64 << 20);
    let mib = text.len() as f64 / f64::from(1 << 20);
    for level in [1, 6, 9] {
        let Some(gz) = system_gzip(&text, level) else {
            eprintln!("gzip is not installed; skipping");
            return;
        };
        let limits = Limits::default();
        let mut decoder = Decoder::new(Format::Gzip, limits);
        let mut buffer = vec![0u8; 64 * 1024];
        let one_call = best_of(5, || assert_eq!(gunzip(&gz, limits).unwrap().len(), text.len()));
        let streamed = best_of(5, || {
            decoder.reset();
            let (mut offset, mut total) = (0, 0);
            loop {
                let progress = decoder.decompress(&gz[offset..], true, &mut buffer).unwrap();
                offset += progress.consumed;
                total += progress.written;
                if progress.status == Status::Done {
                    break;
                }
            }
            assert_eq!(total, text.len());
        });
        eprintln!(
            "gzip -{level}: {mib:.0} MiB of CSV from {:.1} MiB: one call {:.0} MiB/s, \
             streaming 64 KiB buffer {:.0} MiB/s",
            gz.len() as f64 / f64::from(1 << 20),
            mib / one_call,
            mib / streamed,
        );
    }
}
