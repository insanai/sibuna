//! The `geoip-snapshot` tool end to end: it must write the snapshots the Zig tool wrote
//! from the same files, and fail with a diagnostic and status 1 on bad input.

use std::path::{Path, PathBuf};
use std::process::Command;

const TOOL: &str = env!("CARGO_BIN_EXE_geoip-snapshot");

fn testdata(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata").join(name)
}

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("geoip-cli");
    std::fs::create_dir_all(&dir).expect("create the scratch directory");
    dir.join(name)
}

#[test]
fn the_tool_writes_the_zig_snapshots() {
    let out = scratch("user-country.sbgeoip");
    let status = Command::new(TOOL)
        .args(["--provider", "user-country", "--version", "2026-09-09"])
        .arg(testdata("user-country-ipv4.csv"))
        .arg(testdata("user-country-ipv6.csv"))
        .args(["--lookup", "1.0.0.1", "--snapshot-out"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(status.status.success());
    let report = String::from_utf8(status.stderr).unwrap();
    assert!(
        report.contains("user-country 2026-09-09: 25 known ranges; SHA-256 adecbbd1"),
        "{report}"
    );
    assert!(report.contains("geoip-snapshot: 1.0.0.1 AU\n"), "{report}");
    assert_eq!(
        std::fs::read(&out).unwrap(),
        std::fs::read(testdata("user-country.sbgeoip")).unwrap()
    );
    let out = scratch("dbip.sbgeoip");
    let status = Command::new(TOOL)
        .args(["--provider", "dbip", "--version", "2026-09"])
        .arg(testdata("countries.csv.gz"))
        .arg("--snapshot-out")
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(std::fs::read(&out).unwrap(), std::fs::read(testdata("dbip.sbgeoip")).unwrap());
    let check = Command::new(TOOL)
        .arg("--snapshot")
        .arg(&out)
        .arg("--lookup")
        .arg("8.8.8.8")
        .output()
        .unwrap();
    assert!(check.status.success());
    assert!(String::from_utf8(check.stderr).unwrap().contains("geoip-snapshot: 8.8.8.8 US\n"));
}

#[test]
fn bad_rows_fail_with_a_located_diagnostic() {
    let source = scratch("bad.csv");
    std::fs::write(&source, "1.0.0.0,1.0.0.255,AU\n1.0.1.0,1.0.1.255,QQ\n").unwrap();
    let empty = scratch("empty.csv");
    std::fs::write(&empty, "").unwrap();
    let output = Command::new(TOOL)
        .args(["--provider", "user-country", "--version", "2026-09-09"])
        .arg(&source)
        .arg(&empty)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stderr).unwrap();
    assert!(text.contains("code outside the ISO list: QQ"), "{text}");
    assert!(text.contains("-- INVALID COUNTRY ---"), "{text}");
    assert!(text.contains("bad.csv:2\n"), "{text}");
    assert!(text.contains("2| 1.0.1.0,1.0.1.255,QQ\n"), "{text}");
    assert!(text.contains("Hint: "), "{text}");
}
