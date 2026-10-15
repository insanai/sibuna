//! Provenance of a result file: when, where, on what machine and from which revision.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use sibuna_crypto::sha256::Sha256;

use crate::json::Json;
use crate::process::CpuSet;

/// Returns the machine and revision metadata common to every result file.
///
/// `root` is the workspace (for `git`), `cpus` the CPUs the measured code ran on (for their
/// frequency governors).
pub fn machine(root: &Path, cpus: &CpuSet) -> Json {
    let kernel = read_trimmed("/proc/sys/kernel/osrelease");
    Json::object()
        .with("date", utc_now())
        .with("host", read_trimmed("/proc/sys/kernel/hostname"))
        .with("cpu", cpu_model())
        .with("logical_cpus", std::thread::available_parallelism().map_or(0, usize::from))
        .with(
            "os",
            format!("Linux {} {}", kernel.as_deref().unwrap_or("?"), std::env::consts::ARCH),
        )
        .with("kernel", kernel)
        .with("governor", governors(cpus))
        .with("load_average", load_average())
        .with("boost", read_trimmed("/sys/devices/system/cpu/cpufreq/boost"))
        .with("rustc", command_line(root, "rustc", &["-V"]))
        .with("git", command_line(root, "git", &["rev-parse", "HEAD"]))
        .with("dirty", command_line(root, "git", &["status", "--porcelain"]).is_some())
}

/// Returns `/proc/loadavg` (1, 5 and 15 minute load averages, runnable and total tasks):
/// the benchmark host may be shared, and this records how busy it was.
pub fn load_average() -> Option<String> {
    read_trimmed("/proc/loadavg")
}

/// Returns the version line of the Zig compiler on `PATH`, if there is one.
pub fn zig_version() -> Option<String> {
    command_line(Path::new("."), "zig", &["version"])
}

/// Returns the size and SHA-256 of the file at `path` as `{"bytes":..,"sha256":..}`.
pub fn binary(path: &Path) -> Json {
    let Ok(bytes) = fs::read(path) else {
        return Json::object().with("path", path.display().to_string());
    };
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
    Json::object()
        .with("path", path.display().to_string())
        .with("bytes", bytes.len())
        .with("sha256", digest)
}

/// Returns the first line of the trimmed output of `program args` run in `dir`, or `None`
/// when it fails or prints nothing.
fn command_line(dir: &Path, program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).current_dir(dir).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines().next().map(str::trim).filter(|line| !line.is_empty()).map(str::to_owned)
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|text| text.trim().to_owned())
}

fn cpu_model() -> Option<String> {
    let text = fs::read_to_string("/proc/cpuinfo").ok()?;
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        matches!(key.trim(), "model name" | "Hardware").then(|| value.trim().to_owned())
    })
}

/// Returns the distinct scaling governors of `cpus`, joined by commas.
fn governors(cpus: &CpuSet) -> Option<String> {
    let mut seen: Vec<String> = Vec::new();
    for cpu in &cpus.cpus {
        let path = format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor");
        if let Some(governor) = read_trimmed(&path)
            && !seen.contains(&governor)
        {
            seen.push(governor);
        }
    }
    (!seen.is_empty()).then(|| seen.join(","))
}

/// Returns the current time in UTC as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn utc_now() -> String {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    format_utc(seconds)
}

/// Formats `seconds` since the Unix epoch as an ISO 8601 UTC timestamp.
fn format_utc(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// Converts days since 1970-01-01 into a proleptic Gregorian date (Howard Hinnant's
/// `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc_timestamps() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(format_utc(1_725_700_000), "2024-09-07T09:06:40Z");
        assert_eq!(format_utc(4_102_444_799), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn hashes_a_binary() {
        let path = std::env::temp_dir().join(format!("sibuna-bench-meta-{}", std::process::id()));
        fs::write(&path, b"abc").unwrap();
        let json = binary(&path);
        fs::remove_file(&path).unwrap();
        let text = json.to_pretty();
        assert!(text.contains("\"bytes\": 3"));
        assert!(text.contains("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    }
}
