//! The command line of `sibuna-parity`.

use std::path::PathBuf;

/// The default Zig daemon: the baseline build of the port's working directory.
const DEFAULT_ZIG: &str = concat!(
    "/tmp/claude-1000/-home-insan-projects-sibuna2/",
    "7eb5843a-dcb8-4e49-b872-04e7f4d823b5/scratchpad/zig-baseline/bin/sibuna"
);

/// The help text.
pub const HELP: &str = "\
Differential test of the Rust daemon against the Zig daemon.

Usage: cargo xtask parity [OPTIONS]

Options:
  --zig <PATH>        The Zig daemon (default: the baseline build named in options.rs)
  --rust <PATH>       The Rust daemon (default: build it with cargo build --release -p sibuna)
  --seed <N>          Corpus seed (default: 20261015)
  --requests <N>      Corpus size in requests (default: 20000)
  --report <DIR>      Report directory (default: target/parity)
  --allow <FILE>      Allow-list of deliberate differences (default: tools/parity/allow-list.json)
  --jobs <N>          Configurations run at the same time (default: 4)
  --workers <N>       Client threads per configuration (default: 4)
  --config <PATTERN>  Only configurations whose name matches; `*` matches any text
  --case <ID>         Only this scenario (repeatable); the corpus is the same
  --keep-all          Also write identical scenarios (both answers) to the report's cases/
  -h, --help          Print this help

The run exits with 0 when every difference is on the allow-list, 1 when some is not or a
daemon failed, and 2 on a usage or setup error.
";

/// The parsed options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// The Zig daemon binary.
    pub zig: PathBuf,
    /// The Rust daemon binary; built when `None`.
    pub rust: Option<PathBuf>,
    /// The corpus seed.
    pub seed: u64,
    /// The corpus size in requests.
    pub requests: usize,
    /// The report directory.
    pub report: PathBuf,
    /// The allow-list file.
    pub allow: PathBuf,
    /// Configurations run at the same time.
    pub jobs: usize,
    /// Client threads per configuration.
    pub workers: usize,
    /// Configuration name patterns, all of which must match.
    pub configs: Vec<String>,
    /// Scenario ids to run; all when empty.
    pub cases: Vec<usize>,
    /// Whether identical scenarios are written to the report too.
    pub keep_all: bool,
}

impl Default for Options {
    fn default() -> Options {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace = root.ancestors().nth(2).map_or_else(|| root.clone(), PathBuf::from);
        Options {
            zig: PathBuf::from(DEFAULT_ZIG),
            rust: None,
            seed: 20_261_015,
            requests: 20_000,
            report: workspace.join("target").join("parity"),
            allow: root.join("allow-list.json"),
            jobs: 4,
            workers: 4,
            configs: Vec::new(),
            cases: Vec::new(),
            keep_all: false,
        }
    }
}

/// Parses the arguments. Returns `None` for `--help`.
///
/// # Errors
///
/// Returns a message naming an unknown option, a missing value or an invalid number.
pub fn parse(arguments: &[String]) -> Result<Option<Options>, String> {
    let mut options = Options::default();
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        if argument == "-h" || argument == "--help" {
            return Ok(None);
        }
        if argument == "--keep-all" {
            options.keep_all = true;
            continue;
        }
        let mut value = || {
            rest.next().cloned().ok_or_else(|| format!("the option `{argument}` needs a value"))
        };
        match argument.as_str() {
            "--zig" => options.zig = value()?.into(),
            "--rust" => options.rust = Some(value()?.into()),
            "--seed" => options.seed = number(argument, &value()?)?,
            "--requests" => options.requests = number(argument, &value()?)?,
            "--report" => options.report = value()?.into(),
            "--allow" => options.allow = value()?.into(),
            "--jobs" => options.jobs = number(argument, &value()?)?,
            "--workers" => options.workers = number(argument, &value()?)?,
            "--config" => options.configs.push(value()?),
            "--case" => options.cases.push(number(argument, &value()?)?),
            other => return Err(format!("there is no option `{other}`")),
        }
    }
    Ok(Some(options))
}

fn number<T: std::str::FromStr>(option: &str, text: &str) -> Result<T, String> {
    text.parse().map_err(|_| format!("the option `{option}` needs a number, not `{text}`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|text| (*text).to_owned()).collect()
    }

    #[test]
    fn options_parse_with_defaults() {
        let options =
            parse(&strings(&["--seed", "7", "--case", "3", "--case", "9"])).unwrap().unwrap();
        assert_eq!(options.seed, 7);
        assert_eq!(options.cases, [3, 9]);
        assert_eq!(options.requests, 20_000);
        assert!(options.allow.ends_with("tools/parity/allow-list.json"));
        assert_eq!(parse(&strings(&["--help"])).unwrap(), None);
    }

    #[test]
    fn mistakes_are_named() {
        assert!(parse(&strings(&["--bogus"])).unwrap_err().contains("--bogus"));
        assert!(parse(&strings(&["--seed"])).unwrap_err().contains("needs a value"));
        assert!(parse(&strings(&["--jobs", "x"])).unwrap_err().contains("needs a number"));
    }
}
