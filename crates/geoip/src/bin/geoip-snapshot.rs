//! Offline country-data tool. Validates provider downloads or an `SBGEOIP1` snapshot and
//! optionally writes a snapshot. It never opens application storage or the network.
//!
//! ```text
//! geoip-snapshot --provider user-country --version 2026-09-09 ipv4.csv ipv6.csv
//! geoip-snapshot --provider dbip --version 2026-09 dbip-country-lite-2026-09.csv.gz
//! geoip-snapshot --snapshot snapshot.bin
//! ... --snapshot-out snapshot.bin   (write after validation)
//! ... --lookup 8.8.8.8              (repeatable, at most 64; prints the country)
//! ```
//!
//! Reports go to standard error, as in the Zig tool. Errors are Elm-style diagnostics and
//! the exit status is 1.

use std::fmt::Write as _;
use std::io::Read as _;
use std::process::ExitCode;

use sibuna_geoip::gzip::{self, GzipError};
use sibuna_geoip::provider::MAX_FILES;
use sibuna_geoip::snapshot::{self, SnapshotError};
use sibuna_geoip::{Compression, Database, LoadError, Loader, Provider, RangeError, country};

/// The largest uncompressed source file the tool reads.
const MAX_INPUT: usize = 32 * 1024 * 1024;
/// The most `--lookup` addresses.
const MAX_LOOKUPS: usize = 64;
const OPTIONS: [&str; 6] =
    ["--provider", "--version", "--snapshot", "--snapshot-out", "--lookup", "--help"];
const USAGE: &str = "usage: geoip-snapshot --provider <name> --version <version> <files>... \
[--snapshot-out <path>] [--lookup <address>]...\n       geoip-snapshot --snapshot <path> \
[--snapshot-out <path>] [--lookup <address>]...";

/// A rendered error: title rule, explanation, excerpt with a caret, and a hint. Boxed, so
/// the error side of every `Result` in the tool stays one pointer wide.
struct Diagnostic(Box<Report>);

struct Report {
    title: &'static str,
    location: String,
    message: String,
    excerpt: Option<Excerpt>,
    hint: String,
}

/// One line of source or of the command line, with the span the caret marks.
struct Excerpt {
    gutter: String,
    text: String,
    start: usize,
    width: usize,
}

impl Diagnostic {
    fn new(
        title: &'static str,
        location: impl Into<String>,
        message: String,
        hint: String,
    ) -> Self {
        let location = location.into();
        Diagnostic(Box::new(Report { title, location, message, excerpt: None, hint }))
    }

    fn with_excerpt(mut self, excerpt: Option<Excerpt>) -> Self {
        self.0.excerpt = excerpt;
        self
    }

    fn render(&self) -> String {
        let report = &self.0;
        let mut out = String::new();
        let used = 3 + report.title.len() + 2 + report.location.len();
        let dashes = "-".repeat(80usize.saturating_sub(used).max(3));
        let _ = writeln!(out, "-- {} {dashes} {}\n", report.title, report.location);
        let _ = writeln!(out, "{}\n", report.message);
        if let Some(excerpt) = &report.excerpt {
            let _ = writeln!(out, "{}{}", excerpt.gutter, excerpt.text);
            let pad = " ".repeat(excerpt.gutter.len() + excerpt.start);
            let _ = writeln!(out, "{pad}{}", "^".repeat(excerpt.width.max(1)));
        }
        let _ = writeln!(out, "Hint: {}", report.hint);
        out
    }
}

/// Returns `text` with every byte that is not printable ASCII replaced by `?`, so caret
/// columns stay byte columns.
fn printable(text: &[u8]) -> String {
    text.iter().map(|&b| if (b' '..=b'~').contains(&b) { b as char } else { '?' }).collect()
}

/// The command line as one excerpt, with the caret under argument `index`.
fn argument_excerpt(args: &[String], index: usize) -> Option<Excerpt> {
    let mut text = String::from("geoip-snapshot");
    let mut span = None;
    for (position, arg) in args.iter().enumerate() {
        text.push(' ');
        if position == index {
            span = Some((text.len(), arg.len()));
        }
        text.push_str(&printable(arg.as_bytes()));
    }
    let (start, width) = span.unwrap_or((text.len(), 1));
    Some(Excerpt { gutter: "  ".to_owned(), text, start, width })
}

/// Levenshtein distance, for "Did you mean" suggestions among a few short words.
fn distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut diagonal = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let above = row[j + 1];
            row[j + 1] = (above + 1).min(row[j] + 1).min(diagonal + usize::from(ca != *cb));
            diagonal = above;
        }
    }
    row[b.len()]
}

fn did_you_mean<'a>(word: &str, choices: impl IntoIterator<Item = &'a str>) -> String {
    let best = choices.into_iter().min_by_key(|choice| distance(word, choice));
    match best {
        Some(choice) if distance(word, choice) <= 3 => format!(" Did you mean `{choice}`?"),
        _ => String::new(),
    }
}

/// The parsed command line.
#[derive(Default)]
struct Options {
    provider: Option<Provider>,
    version: Option<String>,
    snapshot: Option<String>,
    out: Option<String>,
    files: Vec<String>,
    lookups: Vec<String>,
    help: bool,
}

fn usage_error(
    args: &[String],
    index: usize,
    title: &'static str,
    message: String,
    hint: String,
) -> Diagnostic {
    Diagnostic::new(title, "command line", message, hint)
        .with_excerpt(argument_excerpt(args, index))
}

/// Returns the value after option `index`, or a diagnostic naming what is missing.
fn value(args: &[String], index: usize, what: &str) -> Result<String, Diagnostic> {
    args.get(index + 1).cloned().ok_or_else(|| {
        let option = &args[index];
        usage_error(
            args,
            index,
            "MISSING VALUE",
            format!("The option `{option}` needs {what} after it."),
            format!("Write `{option} <{what}>`."),
        )
    })
}

fn parse_provider(args: &[String], index: usize) -> Result<Provider, Diagnostic> {
    let name = value(args, index, "provider name")?;
    Provider::parse(&name).ok_or_else(|| {
        let names = Provider::ALL.map(Provider::name);
        usage_error(
            args,
            index + 1,
            "UNKNOWN PROVIDER",
            format!("No provider is named `{}`.", printable(name.as_bytes())),
            format!("Use `user-country` or `dbip`.{}", did_you_mean(&name, names)),
        )
    })
}

fn parse_args(args: &[String]) -> Result<Options, Diagnostic> {
    let mut options = Options::default();
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        match arg.as_str() {
            "--provider" => options.provider = Some(parse_provider(args, index)?),
            "--version" => options.version = Some(value(args, index, "version")?),
            "--snapshot" => options.snapshot = Some(value(args, index, "path")?),
            "--snapshot-out" => options.out = Some(value(args, index, "path")?),
            "--lookup" => {
                if options.lookups.len() == MAX_LOOKUPS {
                    let message = format!("At most {MAX_LOOKUPS} addresses can be looked up.");
                    let hint = "Run the tool again for the remaining addresses.".to_owned();
                    return Err(usage_error(args, index, "TOO MANY LOOKUPS", message, hint));
                }
                options.lookups.push(value(args, index, "address")?);
            }
            "--help" | "-h" => options.help = true,
            option if option.starts_with("--") => {
                let message = format!("There is no option `{}`.", printable(option.as_bytes()));
                let hint =
                    format!("Run with --help for the options.{}", did_you_mean(option, OPTIONS));
                return Err(usage_error(args, index, "UNKNOWN OPTION", message, hint));
            }
            _ => {
                if options.files.len() == MAX_FILES {
                    let message =
                        format!("A provider publishes at most {MAX_FILES} source files.");
                    let hint = "Name only the files of one generation.".to_owned();
                    return Err(usage_error(args, index, "TOO MANY FILES", message, hint));
                }
                options.files.push(arg.clone());
                index += 1;
                continue;
            }
        }
        index += if arg.starts_with("--") && arg != "--help" { 2 } else { 1 };
    }
    Ok(options)
}

/// Checks that the options describe one source: a snapshot, or a provider's files.
fn check_options(args: &[String], options: &Options) -> Result<(), Diagnostic> {
    let position = |name: &str| args.iter().position(|arg| arg == name).unwrap_or(0);
    if options.snapshot.is_some() {
        if !options.files.is_empty() || options.provider.is_some() {
            let message = "A snapshot already names its provider and holds its data, so \
                           `--snapshot` cannot be combined with `--provider` or source files."
                .to_owned();
            let hint = "Validate either a snapshot or a set of source files.".to_owned();
            let at = position("--snapshot");
            return Err(usage_error(args, at, "CONFLICTING OPTIONS", message, hint));
        }
        return Ok(());
    }
    let Some(provider) = options.provider else {
        let message = "The tool needs a provider to read source files.".to_owned();
        let hint = "Add `--provider user-country` or `--provider dbip`.".to_owned();
        return Err(usage_error(args, args.len(), "MISSING PROVIDER", message, hint));
    };
    if options.files.len() != usize::from(provider.file_count()) {
        let message = format!(
            "The provider `{provider}` publishes {}, but {} named.",
            count(usize::from(provider.file_count()), "source file"),
            count(options.files.len(), "file was")
        );
        let hint = match provider {
            Provider::UserCountry => "Name `user-country-ipv4.csv`, then `user-country-ipv6.csv`.",
            Provider::Dbip => "Name the one `dbip-country-lite-YYYY-MM.csv.gz` archive.",
        };
        let at = position("--provider") + 1;
        return Err(usage_error(args, at, "WRONG FILE COUNT", message, hint.to_owned()));
    }
    let version = options.version.as_deref().unwrap_or("");
    if !provider.is_version_valid(version) {
        let message = format!(
            "`{}` is not a version of `{provider}`, which uses {}.",
            printable(version.as_bytes()),
            provider.version_syntax()
        );
        let hint = format!(
            "Write the version as {}, for example the date of the download.",
            provider.version_syntax()
        );
        let at = args.iter().position(|arg| arg == "--version").map_or(args.len(), |i| i + 1);
        return Err(usage_error(args, at, "INVALID VERSION", message, hint));
    }
    Ok(())
}

/// Returns "1 file was" or "2 files were" style phrases for `noun` given in the singular.
fn count(n: usize, noun: &str) -> String {
    if n == 1 {
        return format!("{n} {noun}");
    }
    match noun.split_once(' ') {
        Some((word, "was")) => format!("{n} {word}s were"),
        _ => format!("{n} {noun}s"),
    }
}

/// Reads at most `limit` bytes of `path`.
fn read_file(path: &str, limit: usize) -> Result<Vec<u8>, Diagnostic> {
    let read_error = |error: std::io::Error| {
        Diagnostic::new(
            "CANNOT READ FILE",
            path,
            format!("The file `{path}` could not be read: {error}."),
            "Check the path and the file permissions.".to_owned(),
        )
    };
    let file = std::fs::File::open(path).map_err(read_error)?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes).map_err(read_error)?;
    if bytes.len() > limit {
        return Err(Diagnostic::new(
            "FILE TOO LARGE",
            path,
            format!("The file `{path}` is larger than {} MiB.", limit >> 20),
            "Check that this is the right file; published country data is far smaller.".to_owned(),
        ));
    }
    Ok(bytes)
}

/// The span of the column a row error is about, as (start, width) in bytes.
fn row_span(line: &[u8], error: RangeError) -> (usize, usize) {
    let mut columns = Vec::new();
    let mut start = 0;
    for piece in line.split(|&b| b == b',') {
        columns.push((start, piece.len()));
        start += piece.len() + 1;
    }
    let column = |n: usize| columns.get(n).copied().unwrap_or((0, line.len()));
    match error {
        RangeError::InvalidCountry => column(2),
        RangeError::InvalidAddress => {
            let (first_start, first_width) = column(0);
            let first = line.get(first_start..first_start + first_width).unwrap_or_default();
            let unquoted =
                first.strip_prefix(b"\"").and_then(|f| f.strip_suffix(b"\"")).unwrap_or(first);
            if sibuna_geoip::address::parse_bytes(unquoted).is_err() {
                column(0)
            } else {
                column(1)
            }
        }
        RangeError::Unordered => (0, column(1).0 + column(1).1),
        RangeError::Overlap => column(0),
        _ => (0, line.len()),
    }
}

fn row_hint(error: RangeError, line: &[u8]) -> String {
    match error {
        RangeError::InvalidRow => {
            "Each row is `start,end,country` within 128 bytes, like `1.0.0.0,1.0.0.255,AU`."
                .to_owned()
        }
        RangeError::InvalidAddress => "Write both addresses in one family: dotted IPv4 without \
                                       leading zeros, or IPv6 in colon notation."
            .to_owned(),
        RangeError::InvalidCountry => {
            let code = line.rsplit(|&b| b == b',').next().unwrap_or_default();
            let upper = code.to_ascii_uppercase();
            let suggestion = match country::Country::parse(&upper) {
                Some(found) if upper != code => format!(" Did you mean `{found}`?"),
                _ => String::new(),
            };
            let codes = "an ISO 3166-1 alpha-2 code in capitals, AN, FX, or ZZ for unknown";
            format!("Use {codes}.{suggestion}")
        }
        RangeError::Unordered => {
            "Swap the two addresses so the range starts at the lower one.".to_owned()
        }
        RangeError::Overlap => {
            "Sort the rows of each family by start address and remove overlapping rows.".to_owned()
        }
        RangeError::Capacity => "A generation holds at most 1,048,576 rows.".to_owned(),
        RangeError::OutOfMemory => "Free some memory and run the tool again.".to_owned(),
    }
}

fn row_title(error: RangeError) -> &'static str {
    match error {
        RangeError::InvalidRow => "INVALID ROW",
        RangeError::InvalidAddress => "INVALID ADDRESS",
        RangeError::InvalidCountry => "INVALID COUNTRY",
        RangeError::Unordered => "UNORDERED RANGE",
        RangeError::Overlap => "OVERLAPPING RANGE",
        RangeError::Capacity => "TOO MANY ROWS",
        RangeError::OutOfMemory => "OUT OF MEMORY",
    }
}

/// A diagnostic for a refused row, quoting the row from the source bytes.
fn row_diagnostic(path: &str, source: &[u8], error: RangeError, line: u64) -> Diagnostic {
    let text =
        source.split(|&b| b == b'\n').nth(line.saturating_sub(1) as usize).unwrap_or_default();
    let text = text.strip_suffix(b"\r").unwrap_or(text);
    let shown = text.get(..120).unwrap_or(text);
    let (start, width) = row_span(text, error);
    let width = width.min(shown.len().saturating_sub(start)).max(1);
    let gutter = format!("{line}| ");
    let excerpt = Excerpt { gutter, text: printable(shown), start: start.min(shown.len()), width };
    let message = format!("Line {line} of `{path}` was refused: {error}.");
    Diagnostic::new(row_title(error), format!("{path}:{line}"), message, row_hint(error, text))
        .with_excerpt(Some(excerpt))
}

fn load_diagnostic(error: LoadError, paths: &[String], sources: &[&[u8]]) -> Diagnostic {
    match error {
        LoadError::Row { error, file, line } => {
            let index = usize::from(file);
            let path = paths.get(index).map_or("input", String::as_str);
            row_diagnostic(path, sources.get(index).copied().unwrap_or_default(), error, line)
        }
        LoadError::Ranges(_) => Diagnostic::new(
            "OVERLAPPING FAMILIES",
            paths.join(", "),
            "An IPv6 row overlaps an IPv4 row once IPv4 is mapped into ::ffff:0:0/96.".to_owned(),
            "Remove IPv6 rows that cover ::ffff:0:0/96, or mark them ZZ.".to_owned(),
        ),
        LoadError::NoRanges => Diagnostic::new(
            "NO RANGES",
            paths.join(", "),
            "The files hold no row with a known country.".to_owned(),
            "Check that these are the provider's country files and not empty downloads."
                .to_owned(),
        ),
        other => Diagnostic::new(
            "INVALID SOURCE",
            paths.join(", "),
            format!("The source files were refused: {other}."),
            "Check that the files are a complete download of one generation.".to_owned(),
        ),
    }
}

/// Lists distinct third-column codes the library rejects, so an import failure names the
/// code instead of only the error. Bounded to sixteen distinct values.
fn report_unknown_codes(path: &str, bytes: &[u8]) {
    let mut seen: Vec<[u8; 2]> = Vec::new();
    for line in bytes.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(code) = line.split(|&b| b == b',').nth(2) else { continue };
        let Ok(code) = <[u8; 2]>::try_from(code) else { continue };
        if country::is_valid(&code) || seen.contains(&code) {
            continue;
        }
        if seen.len() == 16 {
            break;
        }
        seen.push(code);
    }
    for code in seen {
        eprintln!("geoip-snapshot: {path}: code outside the ISO list: {}", printable(&code));
    }
}

fn load_sources(options: &Options, provider: Provider) -> Result<Database, Diagnostic> {
    let version = options.version.as_deref().unwrap_or("");
    if provider.compression() == Compression::Gzip {
        let path = &options.files[0];
        let bytes = read_file(path, gzip::MAX_COMPRESSED_BYTES)?;
        let stopping = std::sync::atomic::AtomicBool::new(false);
        return gzip::decode(provider, version, &bytes, &stopping)
            .map_err(|error| gzip_diagnostic(error, path, &bytes));
    }
    let mut sources = Vec::new();
    for path in &options.files {
        let bytes = read_file(path, MAX_INPUT)?;
        report_unknown_codes(path, &bytes);
        sources.push(bytes);
    }
    let views: Vec<&[u8]> = sources.iter().map(Vec::as_slice).collect();
    let mut loader = Loader::new();
    let mut load = || {
        for source in &views {
            loader.feed(source)?;
            loader.end_file()?;
        }
        Ok(())
    };
    let fed: Result<(), LoadError> = load();
    fed.and_then(|()| loader.finish(provider, version))
        .map_err(|error| load_diagnostic(error, &options.files, &views))
}

fn gzip_diagnostic(error: GzipError, path: &str, compressed: &[u8]) -> Diagnostic {
    match error {
        GzipError::Load(load) => {
            // Expand again to quote the refused row; the archive passed this far once.
            let limits = sibuna_inflate::Limits {
                max_input_bytes: gzip::MAX_COMPRESSED_BYTES as u64,
                max_output_bytes: sibuna_geoip::MAX_CSV_BYTES as u64,
                ..Default::default()
            };
            let expanded = sibuna_inflate::gunzip(compressed, limits).unwrap_or_default();
            load_diagnostic(load, &[path.to_owned()], &[&expanded])
        }
        other => Diagnostic::new(
            "INVALID ARCHIVE",
            path,
            format!("The archive `{path}` was refused: {other}."),
            "Download the archive again; the publisher's file is a single gzip member.".to_owned(),
        ),
    }
}

fn snapshot_diagnostic(error: SnapshotError, path: &str) -> Diagnostic {
    Diagnostic::new(
        "INVALID SNAPSHOT",
        path,
        format!("The snapshot `{path}` was refused: {error}."),
        "Create the snapshot again with `geoip-snapshot --provider <name> --version <v> \
         <files> --snapshot-out <path>`."
            .to_owned(),
    )
}

fn report(db: &Database) {
    let hex = |bytes: &[u8]| {
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    };
    eprintln!(
        "geoip-snapshot: {} {}: {} known ranges; SHA-256 {}",
        db.provider().name(),
        db.version(),
        db.range_count(),
        hex(db.digest())
    );
    for (index, digest) in db.file_digests().iter().enumerate() {
        eprintln!("geoip-snapshot: file {index} SHA-256 {}", hex(digest));
    }
}

fn write_snapshot(path: &str, db: &Database) -> Result<(), Diagnostic> {
    let bytes = snapshot::encode(db).map_err(|error| snapshot_diagnostic(error, path))?;
    std::fs::write(path, bytes).map_err(|error| {
        Diagnostic::new(
            "CANNOT WRITE FILE",
            path,
            format!("The snapshot could not be written to `{path}`: {error}."),
            "Check that the directory exists and is writable.".to_owned(),
        )
    })?;
    eprintln!("geoip-snapshot: wrote {path}");
    Ok(())
}

fn run(args: &[String]) -> Result<(), Diagnostic> {
    let options = parse_args(args)?;
    if options.help {
        eprintln!("{USAGE}");
        return Ok(());
    }
    check_options(args, &options)?;
    let db = match (&options.snapshot, options.provider) {
        (Some(path), _) => {
            let bytes = read_file(path, snapshot::MAX_BYTES)?;
            snapshot::decode(&bytes).map_err(|error| snapshot_diagnostic(error, path))?
        }
        (None, Some(provider)) => load_sources(&options, provider)?,
        (None, None) => unreachable!("check_options requires a snapshot or a provider"),
    };
    report(&db);
    for text in &options.lookups {
        let found = db.lookup_text(text).map_or_else(|| "ZZ".to_owned(), |c| c.to_string());
        eprintln!("geoip-snapshot: {} {found}", printable(text.as_bytes()));
    }
    if let Some(path) = &options.out {
        write_snapshot(path, &db)?;
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> =
        std::env::args_os().skip(1).map(|arg| arg.to_string_lossy().into_owned()).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(diagnostic) => {
            eprint!("{}", diagnostic.render());
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Vec<String> {
        text.split(' ').map(str::to_owned).collect()
    }

    fn error(text: &str) -> &'static str {
        let args = args(text);
        let options = match parse_args(&args) {
            Ok(options) => options,
            Err(diagnostic) => return diagnostic.0.title,
        };
        match check_options(&args, &options) {
            Ok(()) => "OK",
            Err(diagnostic) => diagnostic.0.title,
        }
    }

    #[test]
    fn options_follow_the_zig_tool() {
        assert_eq!(error("--provider dbip --version 2026-09 a.gz --snapshot-out b"), "OK");
        assert_eq!(
            error("--provider user-country --version 2026-09-09 a b --lookup 1.1.1.1"),
            "OK"
        );
        assert_eq!(error("--snapshot s --lookup 8.8.8.8 --snapshot-out t"), "OK");
        assert_eq!(error("--provider"), "MISSING VALUE");
        assert_eq!(error("--provider maxmind"), "UNKNOWN PROVIDER");
        assert_eq!(error("--frobnicate"), "UNKNOWN OPTION");
        assert_eq!(error("a b c"), "TOO MANY FILES");
        assert_eq!(error("--snapshot s a.csv"), "CONFLICTING OPTIONS");
        assert_eq!(error("a.csv"), "MISSING PROVIDER");
        assert_eq!(error("--provider dbip --version 2026-09 a b"), "WRONG FILE COUNT");
        assert_eq!(error("--provider dbip --version 2026-09-09 a"), "INVALID VERSION");
        assert_eq!(error("--provider dbip a"), "INVALID VERSION");
        let many = format!("--snapshot s{}", " --lookup 1.1.1.1".repeat(MAX_LOOKUPS + 1));
        assert_eq!(error(&many), "TOO MANY LOOKUPS");
    }

    #[test]
    fn diagnostics_have_a_title_rule_an_excerpt_and_a_hint() {
        let diagnostic = parse_args(&args("--provider maxmind")).err().unwrap();
        let text = diagnostic.render();
        let mut lines = text.lines();
        let rule = lines.next().unwrap();
        assert!(rule.starts_with("-- UNKNOWN PROVIDER ---"), "{rule}");
        assert!(rule.ends_with(" command line"), "{rule}");
        assert_eq!(rule.len(), 80);
        assert!(text.contains("  geoip-snapshot --provider maxmind\n"), "{text}");
        assert!(text.contains("\n                            ^^^^^^^\n"), "{text}");
        assert!(text.contains("Hint: Use `user-country` or `dbip`."), "{text}");
        let suggestion = parse_args(&args("--provider dbp")).err().unwrap().render();
        assert!(suggestion.contains("Did you mean `dbip`?"), "{suggestion}");
    }

    #[test]
    fn row_carets_mark_the_offending_column() {
        let line = b"1.0.0.0,1.0.0.255,us";
        assert_eq!(row_span(line, RangeError::InvalidCountry), (18, 2));
        assert_eq!(row_span(b"01.0.0.0,1.0.0.255,US", RangeError::InvalidAddress), (0, 8));
        assert_eq!(row_span(b"1.0.0.0,1.0.0,US", RangeError::InvalidAddress), (8, 5));
        assert_eq!(row_span(line, RangeError::Unordered), (0, 17));
        assert_eq!(row_span(line, RangeError::Overlap), (0, 7));
        let diagnostic =
            row_diagnostic("a.csv", b"x\n1.0.0.0,1.0.0.255,us\r\n", RangeError::InvalidCountry, 2);
        let text = diagnostic.render();
        assert!(text.contains("2| 1.0.0.0,1.0.0.255,us\n                     ^^\n"), "{text}");
        assert!(text.contains("Did you mean `US`?"), "{text}");
        assert_eq!(count(1, "file was"), "1 file was");
        assert_eq!(count(3, "file was"), "3 files were");
        assert_eq!(count(2, "source file"), "2 source files");
        assert_eq!(printable(b"a\x00\xffb"), "a??b");
        assert_eq!(distance("--provder", "--provider"), 1);
    }
}
