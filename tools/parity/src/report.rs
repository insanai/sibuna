//! The report directory: `summary.txt` with counts per category and configuration, one
//! file per unexplained mismatch under `mismatches/` with the requests and both daemons'
//! answers, examples of allowed differences under `allowed/`, and with `--keep-all` the
//! identical scenarios under `cases/`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::Path;

use crate::client::Transcript;
use crate::compare::escape;
use crate::corpus::Category;
use crate::response::Event;
use crate::runner::{ConfigOutcome, Outcome};

/// How many example files each allow-list entry gets.
const ALLOWED_EXAMPLES: usize = 20;
/// How many bytes of each body a mismatch file shows.
const BODY_LIMIT: usize = 16 * 1024;

/// What the run was, for the report's header.
#[derive(Clone, Debug)]
pub struct RunInfo {
    /// The corpus seed.
    pub seed: u64,
    /// The requested corpus size.
    pub requests: usize,
    /// The Zig binary.
    pub zig: String,
    /// The Rust binary.
    pub rust: String,
    /// The command that reruns one scenario, with `{case}` for its id.
    pub rerun: String,
}

/// Counts for one row of the summary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Scenarios.
    pub scenarios: usize,
    /// Requests sent (to each daemon).
    pub requests: usize,
    /// Scenarios answered identically.
    pub identical: usize,
    /// Scenarios whose differences are all allowed.
    pub allowed: usize,
    /// Scenarios with an unexplained difference.
    pub unexplained: usize,
}

impl Counts {
    /// Adds one scenario's outcome.
    pub fn add(&mut self, outcome: &Outcome) {
        self.scenarios += 1;
        self.requests += outcome.requests;
        if outcome.findings.is_empty() {
            self.identical += 1;
        } else if outcome.is_unexplained() {
            self.unexplained += 1;
        } else {
            self.allowed += 1;
        }
    }

    fn row(&self, name: &str) -> String {
        format!(
            "{name:<44} {:>9} {:>9} {:>9} {:>9} {:>11}\n",
            self.scenarios, self.requests, self.identical, self.allowed, self.unexplained
        )
    }
}

/// The totals over all configurations: per category, per configuration and overall.
pub fn tally(
    results: &[ConfigOutcome],
) -> (BTreeMap<Category, Counts>, Vec<(String, Counts)>, Counts) {
    let mut categories = BTreeMap::new();
    let mut configs = Vec::new();
    let mut total = Counts::default();
    for result in results {
        let mut counts = Counts::default();
        for outcome in &result.outcomes {
            counts.add(outcome);
            total.add(outcome);
            categories.entry(outcome.category).or_insert_with(Counts::default).add(outcome);
        }
        configs.push((result.config.clone(), counts));
    }
    (categories, configs, total)
}

/// Writes the summary text.
pub fn summary(info: &RunInfo, results: &[ConfigOutcome]) -> String {
    let (categories, configs, total) = tally(results);
    let mut text = String::new();
    let _ = writeln!(text, "Sibuna daemon parity: Zig versus Rust\n");
    let _ = writeln!(text, "seed {}, corpus of at least {} requests", info.seed, info.requests);
    let _ = writeln!(text, "zig:  {}\nrust: {}\n", info.zig, info.rust);
    let header = format!(
        "{:<44} {:>9} {:>9} {:>9} {:>9} {:>11}\n",
        "", "scenarios", "requests", "identical", "allowed", "unexplained"
    );
    text.push_str(&header.replacen(&" ".repeat(44), &format!("{:<44}", "category"), 1));
    for (category, counts) in &categories {
        text.push_str(&counts.row(category.name()));
    }
    text.push_str(&total.row("total"));
    text.push('\n');
    text.push_str(&header.replacen(&" ".repeat(44), &format!("{:<44}", "configuration"), 1));
    for (config, counts) in &configs {
        text.push_str(&counts.row(config));
    }
    text.push('\n');
    write_answers(&mut text, results);
    write_allowed_counts(&mut text, results);
    write_failures(&mut text, results);
    write_unexplained(&mut text, info, results);
    text
}

/// What the Zig daemon answered, per category: how often each status, closed connection,
/// timeout or non-response occurred.
fn write_answers(text: &mut String, results: &[ConfigOutcome]) {
    let mut by_category: BTreeMap<Category, BTreeMap<&str, usize>> = BTreeMap::new();
    for outcome in results.iter().flat_map(|result| &result.outcomes) {
        let counts = by_category.entry(outcome.category).or_default();
        for answer in &outcome.answers {
            *counts.entry(answer.as_str()).or_default() += 1;
        }
    }
    let _ = writeln!(text, "Answers of the Zig daemon by category (status or event: count):");
    for (category, counts) in by_category {
        let list: Vec<String> =
            counts.iter().map(|(answer, n)| format!("{answer}: {n}")).collect();
        let _ = writeln!(text, "  {:<12} {}", category.name(), list.join(", "));
    }
    text.push('\n');
}

fn write_allowed_counts(text: &mut String, results: &[ConfigOutcome]) {
    let mut by_entry: BTreeMap<&str, BTreeMap<&str, usize>> = BTreeMap::new();
    let findings = results.iter().flat_map(|r| &r.outcomes).flat_map(|o| &o.findings);
    for finding in findings {
        if let Some(entry) = &finding.allowed_by {
            let fields = by_entry.entry(entry).or_default();
            *fields.entry(finding.difference.field.as_str()).or_default() += 1;
        }
    }
    let _ = writeln!(text, "Allowed differences by allow-list entry (field: count):");
    if by_entry.is_empty() {
        let _ = writeln!(text, "  (none)");
    }
    for (entry, fields) in by_entry {
        let list: Vec<String> = fields.iter().map(|(field, n)| format!("{field}: {n}")).collect();
        let _ = writeln!(text, "  {entry}: {}", list.join(", "));
    }
    text.push('\n');
}

fn write_failures(text: &mut String, results: &[ConfigOutcome]) {
    for result in results {
        for failure in &result.failures {
            let _ = writeln!(text, "DAEMON FAILURE in {}: {failure}", result.config);
        }
    }
}

fn write_unexplained(text: &mut String, info: &RunInfo, results: &[ConfigOutcome]) {
    let _ = writeln!(text, "Unexplained mismatches:");
    let mut any = false;
    for result in results {
        for outcome in results_unexplained(result) {
            any = true;
            let _ = writeln!(
                text,
                "  case {} [{}] {} ({})",
                outcome.case,
                outcome.category.name(),
                outcome.label,
                result.config
            );
            for finding in outcome.findings.iter().filter(|finding| finding.allowed_by.is_none()) {
                let difference = &finding.difference;
                let _ = writeln!(
                    text,
                    "    connection {} request {} {}: zig {:?} / rust {:?}",
                    difference.connection,
                    difference.step,
                    difference.field,
                    shorten(&difference.zig),
                    shorten(&difference.rust)
                );
            }
            let _ = writeln!(
                text,
                "    rerun: {}",
                info.rerun.replace("{case}", &outcome.case.to_string())
            );
        }
    }
    if !any {
        let _ = writeln!(text, "  (none)");
    }
}

fn results_unexplained(result: &ConfigOutcome) -> impl Iterator<Item = &Outcome> {
    result.outcomes.iter().filter(|outcome| outcome.is_unexplained())
}

/// The first line of `text`, cut to 120 characters.
fn shorten(text: &str) -> String {
    let line = text.lines().next().unwrap_or_default();
    line.chars().take(120).collect()
}

/// Writes the report directory: the summary and the mismatch and example files.
///
/// # Errors
///
/// Returns the first file system error.
pub fn write(dir: &Path, info: &RunInfo, results: &[ConfigOutcome]) -> io::Result<String> {
    let summary = summary(info, results);
    fs::create_dir_all(dir)?;
    for sub in ["mismatches", "allowed", "cases"] {
        let path = dir.join(sub);
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
    }
    fs::write(dir.join("summary.txt"), &summary)?;
    let mut examples: BTreeMap<String, usize> = BTreeMap::new();
    for result in results {
        for outcome in &result.outcomes {
            if outcome.findings.is_empty() {
                if outcome.zig.is_some() {
                    let name = format!("{}-{}.txt", case_name(outcome.case), result.config);
                    fs::write(dir.join("cases").join(name), detail(info, result, outcome))?;
                }
                continue;
            }
            let name = format!("{}-{}.txt", case_name(outcome.case), result.config);
            if outcome.is_unexplained() {
                fs::write(dir.join("mismatches").join(name), detail(info, result, outcome))?;
                continue;
            }
            let entry =
                outcome.findings.iter().find_map(|f| f.allowed_by.clone()).unwrap_or_default();
            let count = examples.entry(entry).or_default();
            if *count < ALLOWED_EXAMPLES {
                *count += 1;
                fs::write(dir.join("allowed").join(name), detail(info, result, outcome))?;
            }
        }
    }
    Ok(summary)
}

fn case_name(case: usize) -> String {
    if case == usize::MAX { "metrics".to_owned() } else { format!("case-{case:05}") }
}

/// The full account of one scenario: its differences, then every request with both
/// daemons' unmasked answers.
pub fn detail(info: &RunInfo, result: &ConfigOutcome, outcome: &Outcome) -> String {
    let mut text = String::new();
    let _ = writeln!(
        text,
        "{} [{}] {}",
        case_name(outcome.case),
        outcome.category.name(),
        outcome.label
    );
    let _ = writeln!(text, "configuration: {}", result.config);
    let _ = writeln!(text, "daemon arguments: {}", result.arguments.join(" "));
    if outcome.case != usize::MAX {
        let _ =
            writeln!(text, "rerun: {}", info.rerun.replace("{case}", &outcome.case.to_string()));
    }
    let _ = writeln!(text, "\nDifferences (after masking):");
    for finding in &outcome.findings {
        let d = &finding.difference;
        let status = finding
            .allowed_by
            .as_deref()
            .map_or("UNEXPLAINED".to_owned(), |id| format!("allowed by {id}"));
        let _ = writeln!(
            text,
            "- connection {} request {} {} ({status})",
            d.connection, d.step, d.field
        );
        let _ = writeln!(text, "  zig:  {}", d.zig.replace('\n', "\n        "));
        let _ = writeln!(text, "  rust: {}", d.rust.replace('\n', "\n        "));
    }
    if let (Some(zig), Some(rust)) = (&outcome.zig, &outcome.rust) {
        write_transcripts(&mut text, zig, rust);
    }
    text
}

fn write_transcripts(text: &mut String, zig: &Transcript, rust: &Transcript) {
    let count = zig.connections.len().max(rust.connections.len());
    for connection in 0..count {
        let _ = writeln!(text, "\n=== connection {connection}");
        let empty = Vec::new();
        let ours = zig.connections.get(connection).unwrap_or(&empty);
        let theirs = rust.connections.get(connection).unwrap_or(&empty);
        for step in 0..ours.len().max(theirs.len()) {
            let request =
                ours.get(step).or_else(|| theirs.get(step)).map(|e| e.request.as_slice());
            let _ = writeln!(
                text,
                "\n--- request {step} (as sent to zig):\n{}",
                escape(request.unwrap_or_default(), BODY_LIMIT)
            );
            for (name, exchanges) in [("zig", ours), ("rust", theirs)] {
                let _ = writeln!(text, "--- {name} answered:");
                match exchanges.get(step) {
                    None => text.push_str("(nothing: the connection had ended)\n"),
                    Some(exchange) => {
                        for event in &exchange.events {
                            text.push_str(&describe(event));
                        }
                    }
                }
            }
        }
    }
    for (name, transcript) in [("zig", zig), ("rust", rust)] {
        if let Some(error) = &transcript.connect_error {
            let _ = writeln!(text, "{name}: connect failed: {error}");
        }
    }
}

/// An event as received, escaped.
fn describe(event: &Event) -> String {
    match event {
        Event::Response(response) => {
            let mut text = format!("{}\n", response.status_line);
            for (name, value) in &response.headers {
                let _ = writeln!(text, "{name}: {value}");
            }
            let _ = writeln!(
                text,
                "[body, framing {}, {} bytes]",
                response.framing.name(),
                response.body.len()
            );
            text.push_str(&escape(&response.body, BODY_LIMIT));
            text.push('\n');
            text
        }
        Event::Closed => "[connection closed]\n".to_owned(),
        Event::Timeout(bytes) => format!("[timeout; received {}]\n", escape(bytes, BODY_LIMIT)),
        Event::Garbage(bytes) => format!("[not a response: {}]\n", escape(bytes, BODY_LIMIT)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compare::Difference;
    use crate::runner::Finding;

    fn outcome(case: usize, allowed_by: Option<&str>, differs: bool) -> Outcome {
        let findings = if differs {
            vec![Finding {
                difference: Difference {
                    connection: 0,
                    step: 0,
                    field: "status".into(),
                    zig: "HTTP/1.1 200 OK".into(),
                    rust: "HTTP/1.1 403 Forbidden".into(),
                },
                allowed_by: allowed_by.map(str::to_owned),
            }]
        } else {
            Vec::new()
        };
        Outcome {
            case,
            category: Category::Bot,
            label: "bot".into(),
            requests: 2,
            answers: vec!["200".into()],
            findings,
            zig: Some(Transcript::default()),
            rust: Some(Transcript::default()),
        }
    }

    #[test]
    fn counts_separate_identical_allowed_and_unexplained() {
        let result = ConfigOutcome {
            config: "c".into(),
            arguments: Vec::new(),
            outcomes: vec![
                outcome(0, None, false),
                outcome(1, Some("x"), true),
                outcome(2, None, true),
            ],
            failures: Vec::new(),
        };
        let (categories, configs, total) = tally(std::slice::from_ref(&result));
        let expected =
            Counts { scenarios: 3, requests: 6, identical: 1, allowed: 1, unexplained: 1 };
        assert_eq!(total, expected);
        assert_eq!(categories[&Category::Bot], expected);
        assert_eq!(configs[0].1, expected);
        let info = RunInfo {
            seed: 1,
            requests: 6,
            zig: "z".into(),
            rust: "r".into(),
            rerun: "run --case {case}".into(),
        };
        let text = summary(&info, &[result]);
        assert!(text.contains("case 2 [bot] bot (c)"), "{text}");
        assert!(text.contains("rerun: run --case 2"));
        assert!(text.contains("x: status: 1"), "{text}");
    }
}
