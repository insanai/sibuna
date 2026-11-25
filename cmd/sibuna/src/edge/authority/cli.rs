//! `sibuna authority COMMAND`: the commands of the operator on the database of the
//! topology (SID 0028). They talk to the database and need no running daemon.
//!
//! ```text
//!   apply:  source --evaluate--> document --publish--> three sections
//!           compose with -c FILE, check the topology
//!           head; same digest? done.  print the difference
//!           commit on the expected revision, or DBA002
//! ```

use std::io::{Read as _, Write as _};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use sibuna_authority::{
    Access, Draft, Error, Head, MAX_NAME, MAX_SOURCE, Origin, Publication, Settings, SqlStore,
    Store, clip, commit_settled, compose, diff, pretty, publish, render_diff, render_history,
    render_nodes, short,
};
use sibuna_core::diagnostic;

/// What `sibuna authority --help` prints.
const USAGE: &str = "\
sibuna authority apply    -c FILE -f SOURCE [--expect N] [--note TEXT] [--author NAME]
sibuna authority diff     -c FILE -f SOURCE
sibuna authority dump     -c FILE [--revision N] [--source]
sibuna authority history  -c FILE [--limit N]
sibuna authority rollback -c FILE REVISION [--expect N] [--note TEXT] [--author NAME]
sibuna authority status   -c FILE

FILE holds the section `authority`, which names the database: the file of a node, or a
file with that section alone. SOURCE is a topology in JSON or JLV. `apply` publishes its
`frontends`, `backends` and `http` as the next revision when the database still holds
the revision that the command read, or the one after `--expect`.
";

/// The options of one command line.
#[derive(Debug, Default, PartialEq, Eq)]
struct Options {
    command: String,
    node_file: Option<String>,
    source: Option<String>,
    expect: Option<u64>,
    revision: Option<u64>,
    limit: Option<u64>,
    note: String,
    author: Option<String>,
    /// `dump --source`: the source as it was given.
    as_source: bool,
}

/// A failure of a command, ready to print.
#[derive(Debug, PartialEq, Eq)]
struct Failure {
    title: String,
    message: String,
    hint: String,
}

impl From<Error> for Failure {
    fn from(error: Error) -> Failure {
        Failure {
            title: format!("{} ({})", error.title(), error.code()),
            message: format!("{}.", capitalised(&error.to_string())),
            hint: error.hint().to_owned(),
        }
    }
}

/// `text` with its first letter in upper case, as a sentence begins.
fn capitalised(text: &str) -> String {
    let mut letters = text.chars();
    match letters.next() {
        Some(first) => first.to_uppercase().chain(letters).collect(),
        None => String::new(),
    }
}

fn usage(message: impl Into<String>) -> Failure {
    Failure {
        title: "MISSING COMMAND (DBA007)".to_owned(),
        message: message.into(),
        hint: format!("The commands are\n  {}", USAGE.trim_end().replace('\n', "\n  ")),
    }
}

/// The value after the option `name`, as a number.
fn number(name: &str, value: Option<&String>) -> Result<u64, Failure> {
    let value = value.ok_or_else(|| usage(format!("`{name}` needs a number.")))?;
    value.parse().map_err(|_| usage(format!("`{value}` after `{name}` is not a number.")))
}

fn text(name: &str, value: Option<&String>) -> Result<String, Failure> {
    value.cloned().ok_or_else(|| usage(format!("`{name}` needs a value.")))
}

/// Reads the words after `authority`.
fn parse(args: &[String]) -> Result<Options, Failure> {
    let [command, rest @ ..] = args else {
        return Err(usage("`sibuna authority` needs a command."));
    };
    let known = ["apply", "diff", "dump", "history", "rollback", "status"];
    if !known.contains(&command.as_str()) {
        return Err(usage(format!("`{command}` is not a command of `sibuna authority`.")));
    }
    let mut options = Options { command: command.clone(), ..Options::default() };
    let mut words = rest.iter();
    while let Some(word) = words.next() {
        match word.as_str() {
            "-c" => options.node_file = Some(text("-c", words.next())?),
            "-f" => options.source = Some(text("-f", words.next())?),
            "--expect" => options.expect = Some(number("--expect", words.next())?),
            "--revision" => options.revision = Some(number("--revision", words.next())?),
            "--limit" => options.limit = Some(number("--limit", words.next())?),
            "--note" => options.note = text("--note", words.next())?,
            "--author" => options.author = Some(text("--author", words.next())?),
            "--source" => options.as_source = true,
            word if command == "rollback" && options.revision.is_none() => {
                options.revision = Some(number("rollback", Some(&word.to_owned()))?);
            }
            other => return Err(usage(format!("`{other}` is not an option of `{command}`."))),
        }
    }
    if options.node_file.is_none() {
        return Err(usage(format!(
            "`{command}` needs `-c FILE`, the file that names the database."
        )));
    }
    let needs_source = matches!(command.as_str(), "apply" | "diff");
    if needs_source && options.source.is_none() {
        return Err(usage(format!("`{command}` needs `-f SOURCE`, the topology to publish.")));
    }
    if command == "rollback" && options.revision.is_none() {
        return Err(usage("`rollback` needs the number of the revision to restore."));
    }
    Ok(options)
}

/// Runs `sibuna authority` with the words after it. Prints the result to standard
/// output and a failure as a diagnostic to standard error.
pub(in super::super) fn run(args: &[String]) -> ExitCode {
    if args.first().is_some_and(|word| word == "--help") {
        print(USAGE.as_bytes());
        return ExitCode::SUCCESS;
    }
    match parse(args).and_then(|options| execute(&options)) {
        Ok(output) => {
            print(&output);
            ExitCode::SUCCESS
        }
        Err(failure) => {
            let mut rendered = String::new();
            let Failure { title, message, hint } = &failure;
            let _ = diagnostic::render(&mut rendered, title, message, hint);
            eprint!("{rendered}");
            ExitCode::FAILURE
        }
    }
}

fn print(bytes: &[u8]) {
    let _ = std::io::stdout().lock().write_all(bytes);
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}

/// The file of the node, evaluated, and the store that it names.
struct Session {
    node_file: Vec<u8>,
    store: SqlStore,
}

fn open(options: &Options) -> Result<Session, Failure> {
    let path = options.node_file.as_deref().unwrap_or_default();
    let node_file = super::super::document(path)
        .map_err(|error| Error::Settings(format!("the file `{path}` cannot be read: {error}")))?;
    let settings = Settings::parse(&node_file)?;
    // Only a command that commits may create the tables. The others read, so the role
    // of a node is enough for them.
    let commits = matches!(options.command.as_str(), "apply" | "rollback");
    let access = if commits { Access::Operator } else { Access::Node };
    let store = SqlStore::new(&settings, access)?;
    Ok(Session { node_file, store })
}

fn execute(options: &Options) -> Result<Vec<u8>, Failure> {
    let mut session = open(options)?;
    match options.command.as_str() {
        "apply" => apply(&mut session, options, true).map(String::into_bytes),
        "diff" => apply(&mut session, options, false).map(String::into_bytes),
        "dump" => dump(&mut session, options),
        "history" => history(&mut session, options).map(String::into_bytes),
        "rollback" => rollback(&mut session, options).map(String::into_bytes),
        _ => status(&mut session).map(String::into_bytes),
    }
}

/// Who commits: the name after `--author`, or the user and the host of the command.
fn author(options: &Options) -> String {
    let name = options.author.clone().unwrap_or_else(|| {
        let user = std::env::var("USER").or_else(|_| std::env::var("LOGNAME"));
        let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .or_else(|_| std::env::var("HOSTNAME").map_err(std::io::Error::other));
        let host = host.map_or("unknown".to_owned(), |host| host.trim().to_owned());
        format!("{}@{host}", user.unwrap_or_else(|_| "unknown".to_owned()))
    });
    clip(&name, MAX_NAME)
}

/// Reads the source and evaluates it. Returns the bytes as given and what they publish.
fn read_source(path: &str) -> Result<(Vec<u8>, Publication), Error> {
    let unreadable = |error: std::io::Error| {
        Error::Rejected(format!("the source `{path}` cannot be read: {error}"))
    };
    let mut raw = Vec::new();
    let file = std::fs::File::open(path).map_err(unreadable)?;
    file.take(MAX_SOURCE as u64 + 1).read_to_end(&mut raw).map_err(unreadable)?;
    if raw.len() > MAX_SOURCE {
        return Err(Error::Rejected(format!(
            "the source `{path}` is longer than {MAX_SOURCE} bytes"
        )));
    }
    let evaluated = super::super::evaluate(path, raw.clone())
        .map_err(|error| Error::Rejected(format!("the source `{path}`: {error}")))?;
    Ok((raw, publish(&evaluated)?))
}

/// Checks that the published `document` gives a topology with the file of the node.
/// The files that the topology names are on the nodes and are not opened here.
fn check(node_file: &[u8], document: &str) -> Result<(), Error> {
    let composition = compose(node_file, document)?;
    sibuna_lb::Config::parse(composition.document.as_bytes())
        .map(drop)
        .map_err(|error| Error::Rejected(format!("the topology does not check: {error}")))
}

/// Fails when the operator named a head that the database does not hold.
fn expect(options: &Options, head: &Head) -> Result<u64, Error> {
    match options.expect {
        Some(expected) if expected != head.revision => {
            Err(Error::Conflict { expected, found: head.revision })
        }
        _ => Ok(head.revision),
    }
}

/// The difference between the head and `after`, as lines. A head that is damaged
/// cannot be compared. We say so and go on, so that a commit can replace it.
fn difference(store: &mut SqlStore, head: &Head, after: &str) -> Result<String, Error> {
    let before = match head.revision {
        0 => None,
        number => match store.revision(number) {
            Ok(revision) => Some(revision.document),
            Err(Error::Damaged(why)) => {
                let all = render_diff(&diff(None, after)?);
                return Ok(format!(
                    "revision {number} is damaged and is not compared: {why}\n{all}"
                ));
            }
            Err(error) => return Err(error),
        },
    };
    Ok(render_diff(&diff(before.as_deref(), after)?))
}

/// `apply` and, without `commit`, `diff`.
fn apply(session: &mut Session, options: &Options, commit: bool) -> Result<String, Failure> {
    let path = options.source.as_deref().unwrap_or_default();
    let (raw, publication) = read_source(path)?;
    check(&session.node_file, &publication.document)?;
    let head = read_head(&mut session.store)?;
    let expected = expect(options, &head)?;
    let mut out = String::new();
    if !publication.left_out.is_empty() {
        let sections = publication.left_out.join(", ");
        out.push_str(&format!("not published, the file of each node owns: {sections}\n"));
    }
    if head.revision > 0 && head.digest == publication.digest {
        out.push_str(&format!("revision {} unchanged {}\n", head.revision, short(&head.digest)));
        return Ok(out);
    }
    out.push_str(&difference(&mut session.store, &head, &publication.document)?);
    let next = head.revision + 1;
    if !commit {
        out.push_str(&format!("revision {} -> {next}, not committed\n", head.revision));
        return Ok(out);
    }
    let name = std::path::Path::new(path).file_name().and_then(|name| name.to_str());
    let author = author(options);
    let draft = Draft {
        document: &publication.document,
        source: &raw,
        source_name: &clip(name.unwrap_or("source"), MAX_NAME),
        origin: Origin::Apply,
        author: &author,
        note: &options.note,
        now: unix_now(),
    };
    let number = commit_settled(&mut session.store, expected, &draft)?;
    out.push_str(&format!("revision {number} committed {}\n", short(&publication.digest)));
    Ok(out)
}

/// `rollback REVISION`: commits the document and the source of an earlier revision.
fn rollback(session: &mut Session, options: &Options) -> Result<String, Failure> {
    let target = options.revision.unwrap_or_default();
    let head = session.store.head()?;
    if head.revision == 0 {
        return Err(Error::Empty.into());
    }
    let expected = expect(options, &head)?;
    let restored = session.store.revision(target)?;
    if restored.entry.digest == head.digest {
        return Ok(format!(
            "revision {} already holds the document of revision {target}\n",
            head.revision
        ));
    }
    // A newer binary may refuse a document that an older one accepted.
    check(&session.node_file, &restored.document)?;
    let mut out = difference(&mut session.store, &head, &restored.document)?;
    let author = author(options);
    let draft = Draft {
        document: &restored.document,
        source: &restored.source,
        source_name: &restored.entry.source_name,
        origin: Origin::Rollback(target),
        author: &author,
        note: &options.note,
        now: unix_now(),
    };
    let number = commit_settled(&mut session.store, expected, &draft)?;
    out.push_str(&format!("revision {number} committed, it restores revision {target}\n"));
    Ok(out)
}

/// `dump`: the evaluated document of a revision, or with `--source` its source.
fn dump(session: &mut Session, options: &Options) -> Result<Vec<u8>, Failure> {
    let number = match options.revision {
        Some(number) => number,
        None => read_head(&mut session.store)?.revision,
    };
    if number == 0 {
        return Err(Error::Empty.into());
    }
    let revision = session.store.revision(number)?;
    if options.as_source {
        return Ok(revision.source);
    }
    Ok(pretty(&revision.document)?.into_bytes())
}

/// The head as a reading command sees it. A database without the tables holds no
/// revision, as one with empty tables does.
fn read_head(store: &mut SqlStore) -> Result<Head, Error> {
    match store.head() {
        Err(Error::Empty) => Ok(Head { revision: 0, digest: String::new() }),
        head => head,
    }
}

/// `history`: the newest revisions, 20 unless `--limit` says otherwise.
fn history(session: &mut Session, options: &Options) -> Result<String, Failure> {
    let limit = options.limit.unwrap_or(20).min(usize::MAX as u64) as usize;
    let head = read_head(&mut session.store)?;
    let entries = match head.revision {
        0 => Vec::new(),
        _ => session.store.history(limit)?,
    };
    Ok(render_history(&entries, head.revision))
}

/// `status`: the head and what every node reports.
fn status(session: &mut Session) -> Result<String, Failure> {
    let head = read_head(&mut session.store)?;
    let nodes = match head.revision {
        0 => Vec::new(),
        _ => session.store.nodes()?,
    };
    Ok(render_nodes(&head, &nodes, None, unix_now()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn every_command_line_parses() {
        let apply = parse(&words("apply -c n.json -f e.jlv --expect 4 --author me")).unwrap();
        assert_eq!(apply.command, "apply");
        assert_eq!(apply.node_file.as_deref(), Some("n.json"));
        assert_eq!(apply.source.as_deref(), Some("e.jlv"));
        assert_eq!((apply.expect, apply.author.as_deref()), (Some(4), Some("me")));
        let rollback = parse(&words("rollback -c n.json 3 --expect 5")).unwrap();
        assert_eq!((rollback.revision, rollback.expect), (Some(3), Some(5)));
        let dump = parse(&words("dump -c n.json --revision 2 --source")).unwrap();
        assert_eq!((dump.revision, dump.as_source), (Some(2), true));
        assert_eq!(parse(&words("history -c n.json --limit 5")).unwrap().limit, Some(5));
        assert!(parse(&words("status -c n.json")).is_ok());
        assert!(parse(&words("diff -c n.json -f e.json")).is_ok());
    }

    #[test]
    fn a_wrong_command_line_names_its_fault() {
        let message = |line: &str| parse(&words(line)).unwrap_err().message;
        assert!(message("").contains("needs a command"));
        assert!(message("publish -c n.json").contains("`publish` is not a command"));
        assert!(message("apply -f e.json").contains("-c FILE"));
        assert!(message("apply -c n.json").contains("-f SOURCE"));
        assert!(message("apply -c n.json -f e.json --expect soon").contains("not a number"));
        assert!(message("apply -c n.json -f e.json --expect").contains("needs a number"));
        assert!(message("rollback -c n.json").contains("number of the revision"));
        assert!(message("rollback -c n.json 3 4").contains("`4` is not an option"));
        assert!(message("status -c n.json extra").contains("`extra` is not an option"));
        let failure = parse(&words("status")).unwrap_err();
        assert!(failure.title.contains("DBA007"));
        assert!(failure.hint.contains("sibuna authority rollback"));
    }

    #[test]
    fn a_failure_of_the_store_keeps_its_code_and_hint() {
        let failure = Failure::from(Error::Conflict { expected: 3, found: 4 });
        assert_eq!(failure.title, "REVISION CONFLICT (DBA002)");
        assert!(failure.message.starts_with("The commit expected revision 3"));
        assert!(failure.hint.contains("--expect"));
    }
}
