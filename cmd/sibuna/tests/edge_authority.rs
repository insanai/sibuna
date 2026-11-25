//! A database owns the published topology and the nodes follow it (SID 0028).
//!
//! Every test runs the binary. The SQLite tests always run. The PostgreSQL tests need
//! the `postgres` feature and a PostgreSQL installed on this machine. They start a
//! server of their own on loopback in a temporary directory and skip with a line on
//! standard error otherwise.
#![cfg(all(unix, feature = "sqlite"))]
#![allow(clippy::unwrap_used)]

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_sibuna");

struct Node {
    child: Child,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The nodes of one database on one host. Each node has a directory with its own file.
/// The file names the database, the name of the node and, under `authority.binds`, the
/// address where this node serves the published frontend.
struct Site {
    directory: PathBuf,
    /// The key and value that name the database in the section `authority`.
    store: String,
    /// The poll interval of the nodes.
    poll: &'static str,
}

impl Site {
    fn new(store: impl Fn(&Path) -> String, poll: &'static str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = format!("sibuna-authority-{}-{serial}", std::process::id());
        let directory = std::env::temp_dir().join(name);
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let store = store(&directory);
        let site = Self { directory, store, poll };
        // The operator has a file with the section `authority` alone.
        fs::write(site.operator(), format!(r#"{{"authority":{{{},"node":"op"}}}}"#, site.store))
            .unwrap();
        site
    }

    /// A site whose database is one SQLite file.
    fn sqlite() -> Self {
        Self::new(
            |directory| format!(r#""sqlite":"{}""#, directory.join("edge.db").display()),
            "200ms",
        )
    }

    fn operator(&self) -> PathBuf {
        self.directory.join("operator.json")
    }

    fn home(&self, index: usize) -> PathBuf {
        self.directory.join(format!("n{index}"))
    }

    fn log(&self, index: usize) -> String {
        fs::read_to_string(self.home(index).join("log")).unwrap_or_default()
    }

    /// Writes the file of the node at `index` with a frontend address of its own.
    fn write_node_file(&self, index: usize) {
        let free = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let file = format!(
            r#"{{"global":{{"admin_socket":"edge.sock"}},
            "authority":{{{},"node":"n{index}","poll":"{}","cache":"cache",
              "binds":{{"web":["{free}"]}}}}}}"#,
            self.store, self.poll
        );
        fs::create_dir_all(self.home(index)).unwrap();
        fs::write(self.home(index).join("node.json"), file).unwrap();
    }

    /// A source with one server of the pool for each name, and `extra` after them.
    fn source(servers: &[&str], extra: &str) -> String {
        let servers: Vec<String> = servers
            .iter()
            .enumerate()
            .map(|(index, name)| {
                format!(r#"{{"name":"{name}","addr":"127.83.7.{}:9"}}"#, index + 9)
            })
            .collect();
        format!(
            r#"{{"frontends":{{"web":{{"proto":"tcp","binds":["127.0.0.1:9"],
              "default_backend":"app"}}}},
            "backends":{{"app":{{"mode":"tcp","balance":{{"kind":"round_robin"}},
              "servers":[{}]}}}}{extra}}}"#,
            servers.join(",")
        )
    }

    /// Runs `sibuna authority COMMAND -c OPERATOR_FILE WORDS`.
    fn authority(&self, command: &str, words: &[&str]) -> Output {
        let mut run = Command::new(BIN);
        run.current_dir(&self.directory).args(["authority", command, "-c"]).arg(self.operator());
        run.args(words).env("USER", "tester").output().unwrap()
    }

    /// Runs a command that must succeed and returns what it printed.
    fn done(&self, command: &str, words: &[&str]) -> String {
        let output = self.authority(command, words);
        let errors = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "authority {command} {words:?}: {errors}");
        String::from_utf8(output.stdout).unwrap()
    }

    /// Runs a command that must fail and returns its diagnostic.
    fn failed(&self, command: &str, words: &[&str]) -> String {
        let output = self.authority(command, words);
        assert!(!output.status.success(), "authority {command} {words:?} succeeded");
        String::from_utf8(output.stderr).unwrap()
    }

    /// Writes `source` to the file `name` and applies it with `words`.
    fn apply(&self, name: &str, source: &str, words: &[&str]) -> String {
        fs::write(self.directory.join(name), source).unwrap();
        self.done("apply", &[&["-f", name], words].concat())
    }

    /// Starts the node at `index` once. Its standard error goes to the file `log`.
    fn start_once(&self, index: usize) -> Result<Node, String> {
        let log = fs::File::create(self.home(index).join("log")).unwrap();
        let child = Command::new(BIN)
            .current_dir(self.home(index))
            .args(["--config-file", "node.json"])
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let mut node = Node { child };
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if self.log(index).contains("listeners ready") {
                return Ok(node);
            }
            if node.child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Err(self.log(index))
    }

    /// Starts the node at `index`. A port that was free a moment ago may be taken by a
    /// test that runs beside this one. The node then gets another address.
    fn start(&self, index: usize) -> Node {
        let mut failure = String::new();
        for _ in 0..5 {
            self.write_node_file(index);
            match self.start_once(index) {
                Ok(node) => return node,
                Err(log) => failure = log,
            }
        }
        panic!("node {index} did not start: {failure}");
    }

    fn ctl(&self, index: usize, words: &[&str]) -> String {
        let socket = self.home(index).join("edge.sock");
        let output = Command::new(BIN).arg("ctl").arg(socket).args(words).output().unwrap();
        String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr)
    }

    /// The names of the servers that the node at `index` serves.
    fn servers(&self, index: usize) -> Vec<String> {
        let table = self.ctl(index, &["show", "servers"]);
        let names = table.lines().skip(1).filter_map(|line| line.split_whitespace().nth(1));
        let mut names: Vec<String> = names.map(str::to_owned).collect();
        names.sort();
        names
    }

    /// Waits until each of the nodes `nodes` serves exactly the servers `names`.
    fn serve(&self, nodes: &[usize], names: &[&str]) -> bool {
        eventually(|| nodes.iter().all(|index| self.servers(*index) == names))
    }

    /// Waits until the log of every node in `nodes` holds `text`. The log is a file, so
    /// this looks more often than the admin socket allows.
    fn logged(&self, nodes: &[usize], text: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if nodes.iter().all(|index| self.log(*index).contains(text)) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }
}

impl Drop for Site {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// Waits up to ten seconds for `holds`, and asks at most seven times a second.
fn eventually(holds: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if holds() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    false
}

#[test]
fn apply_shows_the_difference_and_a_stale_expectation_is_a_conflict() {
    let site = Site::sqlite();
    assert!(site.done("status", &[]).starts_with("no revision"));
    assert!(site.failed("dump", &[]).contains("DBA004"));
    fs::write(site.directory.join("edge.json"), Site::source(&["a"], "")).unwrap();
    // `diff` shows what `apply` would commit and commits nothing.
    let shown = site.done("diff", &["-f", "edge.json"]);
    assert!(shown.contains("+ frontends: "), "{shown}");
    assert!(shown.contains("revision 0 -> 1, not committed"), "{shown}");
    assert!(site.done("status", &[]).starts_with("no revision"));
    let first = site.apply("edge.json", &Site::source(&["a"], ""), &["--note", "first"]);
    assert!(first.contains("+ backends: ") && first.contains("revision 1 committed"), "{first}");
    // The same source again commits nothing.
    let again = site.apply("edge.json", &Site::source(&["a"], ""), &[]);
    assert!(again.contains("revision 1 unchanged"), "{again}");
    // An operator who read revision 0 does not overwrite revision 1.
    fs::write(site.directory.join("edge.json"), Site::source(&["a", "b"], "")).unwrap();
    let conflict = site.failed("apply", &["-f", "edge.json", "--expect", "0"]);
    assert!(conflict.contains("REVISION CONFLICT (DBA002)"), "{conflict}");
    assert!(conflict.contains("expected revision 0, and the database is at revision 1"));
    assert!(site.done("status", &[]).starts_with("revision 1 "));
    let second = site.done("apply", &["-f", "edge.json", "--expect", "1"]);
    assert!(second.contains("+ backends.app.servers[b]: "), "{second}");
    assert!(second.contains("revision 2 committed"), "{second}");
    // A source that gives no topology is refused, and so is a section of the host.
    let dangling =
        Site::source(&["a"], "").replace(r#""default_backend":"app""#, r#""default_backend":"x""#);
    fs::write(site.directory.join("bad.json"), dangling).unwrap();
    let refused = site.failed("apply", &["-f", "bad.json"]);
    assert!(refused.contains("SOURCE REJECTED (DBA001)"), "{refused}");
    fs::write(site.directory.join("bad.json"), Site::source(&["a"], r#","routes":{}"#)).unwrap();
    assert!(site.failed("apply", &["-f", "bad.json"]).contains("DBA001"));
    let local =
        site.apply("edge.json", &Site::source(&["a", "b"], r#","global":{"workers":2}"#), &[]);
    assert!(local.contains("the file of each node owns: global"), "{local}");
    assert!(local.contains("revision 2 unchanged"), "{local}");
    assert!(site.failed("publish", &[]).contains("MISSING COMMAND (DBA007)"));
}

#[test]
fn history_lists_every_revision_and_rollback_appends_an_earlier_one() {
    let site = Site::sqlite();
    site.apply("edge.json", &Site::source(&["a"], ""), &["--note", "one", "--author", "ann"]);
    site.apply("edge.json", &Site::source(&["a", "b"], ""), &["--note", "two"]);
    site.apply("edge.json", &Site::source(&["a", "b", "c"], ""), &[]);
    let stale = site.failed("rollback", &["1", "--expect", "2"]);
    assert!(stale.contains("DBA002"), "{stale}");
    assert!(site.failed("rollback", &["9"]).contains("here is no revision 9"));
    let restored = site.done("rollback", &["1", "--note", "back"]);
    assert!(restored.contains("- backends.app.servers[b]"), "{restored}");
    assert!(restored.contains("- backends.app.servers[c]"), "{restored}");
    assert!(restored.contains("revision 4 committed, it restores revision 1"), "{restored}");
    // The history keeps all four. Nothing was rewritten.
    let history = site.done("history", &[]);
    let rows: Vec<&str> = history.lines().skip(1).collect();
    assert_eq!(rows.len(), 4, "{history}");
    assert!(rows[0].starts_with("4* ") && rows[0].contains("rollback-to-1"), "{history}");
    assert!(rows[0].contains("tester@") && rows[0].ends_with("back"), "{history}");
    assert!(rows[3].starts_with("1 ") && rows[3].contains(" ann ") && rows[3].ends_with("one"));
    assert_eq!(site.done("history", &["--limit", "2"]).lines().count(), 3);
    // Revision 4 holds the document of revision 1, and revision 3 is still there.
    assert_eq!(site.done("dump", &[]), site.done("dump", &["--revision", "1"]));
    assert!(site.done("dump", &["--revision", "3"]).contains(r#""name": "c""#));
    assert!(site.done("rollback", &["1"]).contains("already holds the document of revision 1"));
    assert!(site.done("status", &[]).starts_with("revision 4 "));
}

#[test]
fn a_dump_applies_to_the_same_revision_and_the_source_comes_back_as_given() {
    let site = Site::sqlite();
    let given = Site::source(&["a", "b"], "");
    site.apply("edge.json", &given, &[]);
    // The evaluated data goes out and comes back as the same document.
    let dump = site.done("dump", &[]);
    assert!(dump.starts_with("{\n") && dump.contains(r#""default_backend": "app""#), "{dump}");
    assert!(site.apply("dump.json", &dump, &[]).contains("revision 1 unchanged"));
    assert_eq!(site.done("dump", &["--source"]), given);
    // A second database that takes the dump holds the same digest.
    let copy = Site::sqlite();
    let committed = copy.apply("dump.json", &dump, &[]);
    let digest = |status: String| status.lines().next().unwrap().to_owned();
    assert!(committed.contains("revision 1 committed"), "{committed}");
    assert_eq!(digest(copy.done("status", &[])), digest(site.done("status", &[])));
    assert_eq!(copy.done("dump", &[]), dump);
    if !cfg!(feature = "jlv") {
        return;
    }
    // A JLV source is evaluated once, by the command. The nodes read its data.
    let jlv = "fn edge() -> Map<Value> {\n    return ".to_owned()
        + &Site::source(&["a", "z"], "")
        + "\n}\n";
    let applied = site.apply("edge.jlv", &jlv, &[]);
    assert!(applied.contains("revision 2 committed"), "{applied}");
    assert_eq!(site.done("dump", &["--source"]), jlv);
    assert!(site.done("dump", &[]).contains(r#""name": "z""#));
    assert!(site.done("history", &[]).contains("edge.jlv"));
}

#[test]
fn two_nodes_follow_a_revision_and_show_cluster_names_what_each_applied() {
    let site = Site::sqlite();
    site.apply("edge.json", &Site::source(&["a"], ""), &[]);
    let _nodes = [site.start(0), site.start(1)];
    assert!(site.serve(&[0, 1], &["a"]));
    let started = Instant::now();
    site.apply("edge.json", &Site::source(&["a", "b"], ""), &[]);
    assert!(site.logged(&[0, 1], "DBA010: revision 2 applied"));
    eprintln!("SQLite, poll 200 ms: both nodes applied revision 2 after {:?}", started.elapsed());
    assert!(site.serve(&[0, 1], &["a", "b"]));
    // Each node reports what it serves, and every node shows the reports of all.
    let shows_both = |index: usize| {
        let table = site.ctl(index, &["show", "cluster"]);
        table.starts_with("revision 2 ")
            && table.matches(" current").count() == 2
            && table.matches("this node").count() == 1
            && table.contains("n0 ")
            && table.contains("n1 ")
    };
    assert!(eventually(|| shows_both(0)), "{}", site.ctl(0, &["show", "cluster"]));
    assert!(eventually(|| shows_both(1)), "{}", site.ctl(1, &["show", "cluster"]));
    let own = site.ctl(1, &["show", "authority"]);
    assert!(own.contains("node: n1\n") && own.contains("applied: 2 "), "{own}");
    assert!(own.contains("head: 2\nstate: current\n"), "{own}");
    let status = site.done("status", &[]);
    assert_eq!(status.matches(" current").count(), 2, "{status}");
    // A rollback is a revision like any other, and the nodes follow it.
    site.done("rollback", &["1"]);
    assert!(site.serve(&[0, 1], &["a"]));
    // The file of a node stays on its host: `reload` reads it, `reload cluster` is refused.
    assert!(site.ctl(0, &["reload"]).contains("reloaded"));
    assert!(site.ctl(0, &["reload", "cluster"]).contains("DBA009"));
    assert!(site.serve(&[0, 1], &["a"]));
}

#[test]
fn a_revision_that_a_node_cannot_serve_is_refused_and_the_node_keeps_its_snapshot() {
    let site = Site::sqlite();
    site.apply("edge.json", &Site::source(&["a"], ""), &[]);
    let _node = site.start(0);
    assert!(site.serve(&[0], &["a"]));
    // The policy file is on the nodes. The command cannot see that this node lacks it.
    let bad = Site::source(&["a", "b"], r#","http":{"policy_file":"absent.policy"}"#)
        .replace(r#""proto":"tcp""#, r#""proto":"http""#)
        .replace(r#""mode":"tcp""#, r#""mode":"http""#);
    let bad = site.apply("edge.json", &bad, &[]);
    assert!(bad.contains("revision 2 committed"), "{bad}");
    assert!(
        site.logged(&[0], "DBA011: revision 2 refused, keeping revision 1"),
        "{}",
        site.log(0)
    );
    assert!(site.serve(&[0], &["a"]));
    let refused = |table: String| table.contains("n0 ") && table.contains("refused 2: ");
    assert!(eventually(|| refused(site.ctl(0, &["show", "cluster"]))));
    assert!(eventually(|| refused(site.done("status", &[]))), "{}", site.done("status", &[]));
    let own = site.ctl(0, &["show", "authority"]);
    assert!(own.contains("applied: 1 ") && own.contains("head: 2\nstate: refused 2: "), "{own}");
    // A reload asks again and gets the same answer. The file itself still loads.
    assert!(site.ctl(0, &["reload"]).contains("reloaded"));
    assert!(site.serve(&[0], &["a"]));
    // The node restarts on the revision of its cache, because the head is refused.
    drop(_node);
    let _node = site.start(0);
    assert!(
        site.log(0).contains("DBA014: started from the cache at revision 1"),
        "{}",
        site.log(0)
    );
    assert!(site.serve(&[0], &["a"]));
    // The next good revision is applied.
    site.apply("edge.json", &Site::source(&["a", "b"], ""), &[]);
    assert!(site.serve(&[0], &["a", "b"]));
    let healed = |table: String| table.starts_with("revision 3 ") && table.contains(" current");
    assert!(eventually(|| healed(site.ctl(0, &["show", "cluster"]))));
}

#[test]
fn a_node_keeps_serving_and_restarts_from_its_cache_without_the_database() {
    let site = Site::sqlite();
    site.apply("edge.json", &Site::source(&["a", "b"], ""), &[]);
    let node = site.start(0);
    assert!(site.serve(&[0], &["a", "b"]));
    assert!(eventually(|| site.home(0).join("cache").is_file()));
    // The node stops, and the database is gone when it starts again: it serves the
    // revision of its cache.
    drop(node);
    let database = site.directory.join("edge.db");
    let saved = site.directory.join("edge.saved");
    fs::rename(&database, &saved).unwrap();
    for suffix in ["edge.db-wal", "edge.db-shm"] {
        let _ = fs::remove_file(site.directory.join(suffix));
    }
    fs::create_dir(&database).unwrap();
    let _node = site.start(0);
    assert!(site.log(0).contains("DBA012: "), "{}", site.log(0));
    assert!(
        site.log(0).contains("DBA014: started from the cache at revision 1"),
        "{}",
        site.log(0)
    );
    assert!(site.serve(&[0], &["a", "b"]));
    let own = site.ctl(0, &["show", "authority"]);
    assert!(own.contains("applied: 1 ") && own.contains("database unavailable for "), "{own}");
    let table = site.ctl(0, &["show", "cluster"]);
    assert!(table.contains("n0 ") && table.contains("database unavailable: "), "{table}");
    assert!(site.failed("status", &[]).contains("DATABASE UNAVAILABLE (DBA003)"));
    // The database comes back with a new revision, and the node follows again.
    fs::remove_dir(&database).unwrap();
    fs::rename(&saved, &database).unwrap();
    site.apply("edge.json", &Site::source(&["a"], ""), &[]);
    assert!(site.logged(&[0], "DBA013: "), "{}", site.log(0));
    assert!(site.serve(&[0], &["a"]));
    // A node without a cache and without a database does not start.
    fs::remove_file(&database).unwrap();
    fs::create_dir(&database).unwrap();
    site.write_node_file(1);
    let refused = site.start_once(1).err().unwrap();
    assert!(refused.contains("DATABASE UNAVAILABLE"), "{refused}");
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use sibuna_authority::testing::{PASSWORD, Postgres, ROLE};

    /// The role of the nodes: it reads revisions and writes its own report.
    const NODE_ROLE: &str = "CREATE ROLE edge_node LOGIN PASSWORD 'node-secret';
        GRANT SELECT ON edge_head, edge_revisions, edge_nodes, sibuna_schema TO edge_node;
        GRANT INSERT, UPDATE ON edge_nodes TO edge_node;";

    /// A site on `server`. The operator connects as the owner of the tables. The nodes
    /// connect with the role of [`NODE_ROLE`] once `as_nodes` has run.
    fn site(server: &Postgres) -> Site {
        let url = server.url_file("operator.url", ROLE, PASSWORD, "postgres");
        // Only a notification can be fast with this poll.
        Site::new(|_| format!(r#""postgres_url_file":"{}""#, url.display()), "60s")
    }

    /// Points the files of the nodes at the role of the nodes.
    fn as_nodes(server: &Postgres, site: &mut Site) {
        server.execute("postgres", NODE_ROLE);
        let url = server.url_file("node.url", "edge_node", "node-secret", "postgres");
        site.store = format!(r#""postgres_url_file":"{}""#, url.display());
    }

    #[test]
    fn nodes_follow_a_notification_with_a_role_that_cannot_commit() {
        let Some(server) = Postgres::start("follow") else { return };
        let mut site = site(&server);
        site.apply("edge.json", &Site::source(&["a"], ""), &[]);
        as_nodes(&server, &mut site);
        let _nodes = [site.start(0), site.start(1)];
        assert!(site.serve(&[0, 1], &["a"]));
        let started = Instant::now();
        site.apply("edge.json", &Site::source(&["a", "b"], ""), &[]);
        assert!(site.logged(&[0, 1], "DBA010: revision 2 applied"));
        let took = started.elapsed();
        eprintln!("PostgreSQL, poll 60 s: both nodes applied revision 2 after {took:?}");
        assert!(took < Duration::from_secs(5), "a notification, not the poll: {took:?}");
        assert!(site.serve(&[0, 1], &["a", "b"]));
        let shows_both = |table: String| {
            table.starts_with("revision 2 ") && table.matches(" current").count() == 2
        };
        assert!(eventually(|| shows_both(site.ctl(0, &["show", "cluster"]))));
        assert!(eventually(|| shows_both(site.done("status", &[]))));
        // The role of a node cannot publish.
        fs::write(site.operator(), format!(r#"{{"authority":{{{}}}}}"#, site.store)).unwrap();
        let denied = site.failed("apply", &["-f", "edge.json", "--note", "as a node"]);
        assert!(denied.contains("permission denied"), "{denied}");
        assert!(site.done("status", &[]).starts_with("revision 2 "));
    }

    #[test]
    fn an_outage_changes_nothing_and_a_damaged_revision_is_refused() {
        let Some(mut server) = Postgres::start("outage") else { return };
        let site = site(&server);
        site.apply("edge.json", &Site::source(&["a"], ""), &[]);
        let _nodes = [site.start(0), site.start(1)];
        assert!(site.serve(&[0, 1], &["a"]));
        server.stop();
        assert!(site.logged(&[0, 1], "DBA012: "), "{}", site.log(0));
        assert!(site.serve(&[0, 1], &["a"]));
        assert!(site.ctl(0, &["show", "cluster"]).contains("database unavailable: "));
        assert!(site.failed("apply", &["-f", "edge.json"]).contains("DBA003"));
        assert!(server.resume());
        assert!(site.logged(&[0, 1], "DBA013: "), "{}", site.log(0));
        // After the outage a notification still arrives.
        let started = Instant::now();
        site.apply("edge.json", &Site::source(&["a", "b"], ""), &[]);
        assert!(site.logged(&[0, 1], "DBA010: revision 2 applied"), "{}", site.log(0));
        eprintln!("PostgreSQL after an outage: revision 2 applied after {:?}", started.elapsed());
        assert!(site.serve(&[0, 1], &["a", "b"]));
        // Somebody writes a revision past the command. Its digest does not fit.
        server.execute(
            "postgres",
            "INSERT INTO edge_revisions SELECT revision + 1, 'apply', NULL, '{\"frontends\":{}}',
               digest, source, source_name, source_digest, author, note, committed_at
               FROM edge_revisions WHERE revision = 2;
             UPDATE edge_head SET revision = 3;",
        );
        assert!(site.logged(&[0, 1], "DBA011: revision 3 refused, keeping revision 2"));
        assert!(site.serve(&[0, 1], &["a", "b"]));
        assert!(site.failed("dump", &[]).contains("REVISION DAMAGED (DBA008)"));
        // The operator replaces the damaged head, and the nodes follow.
        let repaired = site.apply("edge.json", &Site::source(&["a"], ""), &[]);
        assert!(repaired.contains("revision 3 is damaged"), "{repaired}");
        assert!(repaired.contains("revision 4 committed"), "{repaired}");
        assert!(site.serve(&[0, 1], &["a"]));
    }
}

/// Says why the PostgreSQL tests did not run in a build without the feature.
#[cfg(not(feature = "postgres"))]
#[test]
fn postgres_is_not_in_this_build() {
    eprintln!("skipped: build with `--features postgres` to test the PostgreSQL authority");
}
