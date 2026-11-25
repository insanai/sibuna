//! One file reloads every node of a mesh (SID 0023).
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::PathBuf;
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

/// Three nodes on one host. Each has a directory of its own with the shared file, the
/// mesh key and the file that names its own mesh address. The nodes share the
/// listener with `reuse_port`, so that the file is the same for all, byte for byte.
struct Cluster {
    directory: PathBuf,
    vip: SocketAddr,
    mesh: Vec<SocketAddr>,
}

impl Cluster {
    fn new(nodes: usize) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = format!("sibuna-cluster-{}-{serial}", std::process::id());
        let directory = std::env::temp_dir().join(name);
        let vip = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        // The mesh address serves UDP for the mesh and TCP for the file.
        let mut mesh = Vec::new();
        while mesh.len() < nodes {
            let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            let address = udp.local_addr().unwrap();
            if TcpListener::bind(address).is_ok() {
                mesh.push(address);
            }
        }
        let cluster = Self { directory, vip, mesh };
        for index in 0..nodes {
            fs::create_dir_all(cluster.home(index)).unwrap();
            fs::write(cluster.home(index).join("mesh.key"), [42u8; 32]).unwrap();
            fs::write(cluster.home(index).join("mesh.self"), cluster.mesh[index].to_string())
                .unwrap();
            fs::write(cluster.file(index), cluster.source(&["a"])).unwrap();
        }
        cluster
    }

    fn home(&self, index: usize) -> PathBuf {
        self.directory.join(format!("n{index}"))
    }

    fn file(&self, index: usize) -> PathBuf {
        self.home(index).join("edge.json")
    }

    /// The file of every node, with one server of the pool for each name.
    fn source(&self, servers: &[&str]) -> String {
        let nodes: Vec<String> = self.mesh.iter().map(|node| format!("\"{node}\"")).collect();
        let servers: Vec<String> = servers
            .iter()
            .enumerate()
            .map(|(index, name)| {
                format!(r#"{{"name":"{name}","addr":"127.83.7.{}:9"}}"#, index + 9)
            })
            .collect();
        format!(
            r#"{{"global":{{"admin_socket":"edge.sock","reuse_port":true}},
            "mesh":{{"nodes":[{}],"key_file":"mesh.key","self_file":"mesh.self",
              "accept_config":true}},
            "frontends":{{"web":{{"proto":"tcp","binds":["{}"],"default_backend":"app"}}}},
            "backends":{{"app":{{"mode":"tcp","balance":{{"kind":"round_robin"}},
              "servers":[{}]}}}}}}"#,
            nodes.join(","),
            self.vip,
            servers.join(",")
        )
    }

    fn start(&self, index: usize) -> Result<Node, String> {
        let mut child = Command::new(BIN)
            .current_dir(self.home(index))
            .args(["--config-file", "edge.json"])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stderr.take().unwrap()).read_line(&mut line).unwrap();
        if !line.contains("ready") {
            let _ = child.kill();
            let _ = child.wait();
            return Err(line);
        }
        Ok(Node { child })
    }

    fn ctl(&self, index: usize, words: &[&str]) -> Output {
        let socket = self.home(index).join("edge.sock");
        Command::new(BIN).arg("ctl").arg(socket).args(words).output().unwrap()
    }

    /// The names of the servers that the node at `index` serves.
    fn servers(&self, index: usize) -> Vec<String> {
        let output = self.ctl(index, &["show", "servers"]);
        let table = String::from_utf8(output.stdout).unwrap();
        let names = table.lines().skip(1).filter_map(|line| line.split_whitespace().nth(1));
        names.map(str::to_owned).collect()
    }

    /// Waits until every node serves exactly the servers `names`.
    fn all_serve(&self, names: &[&str]) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if (0..self.mesh.len()).all(|index| self.servers(index) == names) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        false
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// Starts a cluster. A port that was free a moment ago may be taken by a test that
/// runs beside this one. The addresses are then chosen again.
fn cluster(nodes: usize) -> (Cluster, Vec<Node>) {
    let mut failure = String::new();
    for _ in 0..5 {
        let cluster = Cluster::new(nodes);
        match (0..nodes).map(|index| cluster.start(index)).collect::<Result<Vec<_>, _>>() {
            Ok(started) => return (cluster, started),
            Err(line) => failure = line,
        }
    }
    panic!("the cluster did not start: {failure}");
}

#[test]
fn reload_cluster_puts_one_file_on_every_node() {
    let (cluster, _nodes) = cluster(3);
    assert!(cluster.all_serve(&["a"]));
    // The operator edits the file of one node and reloads the cluster from it.
    let next = cluster.source(&["a", "b"]);
    fs::write(cluster.file(0), &next).unwrap();
    let output = cluster.ctl(0, &["reload", "cluster"]);
    let answer = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(output.status.success(), "{answer}{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(answer.matches(" reloaded").count(), 3, "{answer}");
    assert!(cluster.all_serve(&["a", "b"]));
    // Every node now holds the same file, so a restart serves the same servers.
    for index in 1..3 {
        assert_eq!(fs::read_to_string(cluster.file(index)).unwrap(), next);
    }
    // `show cluster` says that every node holds the file of this one.
    let table = String::from_utf8(cluster.ctl(0, &["show", "cluster"]).stdout).unwrap();
    assert_eq!(table.matches(" same").count(), 2, "{table}");
    assert_eq!(table.matches(" this node").count(), 1, "{table}");
    // A file that does not check stops at the first node. No peer is asked.
    fs::write(cluster.file(0), "{").unwrap();
    assert!(!cluster.ctl(0, &["reload", "cluster"]).status.success());
    assert!(cluster.all_serve(&["a", "b"]));
    assert_eq!(fs::read_to_string(cluster.file(1)).unwrap(), next);
    // The broken file of the first node now differs from the file of its peers.
    let table = String::from_utf8(cluster.ctl(1, &["show", "cluster"]).stdout).unwrap();
    assert_eq!(table.matches(" differs").count(), 1, "{table}");
    assert_eq!(table.matches(" same").count(), 1, "{table}");
}

#[test]
fn a_node_with_another_key_refuses_the_file_and_the_command_says_so() {
    let (cluster, mut nodes) = cluster(3);
    // The third node restarts with another key. It is outside the mesh now.
    drop(nodes.pop());
    fs::write(cluster.home(2).join("mesh.key"), [43u8; 32]).unwrap();
    nodes.push(cluster.start(2).unwrap());
    fs::write(cluster.file(0), cluster.source(&["a", "b"])).unwrap();
    let output = cluster.ctl(0, &["reload", "cluster"]);
    let said = String::from_utf8_lossy(&output.stderr).into_owned()
        + &String::from_utf8_lossy(&output.stdout);
    assert!(!output.status.success(), "{said}");
    assert!(said.contains("CLUSTER RELOAD INCOMPLETE"), "{said}");
    assert!(said.contains(&format!("{} reloaded", cluster.mesh[1])), "{said}");
    assert!(said.contains(&format!("{} refused", cluster.mesh[2])), "{said}");
    assert_eq!(cluster.servers(0), ["a", "b"]);
    assert_eq!(cluster.servers(1), ["a", "b"]);
    assert_eq!(cluster.servers(2), ["a"]);
    // A node with another key gets no digest, and gives none.
    let table = String::from_utf8(cluster.ctl(0, &["show", "cluster"]).stdout).unwrap();
    assert_eq!(table.matches(" same").count(), 1, "{table}");
    assert_eq!(table.matches("no answer").count(), 1, "{table}");
}
