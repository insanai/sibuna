//! The three plugin tiers through the edge binary (SID 0030): each tier admits, denies
//! and fails with its configured outcome, on the event-driven workers and on the thread
//! path. Everything runs on loopback.
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

#[path = "../../../crates/plugin/tests/support/mod.rs"]
mod assemble;
mod traffic;

use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use assemble::{constant_hook, hook, i32c, spinning_hook, temp_file, temp_path, trapping_hook};
use sibuna_encoding::base64;
use sibuna_plugin::{Frame, FrameKind, read_frame, write_frame};
use traffic::{Edge, Message, Origin, Topology, both, get, get_with, read_message, request};

const EXAMPLE: &[u8] = include_bytes!("../../../crates/plugin/tests/data/example_hook.wasm");

/// A topology whose frontend attaches the plugin `name`, defined by `plugin`, at the
/// stages of `hooks`.
fn hooked(origin: &Origin, plugin: &str, hooks: &str) -> Topology {
    Topology::new(&[origin.address])
        .root(&format!(r#""plugins":{{"p":{plugin}}},"#))
        .frontend(&format!(r#""hooks":{hooks},"#))
}

fn wasm(bytes: &[u8], more: &str) -> String {
    let module = temp_file("hook.wasm", bytes);
    format!(r#"{{"kind":"wasm","module":"{module}"{more}}}"#)
}

const REQUEST: &str = r#"{"request":["p"]}"#;

/// The cell under `column` in the row of the plugin `p` in `show hooks`.
fn shown(edge: &Edge, column: &str) -> u64 {
    let table = edge.ctl("show hooks");
    let mut lines = table.lines();
    let head: Vec<&str> = lines.next().unwrap().trim_start_matches("# ").split(' ').collect();
    let row: Vec<&str> =
        lines.next().unwrap_or_else(|| panic!("no plugin in {table}")).split(' ').collect();
    let index = head.iter().position(|cell| *cell == column).unwrap();
    row[index].parse().unwrap_or_else(|_| panic!("{column} in {table}"))
}

/// Sends `GET path` on the kept connection `client` and returns the response.
fn ask(client: &mut BufReader<TcpStream>, path: &str) -> Message {
    let head = format!("GET {path} HTTP/1.1\r\nHost: app.example\r\n\r\n");
    request(client, head.as_bytes());
    read_message(client, false).expect("a response")
}

// ---- the native tier ----

#[test]
fn a_native_hook_admits_and_denies_requests() {
    both(|event_loop| {
        let origin = Origin::start("a");
        let plugin = r#"{"kind":"native","hook":"require_header",
            "settings":{"name":"x-token","value":"open"}}"#;
        let edge = hooked(&origin, plugin, REQUEST).start(event_loop);
        assert_eq!(get_with(&edge, "/who", "X-Token: open\r\n").text(), "a");
        let denied = get(&edge, "/who");
        assert_eq!(denied.status(), 403);
        assert_eq!(get_with(&edge, "/who", "X-Token: shut\r\n").status(), 403);
        assert_eq!(
            (shown(&edge, "calls"), shown(&edge, "admitted"), shown(&edge, "denied")),
            (3, 1, 2)
        );
        // The access log names the verdict of the request that the hook denied.
        let lines = edge.log_lines(3);
        assert_eq!(traffic::logged(&lines[1], "verdict"), "deny");
        let stats = edge.ctl("show stats");
        let series =
            "sibuna_edge_hook_calls_total{plugin=\"p\",tier=\"native\",result=\"deny\"} 2";
        assert!(stats.contains(series), "{stats}");
    });
}

#[test]
fn a_plugin_that_does_not_load_is_a_diagnostic_of_the_check() {
    let origin = Origin::start("a");
    let unknown = r#"{"kind":"native","hook":"nothing"}"#;
    let error = hooked(&origin, unknown, REQUEST).check().unwrap_err();
    assert!(error.contains("HOOK007") && error.contains("require_header"), "{error}");
    assert!(error.contains("Hint"), "{error}");

    let mut wasi = hook(&i32c(0));
    wasi.imports[1] = ("wasi_snapshot_preview1", "clock_time_get", vec![], Some(assemble::I64));
    let error = hooked(&origin, &wasm(&wasi.build(), ""), REQUEST).check().unwrap_err();
    assert!(error.contains("HOOK005") && error.contains("wasi_snapshot_preview1"), "{error}");

    let error = hooked(&origin, &wasm(b"not wasm", ""), REQUEST).check().unwrap_err();
    assert!(error.contains("HOOK004"), "{error}");
    let fuel = wasm(EXAMPLE, r#","fuel_limit":5"#);
    let error = hooked(&origin, &fuel, REQUEST).check().unwrap_err();
    assert!(error.contains("HOOK002") && error.contains("fuel_limit"), "{error}");
    // The same file with its bounds in range passes.
    hooked(&origin, &wasm(EXAMPLE, ""), REQUEST).check().unwrap();
}

// ---- the Wasm tier ----

#[test]
fn the_example_wasm_hook_admits_with_a_field_denies_and_challenges() {
    both(|event_loop| {
        let origin = Origin::start("a");
        let edge = hooked(&origin, &wasm(EXAMPLE, ""), REQUEST).start(event_loop);
        // The origin answers `/head` with the head it received.
        let head = get(&edge, "/head").text();
        assert!(head.contains("X-Hook: example"), "{head}");
        assert_eq!(get(&edge, "/admin/users").status(), 403);
        assert_eq!(get_with(&edge, "/admin/users", "X-Role: admin\r\n").status(), 200);
        // A client that is no browser gets the address of the challenge.
        let challenged = get(&edge, "/guarded");
        assert_eq!(challenged.status(), 401);
        assert!(challenged.text().contains("challenge_required"), "{}", challenged.text());
        assert_eq!((shown(&edge, "admitted"), shown(&edge, "denied")), (2, 1));
        assert_eq!(shown(&edge, "challenged"), 1);
        // The origin saw the two admitted requests only.
        assert_eq!(origin.requests.load(Ordering::SeqCst), 2);
    });
}

/// The text of the member `key` of the JSON object `body`.
fn member(body: &[u8], key: &str) -> String {
    let value = sibuna::extract_json_string(body, key.as_bytes());
    String::from_utf8(value.unwrap_or_else(|| panic!("{key} in {body:?}")).to_vec()).unwrap()
}

/// Pays for the challenge that `challenged` announces and returns the session cookie
/// as a field line.
fn pay(edge: &Edge, challenged: &Message) -> String {
    let issued = get(edge, &member(&challenged.body, "challenge"));
    assert_eq!(issued.status(), 200, "{}", issued.text());
    assert_eq!(member(&issued.body, "algorithm"), "posw");
    let id = member(&issued.body, "id");
    let params = sibuna_pow::posw::Params {
        depth: member(&issued.body, "difficulty").parse().unwrap(),
        challenges: member(&issued.body, "challenges").parse().unwrap(),
    };
    let mut workspace = Box::new(sibuna_pow::posw::Workspace::new());
    let proof = sibuna_pow::posw::solve(id.as_bytes(), params, &mut workspace).unwrap();
    let proof = base64::encode(base64::URL_SAFE_NO_PAD, proof);
    let body = format!("{{\"challenge_id\":\"{id}\",\"proof\":\"{proof}\"}}");
    let verified = traffic::post(edge, "/__sibuna/verify", body.as_bytes());
    assert_eq!(verified.status(), 200, "{}", verified.text());
    let cookie = verified.field("set-cookie").expect("a session cookie");
    format!("Cookie: {}\r\n", cookie.split(';').next().unwrap())
}

#[test]
fn a_paid_challenge_of_a_hook_is_cleared_and_the_hook_behind_it_still_judges() {
    both(|event_loop| {
        let origin = Origin::start("a");
        let module = temp_file("hook.wasm", EXAMPLE);
        let plugins = format!(
            r#""plugins":{{"p":{{"kind":"wasm","module":"{module}"}},
            "token":{{"kind":"native","hook":"require_header","settings":{{"name":"x-token"}}}}}},"#
        );
        let edge = Topology::new(&[origin.address])
            .root(&plugins)
            .frontend(r#""hooks":{"request":["p","token"]},"#)
            .start(event_loop);
        let challenged = get_with(&edge, "/guarded", "X-Token: 1\r\n");
        assert_eq!(challenged.status(), 401);
        let cookie = pay(&edge, &challenged);
        // The session clears the challenge of the first hook. The second still denies
        // a request without its field.
        assert_eq!(get_with(&edge, "/guarded", &cookie).status(), 403);
        let both_fields = format!("{cookie}X-Token: 1\r\n");
        assert_eq!(get_with(&edge, "/guarded", &both_fields).status(), 200);
        // Without the session the challenge stands.
        assert_eq!(get_with(&edge, "/guarded", "X-Token: 1\r\n").status(), 401);
        assert_eq!(origin.requests.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn a_wasm_hook_that_spins_or_traps_gets_the_configured_outcome() {
    both(|event_loop| {
        let origin = Origin::start("a");
        let closed = hooked(&origin, &wasm(&spinning_hook(), ""), REQUEST).start(event_loop);
        let started = Instant::now();
        assert_eq!(get(&closed, "/who").status(), 403);
        // The fuel of one invocation is spent in far less than a second.
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
        assert_eq!((shown(&closed, "timeout"), shown(&closed, "denied")), (1, 0));
        // The thread serves on after the timeout.
        assert_eq!(get(&closed, "/who").status(), 403);

        let advisory = wasm(&spinning_hook(), r#","on_failure":"admit""#);
        let open = hooked(&origin, &advisory, REQUEST).start(event_loop);
        assert_eq!(get(&open, "/who").text(), "a");
        assert_eq!(shown(&open, "timeout"), 1);

        let trap = hooked(&origin, &wasm(&trapping_hook(), ""), REQUEST).start(event_loop);
        assert_eq!(get(&trap, "/who").status(), 403);
        assert_eq!(shown(&trap, "trap"), 1);
        let advisory = wasm(&trapping_hook(), r#","on_failure":"admit""#);
        let open = hooked(&origin, &advisory, REQUEST).start(event_loop);
        assert_eq!(get(&open, "/who").text(), "a");
    });
}

#[test]
fn a_request_too_large_for_the_input_buffer_overflows_and_is_not_cut() {
    both(|event_loop| {
        let origin = Origin::start("a");
        // The buffer of this hook holds 4,096 bytes, and it admits whatever it sees.
        let edge = hooked(&origin, &wasm(&constant_hook(0), ""), REQUEST).start(event_loop);
        assert_eq!(get(&edge, "/who").text(), "a");
        let long = format!("X-Long: {}\r\n", "a".repeat(5000));
        assert_eq!(get_with(&edge, "/who", &long).status(), 403);
        assert_eq!(shown(&edge, "overload"), 1);
    });
}

#[test]
fn a_connection_hook_closes_a_connection_before_any_request() {
    both(|event_loop| {
        let origin = Origin::start("a");
        let hooks = r#"{"connection":["p"]}"#;
        let edge = hooked(&origin, &wasm(&constant_hook(1), ""), hooks).start(event_loop);
        let mut client = edge.connect();
        let _ = client.get_mut().write_all(b"GET /who HTTP/1.1\r\nHost: app.example\r\n\r\n");
        assert!(read_message(&mut client, false).is_none(), "a denied connection was answered");
        assert_eq!((shown(&edge, "calls"), shown(&edge, "denied")), (1, 1));
        assert_eq!(origin.requests.load(Ordering::SeqCst), 0);
        let stats = edge.ctl("show stats");
        assert!(stats.contains("reason=\"hook\"} 1"), "{stats}");
    });
}

#[test]
fn a_reload_changes_the_hooks_and_a_bad_module_keeps_the_serving_ones() {
    both(|event_loop| {
        let origin = Origin::start("a");
        let deny = hooked(&origin, &wasm(&constant_hook(1), ""), REQUEST);
        let edge = deny.start(event_loop);
        assert_eq!(get(&edge, "/who").status(), 403);

        edge.rewrite(&hooked(&origin, &wasm(&constant_hook(0), ""), REQUEST), event_loop);
        edge.ctl("reload");
        assert_eq!(get(&edge, "/who").text(), "a");
        // The counters of the plugin go on over the reload.
        assert_eq!((shown(&edge, "calls"), shown(&edge, "denied")), (2, 1));

        edge.rewrite(&hooked(&origin, &wasm(b"\0asm garbage", ""), REQUEST), event_loop);
        let refused = edge.ctl_refused("reload");
        assert!(refused.contains("HOOK004"), "{refused}");
        assert_eq!(get(&edge, "/who").text(), "a");

        // A file without hooks: the request path asks nobody.
        edge.rewrite(&Topology::new(&[origin.address]), event_loop);
        edge.ctl("reload");
        assert_eq!(get(&edge, "/who").text(), "a");
        assert_eq!(edge.ctl("show hooks").lines().count(), 1);
    });
}

// ---- the agent tier ----

const ADMIT: u8 = 0;
const DENY: u8 = 1;
const SILENT: u8 = 2;

/// A small agent on a Unix socket. Its mode says what it does with a `decide`.
struct Agent {
    path: PathBuf,
    mode: Arc<AtomicU8>,
    samples: Arc<Mutex<Vec<Vec<u8>>>>,
}

fn serve_agent(mut stream: UnixStream, mode: &AtomicU8, samples: &Mutex<Vec<Vec<u8>>>) {
    while let Ok(Frame { kind, id, payload }) = read_frame(&mut stream) {
        if kind == FrameKind::Sample {
            samples.lock().unwrap().push(payload);
            continue;
        }
        let payload: &[u8] = match mode.load(Ordering::Acquire) {
            ADMIT => b"\x00X-User: ada\r\n",
            DENY => b"\x01",
            _ => continue,
        };
        let mut out = Vec::new();
        write_frame(&mut out, FrameKind::Verdict, id, payload).unwrap();
        if stream.write_all(&out).is_err() {
            return;
        }
    }
}

impl Agent {
    fn start_at(path: PathBuf, mode: u8) -> Agent {
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let mode = Arc::new(AtomicU8::new(mode));
        let samples = Arc::new(Mutex::new(Vec::new()));
        let (shared, seen) = (Arc::clone(&mode), Arc::clone(&samples));
        std::thread::spawn(move || {
            for stream in listener.incoming().map_while(Result::ok) {
                let (shared, seen) = (Arc::clone(&shared), Arc::clone(&seen));
                std::thread::spawn(move || serve_agent(stream, &shared, &seen));
            }
        });
        Agent { path, mode, samples }
    }

    fn plugin(path: &std::path::Path, more: &str) -> String {
        format!(
            r#"{{"kind":"agent","socket":"{}","deadline":"300ms",
            "breaker":{{"failures":2,"open":"400ms"}}{more}}}"#,
            path.display()
        )
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[test]
fn an_agent_admits_with_a_field_denies_and_times_out() {
    both(|event_loop| {
        let origin = Origin::start("a");
        let agent = Agent::start_at(temp_path("agent.sock"), ADMIT);
        let edge = hooked(&origin, &Agent::plugin(&agent.path, ""), REQUEST).start(event_loop);
        let head = get(&edge, "/head").text();
        assert!(head.contains("X-User: ada"), "{head}");

        agent.mode.store(DENY, Ordering::Release);
        assert_eq!(get(&edge, "/who").status(), 403);

        agent.mode.store(SILENT, Ordering::Release);
        let started = Instant::now();
        assert_eq!(get(&edge, "/who").status(), 403);
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(300), "answered before the deadline: {waited:?}");
        assert!(waited < Duration::from_millis(1500), "held far past the deadline: {waited:?}");
        assert_eq!((shown(&edge, "admitted"), shown(&edge, "denied")), (1, 1));
        assert_eq!(shown(&edge, "timeout"), 1);
    });
}

#[test]
fn an_advisory_agent_that_is_away_admits() {
    both(|event_loop| {
        let origin = Origin::start("a");
        let path = temp_path("away.sock");
        let plugin = Agent::plugin(&path, r#","on_failure":"admit""#);
        let edge = hooked(&origin, &plugin, REQUEST).start(event_loop);
        assert_eq!(get(&edge, "/who").text(), "a");
        assert_eq!(shown(&edge, "unavailable"), 1);
    });
}

#[test]
fn the_breaker_of_an_agent_opens_and_closes() {
    both(|event_loop| {
        let origin = Origin::start("a");
        let path = temp_path("breaker.sock");
        let edge = hooked(&origin, &Agent::plugin(&path, ""), REQUEST).start(event_loop);
        // One kept connection stays on one thread, so one breaker sees every request.
        let mut client = edge.connect();
        for _ in 0..2 {
            assert_eq!(shown(&edge, "open_breakers"), 0);
            assert_eq!(ask(&mut client, "/who").status(), 403);
        }
        assert_eq!(shown(&edge, "open_breakers"), 1);
        // The agent comes up. The open breaker refuses on, and asks the agent nothing.
        let agent = Agent::start_at(path, ADMIT);
        assert_eq!(ask(&mut client, "/who").status(), 403);
        assert_eq!(shown(&edge, "unavailable"), 3);
        // After its time one probe goes out, succeeds and closes the breaker.
        std::thread::sleep(Duration::from_millis(450));
        assert_eq!(ask(&mut client, "/who").text(), "a");
        assert_eq!(shown(&edge, "open_breakers"), 0);
        assert_eq!(ask(&mut client, "/who").text(), "a");
        drop(agent);
    });
}

#[test]
fn a_telemetry_agent_receives_a_sample_of_every_answered_request() {
    both(|event_loop| {
        let origin = Origin::start("a");
        let agent = Agent::start_at(temp_path("samples.sock"), ADMIT);
        let hooks = r#"{"telemetry":["p"]}"#;
        let edge = hooked(&origin, &Agent::plugin(&agent.path, ""), hooks).start(event_loop);
        let deadline = Instant::now() + Duration::from_secs(10);
        // The first sample asks for the connection. A later one is sent on it.
        while agent.samples.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline, "no sample reached the agent");
            assert_eq!(get(&edge, "/status/404").status(), 404);
            std::thread::sleep(Duration::from_millis(20));
        }
        let samples = agent.samples.lock().unwrap();
        let sample = &samples[0];
        // The wire form: version 1, stage 3, the status at offset 40.
        assert_eq!((sample[0], sample[1]), (1, 3));
        assert_eq!(u16::from_le_bytes([sample[40], sample[41]]), 404);
        let text = String::from_utf8_lossy(sample);
        assert!(text.contains("/status/404") && text.contains("web"), "{text}");
    });
}
