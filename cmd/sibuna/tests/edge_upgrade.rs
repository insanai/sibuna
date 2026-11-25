//! Replacing a running edge through `global.upgrade_socket` (SID 0029): the old process
//! passes its listeners and its UDP mappings to the new one.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

mod upgrade;

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use upgrade::{Load, Mode, Scene, ask, echo, request};

/// Replaces the daemon of `scene` while clients keep opening connections and one long
/// stream keeps the old process in its drain. Returns the load counters and how long
/// the old process drained.
fn replace_under_load(mode: Mode) -> (usize, usize, Duration) {
    let mut scene = Scene::start(mode);
    // A stream that lives across the upgrade. The old process keeps it.
    let mut long = std::net::TcpStream::connect(scene.tcp_vip).unwrap();
    long.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    assert!(upgrade::exchange(&mut long, b"before"));
    let load = Load::start(scene.http_vip, scene.tcp_vip, 4);
    std::thread::sleep(Duration::from_millis(300));
    assert!(load.served() > 20, "the load did not start: {}", load.served());

    let new = scene.daemon();
    let old = std::mem::replace(&mut scene.daemon, new);
    if mode == Mode::ReusePort {
        old.signal("-TERM");
    }
    // The old process drains for as long as the stream is open. The load goes on.
    let draining = Instant::now();
    std::thread::sleep(Duration::from_millis(1500));
    assert!(old.is_running(), "the old process left its stream");
    assert!(upgrade::exchange(&mut long, b"during"), "the long stream broke");
    drop(long);
    let status = old.wait(Duration::from_secs(8));
    let drained = draining.elapsed();
    assert!(status.success(), "the old process ended with {status}");
    std::thread::sleep(Duration::from_millis(300));
    let (served, failed) = load.stop();
    // The new process answers on the admin socket of the old one.
    let info = scene.ctl("show info");
    assert!(info.contains(&format!("pid: {}", scene.daemon.id())), "{info}");
    if mode == Mode::Handoff {
        old.expect_line("UPG010: handed 3 listeners");
        scene.daemon.expect_line("UPG020: took 3 listeners");
    }
    (served, failed, drained)
}

#[test]
fn no_connection_is_lost_while_the_listeners_are_handed_over() {
    let (served, failed, drained) = replace_under_load(Mode::Handoff);
    eprintln!("handoff: {served} served, {failed} failed, old process drained {drained:?}");
    assert!(served > 200, "served {served}");
    assert_eq!(failed, 0, "{failed} of {served} connections failed during the handoff");
}

#[test]
fn the_reuse_port_path_is_measured_beside_the_handoff() {
    // The same load on the path of `global.reuse_port`. The old process has an accept
    // queue of its own there, and refuses or resets what arrives in it while it
    // drains. The number is printed for the record; SID 0029 quotes it. We assert
    // only that the path still replaces the process.
    let (served, failed, drained) = replace_under_load(Mode::ReusePort);
    eprintln!("reuse_port: {served} served, {failed} failed, old process drained {drained:?}");
    assert!(served > 100, "served {served}");
}

#[test]
fn udp_clients_keep_their_server_across_two_upgrades() {
    let mut scene = Scene::start(Mode::Handoff);
    let clients: Vec<_> = (0..40).map(|_| upgrade::udp_client()).collect();
    let before: Vec<String> = clients.iter().map(|c| ask(c, scene.udp_vip).unwrap()).collect();
    // Both servers have clients, so a new placement would move some of them.
    for server in ["0 ", "1 "] {
        assert!(before.iter().any(|answer| answer.starts_with(server)), "{before:?}");
    }
    // One client keeps sending through the cutover and counts what it loses.
    let stop = Arc::new(AtomicBool::new(false));
    let (started, has_mapping) = std::sync::mpsc::channel();
    let pinger = {
        let (stop, vip) = (stop.clone(), scene.udp_vip);
        std::thread::spawn(move || {
            let client = upgrade::udp_client();
            let first = ask(&client, vip).unwrap();
            started.send(()).unwrap();
            let (mut sent, mut lost, mut moved) = (0u32, 0u32, 0u32);
            while !stop.load(Ordering::Relaxed) {
                sent += 1;
                match ask(&client, vip) {
                    Some(answer) if answer == first => {}
                    Some(_) => moved += 1,
                    None => lost += 1,
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            (sent, lost, moved)
        })
    };
    has_mapping.recv().unwrap();
    for round in 0..2 {
        let new = scene.daemon();
        let old = std::mem::replace(&mut scene.daemon, new);
        let status = old.wait(Duration::from_secs(8));
        assert!(status.success(), "round {round}: the old process ended with {status}");
        let line = old.line("UPG010: handed 3 listeners and 41 UDP mappings");
        eprintln!("udp round {round}: {line}");
        scene.daemon.expect_line("and 41 UDP mappings from pid");
        // The same server answers, and it sees the same source address: the socket
        // towards the server is the one the old process opened.
        let after: Vec<String> = clients.iter().map(|c| ask(c, scene.udp_vip).unwrap()).collect();
        assert_eq!(before, after, "round {round}");
    }
    stop.store(true, Ordering::Relaxed);
    let (sent, lost, moved) = pinger.join().unwrap();
    eprintln!("udp: {sent} datagrams through two cutovers, {lost} lost, {moved} moved");
    assert!(sent > 100);
    assert_eq!((lost, moved), (0, 0), "of {sent} datagrams");
    // A new client is served by the replacement.
    assert!(ask(&upgrade::udp_client(), scene.udp_vip).is_some());
    assert!(scene.ctl("show info").contains("flows: 42"));
}

#[test]
fn six_thousand_mappings_move_in_two_pieces() {
    let mut scene = Scene::start_with(Mode::Handoff, r#""max_flows":20000,"#, "");
    let clients: Vec<_> = (0..6000).map(|_| upgrade::udp_client()).collect();
    let before: Vec<String> = clients.iter().map(|c| ask(c, scene.udp_vip).unwrap()).collect();
    let started = Instant::now();
    let new = scene.daemon();
    let replaced = started.elapsed();
    let old = std::mem::replace(&mut scene.daemon, new);
    assert!(old.wait(Duration::from_secs(8)).success());
    let line = old.line("UPG010: handed 3 listeners and 6000 UDP mappings");
    eprintln!("6000 mappings: replacement up in {replaced:?}; {line}");
    assert!(line.contains(" 0 mappings dropped"), "{line}");
    let after: Vec<String> = clients.iter().map(|c| ask(c, scene.udp_vip).unwrap()).collect();
    let moved: Vec<_> = before.iter().zip(&after).filter(|(old, new)| old != new).collect();
    assert!(moved.is_empty(), "{} of 6000 clients moved, the first {:?}", moved.len(), moved[0]);
    assert!(scene.ctl("show info").contains("flows: 6000"));
}

/// A frontend with HTTP/3 is replaced too. Its UDP socket is not passed: the
/// replacement binds its own beside the old one.
#[cfg(feature = "https")]
#[test]
fn a_frontend_with_http3_is_replaced_and_its_tcp_listener_is_passed() {
    let data = concat!(env!("CARGO_MANIFEST_DIR"), "/../../crates/tls/tests/data");
    let tls: &'static str = Box::leak(
        format!(
            r#""tls":{{"cert_file":"{data}/localhost.pem","key_file":"{data}/localhost.key",
                     "http3":true}},"#
        )
        .into_boxed_str(),
    );
    let mut scene = Scene::start_with(Mode::Handoff, "", tls);
    let load = Load::start_tcp(scene.tcp_vip, 2);
    let new = scene.daemon();
    let old = std::mem::replace(&mut scene.daemon, new);
    assert!(old.wait(Duration::from_secs(8)).success());
    old.expect_line("UPG010: handed 3 listeners");
    // The TLS listener answers a connection, and the TCP frontend lost nothing.
    assert!(std::net::TcpStream::connect(scene.http_vip).is_ok());
    std::thread::sleep(Duration::from_millis(200));
    let (served, failed) = load.stop();
    assert!(served > 20, "served {served}");
    assert_eq!(failed, 0);
    assert!(scene.daemon.is_running());
}

#[test]
fn a_replacement_that_fails_leaves_the_old_process_serving() {
    let scene = Scene::start(Mode::Handoff);
    let client = upgrade::udp_client();
    let before = ask(&client, scene.udp_vip).unwrap();
    let serves = |why: &str| {
        assert!(request(scene.http_vip), "HTTP after {why}");
        assert!(echo(scene.tcp_vip), "TCP after {why}");
        assert_eq!(ask(&client, scene.udp_vip).as_deref(), Some(before.as_str()), "UDP {why}");
        assert!(scene.daemon.is_running(), "the old process ended after {why}");
        let info = scene.ctl("show info");
        assert!(info.contains(&format!("pid: {}", scene.daemon.id())), "{why}: {info}");
    };

    // A file that does not check: the replacement never connects.
    let broken = scene.write_config("broken", "\"shutdown_timeout\":\"soon\",");
    let output = scene.run(&broken);
    assert!(!output.status.success());
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("INVALID CONFIGURATION (EDGE001)"), "{text}");
    serves("a file that does not check");

    // A file that checks, and a start that fails after the listeners were taken: the
    // access log cannot be opened.
    let log = r#""observability":{"access_log":{"output":"/nonexistent-dir/sibuna/x.log"}},"#;
    let unstartable = scene.write_root("unstartable", log);
    let output = scene.run(&unstartable);
    assert!(!output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    scene.daemon.expect_line("UPG011: the replacement pid");
    scene.daemon.expect_line("Serving on.");
    serves("a start that fails");

    // A replacement that stops in the middle of the cutover: it said READY, took the
    // mappings and never acknowledged. The old process ends it and reads UDP again.
    let stalled = upgrade::stalled_replacement(&scene.upgrade_socket);
    let started = Instant::now();
    // TCP is served during the whole cutover. UDP waits.
    while started.elapsed() < Duration::from_secs(4) {
        assert!(request(scene.http_vip) && echo(scene.tcp_vip), "TCP during a stalled cutover");
        std::thread::sleep(Duration::from_millis(100));
    }
    client.send_to(&[b'w'; 48], scene.udp_vip).unwrap();
    scene.daemon.expect_line_within("no answer in time. Serving on.", Duration::from_secs(15));
    let status = upgrade::reap(stalled);
    assert_eq!(std::os::unix::process::ExitStatusExt::signal(&status), Some(9), "{status}");
    // The datagram that waited in the socket is answered by the old process.
    let mut answer = [0u8; 128];
    client.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let (size, from) = client.recv_from(&mut answer).unwrap();
    assert_eq!(from, scene.udp_vip);
    assert_eq!(String::from_utf8_lossy(&answer[..size]), before);
    serves("a stalled cutover");

    // After three failures a good replacement still takes over.
    let mut scene = scene;
    let new = scene.daemon();
    let old = std::mem::replace(&mut scene.daemon, new);
    assert!(old.wait(Duration::from_secs(8)).success());
    assert_eq!(ask(&client, scene.udp_vip).as_deref(), Some(before.as_str()));
}

#[test]
fn a_wrong_peer_is_refused_by_both_ends() {
    let scene = Scene::start(Mode::Handoff);
    // Only the user of the daemon can connect at all.
    let mode = std::fs::metadata(&scene.upgrade_socket).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    // A peer that is no replacement.
    let mut stranger = UnixStream::connect(&scene.upgrade_socket).unwrap();
    stranger.write_all(b"GET /listeners HTTP/1.1\r\n\r\n").unwrap();
    scene.daemon.expect_line("UPG012: refused an upgrade peer");
    let mut told = Vec::new();
    stranger.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let _ = stranger.read_to_end(&mut told);
    // The refusal is a REFUSE frame, and no descriptor came with it.
    assert_eq!(told.first(), Some(&2), "{told:?}");
    assert_eq!(&told[5..7], &[0, 0]);

    // A replacement of a version the daemon does not speak.
    let mut future = UnixStream::connect(&scene.upgrade_socket).unwrap();
    let mut hello = vec![1, 8, 0, 0, 0, 0, 0];
    hello.extend_from_slice(b"SBUP");
    hello.extend_from_slice(&[7, 0, 9, 0]);
    future.write_all(&hello).unwrap();
    scene.daemon.expect_line("the peer speaks versions 7 to 9");
    assert!(request(scene.http_vip));
    assert!(scene.daemon.is_running());

    // The other end: a replacement that finds something else at the path gives up
    // and binds nothing.
    let fake = scene.directory.join("fake.sock");
    let listener = UnixListener::bind(&fake).unwrap();
    let answering = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest);
    });
    let lured = scene.write_config_at("lured", &fake);
    let output = scene.run(&lured);
    answering.join().unwrap();
    assert!(!output.status.success());
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("-- UPGRADE PROTOCOL ERROR (UPG003) "), "{text}");
    assert!(text.contains("Hint:"), "{text}");

    // A daemon that refuses names the reason to the replacement.
    let refusing = scene.directory.join("refusing.sock");
    let listener = UnixListener::bind(&refusing).unwrap();
    let answering = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let reason = b"user 1 is not user 2";
        let mut frame = vec![2, (2 + reason.len()) as u8, 0, 0, 0, 0, 0, 1, 0];
        frame.extend_from_slice(reason);
        let _ = stream.write_all(&frame);
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest);
    });
    let turned_away = scene.write_config_at("turned-away", &refusing);
    let output = scene.run(&turned_away);
    answering.join().unwrap();
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("-- UPGRADE PEER REFUSED (UPG001) "), "{text}");
    assert!(text.contains("user 1 is not user 2"), "{text}");
    assert!(request(scene.http_vip));
}

#[test]
fn the_daemon_of_another_service_is_not_replaced() {
    let (one, other) = (Scene::start(Mode::Handoff), Scene::start(Mode::Handoff));
    // The file of the second service names the socket of the first by mistake.
    let mistaken = other.write_config_at("mistaken", &one.upgrade_socket);
    let output = other.run(&mistaken);
    assert!(!output.status.success());
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("-- UPGRADE SOCKET OF ANOTHER DAEMON (UPG008) "), "{text}");
    one.daemon.expect_line("UPG011: the replacement pid");
    for scene in [&one, &other] {
        assert!(scene.daemon.is_running());
        assert!(request(scene.http_vip) && echo(scene.tcp_vip));
        assert!(ask(&upgrade::udp_client(), scene.udp_vip).is_some());
    }
}

#[test]
fn a_reload_cannot_move_the_upgrade_socket() {
    let scene = Scene::start(Mode::Handoff);
    let elsewhere = scene.directory.join("other.sock");
    std::fs::write(&scene.config, scene.source(Some(&elsewhere), "", "")).unwrap();
    let answer = scene.ctl("reload");
    assert!(answer.contains("changing global.upgrade_socket requires a restart"), "{answer}");
    assert!(request(scene.http_vip));
}

/// Not a test of its own: the body of the stalled replacement, which the test above
/// starts as a process of this test binary.
#[test]
fn stalled_replacement_helper() {
    upgrade::stall_if_asked();
}
