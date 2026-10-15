//! Throughput of the listener over loopback: eight clients, one request per connection.
//! Ignored by default; run it with
//! `cargo test --release -p sibuna-serve --test timing -- --ignored --nocapture`.
//!
//! The Zig benchmark has no listener workload. To compare with the Zig kernel, start a Zig
//! program serving the same reply and set `SIBUNA_SERVE_TARGET=127.0.0.1:<port>`; the same
//! client then measures that listener instead of ours.

// Test code: a panic is how a failure is reported, also in helper functions.
#![allow(clippy::unwrap_used, clippy::print_stdout)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::Instant;

use sibuna_serve::{Context, Options, ServeError, Server};

fn handler(context: &mut Context<'_>) -> Result<(), ServeError> {
    context.respond(200, b"application/json", b"{\"ok\":true}", &[])
}

#[test]
#[ignore = "timing: run with --release -- --ignored --nocapture"]
fn requests_per_second_over_loopback() {
    let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = Server::start(address, handler, Options::default()).unwrap();
    let address = match std::env::var("SIBUNA_SERVE_TARGET") {
        Ok(target) => target.parse().unwrap(),
        Err(_) => server.local_addr(),
    };
    let (clients, per_client) = (8, 5_000);
    let start = Instant::now();
    thread::scope(|scope| {
        for _ in 0..clients {
            scope.spawn(move || {
                let mut reply = Vec::with_capacity(1024);
                for _ in 0..per_client {
                    let mut stream = TcpStream::connect(address).unwrap();
                    stream
                        .write_all(b"GET /console/api/session HTTP/1.1\r\nHost: c\r\n\r\n")
                        .unwrap();
                    reply.clear();
                    stream.read_to_end(&mut reply).unwrap();
                    assert!(reply.starts_with(b"HTTP/1.1 200 OK\r\n"));
                }
            });
        }
    });
    let elapsed = start.elapsed();
    let requests = clients * per_client;
    let rate = requests as f64 / elapsed.as_secs_f64();
    let each = 1e6 / rate;
    println!("{address}: {requests} requests, one per connection: {rate:.0}/s, {each:.1} us each");
    server.stop();
}
