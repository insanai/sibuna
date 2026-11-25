//! The cost of one invocation of each tier, measured in this process (SID 0030,
//! "Measured cost"). The tests are ignored: they measure, they assert nothing about
//! time. Run them optimized and alone:
//!
//! ```text
//! cargo test -p sibuna-plugin --release --test cost -- --ignored --nocapture --test-threads 1
//! ```
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

mod support;

use std::hint::black_box;
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::time::Instant;

use sibuna_plugin::wasm::{Budget, Host, Instance, Module, Trap};
use sibuna_plugin::{
    AgentSpec, Attach, Edits, Failure, Field, FrameKind, Hook, Kind, Local, Native, OnFailure,
    Plan, Protocol, Settings, Slot, Spec, Stage, Verdict, View, WasmSpec, read_frame, write_frame,
};
use support::{temp_file, temp_path};

const EXAMPLE: &[u8] = include_bytes!("data/example_hook.wasm");

/// The native hook of the measurement does what the example Wasm hook does.
struct Example;

impl Hook for Example {
    fn on_request(&mut self, view: &View<'_>, edits: &mut Edits) -> Result<Verdict, Failure> {
        if view.path.starts_with(b"/admin") && view.field(b"x-role") != Some(b"admin") {
            return Ok(Verdict::Deny);
        }
        if view.path.starts_with(b"/guarded") {
            return Ok(Verdict::Challenge);
        }
        edits.add(b"X-Hook", b"example");
        Ok(Verdict::Admit)
    }
}

fn build(_: &[(String, String)]) -> Result<Box<dyn Hook>, String> {
    Ok(Box::new(Example))
}

const NATIVES: [Native; 1] = [Native { name: "example", build }];

fn slot_of(kind: Kind) -> Slot {
    let plugins = vec![Spec { name: "p".to_owned(), on_failure: OnFailure::Deny, kind }];
    let attach = Attach { request: vec!["p".to_owned()], ..Attach::default() };
    let frontends = vec![("web".to_owned(), attach)];
    let settings = Settings { plugins, frontends, ..Settings::default() };
    let slot = Slot::new();
    slot.publish(Plan::load(&settings, &NATIVES).unwrap());
    slot
}

/// A request like a browser's: eight fields, about 450 bytes on the wire.
const FIELDS: [Field<'static>; 8] = [
    Field { name: b"Host", value: b"app.example.org" },
    Field { name: b"User-Agent", value: b"Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101" },
    Field { name: b"Accept", value: b"text/html,application/xhtml+xml,application/xml;q=0.9" },
    Field { name: b"Accept-Language", value: b"en-GB,en;q=0.5" },
    Field { name: b"Accept-Encoding", value: b"gzip, deflate, br" },
    Field { name: b"Cookie", value: b"session=0123456789abcdef0123456789abcdef; theme=dark" },
    Field { name: b"X-Role", value: b"reader" },
    Field { name: b"Connection", value: b"keep-alive" },
];

fn request() -> View<'static> {
    View {
        stage: Stage::Request,
        protocol: Protocol::Http1,
        client: "127.0.0.1:5000".parse().unwrap(),
        local: "127.0.0.1:8080".parse().unwrap(),
        frontend: "web",
        method: b"GET",
        host: b"app.example.org",
        path: b"/articles/2026/plugin-tiers",
        query: b"page=2",
        fields: &FIELDS,
        ..View::default()
    }
}

/// Nanoseconds per call of `step`: the best of five rounds of `count` calls.
fn measure(count: u32, mut step: impl FnMut()) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..5 {
        let started = Instant::now();
        for _ in 0..count {
            step();
        }
        best = best.min(started.elapsed().as_nanos() as f64 / f64::from(count));
    }
    best
}

#[test]
#[ignore = "a measurement"]
fn cost_of_one_invocation_of_each_tier() {
    let view = request();

    let empty = Slot::new();
    let none = measure(10_000_000, || {
        black_box(black_box(&empty).has(Stage::Request));
    });
    println!("no hook, Slot::has:        {none:>9.1} ns");

    let slot = slot_of(Kind::Native { hook: "example".to_owned(), settings: Vec::new() });
    let mut local = Local::new();
    let native = measure(2_000_000, || {
        black_box(local.run(&slot, black_box(&view)).verdict);
    });
    println!("native:                    {native:>9.1} ns");

    let module = temp_file("cost.wasm", EXAMPLE);
    let slot = slot_of(Kind::Wasm(WasmSpec { module, ..WasmSpec::default() }));
    let mut local = Local::new();
    let wasm = measure(200_000, || {
        black_box(local.run(&slot, black_box(&view)).verdict);
    });
    println!("wasm (example hook):       {wasm:>9.1} ns");

    let path = temp_path("cost.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                let mut out = Vec::new();
                while let Ok(frame) = read_frame(&mut stream) {
                    out.clear();
                    let answer = b"\x00X-Hook: example\r\n";
                    write_frame(&mut out, FrameKind::Verdict, frame.id, answer).unwrap();
                    if stream.write_all(&out).is_err() {
                        return;
                    }
                }
            });
        }
    });
    let socket = path.to_string_lossy().into_owned();
    let spec = AgentSpec { socket, deadline_ms: 1000, ..AgentSpec::default() };
    let slot = slot_of(Kind::Agent(spec));
    let mut local = Local::new();
    assert_eq!(local.run(&slot, &view).verdict, Verdict::Admit);
    let agent = measure(50_000, || {
        black_box(local.run(&slot, black_box(&view)).verdict);
    });
    println!("agent (thread, Unix socket): {agent:>7.1} ns");

    // The same call parked: a case goes to one judge and the answer comes back.
    let slot = Arc::new(slot);
    let options = sibuna_plugin::JudgeOptions { threads: 1, queue: 8 };
    let judges = sibuna_plugin::Judges::start(&slot, options).unwrap();
    let (answers, received) = std::sync::mpsc::channel();
    let round = || {
        let answers = answers.clone();
        let deliver = Box::new(move |answer| {
            let _ = answers.send(answer);
        });
        assert!(judges.submit(sibuna_plugin::Case::of(black_box(&view)), deliver).is_ok());
        black_box(received.recv().unwrap().verdict);
    };
    round();
    let parked = measure(50_000, round);
    println!("agent, parked with a judge:  {parked:>7.1} ns");
    let _ = std::fs::remove_file(path);
}

/// Answers `add_header` with success and stores nothing.
struct Accepting;

impl Host for Accepting {
    fn call(&mut self, _: u32, _: &[u64], _: &mut [u8]) -> Result<u64, Trap> {
        Ok(0)
    }
}

#[test]
#[ignore = "a measurement"]
fn cost_of_the_interpreter_alone_on_the_example_hook() {
    // What the comparison with another interpreter measures: copy the encoded view
    // into the memory of the instance and call `sibuna_on_request`.
    let mut encoded = Vec::new();
    sibuna_plugin::encode(&request(), &mut encoded, 4096).unwrap();
    if let Ok(path) = std::env::var("SIBUNA_COST_VIEW") {
        std::fs::write(path, &encoded).unwrap();
    }
    let started = Instant::now();
    let module = Module::load(EXAMPLE).unwrap();
    let loaded = started.elapsed().as_secs_f64() * 1e6;
    let started = Instant::now();
    black_box(Module::load(include_bytes!("data/pow_solver.wasm")).unwrap());
    let solver = started.elapsed().as_secs_f64() * 1e3;
    println!("load and validate: example hook {loaded:.0} us, solver {solver:.2} ms");
    let mut instance = Instance::new(Arc::new(module), 4).unwrap();
    let export = |instance: &Instance, name: &str| instance.module().exported_func(name).unwrap();
    let (input, on_request) =
        (export(&instance, "sibuna_input"), export(&instance, "sibuna_on_request"));
    let mut budget = Budget { fuel: 1000, host_calls: 0 };
    let at = instance.call(input, &[], &mut budget, &mut Accepting).unwrap().unwrap() as usize;
    let mut spent = 0;
    let bare = measure(200_000, || {
        let mut budget = Budget { fuel: 100_000, host_calls: 16 };
        instance.memory_mut()[at..at + encoded.len()].copy_from_slice(&encoded);
        let length = encoded.len() as u64;
        black_box(instance.call(on_request, &[length], &mut budget, &mut Accepting).unwrap());
        spent = 100_000 - budget.fuel;
    });
    println!(
        "interpreter alone, example hook: {bare:.1} ns, {spent} operations, view {} bytes",
        encoded.len()
    );
}

struct NoHost;

impl Host for NoHost {
    fn call(&mut self, _: u32, _: &[u64], _: &mut [u8]) -> Result<u64, Trap> {
        Err(Trap::Host)
    }
}

#[test]
#[ignore = "a measurement"]
fn speed_of_the_interpreter_on_sha256() {
    // 20,000 hashcash trials of the compiled solver: SHA-256 in a tight loop.
    let module = Module::load(include_bytes!("data/pow_solver.wasm")).unwrap();
    let mut instance = Instance::new(Arc::new(module), 32).unwrap();
    let export = |instance: &Instance, name: &str| instance.module().exported_func(name).unwrap();
    let buffer = export(&instance, "sibuna_get_buffer_ptr");
    let step = export(&instance, "sibuna_solve_step");
    let mut budget = Budget { fuel: u64::MAX, host_calls: 0 };
    let at = instance.call(buffer, &[], &mut budget, &mut NoHost).unwrap().unwrap();
    instance.memory_mut()[at as usize..at as usize + 6].copy_from_slice(b"sibuna");
    let mut best = f64::MAX;
    let mut spent = 0;
    for _ in 0..5 {
        let mut budget = Budget { fuel: u64::MAX, host_calls: 0 };
        let started = Instant::now();
        // 64 bits never match, so every one of the 20,000 trials runs.
        let found = instance.call(step, &[at, 6, 64, 0, 20_000], &mut budget, &mut NoHost);
        best = best.min(started.elapsed().as_secs_f64());
        spent = u64::MAX - budget.fuel;
        black_box(found.unwrap());
    }
    let rate = spent as f64 / best / 1e6;
    println!(
        "interpreter: 20,000 trials in {:.1} ms, {spent} operations, {rate:.0} M/s",
        best * 1e3
    );
    let started = Instant::now();
    black_box(sibuna_pow::hashcash::Search::new(b"sibuna").find(64, 0, 20_000));
    println!("native:      20,000 trials in {:.1} ms", started.elapsed().as_secs_f64() * 1e3);
}
