//! The agent tier against a small agent in this process: verdicts, the deadline, the
//! queue, the breaker and telemetry (SID 0030, acceptance rows 3 and 8).
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

mod support;

use std::io::Write;
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sibuna_plugin::{
    AgentSpec, Answer, Attach, BreakerLimits, Case, Field, Frame, FrameKind, JudgeOptions, Judges,
    Kind, Local, OnFailure, Plan, PluginStatus, Protocol, Settings, Slot, Spec, Stage, Verdict,
    View, encode, read_frame, write_frame,
};
use support::temp_path;

/// What the test agent does with a `decide`.
#[derive(Clone)]
enum Reply {
    /// Answer with this verdict code and these field lines.
    Verdict(u8, &'static [u8]),
    /// Answer after a delay.
    Slow(Duration, u8),
    /// Read and never answer.
    Silent,
    /// Answer with bytes that are no frame.
    Garbage,
    /// Answer a well-formed verdict for another call.
    WrongId,
}

/// A small agent on a Unix socket. It serves each connection on a thread.
struct Agent {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    streams: Arc<Mutex<Vec<UnixStream>>>,
    /// The payloads of the samples received.
    samples: Arc<Mutex<Vec<Vec<u8>>>>,
    decides: Arc<Mutex<u32>>,
    accept: Option<JoinHandle<()>>,
}

fn serve(
    mut stream: UnixStream,
    reply: Reply,
    samples: &Mutex<Vec<Vec<u8>>>,
    decides: &Mutex<u32>,
) {
    while let Ok(Frame { kind, id, payload }) = read_frame(&mut stream) {
        if kind == FrameKind::Sample {
            samples.lock().unwrap().push(payload);
            continue;
        }
        *decides.lock().unwrap() += 1;
        let mut out = Vec::new();
        let answered = match &reply {
            Reply::Verdict(code, lines) => {
                let payload = [&[*code][..], lines].concat();
                write_frame(&mut out, FrameKind::Verdict, id, &payload)
            }
            Reply::Slow(delay, code) => {
                std::thread::sleep(*delay);
                write_frame(&mut out, FrameKind::Verdict, id, &[*code])
            }
            Reply::Silent => continue,
            Reply::Garbage => {
                out.extend_from_slice(&[0xff; 32]);
                Ok(())
            }
            Reply::WrongId => write_frame(&mut out, FrameKind::Verdict, id + 1000, &[0]),
        };
        if answered.is_err() || stream.write_all(&out).is_err() {
            return;
        }
    }
}

impl Agent {
    fn start_at(path: PathBuf, reply: Reply) -> Agent {
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind the test agent");
        let stop = Arc::new(AtomicBool::new(false));
        let streams = Arc::new(Mutex::new(Vec::new()));
        let samples = Arc::new(Mutex::new(Vec::new()));
        let decides = Arc::new(Mutex::new(0));
        let (stopping, held) = (Arc::clone(&stop), Arc::clone(&streams));
        let (seen, counted) = (Arc::clone(&samples), Arc::clone(&decides));
        let accept = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stopping.load(Ordering::Acquire) {
                    return;
                }
                let Ok(stream) = stream else { return };
                held.lock().unwrap().push(stream.try_clone().unwrap());
                let (reply, seen, counted) =
                    (reply.clone(), Arc::clone(&seen), Arc::clone(&counted));
                std::thread::spawn(move || serve(stream, reply, &seen, &counted));
            }
        });
        Agent { path, stop, streams, samples, decides, accept: Some(accept) }
    }

    fn start(reply: Reply) -> Agent {
        Agent::start_at(temp_path("agent.sock"), reply)
    }

    fn decides(&self) -> u32 {
        *self.decides.lock().unwrap()
    }

    /// Stops the agent: closes every connection and removes the socket.
    fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // The accept loop wakes on one more connection.
        let _ = UnixStream::connect(&self.path);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        for stream in self.streams.lock().unwrap().drain(..) {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.stop();
    }
}

fn spec(path: &std::path::Path, on_failure: OnFailure) -> Spec {
    let agent = AgentSpec {
        socket: path.to_string_lossy().into_owned(),
        deadline_ms: 200,
        queue: 8,
        breaker: BreakerLimits { failures: 3, open_ms: 150 },
    };
    Spec { name: "authz".to_owned(), on_failure, kind: Kind::Agent(agent) }
}

fn published(spec: Spec) -> Slot {
    let names = vec![spec.name.clone()];
    let attach = Attach { connection: names.clone(), request: names.clone(), telemetry: names };
    let frontends = vec![("web".to_owned(), attach)];
    let settings = Settings { plugins: vec![spec], frontends, ..Settings::default() };
    let slot = Slot::new();
    slot.publish(Plan::load(&settings, &[]).expect("the plan loads"));
    slot
}

fn view(stage: Stage) -> View<'static> {
    View {
        stage,
        protocol: Protocol::Http1,
        client: "127.0.0.1:5000".parse().unwrap(),
        local: "127.0.0.1:8080".parse().unwrap(),
        frontend: "web",
        method: b"GET",
        host: b"example.test",
        path: b"/",
        ..View::default()
    }
}

fn decide(local: &mut Local, slot: &Slot) -> (Verdict, String) {
    let decision = local.run(slot, &view(Stage::Request));
    (decision.verdict, String::from_utf8_lossy(decision.added).into_owned())
}

fn status(slot: &Slot) -> PluginStatus {
    slot.load().status().remove(0)
}

/// Waits until `done` holds, for at most two seconds.
fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(2);
    while !done() {
        assert!(Instant::now() < until, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn an_agent_admits_with_fields_denies_and_challenges() {
    let agent = Agent::start(Reply::Verdict(0, b"X-User: ada\r\nHost: evil\r\n"));
    let slot = published(spec(&agent.path, OnFailure::Deny));
    let mut local = Local::new();
    assert_eq!(decide(&mut local, &slot), (Verdict::Admit, "X-User: ada\r\n".to_owned()));
    assert_eq!(decide(&mut local, &slot).0, Verdict::Admit);
    let seen = status(&slot);
    assert_eq!((seen.tier, seen.calls, seen.admitted, seen.refused_fields), ("agent", 2, 2, 2));
    // The connection stage asks the same agent and takes no fields.
    assert_eq!(local.run(&slot, &view(Stage::Connection)).verdict, Verdict::Admit);

    for (code, verdict) in [(1, Verdict::Deny), (2, Verdict::Challenge)] {
        let agent = Agent::start(Reply::Verdict(code, b"X-Ignored: 1\r\n"));
        let slot = published(spec(&agent.path, OnFailure::Deny));
        assert_eq!(decide(&mut Local::new(), &slot), (verdict, String::new()));
    }
}

#[test]
fn a_silent_agent_costs_one_deadline_and_the_configured_outcome() {
    let agent = Agent::start(Reply::Silent);
    for (on_failure, verdict) in
        [(OnFailure::Deny, Verdict::Deny), (OnFailure::Admit, Verdict::Admit)]
    {
        let slot = published(spec(&agent.path, on_failure));
        let began = Instant::now();
        assert_eq!(decide(&mut Local::new(), &slot).0, verdict);
        let took = began.elapsed();
        assert!(took >= Duration::from_millis(200), "returned before the deadline: {took:?}");
        assert!(took < Duration::from_millis(400), "held past the deadline: {took:?}");
        assert_eq!(status(&slot).failures, [1, 0, 0, 0]);
    }
}

#[test]
fn an_answer_outside_the_protocol_is_a_trap() {
    for reply in [Reply::Garbage, Reply::WrongId, Reply::Verdict(9, b"")] {
        let agent = Agent::start(reply);
        let slot = published(spec(&agent.path, OnFailure::Deny));
        assert_eq!(decide(&mut Local::new(), &slot).0, Verdict::Deny);
        assert_eq!(status(&slot).failures, [0, 0, 1, 0]);
    }
}

#[test]
fn an_agent_that_is_not_there_is_unavailable() {
    let path = temp_path("absent.sock");
    let slot = published(spec(&path, OnFailure::Deny));
    assert_eq!(decide(&mut Local::new(), &slot).0, Verdict::Deny);
    assert_eq!(status(&slot).failures, [0, 0, 0, 1]);
    let slot = published(spec(&path, OnFailure::Admit));
    assert_eq!(decide(&mut Local::new(), &slot).0, Verdict::Admit);
}

#[test]
fn the_breaker_opens_after_failures_in_a_row_and_closes_after_a_good_probe() {
    let path = temp_path("breaker.sock");
    let slot = published(spec(&path, OnFailure::Deny));
    let mut local = Local::new();
    // Three failures in a row open the breaker of this thread.
    for _ in 0..3 {
        assert_eq!(status(&slot).open_breakers, 0);
        assert_eq!(decide(&mut local, &slot).0, Verdict::Deny);
    }
    assert_eq!(status(&slot).open_breakers, 1);
    // The agent comes up. The open breaker still refuses, and asks the agent nothing.
    let agent = Agent::start_at(path, Reply::Verdict(0, b""));
    let began = Instant::now();
    assert_eq!(decide(&mut local, &slot).0, Verdict::Deny);
    assert!(began.elapsed() < Duration::from_millis(50), "an open breaker must answer at once");
    assert_eq!(agent.decides(), 0);
    assert_eq!(status(&slot).failures, [0, 0, 0, 4]);
    // After its time one probe goes out, succeeds and closes the breaker.
    std::thread::sleep(Duration::from_millis(170));
    assert_eq!(decide(&mut local, &slot).0, Verdict::Admit);
    assert_eq!(status(&slot).open_breakers, 0);
    assert_eq!(decide(&mut local, &slot).0, Verdict::Admit);
    assert_eq!(agent.decides(), 2);
}

#[test]
fn a_probe_that_fails_keeps_the_breaker_open() {
    let path = temp_path("reopen.sock");
    let slot = published(spec(&path, OnFailure::Deny));
    let mut local = Local::new();
    for _ in 0..3 {
        decide(&mut local, &slot);
    }
    std::thread::sleep(Duration::from_millis(170));
    // The probe finds no agent. The breaker holds for another interval.
    assert_eq!(decide(&mut local, &slot).0, Verdict::Deny);
    assert_eq!(status(&slot).open_breakers, 1);
    let agent = Agent::start_at(path, Reply::Verdict(0, b""));
    assert_eq!(decide(&mut local, &slot).0, Verdict::Deny);
    assert_eq!(agent.decides(), 0);
    std::thread::sleep(Duration::from_millis(170));
    assert_eq!(decide(&mut local, &slot).0, Verdict::Admit);
    assert_eq!(status(&slot).open_breakers, 0);
}

#[test]
fn each_thread_has_a_breaker_of_its_own() {
    let path = temp_path("threads.sock");
    let slot = published(spec(&path, OnFailure::Deny));
    let gate = std::sync::Barrier::new(5);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                let mut local = Local::new();
                for _ in 0..3 {
                    decide(&mut local, &slot);
                }
                // The instances live until the gate opens.
                gate.wait();
            });
        }
        wait_for("four open breakers", || status(&slot).open_breakers == 4);
        gate.wait();
    });
    // A thread that ends takes its breaker with it.
    assert_eq!(status(&slot).open_breakers, 0);
}

#[test]
fn a_call_beyond_the_queue_is_an_overload_and_does_not_blame_the_agent() {
    let agent = Agent::start(Reply::Slow(Duration::from_millis(100), 0));
    let mut spec = spec(&agent.path, OnFailure::Deny);
    if let Kind::Agent(agent) = &mut spec.kind {
        (agent.queue, agent.deadline_ms, agent.breaker.failures) = (1, 1000, 1);
    }
    let slot = published(spec);
    std::thread::scope(|scope| {
        let first = scope.spawn(|| decide(&mut Local::new(), &slot).0);
        wait_for("the first call to reach the agent", || agent.decides() == 1);
        // The one place is taken: this call fails at once and never reaches the agent.
        let began = Instant::now();
        let mut second = Local::new();
        assert_eq!(decide(&mut second, &slot).0, Verdict::Deny);
        assert!(began.elapsed() < Duration::from_millis(50));
        assert_eq!(status(&slot).failures, [0, 1, 0, 0]);
        assert_eq!(first.join().unwrap(), Verdict::Admit);
        // With a breaker limit of one, a counted failure would have opened it.
        assert_eq!(status(&slot).open_breakers, 0);
        assert_eq!(decide(&mut second, &slot).0, Verdict::Admit);
    });
}

#[test]
fn a_restarted_agent_is_reached_again_without_a_failure() {
    let path = temp_path("restart.sock");
    let mut agent = Agent::start_at(path.clone(), Reply::Verdict(0, b""));
    let slot = published(spec(&path, OnFailure::Deny));
    let mut local = Local::new();
    assert_eq!(decide(&mut local, &slot).0, Verdict::Admit);
    agent.stop();
    let _agent = Agent::start_at(path, Reply::Verdict(0, b""));
    // The kept connection is closed. The call connects again within its deadline.
    assert_eq!(decide(&mut local, &slot).0, Verdict::Admit);
    assert_eq!(status(&slot).failures, [0; 4]);
}

#[test]
fn samples_reach_the_agent_and_are_dropped_when_it_is_away() {
    let path = temp_path("samples.sock");
    let slot = published(spec(&path, OnFailure::Deny));
    let mut local = Local::new();
    let sample = View { status: 200, duration_us: 1234, ..view(Stage::Telemetry) };
    // No agent: the sample is dropped, and the request it describes is untouched.
    assert_eq!(local.run(&slot, &sample).verdict, Verdict::Admit);
    assert_eq!(status(&slot).dropped, 1);
    let agent = Agent::start_at(path, Reply::Verdict(0, b""));
    // The first sample after the agent came up asks for a connection. Later ones use it.
    wait_for("three samples at the agent", || {
        local.run(&slot, &sample);
        agent.samples.lock().unwrap().len() >= 3
    });
    let samples = agent.samples.lock().unwrap();
    let first = &samples[0];
    assert_eq!((first[0], first[1]), (1, Stage::Telemetry.wire()));
    assert_eq!(u16::from_le_bytes([first[40], first[41]]), 200);
    assert_eq!(u32::from_le_bytes([first[44], first[45], first[46], first[47]]), 1234);
}

#[test]
fn an_agent_that_does_not_read_fills_a_bounded_backlog_and_never_holds_the_thread() {
    // A listener that accepts and reads nothing.
    let path = temp_path("stuck.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let held = std::thread::spawn(move || listener.accept().map(|(stream, _)| stream));
    let mut spec = spec(&path, OnFailure::Deny);
    if let Kind::Agent(agent) = &mut spec.kind {
        agent.queue = 4;
    }
    let slot = published(spec);
    let mut local = Local::new();
    let path_text = vec![b'p'; 2000];
    let sample = View { path: &path_text, ..view(Stage::Telemetry) };
    let began = Instant::now();
    wait_for("a dropped sample", || {
        local.run(&slot, &sample);
        status(&slot).dropped > 1
    });
    for _ in 0..2000 {
        local.run(&slot, &sample);
    }
    // 2,000 samples of 2 KiB against a peer that reads nothing: none of them waited.
    assert!(began.elapsed() < Duration::from_secs(2), "{:?}", began.elapsed());
    let seen = status(&slot);
    assert!(seen.dropped >= 2000, "{seen:?}");
    assert_eq!(seen.failures[1], seen.dropped - seen.failures[3], "{seen:?}");
    drop(held);
}

/// Gives `count` cases of `view` to `judges` and returns the receiver of their answers
/// and how many the queue refused.
fn submit(
    judges: &Judges,
    view: &View<'_>,
    count: usize,
) -> (std::sync::mpsc::Receiver<Answer>, usize) {
    let (answers, received) = std::sync::mpsc::channel();
    let mut refused = 0;
    for _ in 0..count {
        let answers = answers.clone();
        let deliver = Box::new(move |answer| {
            let _ = answers.send(answer);
        });
        refused += usize::from(judges.submit(Case::of(view), deliver).is_err());
    }
    (received, refused)
}

#[test]
fn a_case_is_a_faithful_copy_of_its_view() {
    let fields = [Field { name: b"Cookie", value: b"a=1" }, Field { name: b"X", value: b"" }];
    let original = View {
        server_name: b"name.test",
        ja4: b"t13d",
        query: b"q=1",
        fields: &fields,
        status: 204,
        duration_us: 77,
        secure: true,
        ..view(Stage::Request)
    };
    let (mut wanted, mut copied) = (Vec::new(), Vec::new());
    encode(&original, &mut wanted, 65_536).unwrap();
    Case::of(&original).with_view(|view| encode(view, &mut copied, 65_536).unwrap());
    assert_eq!(wanted, copied);
}

#[test]
fn judges_decide_parked_cases_and_a_silent_agent_never_holds_the_caller() {
    let agent = Agent::start(Reply::Silent);
    let slot = Arc::new(published(spec(&agent.path, OnFailure::Deny)));
    let mut local = Local::new();
    let connection = view(Stage::Connection);
    assert!(local.parks(&slot, "web", Stage::Connection));
    assert!(!local.parks(&slot, "other", Stage::Connection));
    let judges = Judges::start(&slot, JudgeOptions { threads: 2, queue: 2 }).unwrap();
    let began = Instant::now();
    // Two cases occupy the judges for the deadline of 200 ms, two wait, the rest
    // find no room. A judge may take a case at once, so the count has a range.
    let (answers, refused) = submit(&judges, &connection, 8);
    assert!((4..=6).contains(&refused), "{refused} refused");
    // The caller sheds what found no room: the agent fails with overload, and denies.
    for _ in 0..refused {
        assert_eq!(local.run_shedding(&slot, &connection).verdict, Verdict::Deny);
    }
    assert!(began.elapsed() < Duration::from_millis(100), "the caller waited");
    assert_eq!(status(&slot).failures[1], refused as u64, "overloads");
    for _ in 0..8 - refused {
        let answer = answers.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(answer, Answer { verdict: Verdict::Deny, hook: "authz".into() });
    }
    // Every case ended as a failure of the agent: a timeout, a shed case or, once the
    // breakers of the judges opened, an agent that is not asked.
    let seen = status(&slot);
    assert_eq!((seen.calls, seen.denied, seen.admitted), (8, 0, 0), "{seen:?}");
    assert!(seen.failures[0] >= 2, "the judges timed out: {seen:?}");
}

#[test]
fn judges_admit_with_a_healthy_agent_and_an_advisory_agent_admits_when_shed() {
    let agent = Agent::start(Reply::Verdict(0, b""));
    let slot = Arc::new(published(spec(&agent.path, OnFailure::Admit)));
    let judges = Judges::start(&slot, JudgeOptions::default()).unwrap();
    let connection = view(Stage::Connection);
    let (answers, refused) = submit(&judges, &connection, 20);
    assert_eq!(refused, 0);
    for _ in 0..20 {
        let answer = answers.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(answer, Answer { verdict: Verdict::Admit, hook: "".into() });
    }
    assert_eq!(agent.decides(), 20);
    let mut local = Local::new();
    assert_eq!(local.run_shedding(&slot, &connection).verdict, Verdict::Admit);
    assert_eq!(agent.decides(), 20, "a shed chain asks no agent");
    // The judges end when their owner drops them.
    drop(judges);
}

#[test]
fn hook_judges_outside_their_range_refuse_the_plan() {
    let spec = spec(&temp_path("none.sock"), OnFailure::Deny);
    for judges in [JudgeOptions { threads: 0, queue: 1 }, JudgeOptions { threads: 65, queue: 1 }] {
        let settings = Settings { plugins: vec![spec.clone()], judges, ..Settings::default() };
        assert_eq!(Plan::load(&settings, &[]).unwrap_err().code, "HOOK002");
    }
}
