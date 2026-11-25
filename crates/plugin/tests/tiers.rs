//! The native and the Wasm tier through the public path: settings, a plan, a slot and a
//! thread's instances. Each tier admits, denies, challenges and fails with its
//! configured outcome (SID 0030, acceptance rows 1 to 3 and 7).

#![allow(clippy::unwrap_used)]

mod support;

use std::sync::Arc;

use sibuna_plugin::wasm::{Budget, Host, Instance, Module, Trap};
use sibuna_plugin::{
    Attach, Decision, Edits, Error, Failure, Field, Hook, Kind, Local, Native, OnFailure, Plan,
    Protocol, Settings, Slot, Spec, Stage, Verdict, View, WasmSpec,
};
use support::{I32, constant_hook, hook, i32c, spinning_hook, temp_file, trapping_hook};

const EXAMPLE: &[u8] = include_bytes!("data/example_hook.wasm");

// ---- a native hook for the tests ----

/// Judges by the path: `/deny`, `/challenge` and `/fail` do what they say.
struct ByPath {
    mark: String,
}

impl Hook for ByPath {
    fn on_connection(&mut self, view: &View<'_>) -> Result<Verdict, Failure> {
        Ok(if view.client.port() == 9 { Verdict::Deny } else { Verdict::Admit })
    }

    fn on_request(&mut self, view: &View<'_>, edits: &mut Edits) -> Result<Verdict, Failure> {
        edits.add(b"X-Native", self.mark.as_bytes());
        match view.path {
            b"/deny" => Ok(Verdict::Deny),
            b"/challenge" => Ok(Verdict::Challenge),
            b"/fail" => Err(Failure::Trap),
            _ => Ok(Verdict::Admit),
        }
    }
}

fn build_by_path(settings: &[(String, String)]) -> Result<Box<dyn Hook>, String> {
    match settings {
        [(key, value)] if key == "mark" => Ok(Box::new(ByPath { mark: value.clone() })),
        _ => Err("by_path needs the one setting `mark`".to_owned()),
    }
}

const NATIVES: [Native; 1] = [Native { name: "by_path", build: build_by_path }];

// ---- helpers ----

fn native(name: &str, on_failure: OnFailure) -> Spec {
    let settings = vec![("mark".to_owned(), name.to_owned())];
    Spec {
        name: name.to_owned(),
        on_failure,
        kind: Kind::Native { hook: "by_path".into(), settings },
    }
}

fn wasm(name: &str, bytes: &[u8], on_failure: OnFailure) -> Spec {
    let module = temp_file(name, bytes);
    let kind = Kind::Wasm(WasmSpec { module, fuel_limit: 20_000, ..WasmSpec::default() });
    Spec { name: name.to_owned(), on_failure, kind }
}

/// Settings that attach `plugins`, in order, at every stage of the frontend `web`.
fn attach_all(plugins: Vec<Spec>) -> Settings {
    let names: Vec<String> = plugins.iter().map(|spec| spec.name.clone()).collect();
    let attach = Attach { connection: names.clone(), request: names.clone(), telemetry: names };
    Settings { plugins, frontends: vec![("web".to_owned(), attach)] }
}

fn published(settings: &Settings) -> Slot {
    let slot = Slot::new();
    slot.publish(Plan::load(settings, &NATIVES).expect("the plan loads"));
    slot
}

fn request<'a>(path: &'a [u8], fields: &'a [Field<'a>]) -> View<'a> {
    View {
        stage: Stage::Request,
        protocol: Protocol::Http1,
        client: "127.0.0.1:5000".parse().unwrap(),
        local: "127.0.0.1:8080".parse().unwrap(),
        frontend: "web",
        method: b"GET",
        host: b"example.test",
        path,
        fields,
        ..View::default()
    }
}

/// Runs the request chain on `path` and returns the verdict, the hook and the fields.
fn decide(local: &mut Local, slot: &Slot, path: &[u8]) -> (Verdict, String, String) {
    let decision = local.run(slot, &request(path, &[]));
    let added = String::from_utf8_lossy(decision.added).into_owned();
    (decision.verdict, decision.hook.to_owned(), added)
}

fn admitted(added: &str) -> (Verdict, String, String) {
    (Verdict::Admit, String::new(), added.to_owned())
}

fn refused(verdict: Verdict, hook: &str) -> (Verdict, String, String) {
    (verdict, hook.to_owned(), String::new())
}

// ---- no hooks ----

#[test]
fn a_slot_without_hooks_answers_from_one_word_and_admits() {
    let slot = Slot::new();
    for stage in Stage::ALL {
        assert!(!slot.has(stage));
    }
    assert_eq!(Local::new().run(&slot, &request(b"/", &[])), Decision::ADMIT);
    // A frontend that attaches nothing is admitted beside one that does.
    let slot = published(&attach_all(vec![native("n", OnFailure::Deny)]));
    let view = View { frontend: "other", ..request(b"/deny", &[]) };
    assert_eq!(Local::new().run(&slot, &view), Decision::ADMIT);
}

// ---- the native tier ----

#[test]
fn the_native_tier_admits_denies_challenges_and_fails_closed() {
    let slot = published(&attach_all(vec![native("n", OnFailure::Deny)]));
    let mut local = Local::new();
    assert!(slot.has(Stage::Request));
    assert_eq!(decide(&mut local, &slot, b"/"), admitted("X-Native: n\r\n"));
    assert_eq!(decide(&mut local, &slot, b"/deny"), refused(Verdict::Deny, "n"));
    assert_eq!(decide(&mut local, &slot, b"/challenge"), refused(Verdict::Challenge, "n"));
    assert_eq!(decide(&mut local, &slot, b"/fail"), refused(Verdict::Deny, "n"));
    let status = &slot.load().status()[0];
    assert_eq!((status.tier, status.calls, status.admitted, status.denied), ("native", 4, 1, 1));
    assert_eq!((status.challenged, status.failures), (1, [0, 0, 1, 0]));
}

#[test]
fn an_advisory_native_hook_admits_on_failure_and_adds_nothing() {
    let slot = published(&attach_all(vec![native("n", OnFailure::Admit)]));
    let mut local = Local::new();
    assert_eq!(decide(&mut local, &slot, b"/fail"), admitted(""));
    // Its verdicts still count: only a failure is turned into an admission.
    assert_eq!(decide(&mut local, &slot, b"/deny"), refused(Verdict::Deny, "n"));
}

#[test]
fn a_chain_runs_in_order_and_a_failing_authorization_hook_blocks_it() {
    let chain = vec![native("first", OnFailure::Admit), native("second", OnFailure::Deny)];
    let slot = published(&attach_all(chain));
    let mut local = Local::new();
    assert_eq!(
        decide(&mut local, &slot, b"/"),
        admitted("X-Native: first\r\nX-Native: second\r\n")
    );
    // The first fails open, the second fails closed: the chain denies by the second.
    assert_eq!(decide(&mut local, &slot, b"/fail"), refused(Verdict::Deny, "second"));
    assert_eq!(decide(&mut local, &slot, b"/deny"), refused(Verdict::Deny, "first"));
}

#[test]
fn the_connection_stage_and_the_telemetry_stage_reach_a_native_hook() {
    let slot = published(&attach_all(vec![native("n", OnFailure::Deny)]));
    let mut local = Local::new();
    let flow = View { stage: Stage::Connection, protocol: Protocol::Tcp, ..request(b"", &[]) };
    assert_eq!(local.run(&slot, &flow).verdict, Verdict::Admit);
    let blocked = View { client: "127.0.0.1:9".parse().unwrap(), ..flow };
    assert_eq!(local.run(&slot, &blocked).verdict, Verdict::Deny);
    let sample = View { stage: Stage::Telemetry, status: 200, ..request(b"/deny", &[]) };
    assert_eq!(local.run(&slot, &sample), Decision::ADMIT);
}

#[test]
fn a_cleared_challenge_lets_the_chain_go_on_to_the_hooks_behind_it() {
    let chain = vec![native("first", OnFailure::Deny), native("second", OnFailure::Deny)];
    let slot = published(&attach_all(chain));
    let mut local = Local::new();
    let mut asked = Vec::new();
    let mut clears = |name: &str| {
        asked.push(name.to_owned());
        name == "first"
    };
    // The first hook challenges and is cleared. The second still judges, and challenges.
    let decision = local.run_clearing(&slot, &request(b"/challenge", &[]), &mut clears);
    assert_eq!((decision.verdict, decision.hook), (Verdict::Challenge, "second"));
    assert_eq!(asked, ["first", "second"]);
    // With both cleared the request is admitted, and a challenging hook added no field.
    let decision = local.run_clearing(&slot, &request(b"/challenge", &[]), &mut |_| true);
    assert_eq!((decision.verdict, decision.added), (Verdict::Admit, &b""[..]));
    // A denial is never offered for clearing.
    let mut never = |_: &str| panic!("a denial must not be cleared");
    let decision = local.run_clearing(&slot, &request(b"/deny", &[]), &mut never);
    assert_eq!(decision.verdict, Verdict::Deny);
}

// ---- the Wasm tier: the example hook ----

#[test]
fn the_example_hook_admits_denies_and_challenges() {
    let slot = published(&attach_all(vec![wasm("example", EXAMPLE, OnFailure::Deny)]));
    let mut local = Local::new();
    assert_eq!(decide(&mut local, &slot, b"/"), admitted("X-Hook: example\r\n"));
    assert_eq!(decide(&mut local, &slot, b"/admin/users"), refused(Verdict::Deny, "example"));
    assert_eq!(decide(&mut local, &slot, b"/guarded"), refused(Verdict::Challenge, "example"));
    let role = [Field { name: b"X-Role", value: b"admin" }];
    let decision = local.run(&slot, &request(b"/admin/users", &role));
    assert_eq!((decision.verdict, decision.added), (Verdict::Admit, &b"X-Hook: example\r\n"[..]));
}

#[test]
fn the_example_hook_judges_connections_and_counts_samples() {
    let slot = published(&attach_all(vec![wasm("example", EXAMPLE, OnFailure::Deny)]));
    let mut local = Local::new();
    let flow = View { stage: Stage::Connection, protocol: Protocol::Tcp, ..request(b"", &[]) };
    assert_eq!(local.run(&slot, &flow).verdict, Verdict::Admit);
    let blocked = View { client: "127.0.0.2:5000".parse().unwrap(), ..flow };
    assert_eq!(local.run(&slot, &blocked), refused_decision(Verdict::Deny, "example"));
    let sample = View { stage: Stage::Telemetry, status: 200, ..request(b"/admin", &[]) };
    for _ in 0..3 {
        assert_eq!(local.run(&slot, &sample), Decision::ADMIT);
    }
    let status = &slot.load().status()[0];
    assert_eq!((status.tier, status.calls, status.dropped), ("wasm", 5, 0));
}

fn refused_decision(verdict: Verdict, hook: &'static str) -> Decision<'static> {
    Decision { verdict, hook, added: b"" }
}

// ---- the Wasm tier: failures ----

/// The verdict of the request chain of one plugin built from `bytes`, on `path`.
fn wasm_outcome(bytes: &[u8], on_failure: OnFailure, path: &[u8]) -> (Verdict, [u64; 4]) {
    let slot = published(&attach_all(vec![wasm("w", bytes, on_failure)]));
    let verdict = Local::new().run(&slot, &request(path, &[])).verdict;
    (verdict, slot.load().status()[0].failures)
}

#[test]
fn a_wasm_hook_that_spins_times_out_with_its_configured_outcome() {
    let spin = spinning_hook();
    assert_eq!(wasm_outcome(&spin, OnFailure::Deny, b"/"), (Verdict::Deny, [1, 0, 0, 0]));
    assert_eq!(wasm_outcome(&spin, OnFailure::Admit, b"/"), (Verdict::Admit, [1, 0, 0, 0]));
}

#[test]
fn a_wasm_hook_that_traps_fails_with_its_configured_outcome() {
    let trap = trapping_hook();
    assert_eq!(wasm_outcome(&trap, OnFailure::Deny, b"/"), (Verdict::Deny, [0, 0, 1, 0]));
    assert_eq!(wasm_outcome(&trap, OnFailure::Admit, b"/"), (Verdict::Admit, [0, 0, 1, 0]));
    // A return value outside the ABI is a trap too.
    assert_eq!(
        wasm_outcome(&constant_hook(7), OnFailure::Deny, b"/"),
        (Verdict::Deny, [0, 0, 1, 0])
    );
}

#[test]
fn a_view_larger_than_the_input_buffer_overflows_and_is_never_cut() {
    // The buffer of the test hooks holds 4,096 bytes. This hook admits what it sees.
    let admit = constant_hook(0);
    let long = vec![b'a'; 5000];
    assert_eq!(wasm_outcome(&admit, OnFailure::Deny, b"/"), (Verdict::Admit, [0; 4]));
    assert_eq!(wasm_outcome(&admit, OnFailure::Deny, &long), (Verdict::Deny, [0, 1, 0, 0]));
    assert_eq!(wasm_outcome(&admit, OnFailure::Admit, &long), (Verdict::Admit, [0, 1, 0, 0]));
}

#[test]
fn host_calls_beyond_the_bound_trap() {
    // Twenty calls of now_ms against the default bound of sixteen.
    let calls: Vec<u8> = (0..20).flat_map(|_| [0x10, 1, 0x1a]).collect();
    let bytes = hook(&[calls, i32c(0)].concat()).build();
    assert_eq!(wasm_outcome(&bytes, OnFailure::Deny, b"/"), (Verdict::Deny, [0, 0, 1, 0]));
    let calls: Vec<u8> = (0..16).flat_map(|_| [0x10, 1, 0x1a]).collect();
    let bytes = hook(&[calls, i32c(0)].concat()).build();
    assert_eq!(wasm_outcome(&bytes, OnFailure::Deny, b"/"), (Verdict::Admit, [0; 4]));
}

#[test]
fn a_hook_that_grows_its_memory_without_end_is_stopped_by_pages_and_fuel() {
    // loop: memory.grow 1; drop; br 0. Growth answers -1 at the budget, the loop goes on.
    let code = [vec![0x03, 0x40], i32c(1), vec![0x40, 0, 0x1a, 0x0c, 0, 0x0b], i32c(0)].concat();
    let bytes = hook(&code).build();
    assert_eq!(wasm_outcome(&bytes, OnFailure::Deny, b"/"), (Verdict::Deny, [1, 0, 0, 0]));
}

#[test]
fn a_field_that_a_hook_may_not_add_is_refused_and_counted() {
    // add_header("Host: evil"), then add_header("X-Ok: 1"), then admit.
    let add = |at: i32, length: i32| [i32c(at), i32c(length), vec![0x10, 0, 0x1a]].concat();
    let mut builder = hook(&[add(100, 10), add(120, 7), i32c(0)].concat());
    builder.data = vec![(100, b"Host: evil".to_vec()), (120, b"X-Ok: 1".to_vec())];
    let slot = published(&attach_all(vec![wasm("w", &builder.build(), OnFailure::Deny)]));
    let mut local = Local::new();
    assert_eq!(decide(&mut local, &slot, b"/"), admitted("X-Ok: 1\r\n"));
    assert_eq!(slot.load().status()[0].refused_fields, 1);
    // Outside the request stage the host function refuses, and nothing is added.
    let flow = View { stage: Stage::Connection, ..request(b"", &[]) };
    assert_eq!(local.run(&slot, &flow), Decision::ADMIT);
}

#[test]
fn an_instance_keeps_its_state_until_a_failure_resets_it() {
    // global 0 counts the calls. A view above 200 bytes traps. The first call of an
    // image admits, every later one denies.
    let code = [
        vec![0x23, 0],
        i32c(1),
        vec![0x6a, 0x24, 0, 0x20, 0],
        i32c(200),
        vec![0x4b, 0x04, 0x40, 0x00, 0x0b, 0x23, 0],
        i32c(1),
        vec![0x47],
    ]
    .concat();
    let mut builder = hook(&code);
    builder.globals = vec![(I32, true, i32c(0))];
    let slot = published(&attach_all(vec![wasm("w", &builder.build(), OnFailure::Deny)]));
    let mut local = Local::new();
    let long = vec![b'a'; 300];
    assert_eq!(decide(&mut local, &slot, b"/").0, Verdict::Admit);
    assert_eq!(decide(&mut local, &slot, b"/").0, Verdict::Deny);
    assert_eq!(decide(&mut local, &slot, &long).0, Verdict::Deny);
    assert_eq!(slot.load().status()[0].failures, [0, 0, 1, 0]);
    // The trap reset the instance: the count starts again.
    assert_eq!(decide(&mut local, &slot, b"/").0, Verdict::Admit);
}

// ---- loading ----

fn load_error(spec: Spec) -> Error {
    Plan::load(&attach_all(vec![spec]), &NATIVES).expect_err("the plan must not load")
}

#[test]
fn a_module_that_imports_wasi_does_not_load() {
    let mut builder = hook(&i32c(0));
    builder.imports[1] = ("wasi_snapshot_preview1", "fd_write", vec![], Some(support::I64));
    let error = load_error(wasm("w", &builder.build(), OnFailure::Deny));
    assert_eq!(error.code, "HOOK005");
    assert!(error.message.contains("wasi_snapshot_preview1.fd_write"), "{error}");
    // A host function under its right name and a wrong type is refused as well.
    let mut builder = hook(&i32c(0));
    builder.imports[1] = ("sibuna", "now_ms", vec![I32], Some(support::I64));
    assert_eq!(load_error(wasm("w", &builder.build(), OnFailure::Deny)).code, "HOOK005");
}

#[test]
fn a_module_outside_the_abi_does_not_load() {
    let mut no_request = hook(&i32c(0));
    no_request.exports.retain(|(name, _)| *name != "sibuna_on_request");
    let error = load_error(wasm("w", &no_request.build(), OnFailure::Deny));
    assert_eq!(error.code, "HOOK006");
    assert!(error.message.contains("sibuna_on_request"), "{error}");

    let mut version_two = hook(&i32c(0));
    version_two.funcs[0].code = i32c(2);
    let error = load_error(wasm("w", &version_two.build(), OnFailure::Deny));
    assert!(error.code == "HOOK006" && error.message.contains("returned 2"), "{error}");

    let mut outside = hook(&i32c(0));
    outside.funcs[1].code = i32c(65_000);
    assert_eq!(load_error(wasm("w", &outside.build(), OnFailure::Deny)).code, "HOOK006");

    let mut spinning_abi = hook(&i32c(0));
    spinning_abi.funcs[0].code = [vec![0x03, 0x40, 0x0c, 0, 0x0b], i32c(1)].concat();
    let error = load_error(wasm("w", &spinning_abi.build(), OnFailure::Deny));
    assert!(error.code == "HOOK006" && error.message.contains("Fuel"), "{error}");
}

#[test]
fn a_module_above_its_page_budget_or_malformed_or_missing_does_not_load() {
    let mut large = hook(&i32c(0));
    large.memory = Some((5, None));
    let error = load_error(wasm("w", &large.build(), OnFailure::Deny));
    assert!(error.code == "HOOK004" && error.message.contains("memory_pages"), "{error}");

    assert_eq!(load_error(wasm("w", b"not a module", OnFailure::Deny)).code, "HOOK004");

    let mut missing = wasm("w", b"", OnFailure::Deny);
    missing.kind =
        Kind::Wasm(WasmSpec { module: "/nonexistent/hook.wasm".into(), ..WasmSpec::default() });
    let error = load_error(missing);
    assert!(error.code == "HOOK003" && error.to_string().contains("Hint:"), "{error}");
}

#[test]
fn settings_out_of_range_and_unknown_names_do_not_load() {
    let mut spec = wasm("w", EXAMPLE, OnFailure::Deny);
    if let Kind::Wasm(wasm) = &mut spec.kind {
        wasm.fuel_limit = 10;
    }
    assert_eq!(load_error(spec).code, "HOOK002");

    let mut settings = attach_all(vec![native("n", OnFailure::Deny)]);
    settings.frontends[0].1.request.push("ghost".to_owned());
    let error = Plan::load(&settings, &NATIVES).unwrap_err();
    assert!(error.code == "HOOK001" && error.message.contains("ghost"), "{error}");

    let mut unknown = native("n", OnFailure::Deny);
    unknown.kind = Kind::Native { hook: "nothing".into(), settings: Vec::new() };
    let error = load_error(unknown);
    assert!(error.code == "HOOK007" && error.message.contains("by_path"), "{error}");

    let mut wrong = native("n", OnFailure::Deny);
    wrong.kind = Kind::Native { hook: "by_path".into(), settings: Vec::new() };
    assert_eq!(load_error(wrong).code, "HOOK008");

    let twice = vec![native("n", OnFailure::Deny), native("n", OnFailure::Deny)];
    assert_eq!(Plan::load(&attach_all(twice), &NATIVES).unwrap_err().code, "HOOK002");
}

// ---- reload and threads ----

#[test]
fn a_thread_takes_a_new_plan_at_its_next_run_and_the_counters_go_on() {
    let slot = published(&attach_all(vec![wasm("w", &constant_hook(0), OnFailure::Deny)]));
    let mut local = Local::new();
    assert_eq!(decide(&mut local, &slot, b"/").0, Verdict::Admit);
    // The same name with a module that denies.
    let next = attach_all(vec![wasm("w", &constant_hook(1), OnFailure::Deny)]);
    slot.publish(Plan::load(&next, &NATIVES).unwrap());
    assert_eq!(decide(&mut local, &slot, b"/").0, Verdict::Deny);
    let status = &slot.load().status()[0];
    assert_eq!((status.calls, status.admitted, status.denied), (2, 1, 1));
    // A plan without hooks: the word that traffic reads is zero again.
    slot.publish(Plan::default());
    assert!(!slot.has(Stage::Request));
    assert_eq!(decide(&mut local, &slot, b"/").0, Verdict::Admit);
}

#[test]
fn a_plan_that_fails_to_load_leaves_the_published_one() {
    let slot = published(&attach_all(vec![native("n", OnFailure::Deny)]));
    let broken = attach_all(vec![wasm("w", b"garbage", OnFailure::Deny)]);
    assert!(Plan::load(&broken, &NATIVES).is_err());
    assert_eq!(decide(&mut Local::new(), &slot, b"/deny"), refused(Verdict::Deny, "n"));
}

#[test]
fn every_thread_owns_its_instances() {
    let slot = published(&attach_all(vec![
        wasm("example", EXAMPLE, OnFailure::Deny),
        native("n", OnFailure::Deny),
    ]));
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                let mut local = Local::new();
                for round in 0..500 {
                    let path: &[u8] = if round % 2 == 0 { b"/" } else { b"/admin" };
                    let expected = if round % 2 == 0 { Verdict::Admit } else { Verdict::Deny };
                    assert_eq!(local.run(&slot, &request(path, &[])).verdict, expected);
                }
            });
        }
    });
    let status = slot.load().status();
    assert_eq!((status[0].calls, status[0].denied), (4000, 2000));
    assert_eq!(status[1].calls, 2000);
}

// ---- conformance: the project's own proof-of-work solver ----

struct NoHost;

impl Host for NoHost {
    fn call(&mut self, _: u32, _: &[u64], _: &mut [u8]) -> Result<u64, Trap> {
        Err(Trap::Host)
    }
}

/// Runs the export `name` of the solver with `args` and enough fuel.
fn solver_call(instance: &mut Instance, name: &str, args: &[u64]) -> u64 {
    let func = instance.module().exported_func(name).expect("the solver exports it");
    let mut budget = Budget { fuel: 2_000_000_000, host_calls: 0 };
    instance.call(func, args, &mut budget, &mut NoHost).expect("the solver runs").unwrap_or(0)
}

#[test]
fn the_interpreter_runs_the_compiled_solver_to_the_native_result() {
    // `sibuna-pow-wasm` built by rustc: SHA-256 and the sequential-work prover.
    let module = Module::load(include_bytes!("data/pow_solver.wasm")).expect("the solver loads");
    let mut instance = Instance::new(Arc::new(module), 32).expect("the solver instantiates");
    let buffer = solver_call(&mut instance, "sibuna_get_buffer_ptr", &[]) as usize;
    for challenge in [
        &b"sibuna"[..],
        b"",
        b"a longer challenge that crosses one SHA-256 block boundary, 64 bytes",
    ] {
        instance.memory_mut()[buffer..buffer + challenge.len()].copy_from_slice(challenge);
        let length = challenge.len() as u64;
        let found = solver_call(
            &mut instance,
            "sibuna_solve_step",
            &[buffer as u64, length, 10, 0, 50_000],
        );
        let native = sibuna_pow::hashcash::solve_bits(challenge, 10, 50_000);
        assert_eq!(Some(found), native, "challenge {challenge:?}");
        assert!(sibuna_pow::hashcash::verify_bits(challenge, found, 10));
    }
    // The prover writes a proof that the native verifier accepts.
    let challenge = b"sequential work";
    instance.memory_mut()[buffer..buffer + challenge.len()].copy_from_slice(challenge);
    let length = solver_call(&mut instance, "sibuna_posw_solve", &[challenge.len() as u64, 8, 4]);
    let proof = solver_call(&mut instance, "sibuna_posw_proof_ptr", &[]) as usize;
    let proof = &instance.memory()[proof..proof + length as usize];
    let params = sibuna_pow::posw::Params { depth: 8, challenges: 4 };
    assert!(length > 0 && sibuna_pow::posw::verify(challenge, params, proof));
}
