//! The interpreter on modules assembled by hand: its semantics, its bounds, and what it
//! does with hostile and malformed input (SID 0030, acceptance rows 4 to 6).

#![allow(clippy::unwrap_used)]

mod support;

use std::sync::Arc;

use sibuna_plugin::wasm::{Budget, Host, Instance, LoadError, Module, PAGE, Trap};
use support::{Builder, I32, I64, i32c, i64c, u};

struct NoHost;

impl Host for NoHost {
    fn call(&mut self, _: u32, _: &[u64], _: &mut [u8]) -> Result<u64, Trap> {
        Err(Trap::Host)
    }
}

/// A host whose one function returns the sum of its arguments.
struct Adder(u32);

impl Host for Adder {
    fn call(&mut self, _: u32, args: &[u64], _: &mut [u8]) -> Result<u64, Trap> {
        self.0 += 1;
        Ok(args.iter().sum())
    }
}

fn instance(builder: &Builder, pages: u32) -> Instance {
    let module = Module::load(&builder.build()).expect("the module loads");
    Instance::new(Arc::new(module), pages).expect("the module instantiates")
}

/// Calls the export `name` with `args` under `fuel`.
fn call(
    instance: &mut Instance,
    name: &str,
    args: &[u64],
    fuel: u64,
) -> Result<Option<u64>, Trap> {
    let func = instance.module().exported_func(name).expect("the export exists");
    let mut budget = Budget { fuel, host_calls: 8 };
    instance.call(func, args, &mut budget, &mut NoHost)
}

fn run(builder: &Builder, name: &str, args: &[u64]) -> Result<Option<u64>, Trap> {
    call(&mut instance(builder, 4), name, args, 1_000_000)
}

#[test]
fn a_loop_with_a_conditional_branch_sums_the_numbers_below_n() {
    // local 1 = sum. loop: sum += n; n -= 1; br_if 0 while n != 0.
    let code = [
        vec![0x03, 0x40],
        vec![0x20, 1, 0x20, 0, 0x6a, 0x21, 1],
        vec![0x20, 0],
        i32c(1),
        vec![0x6b, 0x22, 0, 0x0d, 0, 0x0b],
        vec![0x20, 1],
    ]
    .concat();
    let mut builder = Builder::default();
    let index = builder.func(&[I32], Some(I32), &[I32], code);
    builder.exports.push(("sum", index));
    assert_eq!(run(&builder, "sum", &[100]), Ok(Some(5050)));
}

#[test]
fn recursion_computes_a_factorial_in_64_bits() {
    // if n == 0 then 1 else n * fact(n - 1)
    let code = [
        vec![0x20, 0, 0x50, 0x04, I64],
        i64c(1),
        vec![0x05, 0x20, 0, 0x20, 0],
        i64c(1),
        vec![0x7d, 0x10, 0, 0x7e, 0x0b],
    ]
    .concat();
    let mut builder = Builder::default();
    builder.export("fact", &[I64], Some(I64), code);
    assert_eq!(run(&builder, "fact", &[20]), Ok(Some(2_432_902_008_176_640_000)));
}

#[test]
fn a_branch_out_of_nested_blocks_keeps_the_result_and_drops_the_rest() {
    // block (result i32): push 7, 8, 9; br 0 keeps 9 and drops 7 and 8.
    let code = [vec![0x02, I32], i32c(7), i32c(8), i32c(9), vec![0x0c, 0, 0x0b]].concat();
    let mut builder = Builder::default();
    builder.export("f", &[], Some(I32), code);
    assert_eq!(run(&builder, "f", &[]), Ok(Some(9)));
}

#[test]
fn a_branch_table_selects_by_index_and_falls_back_to_its_default() {
    // Three nested blocks. br_table [0, 1] default 2 on the argument.
    let code = [
        vec![0x02, 0x40, 0x02, 0x40, 0x02, 0x40, 0x20, 0, 0x0e, 2, 0, 1, 2, 0x0b],
        i32c(10),
        vec![0x0f, 0x0b],
        i32c(20),
        vec![0x0f, 0x0b],
        i32c(30),
    ]
    .concat();
    let mut builder = Builder::default();
    builder.export("pick", &[I32], Some(I32), code);
    assert_eq!(run(&builder, "pick", &[0]), Ok(Some(10)));
    assert_eq!(run(&builder, "pick", &[1]), Ok(Some(20)));
    assert_eq!(run(&builder, "pick", &[2]), Ok(Some(30)));
    assert_eq!(run(&builder, "pick", &[u64::from(u32::MAX)]), Ok(Some(30)));
}

#[test]
fn memory_reads_back_what_was_stored_with_the_sign_asked_for() {
    // store8 0xff at 10; load8_s gives -1, load8_u gives 255; their sum is 254.
    let code = [
        i32c(10),
        i32c(0xff),
        vec![0x3a, 0, 0],
        i32c(10),
        vec![0x2c, 0, 0],
        i32c(10),
        vec![0x2d, 0, 0, 0x6a],
    ]
    .concat();
    let mut builder = Builder { memory: Some((1, None)), ..Builder::default() };
    builder.export("f", &[], Some(I32), code);
    assert_eq!(run(&builder, "f", &[]), Ok(Some(254)));
}

#[test]
fn a_data_segment_and_a_global_are_part_of_the_initial_image() {
    // Read the i32 at 16, add the global, store the sum in the global, return it.
    let code = [i32c(16), vec![0x28, 2, 0, 0x23, 0, 0x6a, 0x24, 0, 0x23, 0]].concat();
    let mut builder = Builder {
        memory: Some((1, None)),
        globals: vec![(I32, true, i32c(5))],
        data: vec![(16, 37u32.to_le_bytes().to_vec())],
        ..Builder::default()
    };
    builder.export("f", &[], Some(I32), code);
    let mut instance = instance(&builder, 1);
    assert_eq!(call(&mut instance, "f", &[], 100), Ok(Some(42)));
    // The global kept its value: state lasts from one call to the next.
    assert_eq!(call(&mut instance, "f", &[], 100), Ok(Some(79)));
    instance.reset();
    assert_eq!(call(&mut instance, "f", &[], 100), Ok(Some(42)));
}

#[test]
fn an_indirect_call_checks_the_entry_and_its_type() {
    let mut builder = Builder::default();
    let seven = builder.func(&[], Some(I32), &[], i32c(7));
    let wide = builder.func(&[], Some(I64), &[], i64c(8));
    builder.table = vec![seven, wide];
    // call_indirect with the type of `seven` (type 0) through the entry of the argument.
    builder.export("via", &[I32], Some(I32), vec![0x20, 0, 0x11, 0, 0]);
    assert_eq!(run(&builder, "via", &[0]), Ok(Some(7)));
    assert_eq!(run(&builder, "via", &[1]), Err(Trap::SignatureMismatch));
    assert_eq!(run(&builder, "via", &[2]), Err(Trap::UndefinedElement));
}

#[test]
fn a_host_function_receives_its_arguments_and_is_counted() {
    let mut builder =
        Builder { imports: vec![("env", "add", vec![I32, I32], Some(I32))], ..Builder::default() };
    let code = [i32c(40), i32c(2), vec![0x10, 0], i32c(1), i32c(1), vec![0x10, 0, 0x6a]].concat();
    builder.export("f", &[], Some(I32), code);
    let mut instance = instance(&builder, 1);
    let func = instance.module().exported_func("f").unwrap();
    let mut host = Adder(0);
    let mut budget = Budget { fuel: 100, host_calls: 2 };
    assert_eq!(instance.call(func, &[], &mut budget, &mut host), Ok(Some(44)));
    assert_eq!((host.0, budget.host_calls), (2, 0));
    // One host call fewer than the module makes: the second is refused.
    let mut budget = Budget { fuel: 100, host_calls: 1 };
    assert_eq!(instance.call(func, &[], &mut budget, &mut host), Err(Trap::HostCallLimit));
}

#[test]
fn traps_are_error_values() {
    let mut builder = Builder { memory: Some((1, None)), ..Builder::default() };
    builder.export("unreachable", &[], None, vec![0x00]);
    builder.export("divide", &[I32], Some(I32), [i32c(1), vec![0x20, 0, 0x6d]].concat());
    builder.export("load", &[I32], Some(I32), vec![0x20, 0, 0x28, 2, 0]);
    assert_eq!(run(&builder, "unreachable", &[]), Err(Trap::Unreachable));
    assert_eq!(run(&builder, "divide", &[0]), Err(Trap::DivideByZero));
    assert_eq!(run(&builder, "load", &[PAGE as u64 - 4]), Ok(Some(0)));
    assert_eq!(run(&builder, "load", &[PAGE as u64 - 3]), Err(Trap::MemoryBounds));
    assert_eq!(run(&builder, "load", &[u64::from(u32::MAX)]), Err(Trap::MemoryBounds));
}

// ---- hostile modules ----

#[test]
fn an_infinite_loop_stops_when_its_fuel_is_spent() {
    let mut builder = Builder::default();
    builder.export("spin", &[], None, vec![0x03, 0x40, 0x0c, 0, 0x0b]);
    let mut instance = instance(&builder, 1);
    let func = instance.module().exported_func("spin").unwrap();
    let mut budget = Budget { fuel: 10_000, host_calls: 0 };
    assert_eq!(instance.call(func, &[], &mut budget, &mut NoHost), Err(Trap::Fuel));
    assert_eq!(budget.fuel, 0);
    // The same module on the same budget stops at the same place: fuel is a count.
    let mut again = Budget { fuel: 10_000, host_calls: 0 };
    assert_eq!(instance.call(func, &[], &mut again, &mut NoHost), Err(Trap::Fuel));
}

#[test]
fn unbounded_recursion_stops_at_the_frame_limit() {
    let mut builder = Builder::default();
    builder.export("dive", &[], None, vec![0x10, 0]);
    assert_eq!(run(&builder, "dive", &[]), Err(Trap::CallDepth));
    // A recursion that also grows the operand stack meets one of the two limits.
    let mut builder = Builder::default();
    builder.export("dive", &[I64], Some(I64), [vec![0x20, 0, 0x20, 0, 0x10, 0, 0x7c]].concat());
    let stopped = run(&builder, "dive", &[1]);
    assert!(matches!(stopped, Err(Trap::CallDepth | Trap::StackLimit)), "{stopped:?}");
}

#[test]
fn memory_growth_stops_at_the_page_budget() {
    // loop: grow by one page; continue while the answer is not -1. Then memory.size.
    let code =
        [vec![0x03, 0x40], i32c(1), vec![0x40, 0], i32c(-1), vec![0x47, 0x0d, 0, 0x0b, 0x3f, 0]]
            .concat();
    let mut builder = Builder { memory: Some((1, None)), ..Builder::default() };
    builder.export("grow", &[], Some(I32), code);
    let mut instance = instance(&builder, 3);
    assert_eq!(call(&mut instance, "grow", &[], 1_000_000), Ok(Some(3)));
    assert_eq!(instance.memory().len(), 3 * PAGE);
    // One huge request is refused whole, and nothing is allocated for it.
    let code = [i32c(65_535), vec![0x40, 0]].concat();
    let mut builder = Builder { memory: Some((1, None)), ..Builder::default() };
    builder.export("grow", &[], Some(I32), code);
    let mut instance = self::instance(&builder, 256);
    assert_eq!(call(&mut instance, "grow", &[], 1_000_000), Ok(Some(u64::from(u32::MAX))));
    assert_eq!(instance.memory().len(), PAGE);
}

#[test]
fn growth_and_bulk_operations_cost_fuel_in_proportion() {
    // Growing by 200 pages costs 200 * 1024 units: a budget of 1,000 does not buy it.
    let code = [i32c(200), vec![0x40, 0]].concat();
    let mut builder = Builder { memory: Some((1, None)), ..Builder::default() };
    builder.export("grow", &[], Some(I32), code);
    let mut instance = instance(&builder, 256);
    assert_eq!(call(&mut instance, "grow", &[], 1_000), Err(Trap::Fuel));
    assert_eq!(instance.memory().len(), PAGE);
    // memory.fill of a whole page costs 4,096 units beside the five operations of the function.
    let code = [i32c(0), i32c(0xaa), i32c(PAGE as i32), vec![0xfc, 11, 0]].concat();
    let mut builder = Builder { memory: Some((1, None)), ..Builder::default() };
    builder.export("fill", &[], None, code);
    let mut instance = self::instance(&builder, 1);
    assert_eq!(call(&mut instance, "fill", &[], 4_000), Err(Trap::Fuel));
    assert_eq!(call(&mut instance, "fill", &[], 4_101), Ok(None));
    assert!(instance.memory().iter().all(|&byte| byte == 0xaa));
}

#[test]
fn a_module_that_starts_above_the_page_budget_does_not_instantiate() {
    let builder = Builder { memory: Some((5, None)), ..Builder::default() };
    let module = Arc::new(Module::load(&builder.build()).unwrap());
    assert!(matches!(Instance::new(module, 4), Err(LoadError::Limit(_))));
}

// ---- validation ----

fn rejects(code: Vec<u8>, result: Option<u8>) -> LoadError {
    let mut builder = Builder { memory: Some((1, None)), ..Builder::default() };
    builder.export("f", &[], result, code);
    Module::load(&builder.build()).expect_err("the module must not validate")
}

#[test]
fn code_that_does_not_type_check_does_not_load() {
    // An i64 where an i32 is expected.
    assert!(matches!(
        rejects([i64c(1), i32c(1), vec![0x6a]].concat(), Some(I32)),
        LoadError::Malformed(_)
    ));
    // An operand that is not there.
    assert!(matches!(rejects(vec![0x6a], Some(I32)), LoadError::Malformed(_)));
    // A result that is not there, and a result too many.
    assert!(matches!(rejects(vec![], Some(I32)), LoadError::Malformed(_)));
    assert!(matches!(rejects(i32c(1), None), LoadError::Malformed(_)));
    // A branch to a label that does not exist.
    assert!(matches!(rejects(vec![0x0c, 5], None), LoadError::Malformed(_)));
    // A local, a global and a function that do not exist.
    assert!(matches!(rejects(vec![0x20, 9, 0x1a], None), LoadError::Malformed(_)));
    assert!(matches!(rejects(vec![0x23, 0, 0x1a], None), LoadError::Malformed(_)));
    assert!(matches!(rejects(vec![0x10, 99], None), LoadError::Malformed(_)));
    // An `if` with a result and no `else`.
    assert!(matches!(
        rejects([i32c(1), vec![0x04, I32], i32c(1), vec![0x0b]].concat(), Some(I32)),
        LoadError::Malformed(_)
    ));
    // An alignment above the width of the access.
    assert!(matches!(
        rejects([i32c(0), vec![0x28, 3, 0, 0x1a]].concat(), None),
        LoadError::Malformed(_)
    ));
}

#[test]
fn code_after_an_unconditional_branch_may_have_any_type() {
    // return; then an addition without operands, which the specification allows.
    let code = [i32c(1), vec![0x0f, 0x6a]].concat();
    let mut builder = Builder::default();
    builder.export("f", &[], Some(I32), code);
    assert_eq!(run(&builder, "f", &[]), Ok(Some(1)));
}

#[test]
fn what_the_interpreter_does_not_run_is_refused_by_name() {
    // A SIMD prefix, and a block with a type index.
    assert!(matches!(rejects(vec![0xfd, 0x0c], None), LoadError::Unsupported(_)));
    assert!(matches!(rejects(vec![0x02, 0x00, 0x0b], None), LoadError::Unsupported(_)));
    // An imported memory.
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    bytes.extend([2, 10, 1, 3, b'e', b'n', b'v', 1, b'm', 2, 0, 1]);
    assert!(matches!(Module::load(&bytes), Err(LoadError::Import(name)) if name == "env.m"));
}

// ---- malformed binaries ----

const EXAMPLE: &[u8] = include_bytes!("data/example_hook.wasm");

#[test]
fn every_prefix_of_a_real_module_is_judged_without_a_panic() {
    assert!(Module::load(EXAMPLE).is_ok());
    // A prefix that ends between two sections is a smaller module, and it may load
    // while it declares no function. Every other prefix is refused.
    let loaded = (0..EXAMPLE.len()).filter(|&length| Module::load(&EXAMPLE[..length]).is_ok());
    let loaded: Vec<usize> = loaded.collect();
    assert!(loaded.contains(&8), "the bare header is the empty module");
    assert!(loaded.len() <= 8, "{loaded:?}");
    assert!((0..8).all(|length| Module::load(&EXAMPLE[..length]).is_err()));
}

/// A small deterministic generator, so that the test needs no crate and repeats.
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn mutated_modules_load_or_fail_and_run_within_their_budget() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let (mut loaded, mut refused) = (0u32, 0u32);
    for _ in 0..20_000 {
        let mut bytes = EXAMPLE.to_vec();
        for _ in 0..=(next(&mut state) % 3) {
            let at = (next(&mut state) % bytes.len() as u64) as usize;
            bytes[at] = next(&mut state) as u8;
        }
        let Ok(module) = Module::load(&bytes) else {
            refused += 1;
            continue;
        };
        loaded += 1;
        let module = Arc::new(module);
        let Ok(mut instance) = Instance::new(Arc::clone(&module), 4) else { continue };
        // Whatever the mutation did to the code, every export ends within its fuel.
        for name in ["sibuna_abi", "sibuna_input", "sibuna_on_request", "sibuna_on_connection"] {
            let Some(func) = module.exported_func(name) else { continue };
            let count = module.func_type(func).map_or(0, |ty| ty.params.len());
            let mut budget = Budget { fuel: 5_000, host_calls: 4 };
            let _ = instance.call(func, &vec![64; count], &mut budget, &mut NoHost);
            assert!(budget.fuel <= 5_000);
            assert!(instance.memory().len() <= 4 * PAGE);
        }
    }
    assert!(loaded > 100 && refused > 100, "loaded {loaded}, refused {refused}");
}

#[test]
fn counts_beyond_the_bounds_are_refused_before_anything_is_allocated() {
    let header = b"\0asm\x01\0\0\0".to_vec();
    // A type section that claims four billion types.
    let types = [header.clone(), vec![1, 5], u(u64::from(u32::MAX))].concat();
    assert!(matches!(Module::load(&types), Err(LoadError::Limit(_))));
    // A function with four billion locals.
    let body = [u(1), u(u64::from(u32::MAX)), vec![I32, 0x0b]].concat();
    let code = [u(1), u(body.len() as u64), body].concat();
    let module = [
        header.clone(),
        vec![1, 4, 1, 0x60, 0, 0],
        vec![3, 2, 1, 0],
        vec![10],
        u(code.len() as u64),
        code,
    ]
    .concat();
    assert!(matches!(Module::load(&module), Err(LoadError::Limit(_))));
    // A table of four billion entries.
    let table = [header.clone(), vec![4, 8, 1, 0x70, 0], u(u64::from(u32::MAX))].concat();
    assert!(matches!(Module::load(&table), Err(LoadError::Limit(_))));
    // Not a module at all.
    assert!(matches!(Module::load(b"\x7fELF\x02\x01\x01\0"), Err(LoadError::Malformed(_))));
    assert!(matches!(Module::load(&vec![0; (4 << 20) + 1]), Err(LoadError::Limit(_))));
}
