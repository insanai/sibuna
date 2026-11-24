//! Evaluate a single JLV/2 edge module on the control plane.

mod document;

use std::io;
use std::sync::Arc;

use jlv_compiler::{Closure, Entry, KeyedTypes, Request, Role};
use jlv_core::{Diagnostic, Limits};
use jlv_lang::Type;
use jlv_lang::native::Context;
use jlv_lang::signature::Registry;
use jlv_stdlib::{Natives, foundation};
use sibuna_lb::Config;

const MODULE: &str = "//:edge.jlv";

/// Compiles and evaluates `fn edge() -> Map<Value>` and validates its output as an edge topology.
/// Compilation and evaluation share a dedicated stack. Only the pure foundation library is loaded.
pub fn parse(path: &str, bytes: &[u8]) -> io::Result<Config> {
    if bytes.len() > Config::DOCUMENT_LIMITS.max_input_bytes {
        return Err(invalid("JLV source exceeds the edge file size limit"));
    }
    let source = std::str::from_utf8(bytes).map_err(invalid)?;
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("sibuna-jlv".into())
            .stack_size(8 << 20)
            .spawn_scoped(scope, || evaluate(path, source))?
            .join()
            .map_err(|_| io::Error::other("JLV evaluator panicked"))?
    })
}

fn invalid(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

fn diagnostic(path: &str, source: &str, error: Diagnostic) -> io::Error {
    let problem = error.problem;
    let start = error.span.and_then(|span| source.get(..span.range().start)).unwrap_or("");
    let line = start.bytes().filter(|&byte| byte == b'\n').count() + 1;
    let column = start.rsplit('\n').next().unwrap_or("").chars().count() + 1;
    invalid(format!("{path}:{line}:{column}: {}: {}", problem.code, problem.message))
}

fn evaluate(path: &str, source: &str) -> io::Result<Config> {
    let mut closure = Closure::default();
    closure.add(MODULE, path, source);
    let mut natives = Natives::new();
    let mut registry = Registry::new();
    registry.add(foundation::library(&mut natives)).map_err(|e| invalid(e.message))?;
    let entry =
        Entry { module: Arc::from(MODULE), function: Arc::from("edge"), role: Role::Transform };
    let limits = Limits {
        module_bytes: Config::DOCUMENT_LIMITS.max_input_bytes,
        modules: 1,
        string_bytes: Config::DOCUMENT_LIMITS.max_input_bytes,
        container_len: Config::DOCUMENT_LIMITS.max_values,
        evaluation_steps: 1_000_000,
        ..Limits::default()
    };
    let compiled = jlv_compiler::compile(Request {
        closure: &closure,
        registry: &registry,
        entry: &entry,
        keyed: &KeyedTypes::new(),
        limits: &limits,
    })
    .map_err(|e| diagnostic(path, source, e))?;
    if !compiled.params.is_empty() || !matches!(compiled.result, Type::Map(_)) {
        return Err(invalid("expected fn edge() -> Map<Value>"));
    }
    let outcome = jlv_lang::eval::run(
        &compiled.program,
        &natives,
        &compiled.costs,
        compiled.entry,
        Vec::new(),
        Context::new(),
        &limits,
    )
    .map_err(|e| diagnostic(path, source, e))?;
    Config::parse(document::encode(&outcome.value)?.as_bytes())
}
