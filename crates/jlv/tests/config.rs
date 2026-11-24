//! Rejected programs and documents through the public edge compiler.

use sibuna_jlv::parse;

fn rejects(source: &str, reason: &str) {
    let error = parse("config.jlv", source.as_bytes()).err().expect("expected refusal");
    assert!(error.to_string().contains(reason), "unexpected reason: {error}");
}

#[test]
fn diagnoses_signature_import_and_document_errors() {
    rejects("fn edge(i: Int) -> Map<Value> { return { n: i } }", "expected fn edge()");
    rejects("fn edge() -> Int { return 1 }", "expected fn edge()");
    rejects("import { x } from helpers\nfn edge() -> Map<Value> { return {} }", "config.jlv:");
    rejects(
        "import { bytes } from jlv.std.foundation\n\
         fn edge() -> Map<Value> { return { bad: bytes.from_text(\"x\") } }",
        "non-JSON value",
    );
    rejects(
        r#"fn edge() -> Map<Value> {
            return {
                frontends: { f: { binds: ["127.0.0.1:9000"], proto: "tcp",
                                  default_backend: "absent" } },
                backends: { p: { mode: "tcp", servers: [{ name: "s", addr: "127.0.0.1:9001" }] } },
            }
        }"#,
        "absent",
    );
}

#[test]
fn limits_evaluation_before_topology_validation() {
    rejects(
        "fn edge() -> Map<Value> {
            let ten = [0,1,2,3,4,5,6,7,8,9]
            var n = 0
            for a in ten { for b in ten { for c in ten { for d in ten {
                for e in ten { for f in ten { n = n + 1 } }
            } } } }
            return { n: n }
        }",
        "1000000",
    );
}
