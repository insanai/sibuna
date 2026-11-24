//! Small helpers shared by the libraries: native wrappers, signatures and arguments.

use std::collections::BTreeMap;
use std::sync::Arc;

use jlv_core::Problem;
use jlv_lang::native::{Call, Native};
use jlv_lang::signature::{Export, Param, Signature, TypeDef};
use jlv_lang::{Type, Value, codes};

/// The function type of a plain native.
pub(crate) type NativeFn = fn(&mut Call<'_>, &[Option<Value>]) -> Result<Value, Problem>;

/// A native implemented by a plain function.
#[derive(Debug)]
pub(crate) struct FnNative(pub NativeFn);

impl Native for FnNative {
    fn call(&self, call: &mut Call<'_>, args: &[Option<Value>]) -> Result<Value, Problem> {
        (self.0)(call, args)
    }
}

/// The natives of the standard library and plugin facades, by qualified name.
pub type Natives = BTreeMap<Arc<str>, Arc<dyn Native>>;

/// Collects one library's exports, types and natives.
#[derive(Debug, Default)]
pub(crate) struct LibraryBuilder {
    pub label: &'static str,
    pub exports: BTreeMap<Arc<str>, Export>,
    pub types: Vec<TypeDef>,
}

impl LibraryBuilder {
    /// A library with this label.
    pub fn new(label: &'static str) -> LibraryBuilder {
        LibraryBuilder { label, ..LibraryBuilder::default() }
    }

    /// The qualified native name of `path` in this library.
    pub fn qualified(&self, path: &str) -> Arc<str> {
        Arc::from(format!("{}#{path}", self.label))
    }

    /// Exports a nominal type with its methods, given as `(name, signature, native)`.
    pub fn type_def(
        &mut self,
        natives: &mut Natives,
        name: &str,
        arity: u8,
        methods: Vec<(&str, Signature, NativeFn)>,
    ) {
        let mut table = BTreeMap::new();
        for (method, signature, f) in methods {
            let native = self.qualified(&format!("{name}.{method}"));
            natives.insert(native.clone(), Arc::new(FnNative(f)));
            table.insert(Arc::from(method), (native, signature));
        }
        self.types.push(TypeDef { name: Arc::from(name), arity, methods: table, equality: false });
        self.exports.insert(Arc::from(name), Export::Type(Arc::from(name)));
    }

    /// Exports a namespace of functions given as `(name, signature, native)`.
    pub fn namespace(
        &mut self,
        natives: &mut Natives,
        namespace: &str,
        functions: Vec<(&str, Signature, NativeFn)>,
    ) {
        let mut members = BTreeMap::new();
        for (name, signature, f) in functions {
            let native = self.qualified(&format!("{namespace}.{name}"));
            natives.insert(native.clone(), Arc::new(FnNative(f)));
            members.insert(Arc::from(name), Export::Function { native, signature });
        }
        self.exports.insert(Arc::from(namespace), Export::Namespace(members));
    }

    /// Exports one function.
    pub fn function(
        &mut self,
        natives: &mut Natives,
        name: &str,
        signature: Signature,
        f: NativeFn,
    ) {
        let native = self.qualified(name);
        natives.insert(native.clone(), Arc::new(FnNative(f)));
        self.exports.insert(Arc::from(name), Export::Function { native, signature });
    }

    /// The finished library.
    pub fn finish(self) -> jlv_lang::signature::Library {
        jlv_lang::signature::Library {
            label: Arc::from(self.label),
            exports: self.exports,
            types: self.types,
        }
    }
}

/// A pure signature from `(name, type)` required parameters.
pub(crate) fn sig(params: &[(&str, Type)], result: Type) -> Signature {
    Signature::new(params.iter().map(|(n, t)| Param::required(n, t.clone())).collect(), result)
}

/// The argument at `i`, or `null` when it was omitted.
pub(crate) fn arg(args: &[Option<Value>], i: usize) -> &Value {
    args.get(i).and_then(Option::as_ref).unwrap_or(&Value::Null)
}

/// The integer argument at `i`.
pub(crate) fn int(args: &[Option<Value>], i: usize) -> Result<i64, Problem> {
    arg(args, i).as_int().ok_or_else(|| wrong(i, "an integer"))
}

/// The text argument at `i`.
pub(crate) fn text(args: &[Option<Value>], i: usize) -> Result<&str, Problem> {
    arg(args, i).as_text().ok_or_else(|| wrong(i, "a text"))
}

/// The list argument at `i`.
pub(crate) fn list(args: &[Option<Value>], i: usize) -> Result<&[Value], Problem> {
    arg(args, i).as_list().ok_or_else(|| wrong(i, "a list"))
}

fn wrong(i: usize, what: &str) -> Problem {
    codes::problem(
        codes::TYPE_MISMATCH,
        &format!("Argument {} must be {what}.", i + 1),
        "Pass a value of the documented type.",
    )
}
