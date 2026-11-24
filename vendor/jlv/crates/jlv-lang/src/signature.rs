//! The signature and schema registry: libraries described as data.
//!
//! The compiler checks calls against a [`Registry`] it receives as data and never links
//! the libraries that publish it (JDD 0002). Source modules, the standard library and
//! locked plugin descriptors all contribute the same [`Library`] shape: named exports
//! that are functions, namespaces of exports, nominal types with methods, or constants.
//! A registry is immutable for one preparation; duplicate labels or types are errors.

use std::collections::BTreeMap;
use std::sync::Arc;

use jlv_core::Problem;

use crate::types::Type;
use crate::value::Value;

/// One callable signature.
#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    /// The parameters in positional order.
    pub params: Vec<Param>,
    /// The result type.
    pub result: Type,
    /// The normalized cost of a call.
    pub cost: Cost,
    /// Whether the call needs the invocation's builder or context, so it cannot run
    /// while module constants initialize.
    pub needs_invocation: bool,
    /// When set, the first this many parameters are passed by position only and the
    /// rest by name only, as a resource's or an action's `name` and fields are (JDD
    /// 0016, "Resources and actions").
    pub positional: Option<usize>,
}

impl Signature {
    /// A pure signature with required parameters and the default cost.
    pub fn new(params: Vec<Param>, result: Type) -> Signature {
        Signature {
            params,
            result,
            cost: Cost::default(),
            needs_invocation: false,
            positional: None,
        }
    }

    /// The same signature with its first `count` parameters positional-only and the
    /// rest named-only.
    pub fn positional_only(mut self, count: usize) -> Signature {
        self.positional = Some(count);
        self
    }

    /// The same signature marked as needing the invocation.
    pub fn invocation(mut self) -> Signature {
        self.needs_invocation = true;
        self
    }
}

/// One parameter.
#[derive(Debug, Clone, PartialEq)]
pub struct Param {
    /// Its name, for named arguments.
    pub name: Arc<str>,
    /// Its type.
    pub ty: Type,
    /// What happens when a call omits it.
    pub omitted: Omitted,
}

impl Param {
    /// A required parameter.
    pub fn required(name: &str, ty: Type) -> Param {
        Param { name: Arc::from(name), ty, omitted: Omitted::Required }
    }

    /// An optional parameter whose omission is visible to the library as absence.
    pub fn optional(name: &str, ty: Type) -> Param {
        Param { name: Arc::from(name), ty, omitted: Omitted::Absent }
    }

    /// A parameter with an exact default value.
    pub fn defaulted(name: &str, ty: Type, default: Value) -> Param {
        Param { name: Arc::from(name), ty, omitted: Omitted::Default(default) }
    }
}

/// How a call may omit a parameter.
#[derive(Debug, Clone, PartialEq)]
pub enum Omitted {
    /// It may not.
    Required,
    /// It may; the library sees absence, which is not `null`.
    Absent,
    /// It may; the library sees this exact value.
    Default(Value),
}

/// A native call's normalized cost: a base charge plus a charge per size unit of its
/// arguments and result (JDD 0004, "Limits and diagnostics").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cost {
    /// Steps charged for every call.
    pub base: u64,
    /// Steps charged per size unit of the arguments and the result.
    pub per_unit: u64,
}

impl Default for Cost {
    fn default() -> Cost {
        Cost { base: 1, per_unit: 1 }
    }
}

/// One export of a library.
#[derive(Debug, Clone, PartialEq)]
pub enum Export {
    /// A native function, by its qualified name.
    Function {
        /// The native's qualified name.
        native: Arc<str>,
        /// Its signature.
        signature: Signature,
    },
    /// A namespace such as `math`, holding further exports.
    Namespace(BTreeMap<Arc<str>, Export>),
    /// A nominal type, by name.
    Type(Arc<str>),
    /// A constant value.
    Constant {
        /// The value.
        value: Value,
        /// Its type.
        ty: Type,
    },
}

/// A nominal type and its approved methods.
#[derive(Debug, Clone, PartialEq)]
pub struct TypeDef {
    /// The name, such as `ResourceRef`.
    pub name: Arc<str>,
    /// The number of type arguments, such as 1 for `SecretRef<T>`.
    pub arity: u8,
    /// Methods by name: the native and its signature without the receiver.
    pub methods: BTreeMap<Arc<str>, (Arc<str>, Signature)>,
    /// Whether values of the type may be compared with `==`.
    pub equality: bool,
}

/// One library: a canonical module label and its exports.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Library {
    /// The canonical label, such as `@jlv//std:foundation.jlv`.
    pub label: Arc<str>,
    /// The exports by name.
    pub exports: BTreeMap<Arc<str>, Export>,
    /// The nominal types the library defines.
    pub types: Vec<TypeDef>,
}

/// The frozen registry of one preparation.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    libraries: BTreeMap<Arc<str>, Library>,
    types: BTreeMap<Arc<str>, TypeDef>,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Registry {
        Registry::default()
    }

    /// Adds a library; a repeated label or type name is an error.
    pub fn add(&mut self, library: Library) -> Result<(), Problem> {
        if self.libraries.contains_key(&library.label) {
            return Err(duplicate("library", &library.label));
        }
        for def in &library.types {
            if self.types.contains_key(&def.name) {
                return Err(duplicate("type", &def.name));
            }
        }
        for def in &library.types {
            self.types.insert(def.name.clone(), def.clone());
        }
        self.libraries.insert(library.label.clone(), library);
        Ok(())
    }

    /// The library with this canonical label.
    pub fn library(&self, label: &str) -> Option<&Library> {
        self.libraries.get(label)
    }

    /// The nominal type with this name.
    pub fn type_def(&self, name: &str) -> Option<&TypeDef> {
        self.types.get(name)
    }

    /// Every library label, sorted.
    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.libraries.keys().map(|k| &**k)
    }
}

fn duplicate(what: &str, name: &str) -> Problem {
    Problem::new(
        "jlv.registry.duplicate",
        "DUPLICATE REGISTRATION",
        &format!("The {what} `{name}` is registered twice in one preparation."),
    )
    .consequence(crate::codes::CONSEQUENCE)
    .hint("Lock one package for each library label; two packages cannot both define it.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_types_are_refused() {
        let def = TypeDef {
            name: Arc::from("Stack"),
            arity: 0,
            methods: BTreeMap::new(),
            equality: false,
        };
        let a = Library {
            label: Arc::from("@a//:a.jlv"),
            types: vec![def.clone()],
            ..Default::default()
        };
        let b = Library { label: Arc::from("@b//:b.jlv"), types: vec![def], ..Default::default() };
        let mut registry = Registry::new();
        registry.add(a).unwrap();
        assert_eq!(registry.add(b).unwrap_err().code, "jlv.registry.duplicate");
        assert!(registry.type_def("Stack").is_some());
    }
}
