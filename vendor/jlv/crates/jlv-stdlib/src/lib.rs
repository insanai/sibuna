//! The JLV standard library (JDD 0004; tier `domain` of JDD 0002).
//!
//! [`standard`] returns the registry data of the `jlv.std` libraries together with
//! their native implementations: [`foundation`] (`math`, `text`, `seq`, `map`,
//! `bytes`), [`schema`] (schemas as values), [`deploy`] (contexts, handles, `stack`,
//! `artifact`), [`operations`] (`ops` recipes) and [`config`] (files written from data).
//! [`resources::facade`] generates a plugin's resource constructors from its schemas.
//! The compiler reads only the registry; an evaluator links the natives by qualified
//! name.

#![forbid(unsafe_code)]

pub mod config;
pub mod deploy;
pub mod foundation;
pub mod operations;
pub mod resources;
pub mod schema;
mod support;

use jlv_core::Problem;
use jlv_lang::signature::Registry;
use jlv_model::{ActionSchema, ResourceSchema};

pub use support::Natives;

/// One plugin facade to register: its library label, namespace and resource schemas.
#[derive(Debug, Clone)]
pub struct Facade {
    /// The label, such as `@host//:plugin.jlv`.
    pub label: String,
    /// The namespace, such as `host`.
    pub namespace: String,
    /// The resource schemas.
    pub schemas: Vec<ResourceSchema>,
    /// The action schemas; those of kinds `NAMESPACE.NAME` get constructors (JDD 0017).
    pub actions: Vec<ActionSchema>,
}

/// The standard libraries and the given plugin facades, with their natives.
///
/// Fails when two libraries share a label or a type name, or when a facade's schema has
/// a field named like a common parameter or two fields of one name.
pub fn standard(facades: &[Facade]) -> Result<(Registry, Natives), Problem> {
    let mut natives = Natives::new();
    let mut registry = Registry::new();
    registry.add(foundation::library(&mut natives))?;
    registry.add(schema::library(&mut natives))?;
    registry.add(deploy::library(&mut natives))?;
    registry.add(operations::library(&mut natives))?;
    registry.add(config::library(&mut natives))?;
    for facade in facades {
        registry.add(resources::facade(
            &facade.label,
            &facade.namespace,
            &facade.schemas,
            &facade.actions,
            &mut natives,
        )?)?;
    }
    Ok((registry, natives))
}

/// The closest of `names` to `name`, for "Did you mean ...?" hints.
pub(crate) fn suggest(name: &str, names: &[&str]) -> Option<String> {
    let mut best: Option<(usize, &str)> = None;
    for candidate in names {
        let distance = edit_distance(name, candidate);
        if distance <= name.len().max(2) / 2 && best.is_none_or(|(d, _)| distance < d) {
            best = Some((distance, candidate));
        }
    }
    best.map(|(_, s)| s.to_string())
}

/// The edit distance of `a` and `b` where inserting, deleting or replacing a letter,
/// or swapping two adjacent letters, each cost one, so `wbe` is one edit from `web`.
fn edit_distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (d[i - 1][j] + 1).min(d[i][j - 1] + 1).min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = best;
        }
    }
    d[a.len()][b.len()]
}

#[cfg(test)]
mod suggestion_tests {
    use super::*;

    #[test]
    fn swapped_letters_are_one_edit() {
        assert_eq!(edit_distance("wbe", "web"), 1);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(suggest("wbe", &["db", "web"]), Some("web".to_string()));
    }
}
