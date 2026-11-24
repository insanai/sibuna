//! The frozen typed IR (JDD 0003, "Typed intermediate representation"; tier
//! `contract` of JDD 0002).
//!
//! Lowering produces a [`Graph`] for a deployment entry or a [`Recipe`] for an
//! operation entry. Both are independent of the compiler's AST and evaluator objects,
//! encode canonically and have domain-separated digests. [`schema`] holds the closed
//! resource and action contracts that plugins publish as data, and [`refs`] the nominal
//! handles that libraries construct.

#![forbid(unsafe_code)]

pub mod graph;
pub mod names;
pub mod recipe;
pub mod refs;
pub mod schema;

pub use graph::{Graph, Resource};
pub use recipe::{Action, Recipe};
pub use schema::{
    ActionSchema, FieldSchema, FieldSource, OutputSchema, Repeatability, ResourceSchema,
    TargetMapping,
};
