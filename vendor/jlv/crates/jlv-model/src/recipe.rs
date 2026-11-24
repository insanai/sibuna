//! Operation recipes (JDD 0003, "Imperative operation entrypoints").
//!
//! An operation entry returns a tree of steps: sequences, bounded parallel groups and
//! actions. Freezing the tree gives a recipe: actions with unique IDs in source order,
//! each naming the actions it must follow, its target handle, arguments and
//! repeatability. Workers receive this action manifest, never source to reinterpret.

use std::collections::BTreeSet;
use std::sync::Arc;

use gd_json::{Object, Value as Json};
use jlv_core::{Diagnostic, Problem};
use jlv_lang::digest::{Digest, RECIPE};
use jlv_lang::value::Entries;
use jlv_lang::{Value, canonical, codes};

use crate::graph::entries_from_json;
use crate::refs;
use crate::schema::Repeatability;

/// One imperative action.
#[derive(Debug, Clone, PartialEq)]
pub struct Action {
    /// The unique action ID, such as `restart-site`.
    pub id: Arc<str>,
    /// The action kind, such as `service_restart`.
    pub kind: Arc<str>,
    /// The identity-bound target handle's payload, if the action has a target.
    pub target: Option<Value>,
    /// The arguments.
    pub args: Entries,
    /// The actions that must complete first, sorted.
    pub after: Vec<Arc<str>>,
    /// How the action may be repeated.
    pub repeatability: Repeatability,
}

/// A frozen operation recipe.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Recipe {
    /// The actions in source order; `after` refers only to earlier actions.
    pub actions: Vec<Action>,
}

impl Recipe {
    /// Freezes the step tree an operation entry returned.
    pub fn from_value(recipe: &Value) -> Result<Recipe, Diagnostic> {
        Self::from_value_with_limit(recipe, jlv_core::Limits::default().actions)
    }

    /// Freezes a recipe while refusing more than `limit` actions before allocation.
    pub fn from_value_with_limit(recipe: &Value, limit: usize) -> Result<Recipe, Diagnostic> {
        let mut out = Recipe::default();
        let mut ids = BTreeSet::new();
        let mut nodes = 0_usize;
        flatten(recipe, &[], &mut out, &mut ids, limit, &mut nodes)?;
        Ok(out)
    }

    /// The canonical JSON record.
    pub fn to_json(&self) -> Json {
        let mut o = Object::new();
        o.insert("format".into(), Json::from(1u64));
        o.insert("kind".into(), Json::String("jlv.recipe".into()));
        o.insert("actions".into(), Json::Array(self.actions.iter().map(action_json).collect()));
        Json::Object(o)
    }

    /// The canonical bytes.
    pub fn canonical_bytes(&self) -> String {
        canonical::to_canonical_json(&self.to_json()).unwrap_or_default()
    }

    /// The recipe identity.
    pub fn digest(&self) -> Digest {
        Digest::of(RECIPE, self.canonical_bytes().as_bytes())
    }

    /// Reads a recipe record.
    pub fn from_json(json: &Json) -> Result<Recipe, Problem> {
        if json.get("kind").and_then(Json::as_str) != Some("jlv.recipe") {
            return Err(invalid("is not a recipe record"));
        }
        let actions = json
            .get("actions")
            .and_then(Json::as_array)
            .ok_or_else(|| invalid("has no actions"))?;
        Ok(Recipe { actions: actions.iter().map(action_from_json).collect::<Result<_, _>>()? })
    }
}

/// Appends the actions of `step`, each following `before`, and returns the step's
/// exits: the actions that must complete before whatever follows it.
fn flatten(
    step: &Value,
    before: &[Arc<str>],
    out: &mut Recipe,
    ids: &mut BTreeSet<Arc<str>>,
    limit: usize,
    nodes: &mut usize,
) -> Result<Vec<Arc<str>>, Diagnostic> {
    let node_limit = limit.saturating_mul(8).max(64);
    *nodes += 1;
    if *nodes > node_limit {
        return Err(Diagnostic::unplaced(
            Problem::new(
                "budget_exhausted",
                "BUDGET EXHAUSTED",
                &format!("The recipe exceeds its limit of {node_limit} step nodes."),
            )
            .consequence("No recipe was produced.")
            .hint("Split the operation or flatten empty sequence and parallel groups."),
        ));
    }
    let payload = refs::payload(step, refs::RECIPE).unwrap_or(step);
    let kind = payload.get("kind").and_then(Value::as_text).unwrap_or_default();
    let steps = payload.get("steps").and_then(Value::as_list).unwrap_or_default();
    match kind {
        "sequence" => {
            let mut exits = before.to_vec();
            for s in steps {
                exits = flatten(s, &exits, out, ids, limit, nodes)?;
            }
            Ok(exits)
        }
        "parallel" => {
            let mut exits: Vec<Arc<str>> = Vec::new();
            for s in steps {
                for exit in flatten(s, before, out, ids, limit, nodes)? {
                    if !exits.contains(&exit) {
                        exits.push(exit);
                    }
                }
            }
            // An empty group finishes at once: what follows it still waits for `before`.
            if exits.is_empty() { Ok(before.to_vec()) } else { Ok(exits) }
        }
        "action" => {
            if out.actions.len() >= limit {
                return Err(Diagnostic::unplaced(
                    Problem::new(
                        "budget_exhausted",
                        "BUDGET EXHAUSTED",
                        &format!("The recipe exceeds its limit of {limit} actions."),
                    )
                    .consequence("No recipe was produced.")
                    .hint("Split the operation or lower its fan-out."),
                ));
            }
            let action = action(payload, before)?;
            if !ids.insert(action.id.clone()) {
                let message =
                    format!("The action ID `{}` is used twice in one recipe.", action.id);
                return Err(Diagnostic::unplaced(codes::problem(
                    codes::DUPLICATE_ADDRESS,
                    &message,
                    "Give each action a unique ID.",
                )));
            }
            let id = action.id.clone();
            out.actions.push(action);
            Ok(vec![id])
        }
        other => {
            let message = format!("`{other}` is not a recipe step.");
            Err(Diagnostic::unplaced(codes::problem(
                codes::TYPE_MISMATCH,
                &message,
                "Build recipes with the `ops` library.",
            )))
        }
    }
}

fn action(payload: &Value, before: &[Arc<str>]) -> Result<Action, Diagnostic> {
    let text = |k: &str| {
        payload.get(k).and_then(Value::as_text).map(Arc::from).unwrap_or_else(|| Arc::from(""))
    };
    let repeatability =
        payload.get("repeatability").and_then(Value::as_text).and_then(Repeatability::named);
    let target = payload.get("target").and_then(|t| refs::payload(t, refs::TARGET_REF)).cloned();
    let mut after: Vec<Arc<str>> = before.to_vec();
    after.sort();
    after.dedup();
    Ok(Action {
        id: text("id"),
        kind: text("action"),
        target,
        args: payload.get("args").and_then(Value::as_map).cloned().unwrap_or_default(),
        after,
        repeatability: repeatability.unwrap_or(Repeatability::NonRepeatable),
    })
}

impl Action {
    /// The action's JSON record.
    pub fn to_json(&self) -> Json {
        action_json(self)
    }

    /// Reads an action's JSON record.
    pub fn from_json(json: &Json) -> Result<Action, Problem> {
        action_from_json(json)
    }
}

fn action_json(a: &Action) -> Json {
    let mut o = Object::new();
    o.insert("id".into(), Json::String(a.id.to_string()));
    o.insert("kind".into(), Json::String(a.kind.to_string()));
    o.insert("target".into(), a.target.as_ref().map_or(Json::Null, canonical::to_json));
    o.insert(
        "args".into(),
        Json::Object(a.args.iter().map(|(k, v)| (k.to_string(), canonical::to_json(v))).collect()),
    );
    o.insert(
        "after".into(),
        Json::Array(a.after.iter().map(|s| Json::String(s.to_string())).collect()),
    );
    o.insert("repeatability".into(), Json::String(a.repeatability.name().into()));
    Json::Object(o)
}

fn action_from_json(json: &Json) -> Result<Action, Problem> {
    let text = |k: &str| {
        json.get(k)
            .and_then(Json::as_str)
            .map(Arc::from)
            .ok_or_else(|| invalid(&format!("has an action without `{k}`")))
    };
    let target = match json.get("target") {
        None | Some(Json::Null) => None,
        Some(t) => Some(canonical::from_json(t)?),
    };
    let after = json
        .get("after")
        .and_then(Json::as_array)
        .ok_or_else(|| invalid("has an action without `after`"))?;
    let repeatability = text("repeatability")?;
    Ok(Action {
        id: text("id")?,
        kind: text("kind")?,
        target,
        args: entries_from_json(json.get("args").unwrap_or(&Json::Null))?,
        after: after.iter().filter_map(Json::as_str).map(Arc::from).collect(),
        repeatability: Repeatability::named(&repeatability)
            .ok_or_else(|| invalid("has an unknown repeatability"))?,
    })
}

fn invalid(what: &str) -> Problem {
    Problem::new("jlv.recipe.invalid", "INVALID RECIPE", &format!("The recipe record {what}."))
        .consequence("The recipe was not read.")
        .hint("Produce recipes with `jlvd compile`; saved recipes are not edited by hand.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_action_budget_is_checked_while_freezing() {
        let recipe = Value::map([
            ("kind", Value::text("parallel")),
            ("steps", Value::list(vec![act("a"), act("b")])),
        ]);
        assert_eq!(Recipe::from_value_with_limit(&recipe, 2).unwrap().actions.len(), 2);
        assert!(Recipe::from_value_with_limit(&recipe, 1).is_err());
        assert!(Recipe::from_value_with_limit(&act("a"), 0).is_err());
    }

    fn act(id: &str) -> Value {
        Value::map([
            ("kind", Value::text("action")),
            ("id", Value::text(id)),
            ("action", Value::text("service_restart")),
            ("args", Value::map([("unit", Value::text("site.service"))])),
            ("repeatability", Value::text("non_repeatable")),
        ])
    }

    fn group(kind: &str, steps: Vec<Value>) -> Value {
        Value::opaque(
            refs::RECIPE,
            1,
            Value::map([("kind", Value::text(kind)), ("steps", Value::list(steps))]),
        )
    }

    #[test]
    fn sequences_and_parallel_groups_order_their_actions() {
        let tree = group(
            "sequence",
            vec![act("a"), group("parallel", vec![act("b"), act("c")]), act("d")],
        );
        let recipe = Recipe::from_value(&tree).unwrap();
        let after: Vec<(String, Vec<&str>)> = recipe
            .actions
            .iter()
            .map(|a| (a.id.to_string(), a.after.iter().map(|s| &**s).collect()))
            .collect();
        assert_eq!(after[1], ("b".to_string(), vec!["a"]));
        assert_eq!(after[3], ("d".to_string(), vec!["b", "c"]));
        assert_eq!(Recipe::from_json(&recipe.to_json()).unwrap(), recipe);
        let twice = group("sequence", vec![act("a"), act("a")]);
        assert_eq!(Recipe::from_value(&twice).unwrap_err().code(), "duplicate_address");
        let mut empty_dag = group("sequence", Vec::new());
        for _ in 0..25 {
            empty_dag = group("sequence", vec![empty_dag.clone(), empty_dag]);
        }
        let err = Recipe::from_value_with_limit(&empty_dag, 8).unwrap_err();
        assert_eq!(err.code(), "budget_exhausted");
    }

    #[test]
    fn an_empty_parallel_group_keeps_the_order_of_a_sequence() {
        let empty = || group("parallel", Vec::new());
        let tree = group(
            "sequence",
            vec![act("stop"), empty(), group("parallel", vec![empty(), empty()]), act("start")],
        );
        let recipe = Recipe::from_value(&tree).unwrap();
        let start = &recipe.actions[1];
        assert_eq!(start.id.as_ref(), "start");
        assert_eq!(start.after.iter().map(|s| &**s).collect::<Vec<_>>(), ["stop"]);
    }
}
