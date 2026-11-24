//! Desired graphs (JDD 0003, "Typed intermediate representation").
//!
//! A graph is the frozen result of a deployment entry: every declared resource exactly
//! once, sorted by address, with its schema identity, desired properties, ownership
//! mask, lifecycle rules, dependencies and health contract, and the stack's outputs.
//! It carries no source spans, layout, session, timestamps or plaintext credentials.
//! Its identity is the domain-separated digest of its canonical bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use gd_json::{Object, Value as Json};
use jlv_core::{Diagnostic, Problem};
use jlv_lang::digest::{Digest, GRAPH};
use jlv_lang::native::Declaration;
use jlv_lang::value::Entries;
use jlv_lang::{Value, canonical, codes};

use crate::refs;

/// The format version of graph records.
pub const FORMAT: u64 = 1;

/// One desired resource.
#[derive(Debug, Clone, PartialEq)]
pub struct Resource {
    /// The stable logical address, `type.name`.
    pub address: Arc<str>,
    /// The resource type, such as `host.file`.
    pub type_name: Arc<str>,
    /// The schema version the properties follow.
    pub schema_version: u32,
    /// The name within the type.
    pub name: Arc<str>,
    /// The desired properties, defaults included; references stay symbolic.
    pub properties: Entries,
    /// The properties we own and compare.
    pub owned: Vec<Arc<str>>,
    /// Whether deletion or replacement needs an explicit policy override.
    pub protect: bool,
    /// Whether an object that already exists is taken over rather than refused, and
    /// released rather than deleted when the resource leaves the source (JDD 0011).
    pub adopt: bool,
    /// The addresses this resource requires, sorted.
    pub depends_on: Vec<Arc<str>>,
    /// The addresses whose verified change triggers a restart, sorted.
    pub triggers: Vec<Arc<str>>,
    /// The probe contract, independent of configuration equality.
    pub health: Option<Value>,
}

/// A desired graph.
///
/// Its resources are sorted by address, each address once. Every constructor keeps that
/// order: [`Graph::new`] sorts the resources it is given, [`Graph::from_declarations`]
/// builds through it, and [`Graph::from_json`] refuses a record out of order.
/// [`Graph::resource`] relies on the order for a binary search; for a graph whose
/// fields were filled by hand out of order it still answers correctly, only more
/// slowly when the address is missing.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Graph {
    /// The resources, sorted by address; build with [`Graph::new`] to keep the order.
    pub resources: Vec<Resource>,
    /// The stack's outputs.
    pub outputs: Entries,
}

impl Graph {
    /// A graph of `resources`, which it sorts by address, and `outputs`. The addresses
    /// should be distinct. It checks neither references nor cycles, as
    /// [`Graph::from_declarations`] and [`Graph::from_json`] do.
    pub fn new(mut resources: Vec<Resource>, outputs: Entries) -> Graph {
        resources.sort_by(|a, b| a.address.cmp(&b.address));
        Graph { resources, outputs }
    }

    /// The resource with this address, or `None` when the graph has none.
    ///
    /// The lookup is a binary search over the sorted resources. A miss among resources
    /// that are out of order, which only a graph filled by hand can have, falls back to
    /// a scan, so the answer never depends on the order.
    pub fn resource(&self, address: &str) -> Option<&Resource> {
        match self.resources.binary_search_by(|r| (*r.address).cmp(address)) {
            Ok(i) => Some(&self.resources[i]),
            Err(_) if self.resources.is_sorted_by(|a, b| a.address <= b.address) => None,
            Err(_) => self.resources.iter().find(|r| *r.address == *address),
        }
    }

    /// Freezes the declarations of one deployment invocation and the value its entry
    /// returned: null, or the map of its outputs (JDD 0016, "Entries"). The graph holds
    /// every declared resource; references must name declared resources, and
    /// required-state dependencies must be acyclic.
    pub fn from_declarations(
        declarations: &[Declaration],
        result: &Value,
    ) -> Result<Graph, Diagnostic> {
        let outputs = match result {
            Value::Null => Entries::new(),
            Value::Map(map) => Entries::clone(map),
            _ => return Err(unplaced("The entry returned neither nothing nor its outputs.")),
        };
        let mut resources = Vec::with_capacity(declarations.len());
        for declaration in declarations.iter().filter(|d| &*d.kind == "resource") {
            resources.push(resource(declaration)?);
        }
        let graph = Graph::new(resources, outputs);
        graph.check_references(declarations)?;
        graph.check_acyclic()?;
        Ok(graph)
    }

    fn check_references(&self, declarations: &[Declaration]) -> Result<(), Diagnostic> {
        let Some((r, address)) = self.dangling_reference() else { return Ok(()) };
        let message =
            format!("`{}` refers to `{address}`, which the entry does not declare.", r.address);
        let span = declarations.iter().find(|d| d.address == r.address).map(|d| d.span);
        let problem = codes::problem(
            codes::UNRESOLVED_REFERENCE,
            &message,
            "Declare the resource in the same deployment.",
        );
        Err(Diagnostic { problem, span, related: Vec::new() })
    }

    /// The first resource that depends on or is triggered by an address the graph does
    /// not contain, with that address.
    fn dangling_reference(&self) -> Option<(&Resource, &Arc<str>)> {
        self.resources.iter().find_map(|r| {
            r.depends_on
                .iter()
                .chain(&r.triggers)
                .find(|a| self.resource(a).is_none())
                .map(|a| (r, a))
        })
    }

    /// Fails with the cycle's path when required-state dependencies loop.
    fn check_acyclic(&self) -> Result<(), Diagnostic> {
        let order = self.topological()?;
        debug_assert_eq!(order.len(), self.resources.len());
        Ok(())
    }

    /// The resources in a stable dependency order: dependencies first, ties broken by
    /// address, so equal graphs give equal orders.
    pub fn topological(&self) -> Result<Vec<usize>, Diagnostic> {
        let index: BTreeMap<&str, usize> =
            self.resources.iter().enumerate().map(|(i, r)| (&*r.address, i)).collect();
        let mut remaining: Vec<usize> =
            self.resources.iter().map(|r| r.depends_on.len()).collect();
        let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); self.resources.len()];
        for (i, r) in self.resources.iter().enumerate() {
            for d in &r.depends_on {
                if let Some(&j) = index.get(&**d) {
                    dependents[j].push(i);
                }
            }
        }
        let mut ready: BTreeSet<usize> =
            (0..self.resources.len()).filter(|i| remaining[*i] == 0).collect();
        let mut order = Vec::with_capacity(self.resources.len());
        while let Some(i) = ready.pop_first() {
            order.push(i);
            for &k in &dependents[i] {
                remaining[k] -= 1;
                if remaining[k] == 0 {
                    ready.insert(k);
                }
            }
        }
        if order.len() < self.resources.len() {
            return Err(self.cycle(&remaining));
        }
        Ok(order)
    }

    fn cycle(&self, remaining: &[usize]) -> Diagnostic {
        let stuck: Vec<&Resource> = self
            .resources
            .iter()
            .zip(remaining)
            .filter(|(_, n)| **n > 0)
            .map(|(r, _)| r)
            .collect();
        let mut path = vec![stuck[0].address.clone()];
        let mut at = stuck[0];
        while let Some(next) =
            at.depends_on.iter().find_map(|d| stuck.iter().find(|r| r.address == *d))
        {
            if let Some(start) = path.iter().position(|a| *a == next.address) {
                path.drain(..start);
                path.push(next.address.clone());
                break;
            }
            path.push(next.address.clone());
            at = next;
        }
        let names: Vec<&str> = path.iter().map(|a| &**a).collect();
        let message = format!("Required state depends on itself: {}.", names.join(" -> "));
        let hint = "Break the cycle; looping runtime relations belong in the topology.";
        unplaced_with(codes::DEPENDENCY_CYCLE, &message, hint)
    }

    /// The canonical JSON record.
    pub fn to_json(&self) -> Json {
        let mut o = Object::new();
        o.insert("format".into(), Json::from(FORMAT));
        o.insert("kind".into(), Json::String("jlv.graph".into()));
        o.insert(
            "resources".into(),
            Json::Array(self.resources.iter().map(resource_json).collect()),
        );
        o.insert("outputs".into(), entries_json(&self.outputs));
        Json::Object(o)
    }

    /// The canonical bytes.
    pub fn canonical_bytes(&self) -> String {
        // Graph records hold no float, so canonicalization cannot fail.
        canonical::to_canonical_json(&self.to_json()).unwrap_or_default()
    }

    /// The graph identity.
    pub fn digest(&self) -> Digest {
        Digest::of(GRAPH, self.canonical_bytes().as_bytes())
    }

    /// Reads a graph record, checking what compilation guarantees: resources sorted by
    /// address, every reference resolved and no dependency cycle.
    pub fn from_json(json: &Json) -> Result<Graph, Problem> {
        if json.get("kind").and_then(Json::as_str) != Some("jlv.graph")
            || json.get("format").and_then(Json::as_u64) != Some(FORMAT)
        {
            return Err(invalid("is not a version 1 graph record"));
        }
        let resources = json
            .get("resources")
            .and_then(Json::as_array)
            .ok_or_else(|| invalid("has no resources"))?;
        let resources = resources.iter().map(resource_from_json).collect::<Result<Vec<_>, _>>()?;
        if resources.windows(2).any(|w| w[0].address >= w[1].address) {
            return Err(invalid("lists resources out of order or twice"));
        }
        let outputs = entries_from_json(json.get("outputs").unwrap_or(&Json::Null))?;
        let graph = Graph { resources, outputs };
        if let Some((r, address)) = graph.dangling_reference() {
            return Err(invalid(&format!(
                "has `{}` refer to `{address}`, which it lacks",
                r.address
            )));
        }
        if let Err(cycle) = graph.topological() {
            return Err(invalid(&format!("has a dependency cycle: {}", cycle.problem.message)));
        }
        Ok(graph)
    }
}

fn resource(d: &Declaration) -> Result<Resource, Diagnostic> {
    let p = &d.payload;
    let text = |k: &str| {
        p.get(k).and_then(Value::as_text).map(Arc::from).unwrap_or_else(|| Arc::from(""))
    };
    let addresses = |k: &str| -> Vec<Arc<str>> {
        let mut found = Vec::new();
        if let Some(v) = p.get(k) {
            refs::addresses_in(v, &mut found);
        }
        let set: BTreeSet<String> = found.into_iter().collect();
        set.into_iter().map(Arc::from).collect()
    };
    let properties = p.get("properties").and_then(Value::as_map).cloned().unwrap_or_default();
    let mut depends: BTreeSet<Arc<str>> = addresses("depends_on").into_iter().collect();
    let mut inner = Vec::new();
    refs::addresses_in(&Value::of_entries(properties.clone()), &mut inner);
    depends.extend(inner.into_iter().map(Arc::from));
    let triggers = addresses("triggers");
    depends.extend(triggers.iter().cloned());
    depends.remove(&d.address);
    let owned = p.get("owned").and_then(Value::as_list).unwrap_or_default();
    Ok(Resource {
        address: d.address.clone(),
        type_name: text("type"),
        schema_version: p.get("schema_version").and_then(Value::as_int).unwrap_or(1) as u32,
        name: text("name"),
        properties,
        owned: owned.iter().filter_map(Value::as_text).map(Arc::from).collect(),
        protect: p.get("protect").and_then(Value::as_bool).unwrap_or(false),
        adopt: p.get("adopt").and_then(Value::as_bool).unwrap_or(false),
        depends_on: depends.into_iter().collect(),
        triggers,
        health: p.get("health").filter(|h| **h != Value::Null).cloned(),
    })
}

fn texts(items: &[Arc<str>]) -> Json {
    Json::Array(items.iter().map(|s| Json::String(s.to_string())).collect())
}

fn entries_json(entries: &Entries) -> Json {
    Json::Object(entries.iter().map(|(k, v)| (k.to_string(), canonical::to_json(v))).collect())
}

impl Resource {
    /// The resource's JSON record.
    pub fn to_json(&self) -> Json {
        resource_json(self)
    }

    /// Reads a resource's JSON record.
    pub fn from_json(json: &Json) -> Result<Resource, Problem> {
        resource_from_json(json)
    }
}

fn resource_json(r: &Resource) -> Json {
    let mut o = Object::new();
    o.insert("address".into(), Json::String(r.address.to_string()));
    o.insert("type".into(), Json::String(r.type_name.to_string()));
    o.insert("schema_version".into(), Json::from(r.schema_version));
    o.insert("name".into(), Json::String(r.name.to_string()));
    o.insert("properties".into(), entries_json(&r.properties));
    o.insert("owned".into(), texts(&r.owned));
    o.insert("protect".into(), Json::Bool(r.protect));
    if r.adopt {
        o.insert("adopt".into(), Json::Bool(true));
    }
    o.insert("depends_on".into(), texts(&r.depends_on));
    o.insert("triggers".into(), texts(&r.triggers));
    o.insert("health".into(), r.health.as_ref().map_or(Json::Null, canonical::to_json));
    Json::Object(o)
}

fn resource_from_json(json: &Json) -> Result<Resource, Problem> {
    let text = |k: &str| {
        json.get(k)
            .and_then(Json::as_str)
            .map(Arc::from)
            .ok_or_else(|| invalid(&format!("has a resource without `{k}`")))
    };
    let list = |k: &str| -> Result<Vec<Arc<str>>, Problem> {
        let items = json
            .get(k)
            .and_then(Json::as_array)
            .ok_or_else(|| invalid(&format!("has a resource without `{k}`")))?;
        Ok(items.iter().filter_map(Json::as_str).map(Arc::from).collect())
    };
    let health = match json.get("health") {
        None | Some(Json::Null) => None,
        Some(h) => Some(canonical::from_json(h)?),
    };
    Ok(Resource {
        address: text("address")?,
        type_name: text("type")?,
        schema_version: json.get("schema_version").and_then(Json::as_u64).unwrap_or(1) as u32,
        name: text("name")?,
        properties: entries_from_json(json.get("properties").unwrap_or(&Json::Null))?,
        owned: list("owned")?,
        protect: json.get("protect").and_then(Json::as_bool).unwrap_or(false),
        adopt: json.get("adopt").and_then(Json::as_bool).unwrap_or(false),
        depends_on: list("depends_on")?,
        triggers: list("triggers")?,
        health,
    })
}

/// Reads a JSON object of tagged values.
pub fn entries_from_json(json: &Json) -> Result<Entries, Problem> {
    let object =
        json.as_object().ok_or_else(|| invalid("has a property set that is not an object"))?;
    object.iter().map(|(k, v)| Ok((Arc::from(k.as_str()), canonical::from_json(v)?))).collect()
}

fn invalid(what: &str) -> Problem {
    Problem::new("jlv.graph.invalid", "INVALID GRAPH", &format!("The graph record {what}."))
        .consequence("The graph was not read.")
        .hint("Produce graphs with `jlvd compile`; saved graphs are not edited by hand.")
}

fn unplaced(message: &str) -> Diagnostic {
    unplaced_with(
        codes::TYPE_MISMATCH,
        message,
        "End the entry without a result, or return its outputs, `{ name: r.output(\"field\") }`.",
    )
}

fn unplaced_with(code: &str, message: &str, hint: &str) -> Diagnostic {
    Diagnostic::unplaced(codes::problem(code, message, hint))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jlv_core::Span;

    fn declaration(address: &str, depends: &[&str]) -> Declaration {
        let depends = Value::list(depends.iter().map(|a| refs::resource_ref(a)).collect());
        let payload = Value::map([
            ("type", Value::text("host.file")),
            ("name", Value::text(address.rsplit('.').next().unwrap())),
            ("properties", Value::map([("path", Value::text("/x"))])),
            ("owned", Value::list(vec![Value::text("path")])),
            ("depends_on", depends),
        ]);
        Declaration {
            kind: Arc::from("resource"),
            address: Arc::from(address),
            payload,
            span: Span::default(),
        }
    }

    /// An entry's result without outputs; the addresses are those the stack holds.
    fn stack(_: &[&str]) -> Value {
        Value::Null
    }

    #[test]
    fn graphs_round_trip_and_order_their_resources() {
        let decls =
            [declaration("host.file.b", &["host.file.a"]), declaration("host.file.a", &[])];
        let graph =
            Graph::from_declarations(&decls, &stack(&["host.file.b", "host.file.a"])).unwrap();
        assert_eq!(&*graph.resources[0].address, "host.file.a");
        assert_eq!(graph.topological().unwrap(), [0, 1]);
        assert_eq!(Graph::from_json(&graph.to_json()).unwrap(), graph);
        let reordered =
            [declaration("host.file.a", &[]), declaration("host.file.b", &["host.file.a"])];
        let again =
            Graph::from_declarations(&reordered, &stack(&["host.file.a", "host.file.b"])).unwrap();
        assert_eq!(again.digest(), graph.digest());
    }

    /// A resource of type `host.file` at `address`, without dependencies.
    fn bare(address: &str) -> Resource {
        let graph = Graph::from_declarations(&[declaration(address, &[])], &stack(&[address]));
        graph.unwrap().resources.remove(0)
    }

    #[test]
    fn lookups_find_every_resource_whatever_order_the_graph_was_built_in() {
        let names = ["host.file.c", "host.file.a", "host.file.b"];
        let made = Graph::new(names.iter().map(|a| bare(a)).collect(), Entries::new());
        let order: Vec<&str> = made.resources.iter().map(|r| &*r.address).collect();
        assert_eq!(order, ["host.file.a", "host.file.b", "host.file.c"]);
        // A graph filled by hand out of order still answers every lookup correctly.
        let by_hand = Graph { resources: names.iter().map(|a| bare(a)).collect(), ..made.clone() };
        for graph in [&made, &by_hand] {
            for name in names {
                assert_eq!(graph.resource(name).map(|r| &*r.address), Some(name));
            }
            assert!(graph.resource("host.file.z").is_none());
        }
        let mut record = by_hand.to_json();
        assert!(Graph::from_json(&record).is_err(), "an unsorted record is refused");
        if let Some(Json::Array(resources)) = record.as_object_mut().unwrap().get_mut("resources")
        {
            resources.sort_by_key(|r| r.get("address").and_then(Json::as_str).map(String::from));
        }
        assert_eq!(Graph::from_json(&record).unwrap().digest(), made.digest());
    }

    #[test]
    fn cycles_orphans_and_dangling_references_are_refused() {
        let decls = [
            declaration("host.file.a", &["host.file.b"]),
            declaration("host.file.b", &["host.file.a"]),
        ];
        let error =
            Graph::from_declarations(&decls, &stack(&["host.file.a", "host.file.b"])).unwrap_err();
        assert_eq!(error.code(), "dependency_cycle");
        assert!(error.problem.message.contains("host.file.a -> host.file.b -> host.file.a"));
        let wrong = Graph::from_declarations(&[declaration("host.file.a", &[])], &Value::Int(1));
        assert!(wrong.is_err(), "a result that is neither null nor outputs");
        let dangling = Graph::from_declarations(
            &[declaration("host.file.a", &["host.file.z"])],
            &stack(&["host.file.a"]),
        );
        assert_eq!(dangling.unwrap_err().code(), "unresolved_reference");
        let pair = Graph::from_declarations(
            &[declaration("host.file.a", &["host.file.b"]), declaration("host.file.b", &[])],
            &stack(&["host.file.a", "host.file.b"]),
        )
        .unwrap();
        let record = gd_json::to_string(&pair.to_json());
        let looped = record.replace("\"depends_on\":[]", "\"depends_on\":[\"host.file.a\"]");
        let missing =
            record.replace("\"depends_on\":[\"host.file.b\"]", "\"depends_on\":[\"host.file.z\"]");
        for edited in [looped, missing] {
            assert_ne!(edited, record);
            let error = Graph::from_json(&gd_json::parse(&edited).unwrap()).unwrap_err();
            assert_eq!(error.code, "jlv.graph.invalid", "{}", error.message);
        }
    }
}
