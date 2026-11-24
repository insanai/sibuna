//! Resource and action schemas: the closed contracts plugins publish as data (JDD
//! 0007, "Schema and model contract").
//!
//! A resource schema names its fields with their types, which are required, which we
//! own and compare, which force a replacement when they change, which are sensitive
//! and which are change triggers, and its typed outputs. An action schema names an
//! imperative action's arguments and its repeatability. Both read and write the JSON
//! descriptor form packaged with a plugin.

use std::sync::Arc;

use gd_json::{Object, Value as Json};
use jlv_core::Problem;
use jlv_lang::{Type, Value, canonical};

/// One field of a resource or action schema.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldSchema {
    /// The field name.
    pub name: Arc<str>,
    /// Its type.
    pub ty: Type,
    /// Whether a declaration must give it.
    pub required: bool,
    /// The exact default when it is omitted.
    pub default: Option<Value>,
    /// Whether we own and compare it (it is in the ownership mask).
    pub owned: bool,
    /// Whether a change requires replacing the resource.
    pub replace: bool,
    /// Whether its value is sensitive and compared only by version evidence.
    pub sensitive: bool,
    /// Whether it lists resources whose verified change triggers a restart.
    pub trigger: bool,
    /// One sentence for generated documentation.
    pub description: Arc<str>,
}

impl FieldSchema {
    /// An owned, required, mutable field.
    pub fn owned(name: &str, ty: Type, description: &str) -> FieldSchema {
        FieldSchema {
            name: name.into(),
            ty,
            required: true,
            default: None,
            owned: true,
            replace: false,
            sensitive: false,
            trigger: false,
            description: description.into(),
        }
    }

    /// The same field, optional with an exact default.
    pub fn defaulted(mut self, default: Value) -> FieldSchema {
        self.required = false;
        self.default = Some(default);
        self
    }

    /// The same field, optional without a default.
    pub fn optional(mut self) -> FieldSchema {
        self.required = false;
        self
    }

    /// The same field, whose change requires replacement.
    pub fn replacing(mut self) -> FieldSchema {
        self.replace = true;
        self
    }

    /// The same field, whose value is sensitive and compared only by version evidence.
    pub fn sensitive(mut self) -> FieldSchema {
        self.sensitive = true;
        self
    }

    /// The same field, not owned: an input such as a target that is not compared.
    pub fn input(mut self) -> FieldSchema {
        self.owned = false;
        self
    }

    /// The same field, a list of change triggers.
    pub fn trigger(mut self) -> FieldSchema {
        self.trigger = true;
        self.owned = false;
        self
    }
}

/// One typed output of a resource.
#[derive(Debug, Clone, PartialEq)]
pub struct OutputSchema {
    /// The output name.
    pub name: Arc<str>,
    /// Its type.
    pub ty: Type,
    /// One sentence for generated documentation.
    pub description: Arc<str>,
}

/// The schema of one resource type.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceSchema {
    /// The type, such as `host.file`; addresses are `type.name`.
    pub type_name: Arc<str>,
    /// The schema version.
    pub version: u32,
    /// The fields, in documentation order.
    pub fields: Vec<FieldSchema>,
    /// The outputs.
    pub outputs: Vec<OutputSchema>,
    /// Whether an object of this type that already exists is adopted rather than
    /// refused, unless a resource's `lifecycle` says otherwise (JDD 0011). Adopted
    /// objects are released, never deleted, when their resource leaves the source.
    pub adopts: bool,
    /// Whether omission releases ownership without undoing the established effect.
    pub retain_on_delete: bool,
    /// Whether the object is made by other resources and this type manages only its
    /// state, as a service manages the run state of a unit whose file a package or a
    /// file resource installs. A create takes over such an object that appeared during
    /// its run, and a delete undoes the managed state but leaves the object, so its
    /// evidence is accepted with the object still present (JDD 0007).
    pub made_elsewhere: bool,
    /// How a bound resource of this type becomes an inventory target, when it does
    /// (JDD 0015, "Produced targets").
    pub target: Option<TargetMapping>,
    /// One sentence for generated documentation.
    pub description: Arc<str>,
}

impl ResourceSchema {
    /// The field named `name`.
    pub fn field(&self, name: &str) -> Option<&FieldSchema> {
        self.fields.iter().find(|f| &*f.name == name)
    }

    /// The output named `name`.
    pub fn output(&self, name: &str) -> Option<&OutputSchema> {
        self.outputs.iter().find(|o| &*o.name == name)
    }

    /// The names of the owned fields: the ownership mask of every resource of this type.
    pub fn owned(&self) -> Vec<Arc<str>> {
        self.fields.iter().filter(|f| f.owned).map(|f| f.name.clone()).collect()
    }

    /// The JSON descriptor form.
    pub fn to_json(&self) -> Json {
        let mut o = Object::new();
        o.insert("type".into(), Json::String(self.type_name.to_string()));
        o.insert("version".into(), Json::from(self.version));
        o.insert("description".into(), Json::String(self.description.to_string()));
        if self.adopts {
            o.insert("adopts".into(), Json::Bool(true));
        }
        if self.retain_on_delete {
            o.insert("retain_on_delete".into(), Json::Bool(true));
        }
        if self.made_elsewhere {
            o.insert("made_elsewhere".into(), Json::Bool(true));
        }
        if let Some(target) = &self.target {
            o.insert("target".into(), target.to_json());
        }
        o.insert("fields".into(), Json::Array(self.fields.iter().map(field_json).collect()));
        let outputs = self.outputs.iter().map(|out| {
            let mut o = Object::new();
            o.insert("name".into(), Json::String(out.name.to_string()));
            o.insert("type".into(), Json::String(out.ty.to_string()));
            o.insert("description".into(), Json::String(out.description.to_string()));
            Json::Object(o)
        });
        o.insert("outputs".into(), Json::Array(outputs.collect()));
        Json::Object(o)
    }

    /// Reads the JSON descriptor form.
    pub fn from_json(json: &Json) -> Result<ResourceSchema, Problem> {
        let outputs = array(json, "outputs")?
            .iter()
            .map(|o| {
                Ok(OutputSchema {
                    name: text(o, "name")?,
                    ty: ty(o)?,
                    description: text(o, "description")?,
                })
            })
            .collect::<Result<_, Problem>>()?;
        Ok(ResourceSchema {
            type_name: text(json, "type")?,
            version: json.get("version").and_then(Json::as_u64).unwrap_or(1) as u32,
            fields: array(json, "fields")?
                .iter()
                .map(field_from_json)
                .collect::<Result<_, _>>()?,
            outputs,
            adopts: json.get("adopts").and_then(Json::as_bool).unwrap_or(false),
            retain_on_delete: json
                .get("retain_on_delete")
                .and_then(Json::as_bool)
                .unwrap_or(false),
            made_elsewhere: json.get("made_elsewhere").and_then(Json::as_bool).unwrap_or(false),
            target: json.get("target").map(TargetMapping::from_json).transpose()?,
            description: text(json, "description")?,
        })
    }
}

/// Where one field of a produced target comes from (JDD 0015, "Produced targets").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldSource {
    /// A verified property of the bound resource.
    Property(Arc<str>),
    /// An output of the resource's latest matching observation.
    Output(Arc<str>),
    /// A fixed text.
    Literal(Arc<str>),
}

impl FieldSource {
    /// The descriptor spelling: `property:NAME`, `output:NAME` or `literal:TEXT`.
    pub fn spelling(&self) -> String {
        match self {
            FieldSource::Property(n) => format!("property:{n}"),
            FieldSource::Output(n) => format!("output:{n}"),
            FieldSource::Literal(t) => format!("literal:{t}"),
        }
    }

    /// The source spelled `text`, or `None` when it has no known prefix or no name.
    pub fn parse(text: &str) -> Option<FieldSource> {
        let (kind, rest) = text.split_once(':')?;
        let rest: Arc<str> = Arc::from(rest);
        match kind {
            "property" if !rest.is_empty() => Some(FieldSource::Property(rest)),
            "output" if !rest.is_empty() => Some(FieldSource::Output(rest)),
            "literal" => Some(FieldSource::Literal(rest)),
            _ => None,
        }
    }
}

/// How a bound resource becomes an inventory target: where each target field comes
/// from. Only `address` is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetMapping {
    /// The target's name; the resource's name when absent.
    pub name: Option<FieldSource>,
    /// `ssh`, or `local` for a target pinned to the worker its address names.
    pub transport: Option<FieldSource>,
    /// The host name or address, or the worker of a pinned local target.
    pub address: FieldSource,
    /// The SSH port.
    pub port: Option<FieldSource>,
    /// The login.
    pub user: Option<FieldSource>,
    /// The pinned host key.
    pub host_key: Option<FieldSource>,
    /// A local target's sandbox root.
    pub root: Option<FieldSource>,
    /// A map of labels.
    pub labels: Option<FieldSource>,
}

/// The optional fields of a target mapping, in descriptor order.
const MAPPED: &[&str] = &["name", "transport", "port", "user", "host_key", "root", "labels"];

impl TargetMapping {
    /// The optional fields with their sources, in descriptor order.
    fn optional(&self) -> [(&'static str, &Option<FieldSource>); 7] {
        [
            ("name", &self.name),
            ("transport", &self.transport),
            ("port", &self.port),
            ("user", &self.user),
            ("host_key", &self.host_key),
            ("root", &self.root),
            ("labels", &self.labels),
        ]
    }

    /// The JSON descriptor form.
    pub fn to_json(&self) -> Json {
        let mut o = Object::new();
        o.insert("address".into(), Json::String(self.address.spelling()));
        for (key, source) in self.optional() {
            if let Some(source) = source {
                o.insert(key.into(), Json::String(source.spelling()));
            }
        }
        Json::Object(o)
    }

    /// Reads the JSON descriptor form; an unknown key or spelling is refused.
    pub fn from_json(json: &Json) -> Result<TargetMapping, Problem> {
        let object = json.as_object().ok_or_else(|| mapping_problem("is not an object"))?;
        if let Some(key) = object.keys().find(|k| *k != "address" && !MAPPED.contains(&k.as_str()))
        {
            return Err(mapping_problem(&format!("has the unknown key `{key}`")));
        }
        let field = |key: &str| -> Result<Option<FieldSource>, Problem> {
            match json.get(key) {
                None => Ok(None),
                Some(v) => v.as_str().and_then(FieldSource::parse).map(Some).ok_or_else(|| {
                    mapping_problem(&format!(
                        "spells `{key}` without `property:`, `output:` or `literal:`"
                    ))
                }),
            }
        };
        Ok(TargetMapping {
            name: field("name")?,
            transport: field("transport")?,
            address: field("address")?.ok_or_else(|| mapping_problem("has no `address`"))?,
            port: field("port")?,
            user: field("user")?,
            host_key: field("host_key")?,
            root: field("root")?,
            labels: field("labels")?,
        })
    }
}

fn mapping_problem(what: &str) -> Problem {
    Problem::new(
        "jlv.descriptor.target",
        "INVALID TARGET MAPPING",
        &format!("A resource schema's target mapping {what}."),
    )
    .consequence("The descriptor was not read.")
    .hint("Use a plugin release built for this jlvd version.")
}

/// How an imperative action may be repeated (JDD 0002, "Declarative deployments and
/// imperative operations").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repeatability {
    /// It changes nothing; it may always run again.
    ReadOnly,
    /// Running it again has the same effect as running it once.
    Idempotent,
    /// The provider deduplicates it by a request token we keep.
    IdempotencyToken,
    /// A second run is a second effect; a lost result blocks replay.
    NonRepeatable,
}

impl Repeatability {
    /// The descriptor spelling.
    pub fn name(self) -> &'static str {
        match self {
            Repeatability::ReadOnly => "read_only",
            Repeatability::Idempotent => "idempotent",
            Repeatability::IdempotencyToken => "idempotency_token",
            Repeatability::NonRepeatable => "non_repeatable",
        }
    }

    /// The repeatability spelled `name`.
    pub fn named(name: &str) -> Option<Repeatability> {
        match name {
            "read_only" => Some(Repeatability::ReadOnly),
            "idempotent" => Some(Repeatability::Idempotent),
            "idempotency_token" => Some(Repeatability::IdempotencyToken),
            "non_repeatable" => Some(Repeatability::NonRepeatable),
            _ => None,
        }
    }
}

/// The schema of one imperative action kind, such as `service_restart`.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionSchema {
    /// The kind.
    pub kind: Arc<str>,
    /// The arguments.
    pub args: Vec<FieldSchema>,
    /// How it may be repeated.
    pub repeatability: Repeatability,
    /// One sentence for generated documentation.
    pub description: Arc<str>,
}

fn field_json(f: &FieldSchema) -> Json {
    let mut o = Object::new();
    o.insert("name".into(), Json::String(f.name.to_string()));
    o.insert("type".into(), Json::String(f.ty.to_string()));
    o.insert("required".into(), Json::Bool(f.required));
    if let Some(default) = &f.default {
        o.insert("default".into(), canonical::to_json(default));
    }
    for (key, flag) in [
        ("owned", f.owned),
        ("replace", f.replace),
        ("sensitive", f.sensitive),
        ("trigger", f.trigger),
    ] {
        o.insert(key.into(), Json::Bool(flag));
    }
    o.insert("description".into(), Json::String(f.description.to_string()));
    Json::Object(o)
}

fn field_from_json(json: &Json) -> Result<FieldSchema, Problem> {
    let flag = |key: &str| json.get(key).and_then(Json::as_bool).unwrap_or(false);
    let default = match json.get("default") {
        Some(d) => Some(canonical::from_json(d)?),
        None => None,
    };
    Ok(FieldSchema {
        name: text(json, "name")?,
        ty: ty(json)?,
        required: flag("required"),
        default,
        owned: flag("owned"),
        replace: flag("replace"),
        sensitive: flag("sensitive"),
        trigger: flag("trigger"),
        description: text(json, "description")?,
    })
}

fn invalid(what: &str) -> Problem {
    Problem::new("jlv.schema.invalid", "INVALID SCHEMA", &format!("The schema descriptor {what}."))
        .consequence("The descriptor was not read.")
        .hint("Regenerate the descriptor with `jlvd plugin build`.")
}

fn text(json: &Json, key: &str) -> Result<Arc<str>, Problem> {
    json.get(key)
        .and_then(Json::as_str)
        .map(Arc::from)
        .ok_or_else(|| invalid(&format!("has no text `{key}`")))
}

fn array<'a>(json: &'a Json, key: &str) -> Result<&'a Vec<Json>, Problem> {
    json.get(key).and_then(Json::as_array).ok_or_else(|| invalid(&format!("has no list `{key}`")))
}

fn ty(json: &Json) -> Result<Type, Problem> {
    let spelled = text(json, "type")?;
    Type::parse(&spelled).ok_or_else(|| invalid(&format!("has the unreadable type `{spelled}`")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptors_round_trip() {
        let schema = ResourceSchema {
            type_name: "host.file".into(),
            version: 1,
            fields: vec![
                FieldSchema::owned("path", Type::Text, "Absolute path.").replacing(),
                FieldSchema::owned("mode", Type::Text, "Octal mode.")
                    .defaulted(Value::text("0644")),
                FieldSchema::owned("secret", Type::nominal("SecretRef"), "Secret.").sensitive(),
                FieldSchema::owned(
                    "restart_on",
                    Type::list(Type::nominal("ResourceRef")),
                    "Triggers.",
                )
                .trigger(),
            ],
            outputs: vec![OutputSchema {
                name: "digest".into(),
                ty: Type::Text,
                description: "Content.".into(),
            }],
            adopts: false,
            retain_on_delete: false,
            made_elsewhere: false,
            target: None,
            description: "A file on a host.".into(),
        };
        assert_eq!(ResourceSchema::from_json(&schema.to_json()).unwrap(), schema);
        assert!(schema.to_json().get("target").is_none(), "no mapping, no key, same digest");
        assert_eq!(schema.owned().len(), 3);
        assert!(schema.field("secret").unwrap().sensitive);
    }

    /// PRD-01: a target mapping round-trips, and a mapping that is not understood is
    /// refused rather than half-read.
    #[test]
    fn target_mappings_round_trip_and_refuse_unknown_spellings() {
        let mapping = TargetMapping {
            name: Some(FieldSource::Property("hostname".into())),
            transport: Some(FieldSource::Literal("ssh".into())),
            address: FieldSource::Output("address".into()),
            port: None,
            user: Some(FieldSource::Output("user".into())),
            host_key: Some(FieldSource::Output("host_key".into())),
            root: None,
            labels: Some(FieldSource::Property("labels".into())),
        };
        let json = mapping.to_json();
        assert_eq!(json.get("address").and_then(Json::as_str), Some("output:address"));
        assert_eq!(TargetMapping::from_json(&json).unwrap(), mapping);
        for bad in [
            r#"{"port": "output:port"}"#,
            r#"{"address": "column:address"}"#,
            r#"{"address": "output:"}"#,
            r#"{"address": "output:a", "sudo": "literal:true"}"#,
        ] {
            let error = TargetMapping::from_json(&gd_json::parse(bad).unwrap()).unwrap_err();
            assert_eq!(error.code, "jlv.descriptor.target", "{bad}");
        }
    }
}
