//! Compile named frontend ACLs to an ordered decision list.
use std::collections::BTreeMap;
use std::io::Result;

use sibuna_json::{ObjectReader, Value};
use sibuna_policy::ja4::{Fingerprint, Pattern};

use crate::config::{Backend, Protocol, field, invalid, required};
use crate::hello::{Hello, valid_host};

#[derive(Clone)]
enum Match {
    Sni(String),
    Alpn(String),
    Ja4(Pattern),
}

pub(crate) struct Rule {
    test: Match,
    backend: Option<std::sync::Arc<str>>,
}

pub(crate) fn select<'a>(
    rules: &'a [Rule],
    hello: &Hello<'_>,
    default: &'a std::sync::Arc<str>,
) -> Option<&'a std::sync::Arc<str>> {
    for rule in rules {
        let matches = match &rule.test {
            Match::Sni(host) => hello.sni.is_some_and(|sni| sni.eq_ignore_ascii_case(host)),
            Match::Ja4(pattern) => {
                let bytes = hello.ja4.get_or_init(|| crate::ja4::fingerprint(hello));
                pattern.matches(bytes.as_ref().and_then(|b| Fingerprint::parse(b)))
            }
            Match::Alpn(protocol) => hello.offers(protocol.as_bytes()),
        };
        if matches {
            return rule.backend.as_ref();
        }
    }
    Some(default)
}

pub(crate) fn parse(
    reader: &mut ObjectReader<'_, '_>,
    pools: &BTreeMap<String, Backend>,
) -> Result<Vec<Rule>> {
    let mut acls = BTreeMap::new();
    if let Some(value) = reader.take("acls") {
        let map = value.as_object().ok_or_else(|| invalid(reader.field_path("acls")))?;
        for (name, value) in map {
            let path = format!("{}.{name}", reader.field_path("acls"));
            let mut r = field(ObjectReader::with_path(value, path.clone()))?;
            let criterion = match (
                field(r.take_str("sni"))?,
                field(r.take_str("alpn"))?,
                field(r.take_str("ja4_prefix"))?,
            ) {
                (Some(host), None, None) if valid_host(host) => Match::Sni(host.into()),
                (None, Some(alpn), None) if (1..=255).contains(&alpn.len()) => {
                    Match::Alpn(alpn.into())
                }
                (None, None, Some(text)) => Match::Ja4(
                    Pattern::parse(text.as_bytes())
                        .ok_or_else(|| invalid(format!("{path}: invalid JA4 pattern")))?,
                ),
                _ => {
                    return Err(invalid(format!(
                        "{path}: expected one SNI, ALPN or JA4 criterion"
                    )));
                }
            };
            field(r.finish())?;
            acls.insert(name, criterion);
        }
    }
    let mut rules = Vec::new();
    for (i, value) in field(reader.take_array("rules"))?.unwrap_or(&[]).iter().enumerate() {
        let path = format!("{}[{i}]", reader.field_path("rules"));
        rules.push(rule(value, path, &acls, pools)?);
    }
    Ok(rules)
}

fn rule(
    value: &Value<'_>,
    path: String,
    acls: &BTreeMap<&str, Match>,
    pools: &BTreeMap<String, Backend>,
) -> Result<Rule> {
    let mut r = field(ObjectReader::with_path(value, path.clone()))?;
    let name = required(&mut r, "when")?;
    let test = acls.get(name.as_str()).ok_or_else(|| invalid(format!("{path}: unknown ACL")))?;
    let backend = match required(&mut r, "action")?.as_str() {
        "deny" => None,
        "use_backend" => {
            let backend = required(&mut r, "backend")?;
            if !pools.get(&backend).is_some_and(|b| b.protocol == Protocol::Tcp) {
                return Err(invalid(format!("{path}: unknown TCP backend {backend}")));
            }
            Some(backend.into())
        }
        _ => return Err(invalid(format!("{path}: unknown routing action"))),
    };
    field(r.finish())?;
    Ok(Rule { test: test.clone(), backend })
}
