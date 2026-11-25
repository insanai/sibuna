//! Reads the `plugins` object and the `hooks` of a frontend (SID 0030) into the plain
//! settings of `sibuna-plugin`. The bounds of the numbers are checked where the plugins
//! are loaded, so they live in one place.

use std::io::Result;

use sibuna_json::{ObjectReader, Value};
use sibuna_plugin::{
    AgentSpec, Attach, BreakerLimits, JudgeOptions, Kind, MAX_PLUGINS, MAX_STAGE_HOOKS, OnFailure,
    Settings, Spec, Stage, WasmSpec,
};

use crate::config::{Protocol, duration, field, invalid, required};

/// Reads the root object `plugins`. A topology without it has no plugins.
pub(crate) fn plugins(root: &mut ObjectReader<'_, '_>) -> Result<Vec<Spec>> {
    let Some(value) = root.take("plugins") else { return Ok(Vec::new()) };
    let entries = value.as_object().filter(|entries| entries.len() <= MAX_PLUGINS);
    let entries = entries.ok_or_else(|| {
        invalid(format!("plugins must be an object of at most {MAX_PLUGINS} named plugins"))
    })?;
    entries.iter().map(|(name, value)| plugin(name, value)).collect()
}

/// Reads the root object `hook_judges`: the threads that decide parked connections
/// and their queue. The bounds are checked where the plugins are loaded.
pub(crate) fn judges(root: &mut ObjectReader<'_, '_>) -> Result<JudgeOptions> {
    let mut options = JudgeOptions::default();
    let Some(mut r) = field(root.take_object("hook_judges"))? else { return Ok(options) };
    if let Some(threads) = field(r.take_u64("threads"))? {
        options.threads = small(&r, "threads", threads)?;
    }
    if let Some(queue) = field(r.take_u64("queue"))? {
        options.queue = small(&r, "queue", queue)?;
    }
    field(r.finish())?;
    Ok(options)
}

fn plugin(name: &str, value: &Value<'_>) -> Result<Spec> {
    let path = format!("plugins.{name}");
    if name.is_empty() || name.len() > 64 || !name.bytes().all(is_name_byte) {
        return Err(invalid(format!(
            "{path}: a plugin name has 1 to 64 letters, digits, `-`, `_` or `.`"
        )));
    }
    let mut r = field(ObjectReader::with_path(value, path.clone()))?;
    let on_failure = match field(r.take_str("on_failure"))? {
        None | Some("deny") => OnFailure::Deny,
        Some("admit") => OnFailure::Admit,
        Some(_) => return Err(invalid(format!("{path}.on_failure must be deny or admit"))),
    };
    let kind = match required(&mut r, "kind")?.as_str() {
        "native" => native(&mut r)?,
        "wasm" => wasm(&mut r)?,
        "agent" => agent(&mut r)?,
        _ => return Err(invalid(format!("{path}.kind must be native, wasm or agent"))),
    };
    field(r.finish())?;
    Ok(Spec { name: name.to_owned(), on_failure, kind })
}

fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

/// A native plugin: the hook of the daemon's table and its settings as text.
fn native(r: &mut ObjectReader<'_, '_>) -> Result<Kind> {
    let hook = required(r, "hook")?;
    let mut settings = Vec::new();
    if let Some(value) = r.take("settings") {
        let path = r.field_path("settings");
        let entries = value.as_object().filter(|entries| entries.len() <= 32);
        let entries = entries
            .ok_or_else(|| invalid(format!("{path} must be an object of at most 32 entries")))?;
        for (key, value) in entries {
            let text = match value {
                Value::String(text) => text.to_string(),
                Value::Bool(flag) => flag.to_string(),
                Value::Number(number) => number.as_str().to_owned(),
                _ => {
                    return Err(invalid(format!("{path}.{key} must be text, a number or a flag")));
                }
            };
            settings.push((key.to_string(), text));
        }
    }
    Ok(Kind::Native { hook, settings })
}

fn wasm(r: &mut ObjectReader<'_, '_>) -> Result<Kind> {
    let mut spec = WasmSpec { module: required(r, "module")?, ..WasmSpec::default() };
    if let Some(fuel) = field(r.take_u64("fuel_limit"))? {
        spec.fuel_limit = fuel;
    }
    if let Some(pages) = field(r.take_u64("memory_pages"))? {
        spec.memory_pages = small(r, "memory_pages", pages)?;
    }
    if let Some(calls) = field(r.take_u64("host_calls"))? {
        spec.host_calls = small(r, "host_calls", calls)?;
    }
    Ok(Kind::Wasm(spec))
}

fn agent(r: &mut ObjectReader<'_, '_>) -> Result<Kind> {
    let mut spec = AgentSpec { socket: required(r, "socket")?, ..AgentSpec::default() };
    if let Some(text) = field(r.take_str("deadline"))? {
        spec.deadline_ms = millis(r, "deadline", text)?;
    }
    if let Some(queue) = field(r.take_u64("queue"))? {
        spec.queue = small(r, "queue", queue)?;
    }
    if let Some(mut breaker) = field(r.take_object("breaker"))? {
        let mut limits = BreakerLimits::default();
        if let Some(failures) = field(breaker.take_u64("failures"))? {
            limits.failures = small(&breaker, "failures", failures)?;
        }
        if let Some(text) = field(breaker.take_str("open"))? {
            limits.open_ms = millis(&breaker, "open", text)?;
        }
        field(breaker.finish())?;
        spec.breaker = limits;
    }
    Ok(Kind::Agent(spec))
}

fn small(r: &ObjectReader<'_, '_>, key: &str, value: u64) -> Result<u32> {
    u32::try_from(value).map_err(|_| invalid(format!("{} is too large", r.field_path(key))))
}

fn millis(r: &ObjectReader<'_, '_>, key: &str, text: &str) -> Result<u64> {
    let parsed = duration(text).ok_or_else(|| {
        invalid(format!("{} must be a duration such as 5ms or 1s", r.field_path(key)))
    })?;
    Ok(parsed.as_millis() as u64)
}

/// Reads the `hooks` object of the frontend `name` into `settings`. Each stage lists
/// plugins of the topology in the order they run. A TCP or UDP frontend has the
/// connection stage only.
pub(crate) fn attach(
    r: &mut ObjectReader<'_, '_>,
    name: &str,
    proto: Protocol,
    settings: &mut Settings,
) -> Result<()> {
    let Some(mut hooks) = field(r.take_object("hooks"))? else { return Ok(()) };
    let known = &settings.plugins;
    let mut attach = Attach::default();
    for stage in Stage::ALL {
        let Some(names) = field(hooks.take_array(stage.name()))? else { continue };
        let path = hooks.field_path(stage.name());
        if stage != Stage::Connection && proto != Protocol::Http {
            return Err(invalid(format!("{path}: only an HTTP frontend has this stage")));
        }
        if names.len() > MAX_STAGE_HOOKS {
            return Err(invalid(format!("{path}: at most {MAX_STAGE_HOOKS} hooks per stage")));
        }
        let mut list = Vec::with_capacity(names.len());
        for value in names {
            let name = value.as_str().unwrap_or("");
            if !known.iter().any(|spec| spec.name == name) {
                return Err(invalid(format!("{path}: no plugin is named {name:?}")));
            }
            if list.iter().any(|listed| listed == name) {
                return Err(invalid(format!("{path}: {name:?} is listed twice")));
            }
            list.push(name.to_owned());
        }
        match stage {
            Stage::Connection => attach.connection = list,
            Stage::Request => attach.request = list,
            Stage::Telemetry => attach.telemetry = list,
        }
    }
    field(hooks.finish())?;
    if attach != Attach::default() {
        settings.frontends.push((name.to_owned(), attach));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sibuna_plugin::{Kind, OnFailure};

    use crate::Config;

    fn topology(plugins: &str, hooks: &str, proto: &str) -> String {
        format!(
            r#"{{"plugins":{plugins},
            "frontends":{{"web":{{"proto":"{proto}","binds":["127.0.0.1:8080"],"hooks":{hooks}}}}},
            "backends":{{"app":{{"mode":"{proto}",
              "servers":[{{"name":"a","addr":"127.0.0.1:9000"}}]}}}}}}"#
        )
    }

    fn error(plugins: &str, hooks: &str, proto: &str) -> String {
        match Config::parse(topology(plugins, hooks, proto).as_bytes()) {
            Ok(_) => panic!("the topology must be refused"),
            Err(error) => error.to_string(),
        }
    }

    const THREE: &str = r#"{
        "role": {"kind":"native","hook":"require_header","settings":{"name":"x-role","n":3}},
        "geo": {"kind":"wasm","module":"/etc/sibuna/geo.wasm","fuel_limit":50000,
                "memory_pages":8,"host_calls":4,"on_failure":"admit"},
        "authz": {"kind":"agent","socket":"/run/authz.sock","deadline":"20ms","queue":32,
                  "breaker":{"failures":3,"open":"2s"}}}"#;

    #[test]
    fn the_three_kinds_and_the_stages_are_read() {
        let hooks = r#"{"connection":["geo"],"request":["role","authz"],"telemetry":["authz"]}"#;
        let config = Config::parse(topology(THREE, hooks, "http").as_bytes()).unwrap();
        let settings = config.plugins();
        assert_eq!(settings.plugins.len(), 3);
        // The parser keeps the order of the file, whatever it is: we look up by name.
        let by = |name: &str| settings.plugins.iter().find(|spec| spec.name == name).unwrap();
        let Kind::Native { hook, settings: pairs } = &by("role").kind else { panic!() };
        assert_eq!(hook, "require_header");
        assert!(pairs.contains(&("name".to_owned(), "x-role".to_owned())));
        assert!(pairs.contains(&("n".to_owned(), "3".to_owned())));
        let Kind::Wasm(wasm) = &by("geo").kind else { panic!() };
        assert_eq!((wasm.fuel_limit, wasm.memory_pages, wasm.host_calls), (50_000, 8, 4));
        assert_eq!(by("geo").on_failure, OnFailure::Admit);
        let Kind::Agent(agent) = &by("authz").kind else { panic!() };
        assert_eq!((agent.deadline_ms, agent.queue), (20, 32));
        assert_eq!((agent.breaker.failures, agent.breaker.open_ms), (3, 2000));
        assert_eq!(by("authz").on_failure, OnFailure::Deny);
        let (frontend, attach) = &settings.frontends[0];
        assert_eq!(frontend, "web");
        assert_eq!(attach.request, ["role", "authz"]);
        assert_eq!((attach.connection.len(), attach.telemetry.len()), (1, 1));
    }

    #[test]
    fn a_topology_without_plugins_has_empty_settings() {
        let text = topology("{}", "{}", "http");
        let config = Config::parse(text.as_bytes()).unwrap();
        assert!(config.plugins().is_empty() && config.plugins().plugins.is_empty());
    }

    #[test]
    fn mistakes_are_refused_with_their_path() {
        let request = r#"{"request":["role"]}"#;
        assert!(error(THREE, r#"{"request":["ghost"]}"#, "http").contains("no plugin is named"));
        assert!(error(THREE, r#"{"request":["role","role"]}"#, "http").contains("twice"));
        assert!(error(THREE, request, "tcp").contains("only an HTTP frontend"));
        assert!(error(THREE, r#"{"response":["role"]}"#, "http").contains("response"));
        let unknown = r#"{"x":{"kind":"lua","script":"a.lua"}}"#;
        assert!(error(unknown, "{}", "http").contains("plugins.x.kind"));
        let extra = r#"{"x":{"kind":"wasm","module":"a.wasm","wasi":true}}"#;
        assert!(error(extra, "{}", "http").contains("wasi"));
        let outcome = r#"{"x":{"kind":"wasm","module":"a.wasm","on_failure":"open"}}"#;
        assert!(error(outcome, "{}", "http").contains("on_failure"));
        let name = r#"{"bad name":{"kind":"wasm","module":"a.wasm"}}"#;
        assert!(error(name, "{}", "http").contains("plugin name"));
        let deadline = r#"{"x":{"kind":"agent","socket":"/s","deadline":"soon"}}"#;
        assert!(error(deadline, "{}", "http").contains("deadline"));
    }

    #[test]
    fn a_frontend_with_http3_attaches_every_stage() {
        let hooks = r#"{"connection":["geo"],"request":["role"]},
            "tls":{"crt":["site.pem"],"http3":true}"#;
        let config = Config::parse(topology(THREE, hooks, "http").as_bytes()).unwrap();
        assert_eq!(config.plugins().frontends[0].1.connection, ["geo"]);
    }

    #[test]
    fn hook_judges_are_read_and_default_to_four_threads() {
        let config = Config::parse(topology(THREE, "{}", "http").as_bytes()).unwrap();
        assert_eq!((config.plugins().judges.threads, config.plugins().judges.queue), (4, 256));
    }

    #[test]
    fn a_tcp_frontend_attaches_the_connection_stage() {
        let text = topology(THREE, r#"{"connection":["geo"]}"#, "tcp");
        let config = Config::parse(text.as_bytes()).unwrap();
        assert_eq!(config.plugins().frontends[0].1.connection, ["geo"]);
    }
}
