//! The daemon's side of the hooks (SID 0030): the table of native hooks, the request
//! stage, the telemetry stage and what the operator reads about them.
//!
//! Each thread that serves traffic owns its instances of the hooks, in a thread-local
//! [`Local`]. A request takes no lock here. Without a hook at a stage the caller has
//! already returned after one atomic load ([`Slot::has`]).

use std::cell::RefCell;
use std::fmt::Write as _;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use sibuna_plugin::{
    Constructor, Edits, Failure, Field, Hook, Local, MAX_ADDED_BYTES, MAX_ADDED_FIELDS, Native,
    PluginStatus, Protocol, Slot, Stage, Verdict, View,
};

use crate::access::Entry;
use crate::context::Ctx;
use crate::dispatch;

thread_local! {
    /// This thread's instances: Wasm memories, agent connections and breakers.
    static LOCAL: RefCell<Local> = RefCell::new(Local::new());
}

/// The native hooks of this build. A hook is added here, at build time.
pub(crate) const NATIVES: [Native; 1] =
    [Native { name: "require_header", build: require_header as Constructor }];

/// Admits a request that carries the field `name`, with the value `value` when one is
/// set. Every other request is denied. It judges requests only.
struct RequireHeader {
    name: Box<[u8]>,
    value: Option<Box<[u8]>>,
}

impl Hook for RequireHeader {
    fn on_request(&mut self, view: &View<'_>, _: &mut Edits) -> Result<Verdict, Failure> {
        let found = match (view.field(&self.name), &self.value) {
            (Some(found), Some(wanted)) => found == &wanted[..],
            (Some(_), None) => true,
            (None, _) => false,
        };
        Ok(if found { Verdict::Admit } else { Verdict::Deny })
    }
}

/// Builds `require_header` from the settings `name` and, optionally, `value`.
fn require_header(settings: &[(String, String)]) -> Result<Box<dyn Hook>, String> {
    let (mut name, mut value) = (None, None);
    for (key, text) in settings {
        match key.as_str() {
            "name" => name = Some(text.as_bytes().into()),
            "value" => value = Some(text.as_bytes().into()),
            other => return Err(format!("require_header has no setting `{other}`")),
        }
    }
    let name: Box<[u8]> = name.ok_or("require_header needs the setting `name`")?;
    if name.is_empty() {
        return Err("require_header: `name` is empty".to_owned());
    }
    Ok(Box::new(RequireHeader { name, value }))
}

/// The room for the field lines that the hooks of one request add.
const ADDED_CAPACITY: usize = MAX_ADDED_BYTES + 4 * MAX_ADDED_FIELDS;

/// What the request hooks decided, copied out of the thread's instances.
enum Judged {
    /// Admitted, with this many bytes of field lines.
    Admit(usize),
    /// Denied or challenged by the hook that the verdict names as `hook:NAME`.
    Refused(dispatch::Verdict),
}

/// The protocol of a request as the hooks name it.
fn protocol_of(name: &str) -> Protocol {
    match name {
        "h2" => Protocol::Http2,
        "h3" => Protocol::Http3,
        _ => Protocol::Http1,
    }
}

const NOWHERE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

/// Runs the request hooks of the frontend of `ctx`. The field lines of an admission
/// are copied to `added`.
fn judge<W: Write>(ctx: &Ctx<'_, W>, slot: &Slot, added: &mut [u8; ADDED_CAPACITY]) -> Judged {
    let Some(ingress) = ctx.ingress else { return Judged::Admit(0) };
    let front = match (&ctx.trace.front, &ctx.server.edge_routes) {
        (Some(front), _) => Some(front.clone()),
        (None, Some(routes)) => routes.frontend(ingress.vip),
        (None, None) => None,
    };
    let Some(front) = front else { return Judged::Admit(0) };
    let mut fields = [Field { name: b"", value: b"" }; sibuna_http::MAX_HEADERS];
    let mut count = 0;
    for (slot, header) in fields.iter_mut().zip(ctx.request.headers()) {
        *slot = Field { name: header.name, value: header.value };
        count += 1;
    }
    // The address the firewall judges by. A proxy names no port for its client.
    let client = match ctx.client_address {
        Some(address) if address != ingress.peer.ip() => SocketAddr::new(address, 0),
        _ => ingress.peer,
    };
    let view = View {
        stage: Stage::Request,
        protocol: protocol_of(ctx.trace.protocol),
        secure: ingress.secure,
        client,
        local: ingress.vip,
        frontend: &front.name,
        ja4: ctx.ja4.map_or(b"", |ja4| ja4.as_bytes()),
        method: ctx.request.method_text,
        host: ctx.request.header(b"host").unwrap_or_default(),
        path: ctx.request.path,
        query: ctx.request.query,
        fields: fields.get(..count).unwrap_or_default(),
        ..View::default()
    };
    // A session that paid for the challenge of a hook clears it, as it clears the
    // challenge of a rule. The hooks behind that one still judge the request.
    let mut clears = |name: &str| {
        let verdict = dispatch::Verdict::hook(name, sibuna_policy::Action::Challenge);
        crate::challenge::session_rule_hash(ctx, &verdict).is_some()
    };
    LOCAL.with_borrow_mut(|local| {
        let decision = local.run_clearing(slot, &view, &mut clears);
        match decision.verdict {
            Verdict::Admit => {
                let lines = decision.added.get(..ADDED_CAPACITY).unwrap_or(decision.added);
                added[..lines.len()].copy_from_slice(lines);
                Judged::Admit(lines.len())
            }
            Verdict::Deny => Judged::Refused(dispatch::Verdict::hook(
                decision.hook,
                sibuna_policy::Action::Deny,
            )),
            Verdict::Challenge => Judged::Refused(dispatch::Verdict::hook(
                decision.hook,
                sibuna_policy::Action::Challenge,
            )),
        }
    })
}

/// Hands a request that the firewall admitted to the request hooks of its frontend,
/// and then to the origin, or answers for the hook that refused it. The arguments and
/// the result are those of [`dispatch::forward`].
pub(crate) fn forward<W: Write>(
    ctx: &mut Ctx<'_, W>,
    slot: &Slot,
    status: &str,
    rule_name: &str,
    rule_hash: u64,
) -> io::Result<bool> {
    let mut added = [0u8; ADDED_CAPACITY];
    match judge(ctx, slot, &mut added) {
        Judged::Admit(length) => {
            let lines = added.get(..length).unwrap_or_default();
            dispatch::forward_admitted(ctx, status, rule_name, rule_hash, lines)
        }
        Judged::Refused(verdict) => dispatch::refuse(ctx, &verdict),
    }
}

/// Shows a request whose answer ended to the telemetry hooks of its frontend. The
/// hooks observe only: whatever they do, the request is already answered.
pub(crate) fn observe(slot: &Slot, entry: &Entry) {
    let Some(front) = &entry.frontend else { return };
    let client = std::str::from_utf8(entry.client()).ok().and_then(|text| text.parse().ok());
    let micros = u32::try_from(entry.elapsed.as_micros()).unwrap_or(u32::MAX);
    let view = View {
        stage: Stage::Telemetry,
        protocol: protocol_of(entry.protocol),
        secure: entry.secure,
        client: client.map_or(NOWHERE, |address| SocketAddr::new(address, 0)),
        local: entry.vip.unwrap_or(NOWHERE),
        frontend: &front.name,
        method: entry.method(),
        host: entry.host(),
        path: entry.path(),
        status: entry.status,
        duration_us: micros,
        ..View::default()
    };
    // A thread that is ending has no instances any more: its last sample is dropped.
    let _ = LOCAL.try_with(|local| {
        if let Ok(mut local) = local.try_borrow_mut() {
            local.run(slot, &view);
        }
    });
}

/// The answer to `show hooks`: one line per plugin under a header.
pub(crate) fn render_status(plugins: &[PluginStatus]) -> String {
    let mut text = String::from(
        "# name tier on_failure calls admitted denied challenged timeout overload trap \
         unavailable dropped refused_fields open_breakers\n",
    );
    for plugin in plugins {
        let [timeout, overload, trap, unavailable] = plugin.failures;
        let on_failure = match plugin.on_failure {
            sibuna_plugin::OnFailure::Deny => "deny",
            sibuna_plugin::OnFailure::Admit => "admit",
        };
        // Writing to a string cannot fail.
        let _ = writeln!(
            text,
            "{} {} {on_failure} {} {} {} {} {timeout} {overload} {trap} {unavailable} {} {} {}",
            plugin.name,
            plugin.tier,
            plugin.calls,
            plugin.admitted,
            plugin.denied,
            plugin.challenged,
            plugin.dropped,
            plugin.refused_fields,
            plugin.open_breakers,
        );
    }
    text
}

/// Writes the series of the plugins in the Prometheus text format. Without a plugin
/// it writes nothing.
pub(crate) fn write_prometheus(plugins: &[PluginStatus], out: &mut String) {
    if plugins.is_empty() {
        return;
    }
    let _ = writeln!(out, "# TYPE sibuna_edge_hook_calls_total counter");
    for plugin in plugins {
        let (name, tier) = (&plugin.name, plugin.tier);
        let verdicts = [
            ("admit", plugin.admitted),
            ("deny", plugin.denied),
            ("challenge", plugin.challenged),
        ];
        for (result, count) in verdicts {
            let _ = writeln!(
                out,
                "sibuna_edge_hook_calls_total{{plugin=\"{name}\",tier=\"{tier}\",\
                 result=\"{result}\"}} {count}"
            );
        }
        for (failure, count) in Failure::ALL.iter().zip(plugin.failures) {
            let _ = writeln!(
                out,
                "sibuna_edge_hook_calls_total{{plugin=\"{name}\",tier=\"{tier}\",\
                 result=\"{}\"}} {count}",
                failure.name()
            );
        }
    }
    let gauges = [
        ("sibuna_edge_hook_samples_dropped_total", "counter"),
        ("sibuna_edge_hook_fields_refused_total", "counter"),
        ("sibuna_edge_hook_breakers_open", "gauge"),
    ];
    for (index, (series, kind)) in gauges.into_iter().enumerate() {
        let _ = writeln!(out, "# TYPE {series} {kind}");
        for plugin in plugins {
            let value = match index {
                0 => plugin.dropped,
                1 => plugin.refused_fields,
                _ => u64::from(plugin.open_breakers),
            };
            let _ = writeln!(out, "{series}{{plugin=\"{}\"}} {value}", plugin.name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter().map(|(key, value)| ((*key).to_owned(), (*value).to_owned())).collect()
    }

    fn judged(hook: &mut dyn Hook, fields: &[Field<'_>]) -> Verdict {
        let view = View { stage: Stage::Request, fields, ..View::default() };
        hook.on_request(&view, &mut Edits::default()).unwrap_or(Verdict::Deny)
    }

    #[test]
    fn require_header_admits_the_field_and_the_value_it_asks_for() {
        let Ok(mut any) = require_header(&pairs(&[("name", "X-Token")])) else { panic!() };
        let token = [Field { name: b"x-token", value: b"abc" }];
        assert_eq!(judged(any.as_mut(), &token), Verdict::Admit);
        assert_eq!(judged(any.as_mut(), &[]), Verdict::Deny);
        let settings = pairs(&[("name", "x-token"), ("value", "abc")]);
        let Ok(mut exact) = require_header(&settings) else { panic!() };
        assert_eq!(judged(exact.as_mut(), &token), Verdict::Admit);
        let other = [Field { name: b"X-Token", value: b"abd" }];
        assert_eq!(judged(exact.as_mut(), &other), Verdict::Deny);
    }

    #[test]
    fn require_header_refuses_settings_it_does_not_know() {
        assert!(require_header(&[]).is_err());
        assert!(require_header(&pairs(&[("name", "")])).is_err());
        assert!(require_header(&pairs(&[("name", "a"), ("colour", "red")])).is_err());
    }

    #[test]
    fn the_status_table_and_the_series_name_every_plugin() {
        let plugin = PluginStatus {
            name: "authz".to_owned(),
            tier: "agent",
            on_failure: sibuna_plugin::OnFailure::Deny,
            calls: 9,
            admitted: 4,
            denied: 2,
            challenged: 1,
            failures: [1, 0, 0, 1],
            dropped: 3,
            refused_fields: 5,
            open_breakers: 2,
        };
        let table = render_status(std::slice::from_ref(&plugin));
        assert!(table.ends_with("authz agent deny 9 4 2 1 1 0 0 1 3 5 2\n"), "{table}");
        let mut series = String::new();
        write_prometheus(&[], &mut series);
        assert!(series.is_empty());
        write_prometheus(&[plugin], &mut series);
        let call = "sibuna_edge_hook_calls_total{plugin=\"authz\",tier=\"agent\",";
        assert!(series.contains(&format!("{call}result=\"deny\"}} 2")), "{series}");
        assert!(series.contains(&format!("{call}result=\"unavailable\"}} 1")));
        assert!(series.contains("sibuna_edge_hook_breakers_open{plugin=\"authz\"} 2"));
    }
}
