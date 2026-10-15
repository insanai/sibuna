//! The live connection: one WebSocket that survives navigation, its subscriptions and
//! the freshness of each topic.
//!
//! Filters change through complete snapshots: a subscription whose filter changed is
//! re-filtered only after its pending snapshot completes, and a view completed under an
//! old filter is never published under the new one. The connection retries with jittered
//! exponential backoff (1 s doubling to 30 s) and a policy close (1008) or an
//! `unauthorized` message ends the session.

use std::fmt::{self, Write as _};

use sibuna_console_protocol::codec::{Decode, Encode, Path, WireEnum};
use sibuna_console_protocol::dashboard;
use sibuna_console_protocol::subscription_client::{Client, Event};
use sibuna_console_protocol::subscriptions::{Args, TOPIC_COUNT};
use sibuna_console_protocol::{StatsSnapshot, Topic};
use sibuna_html::write_value;
use sibuna_json::Value;

use crate::commands::Commands;
use crate::error::UiError;
use crate::json;
use crate::page::{Context, SESSION_ENDED};
use crate::render::Html;
use crate::secret::Secret;
use crate::state::State;

/// The freshness of one topic, as the pages show it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    /// When the last view arrived, in browser seconds; 0 for never.
    pub received_at: u64,
    /// When the server last observed storage for row topics, in Unix seconds.
    pub observed_at: u64,
    /// Source ids the live feed could not deliver.
    pub missing_ids: u64,
    /// Rows newer than the page's fixed query boundary.
    pub newer: u8,
    /// The server has observations for the topic.
    pub available: bool,
    /// The view is not current.
    pub stale: bool,
}

impl Default for Observation {
    fn default() -> Observation {
        Observation {
            received_at: 0,
            observed_at: 0,
            missing_ids: 0,
            newer: 0,
            available: false,
            stale: true,
        }
    }
}

/// The freshness of every topic, and the policy revisions the `policy` topic reports.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Observations {
    /// One observation per topic, indexed by [`Topic::index`].
    pub topics: [Observation; TOPIC_COUNT],
    /// The committed policy revision.
    pub committed: u64,
    /// The policy revision this node applied.
    pub applied: u64,
}

impl Observations {
    /// Returns the observation of `topic`.
    pub fn topic(&self, topic: Topic) -> &Observation {
        // `Topic::index` is below TOPIC_COUNT by construction.
        &self.topics[topic.index()]
    }

    /// Returns the observation of `topic` for changes.
    pub fn topic_mut(&mut self, topic: Topic) -> &mut Observation {
        &mut self.topics[topic.index()]
    }

    fn mark_stale(&mut self) {
        for topic in &mut self.topics {
            topic.stale = true;
        }
    }
}

/// One topic's subscription as the server knows it.
#[derive(Clone, Debug, Default, PartialEq)]
struct Subscription {
    active: bool,
    /// A snapshot under `args` has not completed yet.
    pending: bool,
    args: Args,
}

/// The connection's lifecycle, owned by the application for the whole page load (the
/// Zig module kept it in module-level variables). A session reset does not touch it;
/// [`Connection::stop`] does.
#[derive(Debug, Default)]
pub struct Connection {
    client: Client,
    subscriptions: [Subscription; TOPIC_COUNT],
    /// The CSRF token of the session that opened the connection.
    principal: Secret<64>,
    connected: bool,
    opening: bool,
    /// A retry timer is pending.
    retry: bool,
    /// Signed out: no connection until the next authentication.
    suspended: bool,
}

impl Connection {
    /// Closes the connection if one is open or opening, and forgets every subscription.
    ///
    /// # Errors
    ///
    /// [`UiError::Write`] if the command cannot be written.
    pub fn stop(&mut self, commands: &mut Commands) -> Result<(), UiError> {
        if self.connected || self.opening {
            commands.disconnect()?;
        }
        *self = Connection::default();
        Ok(())
    }

    /// Stops and stays closed until [`Connection::authenticated`].
    ///
    /// # Errors
    ///
    /// [`UiError::Write`] if the command cannot be written.
    pub fn sign_out(&mut self, commands: &mut Commands) -> Result<(), UiError> {
        self.stop(commands)?;
        self.suspended = true;
        Ok(())
    }

    /// Allows connecting again after a successful authentication.
    pub fn authenticated(&mut self) {
        self.suspended = false;
    }

    /// The retry timer fired; the next synchronisation reconnects.
    pub fn retry_elapsed(&mut self) {
        self.retry = false;
    }
}

/// Returns the filter `topic` should have in `cx`'s state, or `None` for no
/// subscription. A wall display subscribes statistics only.
fn desired(cx: &Context<'_>, topic: Topic) -> Option<Args> {
    let state = &*cx.state;
    if state.kiosk && topic != Topic::Stats {
        return None;
    }
    if topic == Topic::Stats {
        return (!state.paused).then(|| Args { node: state.dashboard_node, ..Args::default() });
    }
    cx.pages.subscription(state, topic)
}

/// Opens, keeps or closes the connection and its subscriptions to match the state. Runs
/// once at the end of every event, with every module registered.
///
/// # Errors
///
/// [`UiError::Write`] if a command cannot be written.
pub(crate) fn sync(cx: &mut Context<'_>) -> Result<(), UiError> {
    if !cx.state.is_full_access() || cx.state.hidden {
        cx.live.stop(cx.commands)?;
        cx.state.live.mark_stale();
        cx.state.stale = true;
        return Ok(());
    }
    if cx.live.suspended {
        return Ok(());
    }
    if !cx.live.principal.is_empty() && cx.live.principal.as_str() != cx.state.csrf.as_str() {
        cx.live.stop(cx.commands)?;
    }
    if !cx.live.connected {
        if cx.live.opening || cx.live.retry {
            return Ok(());
        }
        cx.live.principal = cx.state.csrf.clone();
        cx.live.opening = true;
        return cx.commands.connect("/console/ws");
    }
    for &topic in Topic::ALL {
        let wanted = desired(cx, topic);
        let index = topic.index();
        let current = cx.live.subscriptions[index].clone();
        if wanted.as_ref().is_some_and(|args| *args != current.args) {
            cx.state.live.topics[index] = Observation::default();
        }
        match wanted {
            None => {
                if current.active {
                    send(cx.commands, "unsub", topic, &Args::default())?;
                }
                cx.live.subscriptions[index] = Subscription::default();
                cx.state.live.topics[index].stale = true;
            }
            Some(args) if !current.active || (!current.pending && args != current.args) => {
                send(cx.commands, if current.active { "filter" } else { "sub" }, topic, &args)?;
                cx.live.subscriptions[index] = Subscription { active: true, pending: true, args };
                cx.state.live.topics[index].stale = true;
            }
            Some(_) => {}
        }
    }
    Ok(())
}

fn send(commands: &mut Commands, op: &str, topic: Topic, args: &Args) -> Result<(), UiError> {
    commands.emit(&mut |json| {
        json.begin_object()?;
        json.key("op")?;
        json.string("send")?;
        json.key("body")?;
        json.begin_object()?;
        json.key("op")?;
        json.string(op)?;
        json.key("topic")?;
        json.string(topic.name())?;
        json.key("args")?;
        args.encode(json)?;
        json.end_object()?;
        json.end_object()
    })
}

/// Handles a stream event (kind 4): the socket opened, closed or delivered a message.
/// Returns the statistics snapshot of a completed `stats` view, which the caller
/// accepts.
///
/// # Errors
///
/// [`UiError::InvalidResponse`] for a message event without a body or a view that is not
/// JSON, and write errors.
pub(crate) fn event(
    cx: &mut Context<'_>,
    value: &Value<'_>,
) -> Result<Option<StatsSnapshot>, UiError> {
    if !cx.state.is_full_access() || cx.live.suspended || cx.state.hidden {
        return Ok(None);
    }
    let kind = json::string(value, "state");
    if kind == "open" {
        cx.live.opening = false;
        cx.live.connected = true;
        return Ok(None);
    }
    if kind != "message" {
        let code = json::field(value, "code").and_then(json::integer);
        if code == Some(1008) {
            expire(cx)?;
        } else {
            failed(cx, value)?;
        }
        return Ok(None);
    }
    let body = json::field(value, "body").ok_or(UiError::InvalidResponse)?;
    let topic = match cx.live.client.receive(body) {
        Err(_) => {
            failed(cx, value)?;
            return Ok(None);
        }
        Ok(Event::None) => return Ok(None),
        Ok(Event::Unauthorized) => {
            expire(cx)?;
            return Ok(None);
        }
        Ok(Event::Gap(topic)) => {
            cx.live.subscriptions[topic.index()].active = false;
            cx.state.live.topic_mut(topic).stale = true;
            return Ok(None);
        }
        Ok(Event::Changed(topic)) => topic,
    };
    changed(cx, value, topic)
}

/// Publishes the completed view of `topic` if it still belongs to the current filter.
fn changed(
    cx: &mut Context<'_>,
    value: &Value<'_>,
    topic: Topic,
) -> Result<Option<StatsSnapshot>, UiError> {
    let index = topic.index();
    cx.live.subscriptions[index].pending = false;
    let Some(args) = desired(cx, topic) else { return Ok(None) };
    let subscription = &cx.live.subscriptions[index];
    if !subscription.active || args != subscription.args {
        return Ok(None);
    }
    let text = cx.live.client.view(topic).to_owned();
    let view = sibuna_json::parse_with_limits(text.as_bytes(), &json::limits(text.len()))
        .map_err(|_| UiError::InvalidResponse)?;
    match publish(cx, topic, &view) {
        Ok(snapshot) => {
            cx.state.reconnect_ms = 1000;
            Ok(snapshot)
        }
        Err(_) => {
            failed(cx, value)?;
            Ok(None)
        }
    }
}

/// Closes the connection after a failure and schedules a jittered retry.
///
/// # Errors
///
/// [`UiError::Write`] if a command cannot be written.
pub(crate) fn failed(cx: &mut Context<'_>, value: &Value<'_>) -> Result<(), UiError> {
    cx.live.stop(cx.commands)?;
    cx.live.retry = true;
    cx.state.live.mark_stale();
    cx.state.stale = true;
    cx.pages.connection_lost(cx.state);
    let entropy = json::field(value, "entropy").and_then(json::integer);
    // The bridge sends a 32-bit random value; Zig kept its low 32 bits.
    let random = entropy.and_then(|number| u64::try_from(number).ok()).unwrap_or(0) as u32;
    let base = cx.state.reconnect_ms;
    let delay = base / 2 + random % (base / 2 + 1);
    cx.commands.timer("live-retry", u64::from(delay))?;
    cx.state.reconnect_ms = base.saturating_mul(2).min(30_000);
    Ok(())
}

/// Ends the session after the server revoked it.
fn expire(cx: &mut Context<'_>) -> Result<(), UiError> {
    cx.end_session(SESSION_ENDED)
}

/// Applies a completed view to the state and the modules.
fn publish(
    cx: &mut Context<'_>,
    topic: Topic,
    view: &Value<'_>,
) -> Result<Option<StatsSnapshot>, UiError> {
    let browser_time = cx.state.browser_time;
    let available = match json::field(view, "available") {
        None => true,
        Some(flag) => flag.as_bool().ok_or(UiError::InvalidResponse)?,
    };
    let observation = cx.state.live.topic_mut(topic);
    observation.received_at = browser_time;
    observation.stale = false;
    observation.available = available;
    match topic {
        Topic::Stats => {
            let decoded = dashboard::View::decode(view, Path::Root)?;
            cx.state.dashboard_scope = Some(decoded.scope);
            if !available {
                cx.state.stats = None;
                cx.state.points.clear();
            }
            return Ok(decoded.value);
        }
        Topic::Policy => {
            if available {
                let read = |key| json::field(view, key).and_then(json::counter);
                cx.state.live.committed = read("committed").ok_or(UiError::InvalidResponse)?;
                cx.state.live.applied = read("applied").ok_or(UiError::InvalidResponse)?;
            }
            return Ok(None);
        }
        Topic::Nodes | Topic::Challenges if !available => return Ok(None),
        Topic::Nodes | Topic::Challenges => {}
        Topic::Events | Topic::Audit => coverage(cx.state, topic, view)?,
    }
    cx.every(&mut |page, cx| page.publish(cx, topic, view))?;
    Ok(None)
}

/// Reads the coverage of a row topic's view into its observation.
fn coverage(state: &mut State, topic: Topic, view: &Value<'_>) -> Result<(), UiError> {
    let coverage = json::field(view, "coverage").ok_or(UiError::InvalidResponse)?;
    let available = json::field(coverage, "available").and_then(Value::as_bool);
    let read = |key| json::field(coverage, key).and_then(json::counter);
    let observation = state.live.topic_mut(topic);
    observation.available = available.ok_or(UiError::InvalidResponse)?;
    observation.observed_at = read("observed_at").ok_or(UiError::InvalidResponse)?;
    observation.missing_ids = read("missing_ids").ok_or(UiError::InvalidResponse)?;
    observation.newer = 0;
    Ok(())
}

/// Returns the freshness label of an observation.
pub fn status(observation: &Observation) -> &'static str {
    if observation.received_at == 0 {
        "Waiting for live updates"
    } else if observation.stale {
        "Disconnected / stale"
    } else if !observation.available {
        "Observations unavailable"
    } else {
        "Live"
    }
}

/// Draws the "Live updates" note of `topic`: its freshness, and for row topics the rows
/// newer than the page and the feed's gaps, and for `policy` the revisions.
///
/// # Errors
///
/// The sink's error.
pub fn render_status(state: &State, topic: Topic, out: &mut Html<'_>) -> fmt::Result {
    let value = state.live.topic(topic);
    let age = |at: u64| if at == 0 { 0 } else { state.browser_time.saturating_sub(at) };
    out.write_str("<section class=\"sb-note my-4\" aria-label=\"Live updates\"><p>")?;
    write_value(out, &status(value))?;
    out.write_str(" \u{b7} Last update ")?;
    write_value(out, &age(value.received_at))?;
    out.write_str(" seconds ago.</p>")?;
    if topic == Topic::Events || topic == Topic::Audit {
        out.write_str("<p>")?;
        write_value(out, &value.newer)?;
        out.write_str(
            " recent summaries newer than this page. Rows stay in place while you read. \
             <button class=\"btn btn-sm\" data-action=\"",
        )?;
        let action = if topic == Topic::Events { "events-refresh" } else { "audit-refresh" };
        write_value(out, &action)?;
        out.write_str(
            "\">Load latest records</button></p><p>At most 64 summaries retained in the live \
             feed; this is not a total count. ",
        )?;
        write_value(out, &value.missing_ids)?;
        out.write_str(
            " unavailable source IDs, including expired history. Storage observation age: ",
        )?;
        write_value(out, &age(value.observed_at))?;
        out.write_str(" seconds.</p>")?;
    }
    if topic == Topic::Policy && value.available {
        out.write_str("<p>Current committed revision ")?;
        write_value(out, &state.live.committed)?;
        out.write_str("; applied revision ")?;
        write_value(out, &state.live.applied)?;
        out.write_str(
            ". Refresh to review newer policy. An open draft keeps its reviewed revision.</p>",
        )?;
    }
    out.write_str("</section>")
}

#[cfg(test)]
mod tests;
