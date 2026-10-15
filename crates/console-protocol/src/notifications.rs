//! Notification destinations, queued events and operator settings. Destination pages carry
//! four rows; a claim owns one delivery. Secret values never cross this boundary in the
//! clear, only inside a sealed envelope.

use std::fmt::{self, Write};

use sibuna_json::{Value, Writer};

use crate::codec::{
    Decode, DecodeError, Encode, Fields, Path, WireEnum, counter_field, decode_list, field,
    optional_counter, optional_counter_field,
};
use crate::error::{MAX_I64, ValidationError, limit};
use crate::retention::Lease;
use crate::settings;
use crate::text::Text;
use crate::users;

/// The most destinations.
pub const CAPACITY: usize = 8;
/// Destinations per page.
pub const PAGE_ROWS: usize = 4;
/// The most queued events.
pub const QUEUE_CAPACITY: usize = 256;
/// Delivery attempts per event and destination.
pub const MAX_ATTEMPTS: u32 = 3;
/// Deliveries kept in history.
pub const HISTORY_CAPACITY: usize = 4096;
/// How long delivery history is kept, in days.
pub const HISTORY_DAYS: u64 = 7;
/// Seconds kept free before a lease expires when claiming a delivery.
pub const CLAIM_MARGIN_SECONDS: u64 = 12;
/// The longest destination label.
pub const MAX_LABEL: usize = 64;
/// The longest destination target.
pub const MAX_TARGET: usize = 256;
/// The longest target host.
pub const MAX_HOST: usize = 128;
/// The longest delivery detail.
pub const MAX_DETAIL: usize = 96;
/// The longest secret.
pub const MAX_SECRET: usize = 64;
/// The longest sealed secret envelope.
pub const MAX_ENVELOPE: usize = 256;
/// The longest setting key.
pub const MAX_SETTING_KEY: usize = 64;
/// The longest setting value: numeric catalog values have at most seven digits.
pub const MAX_SETTING_VALUE: usize = 7;
/// Every setting key.
pub const KNOWN_SETTINGS: [&str; settings::KEYS.len()] = settings::KEYS;

/// Something a destination can be notified of.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Event {
    /// Denials rose above the spike threshold.
    #[default]
    DenialSpike,
    /// An address was banned.
    Ban,
    /// A node became unhealthy.
    NodeUnhealthy,
    /// The cluster leader changed.
    LeaderChange,
}

impl Event {
    /// Returns this event's bit in an event set.
    pub fn bit(self) -> u8 {
        1 << self.ordinal()
    }
}

impl WireEnum for Event {
    const ALL: &'static [Event] =
        &[Event::DenialSpike, Event::Ban, Event::NodeUnhealthy, Event::LeaderChange];

    fn name(self) -> &'static str {
        match self {
            Event::DenialSpike => "denial_spike",
            Event::Ban => "ban",
            Event::NodeUnhealthy => "node_unhealthy",
            Event::LeaderChange => "leader_change",
        }
    }
}

/// Every event bit.
pub const ALL_EVENTS: u8 = 15;

/// How a destination is reached.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Kind {
    /// An HTTPS webhook.
    #[default]
    Webhook,
    /// A syslog receiver.
    Syslog,
}

impl WireEnum for Kind {
    const ALL: &'static [Kind] = &[Kind::Webhook, Kind::Syslog];

    fn name(self) -> &'static str {
        match self {
            Kind::Webhook => "webhook",
            Kind::Syslog => "syslog",
        }
    }
}

/// The syslog transport.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Transport {
    /// UDP (also the value for webhooks).
    #[default]
    Udp,
    /// TCP.
    Tcp,
}

impl WireEnum for Transport {
    const ALL: &'static [Transport] = &[Transport::Udp, Transport::Tcp];

    fn name(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        }
    }
}

/// A delivery's result.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// Delivered.
    #[default]
    Delivered,
    /// Failed.
    Failed,
}

impl WireEnum for Outcome {
    const ALL: &'static [Outcome] = &[Outcome::Delivered, Outcome::Failed];

    fn name(self) -> &'static str {
        match self {
            Outcome::Delivered => "delivered",
            Outcome::Failed => "failed",
        }
    }
}

/// A notification destination.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Destination {
    /// The destination id.
    pub id: u64,
    /// The destination revision.
    pub revision: u64,
    /// How it is reached.
    pub kind: Kind,
    /// The syslog transport.
    pub transport: Transport,
    /// A display label.
    pub label: Text<MAX_LABEL>,
    /// The webhook URL or syslog address.
    pub target: Text<MAX_TARGET>,
    /// The target's host, for display.
    pub target_host: Text<MAX_HOST>,
    /// A secret is configured.
    pub secret_set: bool,
    /// The event bits it receives.
    pub events: u8,
    /// The least time between deliveries, in seconds.
    pub cooldown_seconds: u32,
    /// Deliveries are enabled.
    pub enabled: bool,
    /// The last attempt, in Unix seconds.
    pub last_attempt_at: Option<u64>,
    /// The last attempt's result.
    pub last_outcome: Option<Outcome>,
    /// The last attempt's detail.
    pub last_detail: Text<MAX_DETAIL>,
}

impl Encode for Destination {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        counter_field(json, "id", self.id)?;
        counter_field(json, "revision", self.revision)?;
        field(json, "kind", &self.kind)?;
        field(json, "transport", &self.transport)?;
        field(json, "label", &self.label)?;
        field(json, "target", &self.target)?;
        field(json, "target_host", &self.target_host)?;
        field(json, "secret_set", &self.secret_set)?;
        field(json, "events", &self.events)?;
        field(json, "cooldown_seconds", &self.cooldown_seconds)?;
        field(json, "enabled", &self.enabled)?;
        optional_counter_field(json, "last_attempt_at", self.last_attempt_at)?;
        field(json, "last_outcome", &self.last_outcome)?;
        field(json, "last_detail", &self.last_detail)?;
        json.end_object()
    }
}

impl Decode for Destination {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Destination, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let destination = Destination {
            id: fields.required("id")?,
            revision: fields.required("revision")?,
            kind: fields.required("kind")?,
            transport: fields.or_default("transport")?,
            label: fields.required("label")?,
            target: fields.required("target")?,
            target_host: fields.required("target_host")?,
            secret_set: fields.required("secret_set")?,
            events: fields.required("events")?,
            cooldown_seconds: fields.required("cooldown_seconds")?,
            enabled: fields.required("enabled")?,
            last_attempt_at: fields.required("last_attempt_at")?,
            last_outcome: fields.required("last_outcome")?,
            last_detail: fields.required("last_detail")?,
        };
        fields.finish()?;
        Ok(destination)
    }
}

/// A page of destinations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Page {
    /// At most [`PAGE_ROWS`] destinations.
    pub rows: Vec<Destination>,
    /// The id to continue after, if more exist.
    pub next: Option<u64>,
}

impl Encode for Page {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "rows", &self.rows)?;
        json.key("next")?;
        optional_counter(json, self.next)?;
        json.end_object()
    }
}

impl Decode for Page {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Page, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let page = Page {
            rows: fields
                .required_with("rows", |value, path| decode_list(value, path, PAGE_ROWS))?,
            next: fields.required("next")?,
        };
        fields.finish()?;
        Ok(page)
    }
}

/// Destination pages and sealed secrets are read by an administrator session or, for
/// deliveries, by the notifier under its fenced lease; the lease takes precedence.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Query {
    /// The administrator's credential.
    pub auth: users::Auth,
    /// The last id of the previous page.
    pub after: u64,
    /// The notifier's lease.
    pub lease: Option<Lease>,
}

/// Creates or changes a destination.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Save {
    /// The administrator's credential.
    pub auth: users::Auth,
    /// The destination id; `None` creates one.
    pub id: Option<u64>,
    /// The revision the administrator saw.
    pub expected_revision: u64,
    /// How it is reached.
    pub kind: Kind,
    /// The syslog transport; UDP for webhooks.
    pub transport: Transport,
    /// A display label.
    pub label: Text<MAX_LABEL>,
    /// The webhook URL or syslog address.
    pub target: Text<MAX_TARGET>,
    /// The target's host.
    pub target_host: Text<MAX_HOST>,
    /// A new sealed secret.
    pub secret_envelope: Option<Text<MAX_ENVELOPE>>,
    /// Remove the secret.
    pub clear_secret: bool,
    /// The event bits, 1 to [`ALL_EVENTS`].
    pub events: u8,
    /// The least time between deliveries, at most a day.
    pub cooldown_seconds: u32,
    /// Deliveries are enabled.
    pub enabled: bool,
}

/// Records a test delivery. Intent and completion share an opaque operation id; network
/// success is separate from confirmation that its completion record reached storage.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TestAudit {
    /// The administrator's credential.
    pub auth: users::Auth,
    /// The destination id.
    pub destination: u64,
    /// The destination revision.
    pub revision: u64,
    /// The operation id.
    pub operation: [u8; 16],
    /// The result, once known.
    pub outcome: Option<Outcome>,
    /// The result's detail.
    pub detail: Text<MAX_DETAIL>,
}

/// Removes a destination.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Remove {
    /// The administrator's credential.
    pub auth: users::Auth,
    /// The destination id.
    pub id: u64,
    /// The revision the administrator saw.
    pub expected_revision: u64,
}

/// Reads a destination's sealed secret.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Read {
    /// The administrator's credential.
    pub auth: users::Auth,
    /// The destination id.
    pub id: u64,
    /// The destination revision.
    pub revision: u64,
    /// The notifier's lease.
    pub lease: Option<Lease>,
}

/// A destination's sealed secret.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Secret {
    /// How it is reached.
    pub kind: Kind,
    /// The webhook URL or syslog address.
    pub target: Text<MAX_TARGET>,
    /// The sealed secret, if any.
    pub envelope: Option<Text<MAX_ENVELOPE>>,
}

/// Queues an event.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Enqueue {
    /// The raising node.
    pub node: u32,
    /// The node's boot id.
    pub boot: [u8; 16],
    /// The event's sequence within the boot.
    pub sequence: u64,
    /// The event.
    pub event: Event,
    /// When it was raised, in Unix seconds.
    pub raised_at: u64,
    /// The event's detail.
    pub detail: Text<MAX_DETAIL>,
}

/// A queued event.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pending {
    /// The queue id.
    pub id: u64,
    /// The raising node.
    pub node: u32,
    /// The event.
    pub event: Event,
    /// When it was raised, in Unix seconds.
    pub raised_at: u64,
    /// The event's detail.
    pub detail: Text<MAX_DETAIL>,
    /// Attempts so far.
    pub attempts: u32,
}

/// A claimed delivery; it owns all its inputs. Retargeting invalidates the revision before
/// another attempt.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Claimed {
    /// The delivery id.
    pub delivery_id: u64,
    /// The event.
    pub event: Pending,
    /// The destination.
    pub destination: Destination,
}

/// Claims the next delivery under the notifier's lease.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Claim {
    /// The notifier's lease.
    pub lease: Lease,
}

/// Records a delivery attempt.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Record {
    /// The notifier's lease.
    pub lease: Lease,
    /// The delivery id.
    pub delivery_id: u64,
    /// The attempt number.
    pub attempt: u32,
    /// The attempt succeeded.
    pub delivered: bool,
    /// The attempt's detail.
    pub detail: Text<MAX_DETAIL>,
}

/// One stored setting.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Setting {
    /// The key.
    pub key: Text<MAX_SETTING_KEY>,
    /// The value, in decimal.
    pub value: Text<MAX_SETTING_VALUE>,
    /// The setting revision.
    pub revision: u64,
    /// When it changed, in Unix seconds.
    pub updated_at: u64,
    /// The changing account.
    pub updated_by: u64,
}

impl Encode for Setting {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        json.begin_object()?;
        field(json, "key", &self.key)?;
        field(json, "value", &self.value)?;
        counter_field(json, "revision", self.revision)?;
        counter_field(json, "updated_at", self.updated_at)?;
        counter_field(json, "updated_by", self.updated_by)?;
        json.end_object()
    }
}

impl Decode for Setting {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<Setting, DecodeError> {
        let mut fields = Fields::new(value, path)?;
        let setting = Setting {
            key: fields.required("key")?,
            value: fields.required("value")?,
            revision: fields.required("revision")?,
            updated_at: fields.required("updated_at")?,
            updated_by: fields.required("updated_by")?,
        };
        fields.finish()?;
        Ok(setting)
    }
}

/// Every stored setting, written as a bare array.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SettingsPage {
    /// At most one row per known setting.
    pub rows: Vec<Setting>,
}

impl Encode for SettingsPage {
    fn encode<W: Write>(&self, json: &mut Writer<W>) -> fmt::Result {
        self.rows.encode(json)
    }
}

impl Decode for SettingsPage {
    fn decode(value: &Value<'_>, path: Path<'_>) -> Result<SettingsPage, DecodeError> {
        Ok(SettingsPage { rows: decode_list(value, path, KNOWN_SETTINGS.len())? })
    }
}

/// Changes a setting.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SettingChange {
    /// The administrator confirmed a disruptive change.
    pub confirmed: bool,
    /// The administrator's credential.
    pub auth: users::Auth,
    /// The key.
    pub key: Text<MAX_SETTING_KEY>,
    /// The new value.
    pub value: Text<MAX_SETTING_VALUE>,
    /// The revision the administrator saw.
    pub expected_revision: u64,
}

/// Returns true if `key` is a setting.
pub fn known_setting(key: &str) -> bool {
    settings::definition(key).is_some()
}

/// Checks a destination save.
///
/// # Errors
///
/// [`ValidationError::InvalidLimit`] for no or unknown events, a cooldown over a day, an
/// empty label or target, an oversized revision, TCP for a webhook, or both a new secret
/// and a cleared one.
pub fn validate_save(input: &Save) -> Result<(), ValidationError> {
    limit(
        input.events == 0
            || input.events > ALL_EVENTS
            || input.cooldown_seconds > 86_400
            || input.label.is_empty()
            || input.target.is_empty()
            || input.expected_revision >= MAX_I64,
    )?;
    limit(input.kind == Kind::Webhook && input.transport != Transport::Udp)?;
    limit(input.secret_envelope.is_some() && input.clear_secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_json, to_json};

    // Port of notifications.zig "destination saves are bounded and secrets are either
    // supplied or cleared".
    #[test]
    fn destination_saves_are_bounded_and_secrets_are_either_supplied_or_cleared() {
        let mut save = Save {
            auth: users::Auth { session_digest: [1; 32], ..users::Auth::default() },
            kind: Kind::Webhook,
            label: Text::new("ops").unwrap(),
            target: Text::new("https://hooks.example/x").unwrap(),
            target_host: Text::new("hooks.example").unwrap(),
            events: Event::Ban.bit() | Event::DenialSpike.bit(),
            cooldown_seconds: 60,
            enabled: true,
            ..Save::default()
        };
        assert_eq!(validate_save(&save), Ok(()));
        save.events = 16;
        assert_eq!(validate_save(&save), Err(ValidationError::InvalidLimit));
        save.events = 1;
        save.clear_secret = true;
        save.secret_envelope = Some(Text::default());
        assert_eq!(validate_save(&save), Err(ValidationError::InvalidLimit));
        assert!(known_setting("notify.spike_factor") && !known_setting("notify.other"));
    }

    #[test]
    fn pages_round_trip() {
        let page = Page {
            rows: vec![Destination {
                id: 1,
                kind: Kind::Syslog,
                transport: Transport::Tcp,
                events: ALL_EVENTS,
                last_outcome: Some(Outcome::Failed),
                last_attempt_at: Some(5),
                ..Destination::default()
            }],
            next: None,
        };
        let text = to_json(&page);
        assert!(text.starts_with(
            "{\"rows\":[{\"id\":1,\"revision\":0,\"kind\":\"syslog\",\"transport\":\"tcp\","
        ));
        assert_eq!(from_json::<Page>(text.as_bytes()), Ok(page));
        let settings = SettingsPage {
            rows: vec![Setting {
                key: Text::new("retention.audit").unwrap(),
                value: Text::new("30").unwrap(),
                ..Setting::default()
            }],
        };
        let text = to_json(&settings);
        assert_eq!(
            text,
            "[{\"key\":\"retention.audit\",\"value\":\"30\",\"revision\":0,\"updated_at\":0,\
             \"updated_by\":0}]"
        );
        assert_eq!(from_json::<SettingsPage>(text.as_bytes()), Ok(settings));
    }
}
